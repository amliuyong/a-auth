use super::{database, tenant};
use agent_auth_http::security_event::{
    MemorySecurityEventStore, SecurityActor, SecurityEvent, SecurityEventCategory,
    SecurityEventCorrelation, SecurityEventCursor, SecurityEventDelivery,
    SecurityEventDeliveryStatus, SecurityEventOutcome, SecurityEventStore, SecuritySubject,
};
use std::sync::Arc;
use tokio::sync::Barrier;

fn event(tenant: &str, id: &str, at: i64) -> SecurityEvent {
    SecurityEvent::new_at(
        id,
        at,
        tenant,
        SecurityActor::admin("administrator"),
        Some(SecuritySubject::user("canonical-user")),
        SecurityEventCategory::UserLifecycle,
        "user.disable",
        SecurityEventOutcome::Success,
        SecurityEventCorrelation {
            operation_id: Some("operation-reference".into()),
            ..Default::default()
        },
    )
    .unwrap()
}

async fn security_event_contract(store: impl SecurityEventStore + Clone + 'static) {
    let tenant = tenant();
    let other = format!("{tenant}-other");
    let now = agent_auth_http::current_unix_secs();
    let first = event(&tenant, &format!("evt_{tenant}_0"), now);
    let delivery = SecurityEventDelivery::pending(now);
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, first, delivery, barrier) = (
            store.clone(),
            first.clone(),
            delivery.clone(),
            barrier.clone(),
        );
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.put_with_delivery(&first, &delivery).await.unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap());
    }
    assert_eq!(winners, 1, "one immutable event admission wins");
    assert!(!store.put_with_delivery(&first, &delivery).await.unwrap());
    let initial = store.list_by_tenant(&tenant, now, now, 10).await.unwrap();
    assert_eq!(initial.len(), 1);
    assert_eq!(initial[0].event, first.clone());
    assert_eq!(initial[0].delivery, delivery);
    assert!(store
        .list_by_tenant(&other, now, now + 10, 10)
        .await
        .unwrap()
        .is_empty());

    let mut extension = delivery.clone();
    extension.start_attempt(now + 1);
    extension.record(SecurityEventDeliveryStatus::Failed, now + 2);
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, first, extension, barrier) = (
            store.clone(),
            first.clone(),
            extension.clone(),
            barrier.clone(),
        );
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            assert!(!store.put_with_delivery(&first, &extension).await.unwrap());
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let mut expected_delivery = delivery.clone();
    expected_delivery.attempts = 1;
    expected_delivery.history = extension.history.clone();
    let merged = store.list_by_tenant(&tenant, now, now, 10).await.unwrap();
    assert_eq!(merged[0].event, first);
    assert_eq!(
        merged[0].delivery, expected_delivery,
        "concurrent duplicate ingress must accumulate one source-history extension"
    );
    assert!(!store.put_with_delivery(&first, &delivery).await.unwrap());
    let mut equivalent_retry = extension.clone();
    equivalent_retry.history[1].occurred_at += 99;
    assert!(!store
        .put_with_delivery(&first, &equivalent_retry)
        .await
        .unwrap());
    extension.record(SecurityEventDeliveryStatus::Retrying, now + 3);
    assert!(!store.put_with_delivery(&first, &extension).await.unwrap());
    assert!(!store.put_with_delivery(&first, &extension).await.unwrap());
    expected_delivery.history = extension.history.clone();
    assert_eq!(
        store.list_by_tenant(&tenant, now, now, 10).await.unwrap()[0].delivery,
        expected_delivery,
        "same-attempt history extensions do not duplicate evidence or increment attempts"
    );
    let mut divergent = extension.clone();
    divergent.history[1].status = SecurityEventDeliveryStatus::Failed;
    assert!(matches!(
        store.put_with_delivery(&first, &divergent).await,
        Err(agent_auth_http::ports::StoreError::Permanent(_))
    ));
    let mut collision = first.clone();
    collision.action = "user.enable".into();
    assert!(matches!(
        store.put_with_delivery(&collision, &extension).await,
        Err(agent_auth_http::ports::StoreError::Permanent(_))
    ));
    let preserved = store.list_by_tenant(&tenant, now, now, 10).await.unwrap();
    assert_eq!(preserved[0].event, first);
    assert_eq!(preserved[0].delivery, expected_delivery);

    let mut expected = vec![first];
    for index in 1..5 {
        let next = event(&tenant, &format!("evt_{tenant}_{index}"), now + index);
        assert!(store.put(&next).await.unwrap());
        expected.push(next);
    }
    let foreign = event(&other, &format!("evt_{other}"), now + 1);
    assert!(store.put(&foreign).await.unwrap());
    expected.reverse();
    assert_eq!(
        store
            .list_by_tenant(&tenant, now + 1, now + 3, 10)
            .await
            .unwrap()
            .into_iter()
            .map(|stored| stored.event)
            .collect::<Vec<_>>(),
        expected[1..4]
    );
    let mut actual = Vec::new();
    let mut cursor = None;
    loop {
        let page = store
            .list_by_tenant_page(&tenant, now, now + 4, 2, cursor.as_ref())
            .await
            .unwrap();
        actual.extend(page.events.into_iter().map(|stored| stored.event));
        let Some(encoded) = page.next_cursor else {
            break;
        };
        cursor =
            Some(SecurityEventCursor::decode_for_query(&encoded, &tenant, now, now + 4).unwrap());
    }
    assert_eq!(
        actual, expected,
        "pagination retains every event exactly once"
    );
    let first_page = store
        .list_by_tenant_page(&tenant, now, now + 4, 1, None)
        .await
        .unwrap();
    let cursor = SecurityEventCursor::decode_for_query(
        first_page.next_cursor.as_deref().unwrap(),
        &tenant,
        now,
        now + 4,
    )
    .unwrap();
    assert!(store
        .list_by_tenant_page(&other, now, now + 4, 1, Some(&cursor))
        .await
        .is_err());
    let default = event("", &format!("evt_{tenant}_default"), now);
    assert!(store.put(&default).await.unwrap());
    assert!(store
        .list_by_tenant("", now, now, 1000)
        .await
        .unwrap()
        .iter()
        .any(|stored| stored.event == default));

    // A trusted archived-delivery fixture tests reopening the ledger, without
    // claiming that this raw port test created an archive object.
    let at = now - 10;
    let archived_event = event(&tenant, &format!("evt_{tenant}_archive"), at);
    let mut archived = SecurityEventDelivery::pending(at);
    archived.record(SecurityEventDeliveryStatus::Archived, at + 1);
    assert!(store
        .put_with_delivery(&archived_event, &archived)
        .await
        .unwrap());
    let mut late = archived.clone();
    late.start_attempt(at + 2);
    late.record(SecurityEventDeliveryStatus::Failed, at + 3);
    let before = agent_auth_http::current_unix_secs();
    assert!(!store
        .put_with_delivery(&archived_event, &late)
        .await
        .unwrap());
    let refreshed = store
        .list_by_tenant(&tenant, at, at, 10)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(refreshed.event, archived_event);
    assert_eq!(
        refreshed.delivery.status,
        SecurityEventDeliveryStatus::ArchiveRefreshPending
    );
    assert_eq!(refreshed.delivery.attempts, 1);
    assert_eq!(
        &refreshed.delivery.history[..late.history.len()],
        &late.history
    );
    let marker = refreshed.delivery.history.last().unwrap();
    assert_eq!(
        marker.status,
        SecurityEventDeliveryStatus::ArchiveRefreshPending
    );
    assert!(
        marker.occurred_at >= before && marker.occurred_at <= agent_auth_http::current_unix_secs()
    );
    assert_eq!(refreshed.delivery.last_attempt_at, Some(marker.occurred_at));
    assert!(!store
        .put_with_delivery(&archived_event, &late)
        .await
        .unwrap());
    assert_eq!(
        store.list_by_tenant(&tenant, at, at, 10).await.unwrap()[0],
        refreshed,
        "replaying a late snapshot must not add another archive-refresh marker"
    );
    late.record(SecurityEventDeliveryStatus::Retrying, at + 4);
    assert!(!store
        .put_with_delivery(&archived_event, &late)
        .await
        .unwrap());
    let pending = store
        .list_by_tenant(&tenant, at, at, 10)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(pending.delivery.attempts, 1);
    assert_eq!(
        pending.delivery.history.len(),
        refreshed.delivery.history.len() + 2
    );
    assert_eq!(
        pending.delivery.history[pending.delivery.history.len() - 2].status,
        SecurityEventDeliveryStatus::Retrying
    );
    assert_eq!(
        pending.delivery.history.last().unwrap().status,
        SecurityEventDeliveryStatus::ArchiveRefreshPending
    );
}

#[tokio::test]
async fn memory_security_event_contract() {
    security_event_contract(MemorySecurityEventStore::default()).await;
}

#[tokio::test]
async fn postgres_security_event_contract() {
    security_event_contract(database().await).await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_security_event_contract() {
    use agent_auth_http::adapters::aws::DynamoSecurityEventStore;
    use aws_sdk_dynamodb::types::{
        AttributeDefinition, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
        ProjectionType, ScalarAttributeType,
    };
    let attributes = vec![
        AttributeDefinition::builder()
            .attribute_name("tenant_id")
            .attribute_type(ScalarAttributeType::S)
            .build()
            .unwrap(),
        AttributeDefinition::builder()
            .attribute_name("occurred_at")
            .attribute_type(ScalarAttributeType::N)
            .build()
            .unwrap(),
    ];
    let index = GlobalSecondaryIndex::builder()
        .index_name("tenant_occurred_at-index")
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("tenant_id")
                .key_type(KeyType::Hash)
                .build()
                .unwrap(),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("occurred_at")
                .key_type(KeyType::Range)
                .build()
                .unwrap(),
        )
        .projection(
            Projection::builder()
                .projection_type(ProjectionType::All)
                .build(),
        )
        .build()
        .unwrap();
    let (db, table) =
        super::aws_contract_database::table("event_id", attributes, vec![index]).await;
    security_event_contract(DynamoSecurityEventStore::new(db.clone(), &table)).await;
    db.delete_table().table_name(table).send().await.unwrap();
}

#[tokio::test]
async fn postgres_security_event_reconciliation_rolls_back_and_rejects_corrupt_authority() {
    use agent_auth_http::ports::StoreError;
    let store = database().await;
    let tenant = tenant();
    let now = agent_auth_http::current_unix_secs();
    let event = event(&tenant, &format!("evt_{tenant}_atomic"), now);
    let initial = SecurityEventDelivery::pending(now);
    assert!(store.put_with_delivery(&event, &initial).await.unwrap());
    let pool = sqlx::PgPool::connect(&std::env::var("A_AUTH_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let constraint = format!("contract_event_{:032x}", rand::random::<u128>());
    sqlx::query(&format!(
        "ALTER TABLE a_auth.security_events ADD CONSTRAINT {constraint} \
         CHECK (event_id <> '{}' OR (delivery->>'attempts')::BIGINT = 0) NOT VALID",
        event.event_id
    ))
    .execute(&pool)
    .await
    .unwrap();
    let mut incoming = initial.clone();
    incoming.start_attempt(now + 1);
    incoming.record(SecurityEventDeliveryStatus::Failed, now + 2);
    let failed = store.put_with_delivery(&event, &incoming).await;
    sqlx::query(&format!(
        "ALTER TABLE a_auth.security_events DROP CONSTRAINT {constraint}"
    ))
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(failed, Err(StoreError::Permanent(_))));
    let preserved = store.list_by_tenant(&tenant, now, now, 10).await.unwrap();
    assert_eq!(preserved[0].event, event);
    assert_eq!(preserved[0].delivery, initial);
    assert!(!store.put_with_delivery(&event, &incoming).await.unwrap());
    let committed = store
        .list_by_tenant(&tenant, now, now, 10)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(
        committed.delivery.attempts, 1,
        "a failed write must not advance the hidden source receipt"
    );
    let older = self::event(&tenant, &format!("evt_{tenant}_older"), now - 1);
    let newer = self::event(&tenant, &format!("evt_{tenant}_newer"), now + 1);
    assert!(store.put(&older).await.unwrap());
    assert!(store.put(&newer).await.unwrap());
    for mutation in [
        r#"event = jsonb_set(event, '{schema_version}', '"private-record-sentinel"')"#,
        r#"event = jsonb_set(event, '{event_id}', '"different-id"')"#,
        r#"event = jsonb_set(event, '{action}', '"invalid action"')"#,
        r#"delivery = jsonb_set(delivery, '{status}', '"private-record-sentinel"')"#,
    ] {
        sqlx::query(&format!(
            "UPDATE a_auth.security_events SET {mutation} WHERE event_id = $1"
        ))
        .bind(&event.event_id)
        .execute(&pool)
        .await
        .unwrap();
        let error = store
            .put_with_delivery(&event, &incoming)
            .await
            .unwrap_err();
        let StoreError::Permanent(message) = error else {
            panic!("corrupt security event must fail permanently");
        };
        assert!(!message.contains("private-record-sentinel"));
        let first_page = store
            .list_by_tenant_page(&tenant, now - 1, now + 1, 1, None)
            .await
            .expect("a corrupt export row must not suppress neighboring evidence");
        assert_eq!(first_page.events.len(), 1);
        assert_eq!(first_page.events[0].event, newer);
        let cursor = SecurityEventCursor::decode_for_query(
            first_page.next_cursor.as_deref().unwrap(),
            &tenant,
            now - 1,
            now + 1,
        )
        .unwrap();
        let second_page = store
            .list_by_tenant_page(&tenant, now - 1, now + 1, 1, Some(&cursor))
            .await
            .unwrap();
        assert_eq!(second_page.events.len(), 1);
        assert_eq!(second_page.events[0].event, older);
        assert!(second_page.next_cursor.is_none());
        assert_eq!(
            store
                .list_by_tenant(&tenant, now - 1, now + 1, 2)
                .await
                .unwrap()
                .into_iter()
                .map(|stored| stored.event)
                .collect::<Vec<_>>(),
            vec![newer.clone(), older.clone()]
        );
        sqlx::query(
            "UPDATE a_auth.security_events SET event = $2, delivery = $3 WHERE event_id = $1",
        )
        .bind(&event.event_id)
        .bind(sqlx::types::Json(&event))
        .bind(sqlx::types::Json(&committed.delivery))
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query("DELETE FROM a_auth.security_events WHERE tenant = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}
