use super::tenant;
use agent_auth_http::{
    adapters::{
        mounted_crypto::EncryptionKeyring,
        postgres::{PostgresSsfStore, PostgresStore},
    },
    security_event::{
        SecurityActor, SecurityEvent, SecurityEventCategory, SecurityEventCorrelation,
        SecurityEventOutcome, SecuritySubject,
    },
    ssf::*,
};
use std::sync::Arc;
use tokio::sync::Barrier;

pub(super) fn stream(tenant: &str, id: &str) -> SsfStream {
    SsfStream::new(
        tenant,
        id,
        "https://receiver.example.test/ssf",
        "receiver-audience",
        vec![RISC_ACCOUNT_DISABLED_EVENT.into()],
        100,
    )
    .unwrap()
}

pub(super) fn event(tenant: &str, id: &str) -> SecurityEvent {
    SecurityEvent::new_at(
        id,
        100,
        tenant,
        SecurityActor::admin("administrator"),
        Some(SecuritySubject::user("canonical-user")),
        SecurityEventCategory::UserLifecycle,
        "user.disable",
        SecurityEventOutcome::Success,
        SecurityEventCorrelation::default(),
    )
    .unwrap()
}

async fn ssf_contract(store: impl SsfStore + Clone + 'static) {
    let tenant = tenant();
    let foreign = format!("{tenant}-foreign");
    let original = stream(&tenant, "stream");
    assert_eq!(store.get_stream(&tenant, "stream").await.unwrap(), None);
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, original, barrier) = (store.clone(), original.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.create_stream(original).await.unwrap()
        }));
    }
    let mut created = 0;
    for task in tasks {
        match task.await.unwrap() {
            SsfStreamCreateOutcome::Created(value) => {
                assert_eq!(value, original);
                created += 1;
            }
            SsfStreamCreateOutcome::AlreadyExists => {}
            other => panic!("unexpected stream admission: {other:?}"),
        }
    }
    assert_eq!(created, 1);
    assert_eq!(
        store.get_stream(&tenant, "stream").await.unwrap(),
        Some(original.clone())
    );
    assert_eq!(
        store.list_streams(&tenant).await.unwrap(),
        vec![original.clone()]
    );
    assert_eq!(store.get_stream(&foreign, "stream").await.unwrap(), None);

    let event = event(&tenant, "evt_ssf_contract");
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, event, barrier) = (store.clone(), event.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .enqueue_event(&event, "https://issuer.example.test", 100)
                .await
                .unwrap()
        }));
    }
    let mut admitted = Vec::new();
    for task in tasks {
        admitted.extend(task.await.unwrap());
    }
    assert_eq!(admitted.len(), 1);
    let delivery = admitted.pop().unwrap();
    assert_eq!(delivery.status, SsfDeliveryStatus::Pending);
    assert_eq!(delivery.stream_revision, 1);
    assert_eq!(
        store
            .get_delivery(&tenant, "stream", 1, &event.event_id)
            .await
            .unwrap(),
        Some(delivery)
    );
    assert_eq!(
        store
            .get_delivery(&foreign, "stream", 1, &event.event_id)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .enqueue_verification(
                &tenant,
                "stream",
                0,
                "verification",
                "https://issuer.example.test",
                None,
                101
            )
            .await
            .unwrap(),
        SsfVerificationOutcome::RevisionConflict {
            current_revision: 1
        }
    );
    let verification = store
        .enqueue_verification(
            &tenant,
            "stream",
            1,
            "verification",
            "https://issuer.example.test",
            Some("verification-state"),
            101,
        )
        .await
        .unwrap()
        .enqueued()
        .unwrap();
    assert_eq!(
        verification.payload,
        serde_json::json!({"state":"verification-state"})
    );
    assert!(store
        .enqueue_verification(
            &tenant,
            "stream",
            1,
            "verification",
            "https://issuer.example.test",
            None,
            101
        )
        .await
        .is_err());
    let first = store
        .list_deliveries(&tenant, "stream", 1, None)
        .await
        .unwrap();
    assert_eq!(first.deliveries.len(), 1);
    assert_eq!(first.deliveries[0].event_id, "verification");
    let cursor = SsfDeliveryCursor::decode_for_stream(
        first.next_cursor.as_ref().unwrap(),
        &tenant,
        "stream",
    )
    .unwrap();
    let second = store
        .list_deliveries(&tenant, "stream", 1, Some(&cursor))
        .await
        .unwrap();
    assert_eq!(second.deliveries.len(), 1);
    assert_eq!(second.deliveries[0].event_id, event.event_id);
    if let Some(encoded) = &second.next_cursor {
        // DynamoDB can return a continuation at an exact page boundary.
        // It must lead to an empty terminal page, never repeat a delivery.
        let after = SsfDeliveryCursor::decode_for_stream(encoded, &tenant, "stream").unwrap();
        let terminal = store
            .list_deliveries(&tenant, "stream", 1, Some(&after))
            .await
            .unwrap();
        assert!(terminal.deliveries.is_empty());
        assert_eq!(terminal.next_cursor, None);
    }
    assert!(store
        .list_deliveries(&foreign, "stream", 1, Some(&cursor))
        .await
        .is_err());

    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, barrier) = (store.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.acquire_due(102, 30, 1).await.unwrap()
        }));
    }
    let mut leases = Vec::new();
    for task in tasks {
        leases.extend(task.await.unwrap());
    }
    assert_eq!(
        leases.len(),
        2,
        "distinct workers share one claim per due delivery"
    );
    let event_lease = leases
        .iter()
        .find(|lease| lease.delivery.event_id == event.event_id)
        .unwrap()
        .clone();
    let verification_lease = leases
        .iter()
        .find(|lease| lease.delivery.event_id == "verification")
        .unwrap()
        .clone();
    let signed = SignedSet {
        compact_jws: "fixture-header.fixture-payload.fixture-signature".into(),
        jti: "signed-event-id".into(),
        kid: "fixture-signing-key".into(),
    };
    assert!(store
        .persist_signed_set(&event_lease, &signed, 103, 103)
        .await
        .unwrap());
    assert!(!store
        .persist_signed_set(&event_lease, &signed, 103, 103)
        .await
        .unwrap());
    let persisted = store
        .get_delivery(&tenant, "stream", 1, &event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(persisted.compact_set, Some(signed.compact_jws.clone()));
    assert_eq!(persisted.signing_kid, Some(signed.kid.clone()));
    let receipt = store
        .finish_attempt(&event_lease, SsfAttemptResult::Accepted, 104)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.status, SsfDeliveryStatus::Delivered);
    assert_eq!(receipt.attempts, 1);
    assert_eq!(receipt.attempt_history.len(), 1);
    assert_eq!(
        receipt.attempt_history[0].outcome,
        SsfDeliveryAttemptOutcome::Accepted
    );
    assert!(store
        .finish_attempt(&event_lease, SsfAttemptResult::Accepted, 104)
        .await
        .unwrap()
        .is_none());
    assert!(store
        .persist_signed_set(&verification_lease, &signed, 103, 103)
        .await
        .unwrap());
    let terminal = store
        .finish_attempt(
            &verification_lease,
            SsfAttemptResult::Terminal {
                status_code: 410,
                error_class: "receiver-terminal".into(),
            },
            104,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(terminal.status, SsfDeliveryStatus::Terminal);
    let redriven = match store
        .redrive_delivery(&tenant, "stream", 1, "verification", 105)
        .await
        .unwrap()
    {
        SsfRedriveOutcome::Redriven(value) => value,
        other => panic!("unexpected redrive: {other:?}"),
    };
    assert_eq!((redriven.redrive_count, redriven.cycle_attempts), (1, 0));
    assert_eq!(redriven.attempt_history.len(), 1);
    let next = store.acquire_due(105, 10, 1).await.unwrap().pop().unwrap();
    assert!(!store
        .persist_signed_set(&verification_lease, &signed, 105, 105)
        .await
        .unwrap());
    assert!(store
        .finish_attempt(&verification_lease, SsfAttemptResult::Accepted, 105)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        store
            .mutate_stream(&tenant, "stream", 0, SsfStreamMutation::Pause, 106)
            .await
            .unwrap(),
        SsfStreamMutationOutcome::RevisionConflict {
            current_revision: 1
        }
    );
    let paused = store
        .mutate_stream(&tenant, "stream", 1, SsfStreamMutation::Pause, 106)
        .await
        .unwrap()
        .updated()
        .unwrap();
    assert_eq!(
        (paused.revision, paused.status),
        (2, SsfStreamStatus::Paused)
    );
    assert!(!store
        .persist_signed_set(&next, &signed, 107, 107)
        .await
        .unwrap());
    assert!(store.acquire_due(116, 10, 100).await.unwrap().is_empty());
    assert_eq!(
        store
            .get_delivery(&tenant, "stream", 1, "verification")
            .await
            .unwrap()
            .unwrap()
            .status,
        SsfDeliveryStatus::Suppressed
    );
    let resumed = store
        .mutate_stream(&tenant, "stream", 2, SsfStreamMutation::Resume, 117)
        .await
        .unwrap()
        .updated()
        .unwrap();
    assert_eq!((resumed.revision, resumed.activation_at), (3, 117));
    let replaced = store
        .mutate_stream(
            &tenant,
            "stream",
            3,
            SsfStreamMutation::Replace {
                endpoint: "https://other-receiver.example.test/ssf".into(),
                audience: "other-audience".into(),
                requested_events: vec![RISC_ACCOUNT_DISABLED_EVENT.into()],
            },
            118,
        )
        .await
        .unwrap()
        .updated()
        .unwrap();
    assert_eq!(replaced.revision, 4);
    assert!(store
        .enqueue_event(&event, "https://issuer.example.test", 119)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(store.revoke_all_by_tenant(&tenant, 120).await.unwrap(), 1);
    assert_eq!(store.revoke_all_by_tenant(&tenant, 121).await.unwrap(), 0);
    assert_eq!(
        store
            .mutate_stream(&tenant, "stream", 4, SsfStreamMutation::Resume, 122)
            .await
            .unwrap(),
        SsfStreamMutationOutcome::Revoked
    );
    assert_eq!(
        store.create_stream(original).await.unwrap(),
        SsfStreamCreateOutcome::AlreadyExists
    );

    let quota = format!("{tenant}-quota");
    for id in 0..SSF_MAX_REGISTERED_STREAMS_PER_TENANT {
        assert!(matches!(
            store
                .create_stream(stream(&quota, &format!("stream-{id}")))
                .await
                .unwrap(),
            SsfStreamCreateOutcome::Created(_)
        ));
    }
    assert_eq!(
        store
            .create_stream(stream(&quota, "over-quota"))
            .await
            .unwrap(),
        SsfStreamCreateOutcome::QuotaExceeded {
            limit: SSF_MAX_REGISTERED_STREAMS_PER_TENANT
        }
    );
    assert_eq!(
        store.revoke_all_by_tenant(&quota, 123).await.unwrap(),
        SSF_MAX_REGISTERED_STREAMS_PER_TENANT
    );
    assert_eq!(
        store
            .create_stream(stream(&quota, "over-quota"))
            .await
            .unwrap(),
        SsfStreamCreateOutcome::QuotaExceeded {
            limit: SSF_MAX_REGISTERED_STREAMS_PER_TENANT
        }
    );

    let retry_tenant = format!("{tenant}-retry");
    store
        .create_stream(stream(&retry_tenant, "stream"))
        .await
        .unwrap();
    store
        .enqueue_verification(
            &retry_tenant,
            "stream",
            1,
            "retry-event",
            "https://issuer.example.test",
            None,
            200,
        )
        .await
        .unwrap();
    let lease = store.acquire_due(200, 10, 1).await.unwrap().pop().unwrap();
    assert!(store
        .persist_signed_set(&lease, &signed, 200, 200)
        .await
        .unwrap());
    let retry = store
        .finish_attempt(
            &lease,
            SsfAttemptResult::Retryable {
                status_code: Some(503),
                error_class: "receiver-temporary".into(),
            },
            201,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (retry.status, retry.next_attempt_at),
        (SsfDeliveryStatus::RetryWait, 206)
    );
    assert!(store.acquire_due(205, 10, 1).await.unwrap().is_empty());
    let next = store.acquire_due(206, 10, 1).await.unwrap().pop().unwrap();
    assert_eq!(next.delivery.compact_set, Some(signed.compact_jws.clone()));
    assert!(!store
        .persist_signed_set(&next, &signed, 206, 206)
        .await
        .unwrap());
    let terminal = store
        .finish_attempt(
            &next,
            SsfAttemptResult::Terminal {
                status_code: 410,
                error_class: "terminal".into(),
            },
            207,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(terminal.attempts, 2);
    assert_eq!(terminal.attempt_history.len(), 2);
    assert_eq!(
        terminal.attempt_history[0].signing_kid,
        Some(signed.kid.clone())
    );
    assert_eq!(
        store
            .redrive_delivery(
                &retry_tenant,
                "stream",
                1,
                "retry-event",
                200 + SSF_MAX_RETRY_AGE_SECS
            )
            .await
            .unwrap(),
        SsfRedriveOutcome::Expired
    );
    assert!(matches!(
        store
            .redrive_delivery(&retry_tenant, "stream", 1, "retry-event", 208)
            .await
            .unwrap(),
        SsfRedriveOutcome::Redriven(_)
    ));
    let next = store.acquire_due(208, 10, 1).await.unwrap().pop().unwrap();
    assert_eq!(next.delivery.compact_set, Some(signed.compact_jws.clone()));
    let fatal = store
        .finish_attempt(
            &next,
            SsfAttemptResult::Fatal {
                error_class: "fatal".into(),
            },
            209,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (fatal.status, fatal.attempts, fatal.redrive_count),
        (SsfDeliveryStatus::DeadLettered, 3, 1)
    );

    let exhausted_tenant = format!("{tenant}-exhausted");
    let mut exhausted = stream(&exhausted_tenant, "stream");
    exhausted.revision = u64::MAX;
    store.create_stream(exhausted.clone()).await.unwrap();
    assert!(store
        .mutate_stream(
            &exhausted_tenant,
            "stream",
            u64::MAX,
            SsfStreamMutation::Pause,
            210
        )
        .await
        .is_err());
    assert_eq!(
        store.get_stream(&exhausted_tenant, "stream").await.unwrap(),
        Some(exhausted)
    );
}

#[tokio::test]
async fn memory_ssf_contract() {
    ssf_contract(MemorySsfStore::default()).await;
}

#[tokio::test]
async fn postgres_ssf_contract() {
    // acquire_due intentionally spans tenants. An owned dedicated database
    // isolates queue contracts from simultaneous cases and retained failures.
    let (database, _pool, admin, name, _url) = isolated_database().await;
    let keys = EncryptionKeyring::new("fixture-ssf-v1", vec![("fixture-ssf-v1".into(), [41; 32])])
        .unwrap();
    ssf_contract(agent_auth_http::state::SsfStoreImpl::Postgres(
        PostgresSsfStore::new(database, keys),
    ))
    .await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

pub(super) async fn isolated_database(
) -> (PostgresStore, sqlx::PgPool, sqlx::PgPool, String, String) {
    let base_url = std::env::var("A_AUTH_TEST_DATABASE_URL").unwrap();
    let admin = sqlx::PgPool::connect(&base_url).await.unwrap();
    let name = format!("contract_ssf_{:032x}", rand::random::<u128>());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .unwrap();
    let mut url = url::Url::parse(&base_url).unwrap();
    url.set_path(&format!("/{name}"));
    let database = PostgresStore::connect(url.as_str(), 8).await.unwrap();
    database.migrate().await.unwrap();
    let pool = sqlx::PgPool::connect(url.as_str()).await.unwrap();
    (database, pool, admin, name, url.to_string())
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_ssf_contract() {
    use agent_auth_http::adapters::aws::DynamoSsfStore;
    use aws_sdk_dynamodb::types::{
        AttributeDefinition, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
        ProjectionType, ScalarAttributeType,
    };
    let attributes = [
        ("due_partition", ScalarAttributeType::S),
        ("due_at", ScalarAttributeType::N),
        ("stream_partition", ScalarAttributeType::S),
        ("stream_created_at", ScalarAttributeType::S),
    ]
    .into_iter()
    .map(|(name, kind)| {
        AttributeDefinition::builder()
            .attribute_name(name)
            .attribute_type(kind)
            .build()
            .unwrap()
    })
    .collect();
    let indexes = [
        ("due-index", "due_partition", "due_at"),
        (
            "stream-created-at-index",
            "stream_partition",
            "stream_created_at",
        ),
    ]
    .into_iter()
    .map(|(name, partition, range)| {
        GlobalSecondaryIndex::builder()
            .index_name(name)
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(partition)
                    .key_type(KeyType::Hash)
                    .build()
                    .unwrap(),
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(range)
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
            .unwrap()
    })
    .collect();
    let (db, table) = super::aws_contract_database::table_with_range(
        "tenant_id",
        Some("record_key"),
        attributes,
        indexes,
    )
    .await;
    ssf_contract(DynamoSsfStore::new(db.clone(), &table)).await;
    db.delete_table().table_name(table).send().await.unwrap();
}
