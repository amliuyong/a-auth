use super::{database, tenant};
use agent_auth_http::{
    adapters::memory_attribute_namespaces::MemoryAttributeNamespaceStore,
    attribute_namespace::{
        AttributeNamespaceStore, AttributeWriteAuthority, AttributeWriteResolution,
        AudienceResolution, BeginNamespaceChange, BeginNamespaceChangeOutcome, NamespaceChangeKind,
        NamespaceChangeOutcome, NamespaceMigrationPhase, NamespaceOperationCheckpoint,
        RegistrationState,
    },
};
use std::{collections::BTreeSet, sync::Arc};
use tokio::sync::Barrier;

fn begin(namespace: &str, audience: &str, operation: &str, revision: u64) -> BeginNamespaceChange {
    BeginNamespaceChange {
        canonical_namespace: namespace.into(),
        exact_audiences: BTreeSet::from([audience.into()]),
        expected_revision: revision,
        operation_id: operation.into(),
        kind: NamespaceChangeKind::Upsert,
    }
}

fn checkpoint(revision: u64, started_mutation: bool) -> NamespaceOperationCheckpoint {
    NamespaceOperationCheckpoint {
        expected_revision: revision,
        phase: NamespaceMigrationPhase::Migrating,
        cursor: None,
        scan_complete: true,
        started_mutation,
        inflight_user_id: None,
        users_scanned: 0,
        users_completed: 0,
        conflict_count: 0,
        conflict_user_ids: vec![],
    }
}

async fn namespace_contract(store: impl AttributeNamespaceStore + Clone + 'static) {
    let tenant = tenant();
    let other = format!("{tenant}-other");
    let audience = format!("https://audience.{tenant}.example.test");
    assert_eq!(
        store.resolve(&tenant, &audience).await.unwrap(),
        AudienceResolution::Unbound
    );
    assert_eq!(
        store
            .resolve_write_authority(&tenant, &audience)
            .await
            .unwrap(),
        AttributeWriteResolution::Authorized(AttributeWriteAuthority::Unbound {
            namespace: audience.clone()
        })
    );
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let (store, barrier, tenant) = (store.clone(), barrier.clone(), tenant.clone());
        let request = begin(
            &format!("https://canonical-{index}.{tenant}.example.test"),
            &audience,
            &format!("operation-{index}"),
            0,
        );
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.begin_change(&tenant, request).await.unwrap()
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        match task.await.unwrap() {
            BeginNamespaceChangeOutcome::Started(record) => winners.push(*record),
            BeginNamespaceChangeOutcome::AudienceConflict { .. } => {}
            outcome => panic!("unexpected competing registration outcome: {outcome:?}"),
        }
    }
    assert_eq!(
        winners.len(),
        1,
        "one canonical namespace can own an exact audience"
    );
    let pending = winners.pop().unwrap();
    let namespace = pending.canonical_namespace.clone();
    let operation = pending.operation.as_ref().unwrap().operation_id.clone();
    assert_eq!(pending.state, RegistrationState::Pending);
    assert_eq!(store.list(&tenant).await.unwrap(), vec![pending.clone()]);
    assert_eq!(store.get(&other, &namespace).await.unwrap(), None);
    assert_eq!(
        store.resolve(&other, &audience).await.unwrap(),
        AudienceResolution::Unbound
    );
    assert_eq!(
        store.resolve(&tenant, &audience).await.unwrap(),
        AudienceResolution::Blocked
    );
    assert_eq!(
        store
            .resolve_write_authority(&tenant, &namespace)
            .await
            .unwrap(),
        AttributeWriteResolution::Blocked
    );
    assert_eq!(
        store
            .begin_change(&tenant, begin(&namespace, &audience, &operation, 0))
            .await
            .unwrap(),
        BeginNamespaceChangeOutcome::Started(Box::new(pending))
    );
    assert_eq!(
        store
            .activate(&tenant, &namespace, &operation, 1)
            .await
            .unwrap(),
        NamespaceChangeOutcome::InvalidState
    );

    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, barrier, tenant, namespace, operation) = (
            store.clone(),
            barrier.clone(),
            tenant.clone(),
            namespace.clone(),
            operation.clone(),
        );
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .checkpoint(&tenant, &namespace, &operation, checkpoint(1, false))
                .await
                .unwrap()
        }));
    }
    let mut updated = 0;
    for task in tasks {
        match task.await.unwrap() {
            NamespaceChangeOutcome::Updated(record) => {
                updated += 1;
                assert_eq!(record.operation.unwrap().revision, 2);
            }
            NamespaceChangeOutcome::OperationConflict { revision: 2, .. } => {}
            outcome => panic!("unexpected competing checkpoint outcome: {outcome:?}"),
        }
    }
    assert_eq!(
        updated, 1,
        "one checkpoint owns the next migration revision"
    );
    assert!(matches!(
        store
            .activate(&tenant, &namespace, &operation, 1)
            .await
            .unwrap(),
        NamespaceChangeOutcome::OperationConflict { revision: 2, .. }
    ));
    let NamespaceChangeOutcome::Updated(active) = store
        .activate(&tenant, &namespace, &operation, 2)
        .await
        .unwrap()
    else {
        panic!("migration must activate")
    };
    assert_eq!(active.state, RegistrationState::Active);
    assert_eq!(active.revision, 1);
    assert_eq!(
        store
            .activate(&tenant, &namespace, &operation, 2)
            .await
            .unwrap(),
        NamespaceChangeOutcome::Updated(active.clone())
    );
    assert_eq!(
        store.resolve(&tenant, &audience).await.unwrap(),
        AudienceResolution::Active {
            canonical_namespace: namespace.clone()
        }
    );
    assert_eq!(
        store.resolve(&tenant, &namespace).await.unwrap(),
        AudienceResolution::Blocked
    );
    assert_eq!(
        store
            .resolve_write_authority(&tenant, &namespace)
            .await
            .unwrap(),
        AttributeWriteResolution::Authorized(AttributeWriteAuthority::ActiveCanonical {
            canonical_namespace: namespace.clone(),
            registration_revision: 1,
        })
    );
    assert_eq!(
        store
            .resolve_write_authority(&tenant, &audience)
            .await
            .unwrap(),
        AttributeWriteResolution::Authorized(AttributeWriteAuthority::ActiveAudience {
            audience: audience.clone(),
            canonical_namespace: namespace.clone(),
            registration_revision: 1,
        })
    );
    assert!(matches!(
        store
            .begin_change(&tenant, begin(&namespace, &audience, &operation, 1))
            .await
            .unwrap(),
        BeginNamespaceChangeOutcome::Busy { .. }
    ));

    let replacement = format!("https://replacement.{tenant}.example.test");
    assert!(matches!(
        store
            .begin_change(
                &tenant,
                begin(&namespace, &replacement, "cancelled\0operation", 1)
            )
            .await
            .unwrap(),
        BeginNamespaceChangeOutcome::Started(_)
    ));
    assert_eq!(
        store.resolve(&tenant, &audience).await.unwrap(),
        AudienceResolution::Blocked
    );
    for _ in 0..2 {
        assert_eq!(
            store
                .cancel(&tenant, &namespace, "cancelled\0operation", 1)
                .await
                .unwrap(),
            NamespaceChangeOutcome::Cancelled(Some(active.clone()))
        );
    }
    assert_eq!(
        store.get(&tenant, &namespace).await.unwrap(),
        Some(active.clone())
    );
    assert_eq!(
        store.resolve(&tenant, &replacement).await.unwrap(),
        AudienceResolution::Unbound
    );
    assert!(matches!(
        store
            .begin_change(
                &tenant,
                begin(&namespace, &replacement, "cancelled\0operation", 1)
            )
            .await
            .unwrap(),
        BeginNamespaceChangeOutcome::Busy { .. }
    ));
    let foreign_namespace = format!("https://foreign.{tenant}.example.test");
    assert!(matches!(
        store
            .begin_change(&other, begin(&foreign_namespace, &audience, "foreign", 0))
            .await
            .unwrap(),
        BeginNamespaceChangeOutcome::Started(_)
    ));
    assert_eq!(
        store
            .cancel(&other, &foreign_namespace, "foreign", 1)
            .await
            .unwrap(),
        NamespaceChangeOutcome::Cancelled(None)
    );
    assert!(matches!(
        store
            .begin_change(
                &tenant,
                BeginNamespaceChange {
                    canonical_namespace: namespace.clone(),
                    exact_audiences: BTreeSet::new(),
                    expected_revision: 1,
                    operation_id: "delete".into(),
                    kind: NamespaceChangeKind::Delete,
                }
            )
            .await
            .unwrap(),
        BeginNamespaceChangeOutcome::Started(_)
    ));
    assert!(matches!(
        store
            .checkpoint(&tenant, &namespace, "delete", checkpoint(1, true))
            .await
            .unwrap(),
        NamespaceChangeOutcome::Updated(_)
    ));
    assert_eq!(
        store
            .cancel(&tenant, &namespace, "delete", 2)
            .await
            .unwrap(),
        NamespaceChangeOutcome::CannotCancel
    );
    let NamespaceChangeOutcome::Updated(retired) = store
        .activate(&tenant, &namespace, "delete", 2)
        .await
        .unwrap()
    else {
        panic!("completed deletion must retire")
    };
    assert_eq!(retired.state, RegistrationState::Retired);
    assert_eq!(retired.revision, 2);
    assert_eq!(
        store.resolve(&tenant, &audience).await.unwrap(),
        AudienceResolution::Blocked
    );
    assert_eq!(
        store
            .resolve_write_authority(&tenant, &namespace)
            .await
            .unwrap(),
        AttributeWriteResolution::Blocked
    );
}

#[tokio::test]
async fn memory_attribute_namespace_contract() {
    namespace_contract(MemoryAttributeNamespaceStore::default()).await;
}

#[tokio::test]
async fn postgres_attribute_namespace_contract() {
    namespace_contract(
        agent_auth_http::state::AttributeNamespaceStoreImpl::Postgres(database().await),
    )
    .await;
}

#[tokio::test]
async fn postgres_attribute_namespace_rejects_incomplete_authority_snapshot() {
    let store = database().await;
    let tenant = tenant();
    let namespace = format!("https://canonical.{tenant}.example.test");
    let audience = format!("https://audience.{tenant}.example.test");
    assert!(matches!(
        store
            .begin_change(&tenant, begin(&namespace, &audience, "operation", 0))
            .await
            .unwrap(),
        BeginNamespaceChangeOutcome::Started(_)
    ));
    let fixture = sqlx::PgPool::connect(&std::env::var("A_AUTH_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    // Fault injection only: authorization is observed through the public port.
    // A truncated durable snapshot must never become unbound authority.
    for damaged_record in ["{", "null", "{}"] {
        sqlx::query("UPDATE a_auth.namespace_catalogs SET record = $2 WHERE tenant = $1")
            .bind(&tenant)
            .bind(damaged_record)
            .execute(&fixture)
            .await
            .unwrap();
        assert!(
            matches!(
                store.resolve(&tenant, &audience).await,
                Err(agent_auth_http::ports::StoreError::Permanent(_))
            ),
            "damaged audience authority must fail closed: {damaged_record}"
        );
        assert!(
            matches!(
                store.resolve_write_authority(&tenant, &namespace).await,
                Err(agent_auth_http::ports::StoreError::Permanent(_))
            ),
            "damaged write authority must fail closed: {damaged_record}"
        );
    }
    fixture.close().await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_attribute_namespace_contract() {
    let (db, table) = super::aws_contract_database::table_with_range(
        "tenant_id",
        Some("lookup_key"),
        vec![],
        vec![],
    )
    .await;
    namespace_contract(
        agent_auth_http::adapters::aws::DynamoAttributeNamespaceStore::new(db.clone(), &table),
    )
    .await;
    db.delete_table().table_name(table).send().await.unwrap();
}
