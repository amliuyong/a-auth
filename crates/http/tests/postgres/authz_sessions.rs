use super::{database, tenant};
use agent_auth_http::{
    adapters::memory::MemoryAuthzSessionStore,
    ports::{AuthzSessionRecord, AuthzSessionStore},
};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Barrier;

fn session(id: &str, expires_at: i64) -> AuthzSessionRecord {
    AuthzSessionRecord {
        session_id: id.into(),
        client_id: "client".into(),
        user_id: None,
        state: "created".into(),
        session_token_hash: "opaque-session-hash".into(),
        sequence: 0,
        last_error: None,
        expires_at,
    }
}

async fn session_contract(store: impl AuthzSessionStore + Clone + 'static) {
    let tenant = tenant();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let record = session("session", now + 600);
    store.create(&tenant, record.clone()).await.unwrap();
    assert_eq!(
        store.get(&tenant, "session").await.unwrap(),
        Some(record.clone())
    );
    assert_eq!(store.get("other", "session").await.unwrap(), None);
    assert!(store
        .list_by_client("other", "client")
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        store.list_by_client(&tenant, "client").await.unwrap(),
        vec!["session"]
    );
    assert_eq!(store.count_active(&tenant, now).await.unwrap(), 1);
    assert_eq!(store.count_active("other", now).await.unwrap(), 0);
    assert_eq!(store.count_active("", now).await.unwrap(), 0);
    assert!(store
        .transition(&tenant, "session", "complete", None, now)
        .await
        .unwrap()
        .is_none());
    assert!(store
        .transition(&tenant, "session", "invalid-state", None, now)
        .await
        .unwrap()
        .is_none());

    // Only one transition can leave the same source state.
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, barrier, tenant) = (store.clone(), barrier.clone(), tenant.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .transition(&tenant, "session", "pending_user_authentication", None, now)
                .await
                .unwrap()
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        if let Some(record) = task.await.unwrap() {
            winners.push(record);
        }
    }
    assert_eq!(winners.len(), 1);
    assert_eq!(winners[0].sequence, 1);
    let bound = store
        .bind_user(&tenant, "session", "user", now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bound.user_id.as_deref(), Some("user"));
    assert_eq!(bound.sequence, 1);
    assert_eq!(
        store
            .bind_user(&tenant, "session", "user", now)
            .await
            .unwrap(),
        Some(bound)
    );
    assert!(store
        .bind_user(&tenant, "session", "other-user", now)
        .await
        .unwrap()
        .is_none());
    let consent = store
        .transition(&tenant, "session", "pending_consent", None, now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(consent.sequence, 2);
    let code = store
        .transition(
            &tenant,
            "session",
            "code_issued_awaiting_exchange",
            None,
            now,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(code.sequence, 3);
    let failed = store
        .transition(
            &tenant,
            "session",
            "exchange_failed",
            Some("structured-error".into()),
            now,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(failed.sequence, 4);
    assert_eq!(failed.last_error.as_deref(), Some("structured-error"));
    assert!(store
        .transition(&tenant, "session", "complete", None, now)
        .await
        .unwrap()
        .is_none());
    assert_eq!(store.count_active(&tenant, now).await.unwrap(), 0);

    store
        .create(&tenant, session("expired", now))
        .await
        .unwrap();
    assert!(store
        .bind_user(&tenant, "expired", "user", now)
        .await
        .unwrap()
        .is_none());
    assert!(store
        .transition(&tenant, "expired", "pending_consent", None, now)
        .await
        .unwrap()
        .is_none());
    store
        .create(&tenant, session("future", now + 600))
        .await
        .unwrap();
    assert_eq!(store.count_active(&tenant, now).await.unwrap(), 1);
    assert_eq!(store.count_active(&tenant, now + 600).await.unwrap(), 0);
    assert_eq!(
        store
            .delete_by_client(&tenant, "other-client")
            .await
            .unwrap(),
        0
    );
    assert_eq!(store.delete_by_client(&tenant, "client").await.unwrap(), 3);
    store
        .create(&tenant, session("delete-one", now + 600))
        .await
        .unwrap();
    store.delete(&tenant, "delete-one").await.unwrap();
    assert_eq!(store.get(&tenant, "delete-one").await.unwrap(), None);
    store
        .create(&tenant, session("cleanup", now + 600))
        .await
        .unwrap();
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 1);
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 0);
}

#[tokio::test]
async fn memory_authz_session_contract() {
    session_contract(MemoryAuthzSessionStore::default()).await;
}

#[tokio::test]
async fn postgres_authz_session_contract() {
    session_contract(database().await).await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_authz_session_contract() {
    use aws_sdk_dynamodb::types::{
        AttributeDefinition, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
        ProjectionType, ScalarAttributeType,
    };
    let attributes = vec![AttributeDefinition::builder()
        .attribute_name("client_id")
        .attribute_type(ScalarAttributeType::S)
        .build()
        .unwrap()];
    let index = GlobalSecondaryIndex::builder()
        .index_name("client_id-index")
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("client_id")
                .key_type(KeyType::Hash)
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
        super::aws_contract_database::table("session_id", attributes, vec![index]).await;
    session_contract(
        agent_auth_http::adapters::aws::DynamoAuthzSessionStore::new(db.clone(), &table),
    )
    .await;
    db.delete_table().table_name(table).send().await.unwrap();
}
