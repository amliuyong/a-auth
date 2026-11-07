use super::{database, tenant};
use agent_auth_http::{
    adapters::memory::MemorySessionStore,
    ports::{SessionRecord, SessionStore},
};
use std::sync::Arc;
use tokio::sync::Barrier;

pub(super) fn record(id: &str, user: &str, epoch: u64) -> SessionRecord {
    SessionRecord {
        session_id: id.into(),
        user_id: user.into(),
        credential_epoch: epoch,
        auth_time: 80,
        created_at: 100,
        last_used_at: 100,
        device: "Contract browser".into(),
        expires_at: 200,
        acr: Some("urn:example:assurance:phishing-resistant".into()),
        amr: vec!["pwd".into(), "otp".into()],
    }
}

async fn session_contract(store: impl SessionStore + Clone + 'static) {
    let tenant = tenant();
    let foreign = format!("{tenant}-foreign");
    let actor = record("actor", "user", u64::MAX);
    store.create(&tenant, actor.clone()).await.unwrap();
    assert_eq!(
        store.get(&tenant, "actor").await.unwrap(),
        Some(actor.clone())
    );
    assert_eq!(store.get(&foreign, "actor").await.unwrap(), None);
    let conflict = store
        .create(&tenant, record("actor", "another-user", 0))
        .await;
    assert!(
        conflict.is_err(),
        "a captured session ID must not be rebound"
    );
    assert_eq!(
        store.get(&tenant, "actor").await.unwrap(),
        Some(actor.clone())
    );
    store.create(&foreign, actor.clone()).await.unwrap();
    store
        .create(&tenant, record("target", "user", 0))
        .await
        .unwrap();
    store
        .create(&tenant, record("other-owner", "another-user", 0))
        .await
        .unwrap();
    let mut expired = record("expired", "user", 0);
    expired.expires_at = 100;
    store.create(&tenant, expired).await.unwrap();
    assert_eq!(store.count_by_user(&tenant, "user", 100).await.unwrap(), 2);
    assert_eq!(
        store
            .list_by_user(&tenant, "user", 100)
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(store.count_by_user(&tenant, "user", 200).await.unwrap(), 0);
    assert_eq!(store.count_by_user(&foreign, "user", 100).await.unwrap(), 1);
    assert!(store.touch_last_used(&tenant, "actor", 150).await.unwrap());
    store.touch_last_used(&tenant, "actor", 120).await.unwrap();
    assert_eq!(
        store
            .get(&tenant, "actor")
            .await
            .unwrap()
            .unwrap()
            .last_used_at,
        150
    );
    assert!(!store
        .touch_last_used(&tenant, "missing", 150)
        .await
        .unwrap());
    assert!(!store
        .delete_owned(&tenant, "user", "actor", "other-owner")
        .await
        .unwrap());
    assert!(!store
        .delete_owned(&tenant, "user", "missing", "target")
        .await
        .unwrap());
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .delete_owned(&tenant, "user", "actor", "target")
                .await
                .unwrap()
        }));
    }
    let mut wins = 0;
    for task in tasks {
        wins += usize::from(task.await.unwrap());
    }
    assert_eq!(wins, 1);
    assert_eq!(store.get(&tenant, "target").await.unwrap(), None);
    let outcome = store
        .delete_others_by_user(&tenant, "user", "actor")
        .await
        .unwrap();
    if let Some(count) = outcome {
        assert_eq!(
            count, 1,
            "expired but authoritative sessions are fenced too"
        );
    }
    assert_eq!(store.get(&tenant, "expired").await.unwrap(), None);
    assert!(!store
        .touch_last_used(&tenant, "expired", 160)
        .await
        .unwrap());
    assert_eq!(
        store
            .list_by_user(&tenant, "user", 100)
            .await
            .unwrap()
            .len(),
        1
    );
    store
        .create(&tenant, record("fresh", "user", 1))
        .await
        .unwrap();
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .revoke_all_by_actor(&tenant, "user", "actor")
                .await
                .unwrap()
        }));
    }
    let mut wins = 0;
    for task in tasks {
        wins += usize::from(task.await.unwrap());
    }
    assert_eq!(wins, 1, "one actor must authorize exactly one mutation");
    assert_eq!(store.get(&tenant, "actor").await.unwrap(), None);
    assert_eq!(store.get(&tenant, "fresh").await.unwrap(), None);
    assert!(!store
        .revoke_all_by_actor(&tenant, "user", "actor")
        .await
        .unwrap());
    assert!(!store
        .delete_owned(&tenant, "user", "actor", "fresh")
        .await
        .unwrap());
    assert!(!store.touch_last_used(&tenant, "fresh", 160).await.unwrap());
    assert!(store.get(&tenant, "other-owner").await.unwrap().is_some());
    assert_eq!(store.get(&foreign, "actor").await.unwrap(), Some(actor));
    store
        .create(&tenant, record("new-generation", "user", 2))
        .await
        .unwrap();
    assert_eq!(store.count_by_user(&tenant, "user", 100).await.unwrap(), 1);
    assert!(
        store
            .delete_by_user_before_epoch(&tenant, "user", 2)
            .await
            .unwrap()
            >= 1
    );
    assert!(store
        .get(&tenant, "new-generation")
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        store
            .delete_by_user_before_epoch(&tenant, "user", 2)
            .await
            .unwrap(),
        0
    );
    assert_eq!(store.delete_by_user(&tenant, "user").await.unwrap(), 1);
    assert_eq!(store.delete_by_user(&tenant, "user").await.unwrap(), 0);
    store.delete(&tenant, "other-owner").await.unwrap();
    store.delete(&tenant, "other-owner").await.unwrap();
    assert!(store.delete_all_by_tenant(&tenant).await.unwrap() > 0);
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 0);
    assert!(store.get(&foreign, "actor").await.unwrap().is_some());
    assert!(store.delete_all_by_tenant(&foreign).await.unwrap() > 0);
}

#[tokio::test]
async fn memory_session_contract() {
    session_contract(MemorySessionStore::default()).await;
}

#[tokio::test]
async fn postgres_session_contract() {
    session_contract(database().await).await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_session_contract() {
    use agent_auth_http::adapters::aws::DynamoSessionStore;
    let (db, table) = super::aws_contract_database::table_with_string_index(
        "session_id",
        "user_id-index",
        "user_id",
    )
    .await;
    session_contract(DynamoSessionStore::new(db.clone(), &table)).await;
    db.delete_table().table_name(table).send().await.unwrap();
}
