use super::{database, tenant};
use agent_auth_grant::GrantConstraints;
use agent_auth_http::{
    adapters::memory::MemoryJtiStore,
    delegation::DelegationRecord,
    ports::{JtiRecord, JtiStore},
};
use std::sync::Arc;
use tokio::sync::Barrier;

fn root(tenant: &str, id: &str) -> JtiRecord {
    JtiRecord {
        jti: id.into(),
        tenant_id: tenant.into(),
        user_id: "user".into(),
        family_id: Some("family".into()),
        grant_id: Some("grant".into()),
        expires_at: 200,
        delegation: None,
    }
}

fn delegated(tenant: &str, id: &str) -> JtiRecord {
    JtiRecord {
        delegation: Some(DelegationRecord {
            version: 1,
            revoked: false,
            credential_epoch: 3,
            token_sha256: "signed-token-digest".into(),
            issuer: "https://issuer.example".into(),
            subject: "pairwise-subject".into(),
            resource: "https://api.example".into(),
            scope: vec!["read".into()],
            actor: "client".into(),
            parent_jti: "root".into(),
            auth_grant: "grant".into(),
            depth: 1,
            constraints: GrantConstraints {
                max_act_chain: 2,
                actor_allowlist: vec!["client".into()],
                expires_at: 200,
            },
            authorization_details: vec![],
            cnf_jkt: Some("key-thumbprint".into()),
            allowed_ip_cidrs: vec![],
            allowed_vpce: vec![],
        }),
        ..root(tenant, id)
    }
}

async fn jti_contract(store: impl JtiStore + Clone + 'static) {
    let tenant = tenant();
    let original = root(&tenant, "root");
    store.put(original.clone()).await.unwrap();
    assert_eq!(
        store.get(&tenant, "root").await.unwrap(),
        Some(original.clone())
    );
    assert_eq!(store.get("other", "root").await.unwrap(), None);
    let mut updated = original;
    updated.expires_at = 300;
    store.put(updated.clone()).await.unwrap();
    assert_eq!(store.get(&tenant, "root").await.unwrap(), Some(updated));
    assert!(!store.revoke_delegation(&tenant, "root").await.unwrap());

    let authority = delegated(&tenant, "child");
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, record, barrier) = (store.clone(), authority.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.put(record).await.is_ok()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap());
    }
    assert_eq!(
        winners, 1,
        "delegation authority is immutable even on identical retries"
    );
    assert_eq!(
        store.get(&tenant, "child").await.unwrap(),
        Some(authority.clone())
    );
    assert!(!store.revoke_delegation("other", "child").await.unwrap());
    assert!(store.revoke_delegation(&tenant, "child").await.unwrap());
    assert!(store.revoke_delegation(&tenant, "child").await.unwrap());
    assert!(store.put(authority).await.is_err());
    let revoked = store.get(&tenant, "child").await.unwrap().unwrap();
    assert!(revoked.delegation.unwrap().revoked);
    assert!(!store.revoke_delegation(&tenant, "absent").await.unwrap());

    // Root and delegated records have separate authority namespaces.
    let root_collision = root(&tenant, "child");
    store.put(root_collision.clone()).await.unwrap();
    assert_eq!(
        store.get(&tenant, "child").await.unwrap(),
        Some(root_collision)
    );
    store.put(root("other", "root")).await.unwrap();
    assert_eq!(store.delete_by_user(&tenant, "absent").await.unwrap(), 0);
    assert_eq!(store.delete_by_user(&tenant, "user").await.unwrap(), 3);
    assert_eq!(store.get(&tenant, "root").await.unwrap(), None);
    assert_eq!(store.get(&tenant, "child").await.unwrap(), None);
    assert!(store.get("other", "root").await.unwrap().is_some());
    store.put(root(&tenant, "last")).await.unwrap();
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 1);
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 0);
    assert_eq!(store.delete_all_by_tenant("other").await.unwrap(), 1);
}

#[tokio::test]
async fn memory_jti_contract() {
    jti_contract(MemoryJtiStore::default()).await;
}

#[tokio::test]
async fn postgres_jti_contract() {
    jti_contract(agent_auth_http::state::JtiStoreImpl::Postgres(
        database().await,
    ))
    .await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_jti_contract() {
    let (db, table) = super::aws_contract_database::table("pk", vec![], vec![]).await;
    jti_contract(agent_auth_http::adapters::aws::DynamoJtiStore::new(
        db.clone(),
        &table,
    ))
    .await;
    db.delete_table().table_name(table).send().await.unwrap();
}
