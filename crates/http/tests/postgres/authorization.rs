use super::{database, tenant};
use agent_auth_grant::{Grant, GrantConstraints, GrantStatus, ResourceGrant};
use agent_auth_http::{
    adapters::memory::{MemoryGrantStore, MemoryPolicyVersionStore},
    ports::{GrantStore, PolicyVersionStore},
};
use std::sync::Arc;
use tokio::sync::Barrier;

fn grant(id: &str) -> Grant {
    Grant {
        grant_id: id.into(),
        user_id: "user".into(),
        client_id: "client".into(),
        per_resource: vec![ResourceGrant {
            resource: "https://api.example".into(),
            scopes: vec!["read".into()],
            authorization_details: vec![],
        }],
        effective_per_resource: vec![],
        effective_pv: 0,
        allowed_ip_cidrs: vec![],
        allowed_vpce: vec![],
        credential_epoch: 3,
        revision: 0,
        constraints: GrantConstraints {
            max_act_chain: 1,
            actor_allowlist: vec!["actor".into()],
            expires_at: 200,
        },
        status: GrantStatus::Active,
    }
}

async fn grant_contract(store: impl GrantStore + Clone + 'static) {
    let tenant = tenant();
    let original = grant("grant");
    store.put(&tenant, original.clone()).await.unwrap();
    assert_eq!(store.get("other", "grant").await.unwrap(), None);
    assert_eq!(
        store.list_by_user(&tenant, "user").await.unwrap(),
        vec![original.clone()]
    );
    assert!(store
        .list_by_user("other", "user")
        .await
        .unwrap()
        .is_empty());
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, barrier, tenant, mut replacement) = (
            store.clone(),
            barrier.clone(),
            tenant.clone(),
            original.clone(),
        );
        replacement.effective_pv = 1;
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .put_conditional(&tenant, replacement, 0)
                .await
                .unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap());
    }
    assert_eq!(winners, 1);
    let updated = store.get(&tenant, "grant").await.unwrap().unwrap();
    assert_eq!(updated.revision, 1);
    assert_eq!(updated.effective_pv, 1);
    assert_eq!(updated.per_resource, original.per_resource);
    assert!(store.list_stale(&tenant, 1).await.unwrap().is_empty());
    assert_eq!(
        store.list_stale(&tenant, 2).await.unwrap(),
        vec![(tenant.clone(), updated.clone())]
    );
    assert!(!store.revoke_if_revision(&tenant, "grant", 0).await.unwrap());
    assert!(!store
        .revoke_if_epoch_before(&tenant, "grant", 3)
        .await
        .unwrap());
    assert!(store
        .revoke_if_epoch_before(&tenant, "grant", 4)
        .await
        .unwrap());
    assert_eq!(
        store.get(&tenant, "grant").await.unwrap().unwrap().status,
        GrantStatus::Revoked
    );
    assert!(!store.put_conditional(&tenant, original, 1).await.unwrap());
    let revoked = store.get(&tenant, "grant").await.unwrap().unwrap();
    assert!(
        !store
            .put_conditional(&tenant, grant("grant"), revoked.revision)
            .await
            .unwrap(),
        "even a current revision must not resurrect revoked authority"
    );
    assert!(store.list_stale(&tenant, 100).await.unwrap().is_empty());
    assert!(!store
        .revoke_if_revision(&tenant, "grant", revoked.revision)
        .await
        .unwrap());

    store.put(&tenant, grant("grant-2")).await.unwrap();
    assert!(store
        .revoke_if_revision(&tenant, "grant-2", 0)
        .await
        .unwrap());
    assert!(!store
        .revoke_if_revision(&tenant, "grant-2", 0)
        .await
        .unwrap());
    store.put(&tenant, grant("grant-3")).await.unwrap();
    assert!(store.revoke(&tenant, "grant-3").await.unwrap());
    assert!(!store.revoke(&tenant, "absent").await.unwrap());
    assert_eq!(
        store
            .delete_by_client(&tenant, "other-client")
            .await
            .unwrap(),
        0
    );
    assert_eq!(store.delete_by_client(&tenant, "client").await.unwrap(), 3);
    assert!(store
        .list_by_user(&tenant, "user")
        .await
        .unwrap()
        .is_empty());
    store.put(&tenant, grant("grant-4")).await.unwrap();
    assert_eq!(store.delete_by_user(&tenant, "user").await.unwrap(), 1);
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 0);
}

#[tokio::test]
async fn memory_grant_contract() {
    grant_contract(MemoryGrantStore::default()).await;
}

#[tokio::test]
async fn postgres_grant_contract() {
    grant_contract(database().await).await;
}

async fn policy_version_contract(store: impl PolicyVersionStore + Clone + 'static) {
    let tenant = tenant();
    assert_eq!(store.get(&tenant).await.unwrap(), 0);
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, barrier, tenant) = (store.clone(), barrier.clone(), tenant.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.bump(&tenant).await.unwrap()
        }));
    }
    let mut versions = Vec::new();
    for task in tasks {
        versions.push(task.await.unwrap());
    }
    versions.sort();
    assert_eq!(versions, (1..=16).collect::<Vec<u64>>());
    assert_eq!(store.get(&tenant).await.unwrap(), 16);
    assert_eq!(store.get("other").await.unwrap(), 0);
    assert_eq!(store.delete(&tenant).await.unwrap(), 1);
    assert_eq!(store.get(&tenant).await.unwrap(), 0);
    assert_eq!(store.delete(&tenant).await.unwrap(), 0);
}

#[tokio::test]
async fn memory_policy_version_contract() {
    policy_version_contract(MemoryPolicyVersionStore::default()).await;
}

#[tokio::test]
async fn postgres_policy_version_contract() {
    policy_version_contract(database().await).await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_grant_contract() {
    use aws_sdk_dynamodb::types::{
        AttributeDefinition, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
        ProjectionType, ScalarAttributeType,
    };
    let attributes = [
        ("user_id", ScalarAttributeType::S),
        ("gv_tenant", ScalarAttributeType::S),
        ("effective_pv", ScalarAttributeType::N),
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
    let user_index = GlobalSecondaryIndex::builder()
        .index_name("user_id-index")
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("user_id")
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
    let policy_index = GlobalSecondaryIndex::builder()
        .index_name("policy_version-index")
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("gv_tenant")
                .key_type(KeyType::Hash)
                .build()
                .unwrap(),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("effective_pv")
                .key_type(KeyType::Range)
                .build()
                .unwrap(),
        )
        .projection(
            Projection::builder()
                .projection_type(ProjectionType::KeysOnly)
                .build(),
        )
        .build()
        .unwrap();
    let (db, table) =
        super::aws_contract_database::table("grant_id", attributes, vec![user_index, policy_index])
            .await;
    grant_contract(agent_auth_http::adapters::aws::DynamoGrantStore::new(
        db.clone(),
        &table,
        "unused-clients",
    ))
    .await;
    db.delete_table().table_name(table).send().await.unwrap();
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_policy_version_contract() {
    let (db, table) = super::aws_contract_database::table("grant_id", vec![], vec![]).await;
    policy_version_contract(
        agent_auth_http::adapters::aws::DynamoPolicyVersionStore::new(db.clone(), &table),
    )
    .await;
    db.delete_table().table_name(table).send().await.unwrap();
}
