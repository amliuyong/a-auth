use super::{database, tenant};
use agent_auth_authn::federation::{FederationConfig, OidcRpParams, UpstreamProtocol};
use agent_auth_http::{
    adapters::memory::{
        MemoryFederationConfigStore, MemoryFederationFlowStore, MemoryMagicLinkStore,
        MemoryWorkloadTrustStore,
    },
    ports::{
        FederationConfigStore, FederationFlowState, FederationFlowStore, MagicLinkRecord,
        MagicLinkStore, WorkloadTrustEntry, WorkloadTrustStore,
    },
};
use agent_auth_workload::{TrustBinding, TrustMechanism};
use std::sync::Arc;
use tokio::sync::Barrier;

fn config(tenant: &str, id: &str) -> FederationConfig {
    FederationConfig {
        tenant_id: tenant.into(),
        upstream_idp_id: id.into(),
        protocol: UpstreamProtocol::Oidc,
        upstream_issuer: "https://idp.example".into(),
        strong_acr_values: vec!["urn:example:strong".into()],
        oidc: Some(OidcRpParams {
            client_id: "rp".into(),
            client_secret_ref: "enterprise/client-secret".into(),
            authorization_endpoint: "https://idp.example/authorize".into(),
            token_endpoint: "https://idp.example/token".into(),
            jwks_uri: "https://idp.example/jwks".into(),
            scopes: vec!["openid".into()],
        }),
    }
}

async fn federation_config_contract(store: impl FederationConfigStore) {
    let tenant = tenant();
    let other = format!("{tenant}-other");
    let original = config(&tenant, "enterprise");
    store.put(original.clone()).await.unwrap();
    assert_eq!(
        store.get(&tenant, "enterprise").await.unwrap(),
        Some(original.clone())
    );
    assert_eq!(store.get(&other, "enterprise").await.unwrap(), None);
    assert!(store.list_by_tenant(&other).await.unwrap().is_empty());
    let mut changed = original;
    changed.strong_acr_values.push("urn:example:second".into());
    store.put(changed.clone()).await.unwrap();
    assert_eq!(
        store.list_by_tenant(&tenant).await.unwrap(),
        vec![changed.clone()]
    );
    store.put(config(&other, "enterprise")).await.unwrap();
    store.delete(&other, "absent").await.unwrap();
    assert_eq!(
        store.get(&tenant, "enterprise").await.unwrap(),
        Some(changed)
    );
    store.delete(&tenant, "enterprise").await.unwrap();
    assert_eq!(store.get(&tenant, "enterprise").await.unwrap(), None);
    assert!(store.get(&other, "enterprise").await.unwrap().is_some());
    store.put(config(&tenant, "second")).await.unwrap();
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 1);
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 0);
    assert_eq!(store.delete_all_by_tenant(&other).await.unwrap(), 1);

    // The existing self-hosted protocol uses the empty tenant partition.
    let single_id = format!("single-{tenant}");
    let single = config("", &single_id);
    store.put(single.clone()).await.unwrap();
    assert_eq!(
        store.get("", &single_id).await.unwrap(),
        Some(single.clone())
    );
    assert!(store.list_by_tenant("").await.unwrap().contains(&single));
    assert_eq!(store.get(&tenant, &single_id).await.unwrap(), None);
    store.delete("", &single_id).await.unwrap();
    assert_eq!(store.get("", &single_id).await.unwrap(), None);
}

fn flow(tenant: &str, state: &str, expiry: i64) -> FederationFlowState {
    FederationFlowState {
        state: state.into(),
        nonce: "nonce".into(),
        code_verifier: "pkce-verifier".into(),
        tenant_id: tenant.into(),
        upstream_idp_id: "enterprise".into(),
        original_authz_request: "client_id=downstream&scope=openid&state=original".into(),
        required_max_age_secs: Some(0),
        expires_at: expiry,
    }
}

async fn federation_flow_contract(store: impl FederationFlowStore + Clone + 'static) {
    let tenant = tenant();
    let state = format!("state-{tenant}");
    let now = agent_auth_http::current_unix_secs();
    let original = flow(&tenant, &state, now + 600);
    store.put(original.clone()).await.unwrap();
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, state, barrier) = (store.clone(), state.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.consume(&state).await.unwrap()
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        if let Some(record) = task.await.unwrap() {
            winners.push(record);
        }
    }
    assert_eq!(
        winners,
        vec![original],
        "one callback consumes the complete upstream/downstream binding"
    );
    assert_eq!(store.consume(&state).await.unwrap(), None);
    let expired_state = format!("{state}-expired");
    store
        .put(flow(&tenant, &expired_state, now - 1))
        .await
        .unwrap();
    assert_eq!(store.consume(&expired_state).await.unwrap(), None);
    assert_eq!(store.consume(&expired_state).await.unwrap(), None);
    let other = format!("{tenant}-other");
    let other_state = format!("{state}-other");
    let other_flow = flow(&other, &other_state, now + 600);
    store.put(other_flow.clone()).await.unwrap();
    store.put(flow(&tenant, &state, now + 600)).await.unwrap();
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 1);
    assert_eq!(store.consume(&state).await.unwrap(), None);
    assert_eq!(store.consume(&other_state).await.unwrap(), Some(other_flow));
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 0);
}

fn link(id: &str, user: &str, nonce: &str) -> MagicLinkRecord {
    MagicLinkRecord {
        link_id: id.into(),
        user_id: user.into(),
        email: "user@example.test".into(),
        session_nonce: nonce.into(),
        authorize_query: "client_id=client&scope=openid".into(),
        next: "/account".into(),
        expires_at: agent_auth_http::current_unix_secs() + 600,
    }
}

async fn magic_link_contract(store: impl MagicLinkStore + Clone + 'static) {
    let tenant = tenant();
    let other = format!("{tenant}-other");
    let original = link("link", "user", "browser");
    store.put(&tenant, original.clone()).await.unwrap();
    assert_eq!(store.get(&other, "link").await.unwrap(), None);
    assert_eq!(
        store
            .consume_bound(&tenant, "link", "wrong-browser")
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        store.get(&tenant, "link").await.unwrap(),
        Some(original.clone())
    );
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .consume_bound(&tenant, "link", "browser")
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
    assert_eq!(winners, vec![original]);
    assert_eq!(store.get(&tenant, "link").await.unwrap(), None);
    assert_eq!(
        store
            .consume_bound(&tenant, "link", "browser")
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .last_sent_at(&tenant, "user@example.test")
            .await
            .unwrap(),
        None
    );
    store
        .mark_sent(&tenant, "user@example.test", 100)
        .await
        .unwrap();
    assert_eq!(
        store
            .last_sent_at(&tenant, "user@example.test")
            .await
            .unwrap(),
        Some(100)
    );
    assert_eq!(
        store
            .last_sent_at(&other, "user@example.test")
            .await
            .unwrap(),
        None
    );
    store
        .mark_sent(&tenant, "user@example.test", 200)
        .await
        .unwrap();
    assert_eq!(
        store
            .last_sent_at(&tenant, "user@example.test")
            .await
            .unwrap(),
        Some(200)
    );
    let retained = link("retained", "other-user", "browser");
    store
        .put(&tenant, link("erased", "user", "browser"))
        .await
        .unwrap();
    store.put(&tenant, retained.clone()).await.unwrap();
    store
        .put(&other, link("erased", "user", "browser"))
        .await
        .unwrap();
    assert_eq!(
        store
            .delete_by_user(&tenant, "user", &["user@example.test".into()])
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .last_sent_at(&tenant, "user@example.test")
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        store.get(&tenant, "retained").await.unwrap(),
        Some(retained)
    );
    assert!(store.get(&other, "erased").await.unwrap().is_some());
    store
        .mark_sent(&tenant, "retained@example.test", 200)
        .await
        .unwrap();
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 2);
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 0);
    assert_eq!(store.delete_all_by_tenant(&other).await.unwrap(), 1);
}

fn trust(tenant: &str, client: &str) -> TrustBinding {
    TrustBinding {
        tenant_id: tenant.into(),
        mechanism: TrustMechanism::Oidc {
            platform_issuer: "https://workload.example".into(),
            jwks_uri: "https://workload.example/jwks".into(),
            subject_pattern: "runtime/service-*".into(),
        },
        mapped_client_id: client.into(),
    }
}

async fn workload_trust_contract(store: impl WorkloadTrustStore) {
    let tenant = tenant();
    let other = format!("{tenant}-other");
    let original = trust(&tenant, "client");
    store
        .put(&tenant, "binding".into(), original.clone())
        .await
        .unwrap();
    assert_eq!(
        store.list_by_tenant(&tenant).await.unwrap(),
        vec![WorkloadTrustEntry {
            binding_id: "binding".into(),
            binding: original
        }]
    );
    assert!(store.list_by_tenant(&other).await.unwrap().is_empty());
    store
        .put(&other, "binding".into(), trust(&other, "other-client"))
        .await
        .unwrap();
    store
        .put(&tenant, "binding".into(), trust(&tenant, "updated-client"))
        .await
        .unwrap();
    assert_eq!(
        store.list_by_tenant(&tenant).await.unwrap()[0]
            .binding
            .mapped_client_id,
        "updated-client"
    );
    store.delete(&other, "absent").await.unwrap();
    store.delete(&tenant, "binding").await.unwrap();
    assert!(store.list_by_tenant(&tenant).await.unwrap().is_empty());
    assert_eq!(store.list_by_tenant(&other).await.unwrap().len(), 1);
    store
        .put(&tenant, "second".into(), trust(&tenant, "client"))
        .await
        .unwrap();
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 1);
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 0);
    assert_eq!(store.delete_all_by_tenant(&other).await.unwrap(), 1);
}

#[tokio::test]
async fn memory_federation_config_contract() {
    federation_config_contract(MemoryFederationConfigStore::default()).await;
}
#[tokio::test]
async fn postgres_federation_config_contract() {
    federation_config_contract(database().await).await;
}
#[tokio::test]
async fn memory_federation_flow_contract() {
    federation_flow_contract(MemoryFederationFlowStore::default()).await;
}
#[tokio::test]
async fn postgres_federation_flow_contract() {
    federation_flow_contract(database().await).await;
}
#[tokio::test]
async fn memory_magic_link_contract() {
    magic_link_contract(MemoryMagicLinkStore::default()).await;
}
#[tokio::test]
async fn postgres_magic_link_contract() {
    magic_link_contract(database().await).await;
}
#[tokio::test]
async fn memory_workload_trust_contract() {
    workload_trust_contract(MemoryWorkloadTrustStore::default()).await;
}
#[tokio::test]
async fn postgres_workload_trust_contract() {
    workload_trust_contract(database().await).await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_federation_config_contract() {
    let (db, table) = super::aws_contract_database::table_with_range(
        "tenant_id",
        Some("upstream_idp_id"),
        vec![],
        vec![],
    )
    .await;
    federation_config_contract(
        agent_auth_http::adapters::aws::DynamoFederationConfigStore::new(db.clone(), &table),
    )
    .await;
    db.delete_table().table_name(table).send().await.unwrap();
}
#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_federation_flow_contract() {
    let (db, table) = super::aws_contract_database::table("state", vec![], vec![]).await;
    federation_flow_contract(
        agent_auth_http::adapters::aws::DynamoFederationFlowStore::new(db.clone(), &table),
    )
    .await;
    db.delete_table().table_name(table).send().await.unwrap();
}
#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_magic_link_contract() {
    let (db, table) = super::aws_contract_database::table("pk", vec![], vec![]).await;
    magic_link_contract(agent_auth_http::adapters::aws::DynamoMagicLinkStore::new(
        db.clone(),
        &table,
    ))
    .await;
    db.delete_table().table_name(table).send().await.unwrap();
}
#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_workload_trust_contract() {
    let (db, table) = super::aws_contract_database::table("binding_id", vec![], vec![]).await;
    workload_trust_contract(
        agent_auth_http::adapters::aws::DynamoWorkloadTrustStore::new(db.clone(), &table),
    )
    .await;
    db.delete_table().table_name(table).send().await.unwrap();
}
