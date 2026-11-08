use super::{database, tenant};
use agent_auth_http::{
    adapters::memory::MemoryAdminAuthStore,
    ports::{
        AdminAuthStore, AdminIdentityField, AdminOidcConfig, AdminOidcConfigDeleteOutcome,
        AdminOidcConfigPutOutcome, AdminOidcFlow, AdminSessionRecord, TenantRole,
    },
};
use std::sync::Arc;
use tokio::sync::Barrier;

fn config(tenant: &str, binding: &str, revision: u64) -> AdminOidcConfig {
    AdminOidcConfig {
        tenant_id: tenant.into(),
        binding_id: binding.into(),
        issuer: "https://idp.example.test".into(),
        client_id: "admin-rp".into(),
        client_secret_ref: "admin/client-secret".into(),
        authorization_endpoint: "https://idp.example.test/authorize".into(),
        token_endpoint: "https://idp.example.test/token".into(),
        jwks_uri: "https://idp.example.test/jwks".into(),
        redirect_uri: "https://auth.example.test/admin/sso/callback".into(),
        scopes: vec!["openid".into()],
        strong_acr_values: vec!["urn:example:strong".into()],
        identity_claim: "sub".into(),
        identity_field: AdminIdentityField::UserId,
        revision,
        updated_at: agent_auth_http::current_unix_secs(),
    }
}

fn flow(config: &AdminOidcConfig, hash: &str, now: i64) -> AdminOidcFlow {
    AdminOidcFlow {
        state_hash: hash.into(),
        nonce: "nonce".into(),
        code_verifier: "pkce-verifier".into(),
        tenant_id: config.tenant_id.clone(),
        config_revision: config.revision,
        config_binding_id: config.binding_id.clone(),
        required_acr: Some("strong".into()),
        required_max_age_secs: Some(0),
        expires_at: now + 300,
    }
}

fn session(config: &AdminOidcConfig, hash: &str, now: i64) -> AdminSessionRecord {
    AdminSessionRecord {
        session_hash: hash.into(),
        tenant_id: config.tenant_id.clone(),
        user_id: "canonical-user".into(),
        upstream_subject: "upstream-user".into(),
        role: TenantRole::Admin,
        credential_epoch: u64::MAX,
        config_revision: config.revision,
        config_binding_id: config.binding_id.clone(),
        acr: Some("strong".into()),
        auth_time: now,
        created_at: now,
        expires_at: now + 300,
    }
}

async fn admin_auth_contract(store: impl AdminAuthStore + Clone + 'static) {
    let tenant = tenant();
    let other = format!("{tenant}-other");
    let now = agent_auth_http::current_unix_secs();
    let initial = config(&tenant, "initial-binding", 1);
    assert_eq!(
        store.put_config(initial.clone(), 0).await.unwrap(),
        AdminOidcConfigPutOutcome::Stored(initial.clone())
    );
    assert_eq!(
        store.get_config(&tenant).await.unwrap(),
        Some(initial.clone())
    );
    assert_eq!(store.get_config(&other).await.unwrap(), None);
    assert_eq!(
        store.put_config(initial.clone(), 0).await.unwrap(),
        AdminOidcConfigPutOutcome::Conflict
    );
    assert_eq!(
        store
            .put_config(config(&tenant, "invalid-revision", 3), 1)
            .await
            .unwrap(),
        AdminOidcConfigPutOutcome::Conflict
    );
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let (store, barrier, candidate) = (
            store.clone(),
            barrier.clone(),
            config(&tenant, &format!("binding-{index}"), 2),
        );
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.put_config(candidate, 1).await.unwrap()
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        if let AdminOidcConfigPutOutcome::Stored(record) = task.await.unwrap() {
            winners.push(record);
        }
    }
    assert_eq!(
        winners.len(),
        1,
        "one configuration revision owns the new binding"
    );
    let current = winners.pop().unwrap();
    assert_eq!(
        store.get_config(&tenant).await.unwrap(),
        Some(current.clone())
    );
    assert_eq!(
        store.delete_config(&tenant, 1).await.unwrap(),
        AdminOidcConfigDeleteOutcome::Conflict
    );

    let state_hash = format!("state-{tenant}");
    let original_flow = flow(&current, &state_hash, now);
    store.put_flow(original_flow.clone()).await.unwrap();
    let foreign_config = config(&other, "other-binding", 1);
    assert!(
        store
            .put_flow(flow(&foreign_config, &state_hash, now))
            .await
            .is_err(),
        "an existing hashed browser flow cannot be replaced or moved between tenants"
    );
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, barrier, state_hash) = (store.clone(), barrier.clone(), state_hash.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.consume_flow(&state_hash, now).await.unwrap()
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        if let Some(record) = task.await.unwrap() {
            winners.push(record);
        }
    }
    assert_eq!(winners, vec![original_flow]);
    let expired_hash = format!("expired-{tenant}");
    store
        .put_flow(flow(&current, &expired_hash, now - 300))
        .await
        .unwrap();
    assert_eq!(store.consume_flow(&expired_hash, now).await.unwrap(), None);
    assert_eq!(
        store.consume_flow(&expired_hash, now - 1).await.unwrap(),
        None
    );

    let session_hash = format!("session-{tenant}");
    let original_session = session(&current, &session_hash, now);
    store
        .create_session(original_session.clone())
        .await
        .unwrap();
    assert!(
        store
            .create_session(session(&foreign_config, &session_hash, now))
            .await
            .is_err(),
        "an existing hashed session cannot change its authority"
    );
    store.delete_session(&other, &session_hash).await.unwrap();
    assert_eq!(
        store.get_session(&session_hash, now).await.unwrap(),
        Some(original_session)
    );
    store.delete_session(&tenant, &session_hash).await.unwrap();
    assert_eq!(store.get_session(&session_hash, now).await.unwrap(), None);
    store.delete_session(&tenant, &session_hash).await.unwrap();
    let expired_session = session(&current, &expired_hash, now - 300);
    store.create_session(expired_session).await.unwrap();
    assert_eq!(store.get_session(&expired_hash, now).await.unwrap(), None);
    store.delete_session(&tenant, &expired_hash).await.unwrap();

    // Recreating revision one still has an unrelated binding identity.
    assert_eq!(
        store.delete_config(&tenant, 2).await.unwrap(),
        AdminOidcConfigDeleteOutcome::Deleted
    );
    let recreated = config(&tenant, "recreated-binding", 1);
    assert_eq!(
        store.put_config(recreated.clone(), 0).await.unwrap(),
        AdminOidcConfigPutOutcome::Stored(recreated.clone())
    );
    assert_ne!(recreated.binding_id, current.binding_id);
    store.put_config(foreign_config.clone(), 0).await.unwrap();
    let pending_hash = format!("pending-{tenant}");
    let retained_hash = format!("retained-{tenant}");
    store
        .put_flow(flow(&recreated, &pending_hash, now))
        .await
        .unwrap();
    store
        .create_session(session(&recreated, &pending_hash, now))
        .await
        .unwrap();
    let foreign_flow = flow(&foreign_config, &retained_hash, now);
    let foreign_session = session(&foreign_config, &retained_hash, now);
    store.put_flow(foreign_flow.clone()).await.unwrap();
    store.create_session(foreign_session.clone()).await.unwrap();
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 3);
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 0);
    assert_eq!(store.get_config(&tenant).await.unwrap(), None);
    assert_eq!(store.consume_flow(&pending_hash, now).await.unwrap(), None);
    assert_eq!(store.get_session(&pending_hash, now).await.unwrap(), None);
    assert_eq!(
        store.consume_flow(&retained_hash, now).await.unwrap(),
        Some(foreign_flow)
    );
    assert_eq!(
        store.get_session(&retained_hash, now).await.unwrap(),
        Some(foreign_session)
    );
    assert_eq!(store.delete_all_by_tenant(&other).await.unwrap(), 2);
    let single = config("", "single-binding", 1);
    assert_eq!(
        store.put_config(single.clone(), 0).await.unwrap(),
        AdminOidcConfigPutOutcome::Stored(single.clone())
    );
    assert_eq!(store.get_config("").await.unwrap(), Some(single));
    assert_eq!(store.delete_all_by_tenant("").await.unwrap(), 1);
}

#[tokio::test]
async fn memory_admin_auth_contract() {
    admin_auth_contract(MemoryAdminAuthStore::default()).await;
}

#[tokio::test]
async fn postgres_admin_auth_contract() {
    admin_auth_contract(agent_auth_http::state::AdminAuthStoreImpl::Postgres(
        database().await,
    ))
    .await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_admin_auth_contract() {
    let (db, durable) = super::aws_contract_database::table("key", vec![], vec![]).await;
    let (_, runtime) = super::aws_contract_database::table("key", vec![], vec![]).await;
    admin_auth_contract(agent_auth_http::adapters::aws::DynamoAdminAuthStore::new(
        db.clone(),
        &durable,
        &runtime,
    ))
    .await;
    for table in [durable, runtime] {
        db.delete_table().table_name(table).send().await.unwrap();
    }
}
