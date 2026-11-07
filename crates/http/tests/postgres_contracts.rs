//! Real-database contracts. Run with scripts/test_postgres_contracts.sh.
//! Missing database configuration is an error, never a silently skipped PASS.

use agent_auth_http::{
    adapters::{
        memory::{
            MemoryClientStore, MemoryCodeStore, MemoryInitialAccessTokenStore, MemoryParStore,
            MemoryRefreshStore, MemoryReplayStore,
        },
        postgres::PostgresStore,
    },
    ports::{
        ClientRecord, ClientStore, CodeRecord, CodeStore, InitialAccessTokenStore, LeaseAcquire,
        ParRecord, ParStore, RefreshFamilyRecord, RefreshLeaseAcquire, RefreshStore, ReplayStore,
    },
};
use std::sync::Arc;
use tokio::sync::Barrier;

#[path = "postgres/authorization.rs"]
mod authorization_contracts;

#[path = "postgres/policy_artifacts.rs"]
mod policy_artifact_contracts;

#[path = "postgres/jti.rs"]
mod jti_contracts;

#[path = "postgres/authz_sessions.rs"]
mod authz_session_contracts;

#[path = "postgres/exchange_failure.rs"]
mod exchange_failure_contracts;

#[path = "postgres/rate_limits.rs"]
mod rate_limit_contracts;

#[path = "postgres/federation.rs"]
mod federation_contracts;

#[path = "postgres/migrations.rs"]
mod migration_contracts;

#[path = "postgres/domain_map.rs"]
mod domain_map_contracts;

#[path = "postgres/passkey_challenges.rs"]
mod passkey_challenge_contracts;

#[path = "postgres/device.rs"]
mod device_contracts;

#[path = "postgres/admin_auth.rs"]
mod admin_auth_contracts;

#[path = "postgres/attribute_namespaces.rs"]
mod attribute_namespace_contracts;

#[path = "postgres/passwords.rs"]
mod password_contracts;

#[path = "postgres/grace.rs"]
mod grace_contracts;

#[path = "postgres/security_events.rs"]
mod security_event_contracts;

#[path = "postgres/federation_mappings.rs"]
mod federation_mapping_contracts;

#[path = "postgres/federation_authority.rs"]
mod federation_authority_contracts;

#[path = "postgres/users.rs"]
mod user_contracts;

#[path = "postgres/users_faults.rs"]
mod user_fault_contracts;

#[path = "postgres/scim_groups.rs"]
mod scim_group_contracts;

#[path = "postgres/scim_groups_faults.rs"]
mod scim_group_fault_contracts;

#[path = "postgres/sessions.rs"]
mod login_session_contracts;

#[path = "postgres/sessions_faults.rs"]
mod login_session_fault_contracts;

#[path = "postgres/recovery.rs"]
mod recovery_contracts;

#[path = "postgres/recovery_faults.rs"]
mod recovery_fault_contracts;

#[cfg(feature = "aws")]
#[path = "postgres/recovery_aws_races.rs"]
mod recovery_aws_race_contracts;

#[path = "postgres/passkeys.rs"]
mod passkey_contracts;

#[path = "postgres/passkeys_faults.rs"]
mod passkey_fault_contracts;

#[path = "postgres/invitations.rs"]
mod invitation_contracts;

#[path = "postgres/invitations_faults.rs"]
mod invitation_fault_contracts;

#[path = "postgres/outbox.rs"]
mod outbox_contracts;

#[path = "postgres/outbox_faults.rs"]
mod outbox_fault_contracts;

#[path = "postgres/governance.rs"]
mod governance_contracts;

#[path = "postgres/governance_faults.rs"]
mod governance_fault_contracts;

#[path = "postgres/ciba.rs"]
mod ciba_contracts;

#[path = "postgres/ciba_faults.rs"]
mod ciba_fault_contracts;

#[path = "postgres/ssf.rs"]
mod ssf_contracts;

#[path = "postgres/ssf_faults.rs"]
mod ssf_fault_contracts;

#[cfg(feature = "aws")]
#[path = "postgres/aws.rs"]
mod aws_contract_database;

#[cfg(feature = "aws")]
#[path = "postgres/foundation_aws.rs"]
mod foundation_aws_contracts;

async fn database() -> PostgresStore {
    let url = std::env::var("A_AUTH_TEST_DATABASE_URL")
        .expect("A_AUTH_TEST_DATABASE_URL must point to a dedicated test PostgreSQL database");
    let store = PostgresStore::connect(&url, 16).await.unwrap();
    store.migrate().await.unwrap();
    store
}

fn tenant() -> String {
    format!("contract-{:032x}", rand::random::<u128>())
}

async fn par_contract(store: impl ParStore + Clone + 'static) {
    let tenant = tenant();
    let record = ParRecord {
        request_uri: "urn:ietf:params:oauth:request_uri:one".into(),
        client_id: "client".into(),
        raw_params: "scope=openid".into(),
        expires_at: 200,
    };
    store.put(&tenant, record.clone()).await.unwrap();
    assert_eq!(
        store
            .consume("another-tenant", &record.request_uri, 100)
            .await
            .unwrap(),
        None
    );

    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, barrier, tenant, uri) = (
            store.clone(),
            barrier.clone(),
            tenant.clone(),
            record.request_uri.clone(),
        );
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.consume(&tenant, &uri, 100).await.unwrap()
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        if let Some(record) = task.await.unwrap() {
            winners.push(record);
        }
    }
    assert_eq!(winners, vec![record.clone()]);
    assert_eq!(
        store
            .consume(&tenant, &record.request_uri, 100)
            .await
            .unwrap(),
        None
    );

    store.put(&tenant, record.clone()).await.unwrap();
    assert_eq!(
        store
            .consume(&tenant, &record.request_uri, 200)
            .await
            .unwrap(),
        None
    );
    // Consuming an expired request removes it; a clock rewind cannot resurrect it.
    assert_eq!(
        store
            .consume(&tenant, &record.request_uri, 100)
            .await
            .unwrap(),
        None
    );
    store.put(&tenant, record.clone()).await.unwrap();
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 1);
    assert_eq!(
        store
            .consume(&tenant, &record.request_uri, 100)
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn memory_par_contract() {
    par_contract(MemoryParStore::default()).await;
}

#[tokio::test]
async fn postgres_par_contract() {
    par_contract(agent_auth_http::state::ParStoreImpl::Postgres(
        database().await,
    ))
    .await;
}

async fn replay_contract(store: impl ReplayStore + Clone + 'static) {
    let tenant = tenant();
    let now = agent_auth_http::current_unix_secs();
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, barrier, tenant) = (store.clone(), barrier.clone(), tenant.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .check_and_set(&tenant, "proof-jti", now + 3600)
                .await
                .unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap());
    }
    assert_eq!(
        winners, 1,
        "a proof is accepted exactly once across connections"
    );
    assert!(!store
        .check_and_set(&tenant, "proof-jti", now + 7200)
        .await
        .unwrap());
    // Expired history can be replaced atomically; live history cannot.
    assert!(store
        .check_and_set(&tenant, "expired", now - 30)
        .await
        .unwrap());
    assert!(store
        .check_and_set(&tenant, "expired", now + 3600)
        .await
        .unwrap());
    assert!(!store
        .check_and_set(&tenant, "expired", now + 3600)
        .await
        .unwrap());
    let other_tenant = format!("{tenant}-other");
    assert!(store
        .check_and_set(&other_tenant, "proof-jti", now + 3600)
        .await
        .unwrap());
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 2);
    assert!(!store
        .check_and_set(&other_tenant, "proof-jti", now + 3600)
        .await
        .unwrap());
    assert_eq!(store.delete_all_by_tenant(&other_tenant).await.unwrap(), 1);
}

#[tokio::test]
async fn memory_replay_contract() {
    replay_contract(MemoryReplayStore::default()).await;
}

#[tokio::test]
async fn postgres_replay_contract() {
    replay_contract(agent_auth_http::state::ReplayStoreImpl::Postgres(
        database().await,
    ))
    .await;
}

fn initial_access_token(token_id: &str) -> agent_auth_http::credential::InitialAccessTokenRecord {
    use agent_auth_http::credential::{
        new_credential_record, CredentialKind, InitialAccessTokenRecord,
    };
    InitialAccessTokenRecord {
        token_id: token_id.into(),
        credential: new_credential_record(
            b"contract-test-pepper",
            CredentialKind::InitialAccessToken,
            "fixture",
            "credential".into(),
            "owner".into(),
            "fixture-token",
            100,
            200,
            "contract-test".into(),
            None,
        ),
        scopes: vec!["dcr:register".into()],
        rate_limit_per_minute: 30,
        one_time: true,
        used_at: None,
        version: 1,
    }
}

async fn initial_access_token_contract(store: impl InitialAccessTokenStore + Clone + 'static) {
    use agent_auth_http::credential::CredentialStatus;
    let tenant = tenant();
    let other_tenant = format!("{tenant}-other");
    let record = initial_access_token("iat-once");
    assert!(store.put_new(&tenant, record.clone()).await.unwrap());
    assert!(!store.put_new(&tenant, record.clone()).await.unwrap());
    assert_eq!(store.get(&other_tenant, "iat-once").await.unwrap(), None);
    assert!(!store
        .consume_once(&tenant, "iat-once", 0, 110)
        .await
        .unwrap());
    assert!(!store
        .consume_once(&tenant, "iat-once", 1, 200)
        .await
        .unwrap());
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, barrier, tenant) = (store.clone(), barrier.clone(), tenant.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .consume_once(&tenant, "iat-once", 1, 110)
                .await
                .unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap());
    }
    assert_eq!(winners, 1);
    let consumed = store.get(&tenant, "iat-once").await.unwrap().unwrap();
    assert_eq!(consumed.used_at, Some(110));
    assert_eq!(consumed.version, 2);
    assert_eq!(consumed.credential.status, CredentialStatus::Consumed);
    assert!(
        !store.put_new(&tenant, record).await.unwrap(),
        "used authority cannot be recreated"
    );
    assert!(!store.revoke(&tenant, "iat-once", 1, 120).await.unwrap());
    assert!(store.revoke(&tenant, "iat-once", 2, 120).await.unwrap());
    assert!(
        store.revoke(&tenant, "iat-once", 0, 120).await.unwrap(),
        "revocation is idempotent"
    );
    let revoked = store.get(&tenant, "iat-once").await.unwrap().unwrap();
    assert_eq!(revoked.credential.status, CredentialStatus::Revoked);
    assert_eq!(revoked.credential.expires_at, 120);
    assert_eq!(revoked.version, 3);

    let mut reusable = initial_access_token("iat-reusable");
    reusable.one_time = false;
    assert!(store.put_new(&tenant, reusable).await.unwrap());
    assert!(!store
        .consume_once(&tenant, "iat-reusable", 1, 110)
        .await
        .unwrap());
    assert!(store
        .put_new(&other_tenant, initial_access_token("iat-once"))
        .await
        .unwrap());
    assert_eq!(store.list(&tenant).await.unwrap().len(), 2);
    store.delete(&tenant, "iat-once").await.unwrap();
    store.delete(&tenant, "iat-reusable").await.unwrap();
    assert_eq!(store.get(&tenant, "iat-once").await.unwrap(), None);
    assert!(store
        .get(&other_tenant, "iat-once")
        .await
        .unwrap()
        .is_some());
    store.delete(&other_tenant, "iat-once").await.unwrap();
}

#[tokio::test]
async fn memory_initial_access_token_contract() {
    initial_access_token_contract(MemoryInitialAccessTokenStore::default()).await;
}

#[tokio::test]
async fn postgres_initial_access_token_contract() {
    initial_access_token_contract(
        agent_auth_http::state::InitialAccessTokenStoreImpl::Postgres(database().await),
    )
    .await;
}

async fn client_contract(store: impl ClientStore + Clone + 'static) {
    use agent_auth_http::credential::{CredentialKind, CredentialSet};
    let tenant = tenant();
    let original = ClientRecord {
        client_id: "client".into(),
        token_endpoint_auth_method: "none".into(),
        redirect_uris: vec!["https://client.example/callback".into()],
        last_used_day: Some(100),
        ..Default::default()
    };
    store.put(&tenant, original.clone()).await.unwrap();
    assert_eq!(store.get("other", "client").await.unwrap(), None);
    let mut metadata = original.clone();
    metadata.redirect_uris = vec!["https://client.example/new-callback".into()];
    assert!(store
        .put_if_credential_versions(&tenant, metadata.clone(), 0, 0)
        .await
        .unwrap());
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, barrier, tenant) = (store.clone(), barrier.clone(), tenant.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .replace_credential_set(
                    &tenant,
                    "client",
                    CredentialKind::ClientSecret,
                    0,
                    CredentialSet {
                        version: 1,
                        ..Default::default()
                    },
                )
                .await
                .unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap());
    }
    assert_eq!(winners, 1);
    assert!(
        !store
            .put_if_credential_versions(&tenant, original, 0, 0)
            .await
            .unwrap(),
        "a stale metadata writer must not overwrite a rotated verifier"
    );
    let snapshot = store.get(&tenant, "client").await.unwrap().unwrap();
    assert_eq!(snapshot.redirect_uris, metadata.redirect_uris);
    assert_eq!(snapshot.client_secret_credentials.version, 1);
    store.touch_last_used(&tenant, "client", 101).await.unwrap();
    assert!(!store
        .convert_to_tombstone(&tenant, "client", 300, Some(100), 0)
        .await
        .unwrap());
    assert!(
        !store
            .put_if_credential_versions(&tenant, snapshot, 1, 0)
            .await
            .unwrap(),
        "a stale writer must not erase a concurrent activity update"
    );
    store.touch_last_used(&tenant, "client", 99).await.unwrap();
    assert_eq!(
        store
            .get(&tenant, "client")
            .await
            .unwrap()
            .unwrap()
            .last_used_day,
        Some(101)
    );
    assert!(store
        .list_reclaim_candidates(&tenant, 100)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        store
            .list_reclaim_candidates(&tenant, 101)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(!store
        .convert_to_tombstone(&tenant, "client", 300, Some(101), 1)
        .await
        .unwrap());
    assert!(store
        .convert_to_tombstone(&tenant, "client", 300, Some(101), 0)
        .await
        .unwrap());
    assert!(!store
        .replace_credential_set(
            &tenant,
            "client",
            CredentialKind::ClientSecret,
            1,
            CredentialSet {
                version: 2,
                ..Default::default()
            }
        )
        .await
        .unwrap());
    let tombstone = store.get(&tenant, "client").await.unwrap().unwrap();
    assert!(tombstone.is_tombstoned());
    store
        .hard_delete_with_audit(&tenant, &tombstone, 400)
        .await
        .unwrap();
    assert_eq!(store.get(&tenant, "client").await.unwrap(), None);
    assert!(store.list(&tenant).await.unwrap().is_empty());
}

#[tokio::test]
async fn memory_client_contract() {
    client_contract(MemoryClientStore::default()).await;
}

#[tokio::test]
async fn postgres_client_contract() {
    client_contract(agent_auth_http::state::ClientStoreImpl::Postgres(
        database().await,
    ))
    .await;
}

fn code_record() -> CodeRecord {
    CodeRecord {
        workload_actor: None,
        code: "code".into(),
        client_id: "client".into(),
        cimd_snapshot: None,
        redirect_uri: "https://client.example/callback".into(),
        code_challenge: "pkce".into(),
        resources: vec!["https://api.example".into()],
        user_id: "user".into(),
        scope: vec!["openid".into()],
        expires_at: 200,
        authz_session_id: None,
        nonce: Some("nonce".into()),
        auth_time: 90,
        authorization_details: vec![],
        acr: None,
        amr: vec!["pwd".into()],
        credential_epoch: Some(1),
        password_credential_version: Some(1),
    }
}

async fn code_contract(codes: impl CodeStore + Clone + 'static, clients: impl ClientStore) {
    let tenant = tenant();
    clients
        .put(
            &tenant,
            ClientRecord {
                client_id: "client".into(),
                token_endpoint_auth_method: "none".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let record = code_record();
    codes.put(&tenant, record.clone()).await.unwrap();
    assert_eq!(
        codes
            .acquire_lease("other", "code", "owner", 100, 110)
            .await
            .unwrap(),
        LeaseAcquire::NotFound
    );
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for i in 0..16 {
        let (codes, barrier, tenant) = (codes.clone(), barrier.clone(), tenant.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let owner = format!("owner-{i}");
            let result = codes
                .acquire_lease(&tenant, "code", &owner, 100, 110)
                .await
                .unwrap();
            (owner, result)
        }));
    }
    let mut owners = Vec::new();
    for task in tasks {
        let (owner, result) = task.await.unwrap();
        match result {
            LeaseAcquire::Acquired(acquired) => {
                assert_eq!(acquired, record);
                owners.push(owner);
            }
            LeaseAcquire::Locked => {}
            result => panic!("unexpected lease result: {result:?}"),
        }
    }
    assert_eq!(owners.len(), 1);
    let stale_owner = &owners[0];
    assert_eq!(
        codes
            .acquire_lease(&tenant, "code", "replacement", 110, 120)
            .await
            .unwrap(),
        LeaseAcquire::Acquired(record.clone())
    );
    assert!(codes
        .finalize(&tenant, "code", "client", 200, 111, stale_owner, None)
        .await
        .is_err());
    assert!(codes
        .release_lease(&tenant, "code", stale_owner, 111)
        .await
        .is_err());
    codes
        .release_lease(&tenant, "code", "replacement", 111)
        .await
        .unwrap();
    assert_eq!(
        codes
            .acquire_lease(&tenant, "code", "final", 112, 122)
            .await
            .unwrap(),
        LeaseAcquire::Acquired(record.clone())
    );
    codes
        .finalize(&tenant, "code", "client", 200, 113, "final", Some("grant"))
        .await
        .unwrap();
    assert_eq!(
        codes
            .acquire_lease(&tenant, "code", "replay", 114, 124)
            .await
            .unwrap(),
        LeaseAcquire::AlreadyConsumed {
            record: record.clone(),
            issued_grant_id: Some("grant".into())
        }
    );
    assert!(!codes
        .has_unexpired_by_client(&tenant, "client", 114)
        .await
        .unwrap());
    assert!(!codes.replay_detected(&tenant, "code").await.unwrap());
    assert!(codes.record_replay(&tenant, "code", 114).await.unwrap());
    assert!(codes.replay_detected(&tenant, "code").await.unwrap());
    assert!(!codes.record_replay(&tenant, "code", 200).await.unwrap());
    assert_eq!(
        codes
            .acquire_lease(&tenant, "code", "expired", 200, 210)
            .await
            .unwrap(),
        LeaseAcquire::NotFound
    );
    assert_eq!(codes.delete_by_user(&tenant, "user").await.unwrap(), 1);
    clients.delete(&tenant, "client").await.unwrap();
}

#[tokio::test]
async fn memory_code_contract() {
    code_contract(MemoryCodeStore::default(), MemoryClientStore::default()).await;
}

#[tokio::test]
async fn postgres_code_contract() {
    let store = database().await;
    code_contract(
        agent_auth_http::state::CodeStoreImpl::Postgres(store.clone()),
        agent_auth_http::state::ClientStoreImpl::Postgres(store),
    )
    .await;
}

fn refresh_record() -> RefreshFamilyRecord {
    RefreshFamilyRecord {
        family_id: "family".into(),
        current_version: 0,
        revoked: false,
        client_id: "client".into(),
        cimd_snapshot: None,
        user_id: "user".into(),
        credential_epoch: 1,
        resources: vec!["https://api.example".into()],
        scope: vec!["openid".into()],
        actor_allowlist: vec![],
        max_act_chain: 1,
        dpop_jkt: Some("bound-key".into()),
        pkce_code_challenge: Some("pkce".into()),
        auth_time: Some(90),
        acr: None,
        password_credential_version: Some(1),
    }
}

async fn refresh_contract(refresh: impl RefreshStore + Clone + 'static, clients: impl ClientStore) {
    let tenant = tenant();
    clients
        .put(
            &tenant,
            ClientRecord {
                client_id: "client".into(),
                token_endpoint_auth_method: "none".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let record = refresh_record();
    refresh.create(&tenant, record.clone()).await.unwrap();
    assert_eq!(refresh.get("other", "family").await.unwrap(), None);
    assert!(refresh
        .has_active_family_by_client(&tenant, "client")
        .await
        .unwrap());
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for i in 0..16 {
        let (refresh, barrier, tenant) = (refresh.clone(), barrier.clone(), tenant.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let owner = format!("owner-{i}");
            let outcome = refresh
                .acquire_lease(&tenant, "family", 0, &owner, 100, 110)
                .await
                .unwrap();
            (owner, outcome)
        }));
    }
    let mut owners = Vec::new();
    for task in tasks {
        let (owner, result) = task.await.unwrap();
        match result {
            RefreshLeaseAcquire::Acquired => owners.push(owner),
            RefreshLeaseAcquire::Locked { retry_after_secs } => assert_eq!(retry_after_secs, 10),
            outcome => panic!("unexpected refresh lease: {outcome:?}"),
        }
    }
    assert_eq!(owners.len(), 1);
    let stale = &owners[0];
    assert!(
        !refresh
            .finalize_rotation(&tenant, "family", 0, stale, 110)
            .await
            .unwrap(),
        "an expired signing lease must not advance the family"
    );
    assert_eq!(
        refresh
            .acquire_lease(&tenant, "family", 0, "replacement", 110, 120)
            .await
            .unwrap(),
        RefreshLeaseAcquire::Acquired
    );
    assert!(!refresh
        .release_lease(&tenant, "family", 0, stale)
        .await
        .unwrap());
    assert!(!refresh
        .finalize_rotation(&tenant, "family", 0, stale, 111)
        .await
        .unwrap());
    assert!(refresh
        .finalize_rotation(&tenant, "family", 0, "replacement", 111)
        .await
        .unwrap());
    assert!(!refresh
        .finalize_rotation(&tenant, "family", 0, "replacement", 111)
        .await
        .unwrap());
    let mut rotated = record;
    rotated.current_version = 1;
    assert_eq!(refresh.get(&tenant, "family").await.unwrap(), Some(rotated));
    assert_eq!(
        refresh
            .acquire_lease(&tenant, "family", 0, "old-version", 112, 122)
            .await
            .unwrap(),
        RefreshLeaseAcquire::VersionMismatch
    );
    assert!(refresh
        .revoke_by_user_before_epoch(&tenant, "user", 1)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        refresh
            .revoke_by_user_before_epoch(&tenant, "user", 2)
            .await
            .unwrap(),
        vec!["family"]
    );
    assert_eq!(
        refresh
            .acquire_lease(&tenant, "family", 1, "revoked", 112, 122)
            .await
            .unwrap(),
        RefreshLeaseAcquire::Revoked
    );
    assert!(!refresh
        .has_active_family_by_client(&tenant, "client")
        .await
        .unwrap());
    assert_eq!(
        refresh.revoke_by_client(&tenant, "client").await.unwrap(),
        vec!["family"]
    );
    assert_eq!(
        refresh.revoke_by_user(&tenant, "user").await.unwrap(),
        vec!["family"]
    );
    assert_eq!(
        refresh.delete_by_user(&tenant, "user").await.unwrap(),
        vec!["family"]
    );
    assert_eq!(refresh.get(&tenant, "family").await.unwrap(), None);
    clients.delete(&tenant, "client").await.unwrap();
}

#[tokio::test]
async fn memory_refresh_contract() {
    refresh_contract(MemoryRefreshStore::default(), MemoryClientStore::default()).await;
}

#[tokio::test]
async fn postgres_refresh_contract() {
    let store = database().await;
    refresh_contract(
        agent_auth_http::state::RefreshStoreImpl::Postgres(store.clone()),
        agent_auth_http::state::ClientStoreImpl::Postgres(store),
    )
    .await;
}

#[tokio::test]
async fn postgres_authority_creation_is_atomic_with_client_revision() {
    let store = database().await;
    let tenant = tenant();
    let client = ClientRecord {
        client_id: "client".into(),
        token_endpoint_auth_method: "none".into(),
        last_used_day: Some(100),
        ..Default::default()
    };
    // A failed client condition rolls back the already-inserted authority row.
    assert!(CodeStore::put(&store, &tenant, code_record())
        .await
        .is_err());
    assert_eq!(
        CodeStore::acquire_lease(&store, &tenant, "code", "owner", 100, 110)
            .await
            .unwrap(),
        LeaseAcquire::NotFound
    );
    assert!(RefreshStore::create(&store, &tenant, refresh_record())
        .await
        .is_err());
    assert_eq!(
        RefreshStore::get(&store, &tenant, "family").await.unwrap(),
        None
    );
    ClientStore::put(&store, &tenant, client.clone())
        .await
        .unwrap();
    CodeStore::put(&store, &tenant, code_record())
        .await
        .unwrap();
    RefreshStore::create(&store, &tenant, refresh_record())
        .await
        .unwrap();
    assert_eq!(
        ClientStore::get(&store, &tenant, "client")
            .await
            .unwrap()
            .unwrap()
            .authority_revision,
        2
    );
    assert!(
        !ClientStore::put_if_credential_versions(&store, &tenant, client, 0, 0)
            .await
            .unwrap()
    );
    assert!(
        !ClientStore::convert_to_tombstone(&store, &tenant, "client", 300, Some(100), 0)
            .await
            .unwrap()
    );
    CodeStore::acquire_lease(&store, &tenant, "code", "owner", 100, 110)
        .await
        .unwrap();
    // Finalization binds the immutable client and expiry as in the AWS adapter.
    assert!(CodeStore::finalize(
        &store,
        &tenant,
        "code",
        "wrong-client",
        200,
        101,
        "owner",
        None
    )
    .await
    .is_err());
    assert!(
        CodeStore::finalize(&store, &tenant, "code", "client", 201, 101, "owner", None)
            .await
            .is_err()
    );
    CodeStore::finalize(
        &store,
        &tenant,
        "code",
        "client",
        200,
        101,
        "owner",
        Some("grant"),
    )
    .await
    .unwrap();
    assert!(CodeStore::put(&store, &tenant, code_record())
        .await
        .is_err());
    assert!(matches!(
        CodeStore::acquire_lease(&store, &tenant, "code", "replay", 102, 112)
            .await
            .unwrap(),
        LeaseAcquire::AlreadyConsumed { .. }
    ));
    RefreshStore::revoke(&store, &tenant, "family")
        .await
        .unwrap();
    assert!(RefreshStore::create(&store, &tenant, refresh_record())
        .await
        .is_err());
    assert!(
        RefreshStore::get(&store, &tenant, "family")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    assert_eq!(
        ClientStore::get(&store, &tenant, "client")
            .await
            .unwrap()
            .unwrap()
            .authority_revision,
        2,
        "failed duplicate writes must roll back their client-version increment"
    );
    assert!(
        ClientStore::convert_to_tombstone(&store, &tenant, "client", 300, Some(100), 2)
            .await
            .unwrap()
    );
    let mut code = code_record();
    code.code = "code-after-tombstone".into();
    assert!(CodeStore::put(&store, &tenant, code).await.is_err());
    let mut family = refresh_record();
    family.family_id = "family-after-tombstone".into();
    assert!(RefreshStore::create(&store, &tenant, family).await.is_err());
    assert_eq!(
        CodeStore::acquire_lease(&store, &tenant, "code-after-tombstone", "owner", 100, 110)
            .await
            .unwrap(),
        LeaseAcquire::NotFound
    );
    assert_eq!(
        RefreshStore::get(&store, &tenant, "family-after-tombstone")
            .await
            .unwrap(),
        None
    );
    CodeStore::delete_all_by_tenant(&store, &tenant)
        .await
        .unwrap();
    RefreshStore::delete_all_by_tenant(&store, &tenant)
        .await
        .unwrap();
    ClientStore::delete(&store, &tenant, "client")
        .await
        .unwrap();
}

#[tokio::test]
async fn postgres_revocation_and_consumption_survive_pool_reconnect() {
    let store = database().await;
    let tenant = tenant();
    let now = agent_auth_http::current_unix_secs();
    ClientStore::put(
        &store,
        &tenant,
        ClientRecord {
            client_id: "client".into(),
            token_endpoint_auth_method: "none".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    CodeStore::put(&store, &tenant, code_record())
        .await
        .unwrap();
    CodeStore::acquire_lease(&store, &tenant, "code", "owner", 100, 110)
        .await
        .unwrap();
    CodeStore::finalize(
        &store,
        &tenant,
        "code",
        "client",
        200,
        101,
        "owner",
        Some("grant"),
    )
    .await
    .unwrap();
    CodeStore::record_replay(&store, &tenant, "code", 102)
        .await
        .unwrap();
    RefreshStore::create(&store, &tenant, refresh_record())
        .await
        .unwrap();
    RefreshStore::revoke(&store, &tenant, "family")
        .await
        .unwrap();
    assert!(
        ReplayStore::check_and_set(&store, &tenant, "proof", now + 3600)
            .await
            .unwrap()
    );
    InitialAccessTokenStore::put_new(&store, &tenant, initial_access_token("iat-once"))
        .await
        .unwrap();
    InitialAccessTokenStore::consume_once(&store, &tenant, "iat-once", 1, 110)
        .await
        .unwrap();
    ParStore::put(
        &store,
        &tenant,
        ParRecord {
            request_uri: "par".into(),
            client_id: "client".into(),
            raw_params: "scope=openid".into(),
            expires_at: 200,
        },
    )
    .await
    .unwrap();
    drop(store);

    // A new pool and repeat migration must use existing database authority.
    let restored = database().await;
    assert_eq!(
        ClientStore::get(&restored, &tenant, "client")
            .await
            .unwrap()
            .unwrap()
            .authority_revision,
        2
    );
    assert!(
        matches!(CodeStore::acquire_lease(&restored, &tenant, "code", "owner", 103, 113).await.unwrap(), LeaseAcquire::AlreadyConsumed { issued_grant_id: Some(grant), .. } if grant == "grant")
    );
    assert!(CodeStore::replay_detected(&restored, &tenant, "code")
        .await
        .unwrap());
    assert!(
        RefreshStore::get(&restored, &tenant, "family")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    assert!(
        !ReplayStore::check_and_set(&restored, &tenant, "proof", now + 3600)
            .await
            .unwrap()
    );
    assert!(
        !InitialAccessTokenStore::consume_once(&restored, &tenant, "iat-once", 1, 110)
            .await
            .unwrap()
    );
    assert!(ParStore::consume(&restored, &tenant, "par", 100)
        .await
        .unwrap()
        .is_some());
    CodeStore::delete_all_by_tenant(&restored, &tenant)
        .await
        .unwrap();
    RefreshStore::delete_all_by_tenant(&restored, &tenant)
        .await
        .unwrap();
    ClientStore::delete(&restored, &tenant, "client")
        .await
        .unwrap();
    ReplayStore::delete_all_by_tenant(&restored, &tenant)
        .await
        .unwrap();
    InitialAccessTokenStore::delete(&restored, &tenant, "iat-once")
        .await
        .unwrap();
}

#[tokio::test]
async fn postgres_replay_has_one_winner_across_independent_pools() {
    let first = database().await;
    let second = database().await;
    let tenant = tenant();
    let now = agent_auth_http::current_unix_secs();
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for i in 0..16 {
        let store = if i % 2 == 0 {
            first.clone()
        } else {
            second.clone()
        };
        let (barrier, tenant) = (barrier.clone(), tenant.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            ReplayStore::check_and_set(&store, &tenant, "proof", now + 3600)
                .await
                .unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap());
    }
    assert_eq!(winners, 1);
    ReplayStore::delete_all_by_tenant(&first, &tenant)
        .await
        .unwrap();
}
