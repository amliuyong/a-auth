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
    grant_contract(agent_auth_http::state::GrantStoreImpl::Postgres(
        database().await,
    ))
    .await;
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
    policy_version_contract(agent_auth_http::state::PolicyVersionStoreImpl::Postgres(
        database().await,
    ))
    .await;
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

#[tokio::test]
async fn postgres_grant_admission_updates_client_authority_and_rejects_retirement_across_pools() {
    use agent_auth_http::{
        ports::{ClientRecord, ClientStore},
        state::{ClientStoreImpl, GrantStoreImpl},
    };
    let bases = [database().await, database().await];
    let clients = bases.clone().map(ClientStoreImpl::Postgres);
    let grants = bases.map(GrantStoreImpl::Postgres);
    let tenant = tenant();
    clients[0]
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
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let (clients, grants, tenant, barrier) = (
            clients[index % 2].clone(),
            grants[index % 2].clone(),
            tenant.clone(),
            barrier.clone(),
        );
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            grants
                .put_for_active_client(&clients, &tenant, grant(&format!("authorized-{index}")))
                .await
                .unwrap()
        }));
    }
    for task in tasks {
        assert!(task.await.unwrap());
    }
    let current = clients[1].get(&tenant, "client").await.unwrap().unwrap();
    assert_eq!(current.authority_revision, 16);
    assert_eq!(
        current.last_used_day,
        Some(agent_auth_http::current_unix_secs().div_euclid(86_400))
    );
    assert_eq!(
        grants[1].list_by_user(&tenant, "user").await.unwrap().len(),
        16
    );
    assert!(!clients[0]
        .convert_to_tombstone(&tenant, "client", 100, None, 0)
        .await
        .unwrap());
    assert!(clients[1]
        .convert_to_tombstone(
            &tenant,
            "client",
            100,
            current.last_used_day,
            current.authority_revision
        )
        .await
        .unwrap());
    assert!(!grants[0]
        .put_for_active_client(&clients[0], &tenant, grant("after-retirement"))
        .await
        .unwrap());
    assert_eq!(
        grants[1].get(&tenant, "after-retirement").await.unwrap(),
        None
    );
    assert!(grants[0]
        .put_for_active_client(&clients[1], &tenant, grant("foreign-pool"))
        .await
        .is_err());
}

#[tokio::test]
async fn postgres_grant_admission_failed_second_write_preserves_client_authority() {
    use agent_auth_http::{
        ports::{ClientRecord, ClientStore},
        state::{ClientStoreImpl, GrantStoreImpl},
    };
    let base = database().await;
    let clients = ClientStoreImpl::Postgres(base.clone());
    let grants = GrantStoreImpl::Postgres(base);
    let tenant = tenant();
    let before = ClientRecord {
        client_id: "client".into(),
        token_endpoint_auth_method: "none".into(),
        authority_revision: 7,
        ..Default::default()
    };
    clients.put(&tenant, before.clone()).await.unwrap();
    let url = std::env::var("A_AUTH_TEST_DATABASE_URL").expect("dedicated PostgreSQL fixture");
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let name = format!("test_grant_{:032x}", rand::random::<u128>());
    let tenant_hex: String = tenant
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    sqlx::query(&format!(
        "ALTER TABLE a_auth.grants ADD CONSTRAINT {name} CHECK (convert_to(tenant, 'UTF8') <> decode('{tenant_hex}', 'hex') OR grant_id <> 'reject-write')"
    )).execute(&pool).await.unwrap();
    assert!(grants
        .put_for_active_client(&clients, &tenant, grant("reject-write"))
        .await
        .is_err());
    assert_eq!(clients.get(&tenant, "client").await.unwrap(), Some(before));
    assert_eq!(grants.get(&tenant, "reject-write").await.unwrap(), None);
    sqlx::query(&format!("ALTER TABLE a_auth.grants DROP CONSTRAINT {name}"))
        .execute(&pool)
        .await
        .unwrap();
    assert!(grants
        .put_for_active_client(&clients, &tenant, grant("reject-write"))
        .await
        .unwrap());
    let current = clients.get(&tenant, "client").await.unwrap().unwrap();
    assert_eq!(current.authority_revision, 8);
    pool.close().await;
}

#[tokio::test]
async fn postgres_client_authority_rejects_missing_nullable_status_without_reactivation() {
    use agent_auth_http::{
        ports::{ClientRecord, ClientStore, CodeStore, LeaseAcquire},
        state::{ClientStoreImpl, CodeStoreImpl, GrantStoreImpl},
    };
    let (base, pool, admin, name, _url) = super::ssf_contracts::isolated_database().await;
    let clients = ClientStoreImpl::Postgres(base.clone());
    let codes = CodeStoreImpl::Postgres(base.clone());
    let grants = GrantStoreImpl::Postgres(base);
    let before = ClientRecord {
        client_id: "retired".into(),
        token_endpoint_auth_method: "none".into(),
        tombstoned_at: Some(100),
        require_dpop: true,
        authority_revision: 17,
        ..Default::default()
    };
    clients.put("", before.clone()).await.unwrap();
    assert_eq!(
        clients.get("", "retired").await.unwrap(),
        Some(before.clone())
    );
    // Option fields otherwise deserialize as None when omitted. A corrupt
    // tombstone must never become an active client, even during a metadata write.
    sqlx::query(
        "UPDATE a_auth.clients SET record = record - 'tombstoned_at' \
         WHERE tenant = '' AND client_id = 'retired'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let corrupt: serde_json::Value = sqlx::query_scalar(
        "SELECT record FROM a_auth.clients WHERE tenant = '' AND client_id = 'retired'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(clients.get("", "retired").await.is_err());
    assert!(clients.list("").await.is_err());
    assert!(clients.touch_last_used("", "retired", 200).await.is_err());
    let now = agent_auth_http::current_unix_secs();
    let mut code = super::code_record();
    code.code = "corrupt-client-code".into();
    code.client_id = "retired".into();
    code.expires_at = now + 3600;
    assert!(codes.put("", code).await.is_err());
    assert_eq!(
        codes
            .acquire_lease("", "corrupt-client-code", "inspect", now, now + 30)
            .await
            .unwrap(),
        LeaseAcquire::NotFound
    );
    let mut blocked = grant("corrupt-client-grant");
    blocked.client_id = "retired".into();
    blocked.constraints.expires_at = now + 3600;
    assert!(grants
        .put_for_active_client(&clients, "", blocked)
        .await
        .is_err());
    assert_eq!(grants.get("", "corrupt-client-grant").await.unwrap(), None);
    let after: serde_json::Value = sqlx::query_scalar(
        "SELECT record FROM a_auth.clients WHERE tenant = '' AND client_id = 'retired'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after, corrupt);
    sqlx::query(
        "UPDATE a_auth.clients SET record = $1 WHERE tenant = '' AND client_id = 'retired'",
    )
    .bind(sqlx::types::Json(before))
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

#[tokio::test]
async fn postgres_code_issuance_http_uses_active_user_authority() {
    use agent_auth_http::{
        adapters::postgres::{PostgresUsersStore, UserAuthorityKey},
        ports::{ClientRecord, ClientStore, CodeStore, LeaseAcquire, UserStatus, UsersStore},
        state::{AuthzSessionStoreImpl, ClientStoreImpl, CodeStoreImpl, UsersStoreImpl},
        AppState,
    };
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    let (base, pool, admin, name, _url) = super::ssf_contracts::isolated_database().await;
    // Exercise the HTTP caller and durable authority seams, not production
    // startup: the other development services intentionally remain fixtures.
    let mut state = AppState::dev("issuer.example.test");
    state.clients = Arc::new(ClientStoreImpl::Postgres(base.clone()));
    state.codes = Arc::new(CodeStoreImpl::Postgres(base.clone()));
    state.authz_sessions = Arc::new(AuthzSessionStoreImpl::Postgres(base.clone()));
    state.users = Arc::new(UsersStoreImpl::Postgres(PostgresUsersStore::new(
        base,
        UserAuthorityKey::new([0x57; 32]).unwrap(),
    )));
    let now = agent_auth_http::current_unix_secs();
    state
        .users
        .create_or_get_by_id("", "user:alice", now)
        .await
        .unwrap();
    state
        .clients
        .put(
            "",
            ClientRecord {
                client_id: "client".into(),
                redirect_uris: vec!["https://client.example.com/callback".into()],
                token_endpoint_auth_method: "none".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (router, _) = agent_auth_http::build_router(state.clone());
    let query = format!(
        "/authorize?response_type=code&client_id=client&redirect_uri=https://client.example.com/callback\
         &code_challenge={}&code_challenge_method=S256&scope=openid&login_user=user:alice",
        agent_auth_client::s256_challenge("0123456789012345678901234567890123456789abc")
    );
    let send = || {
        router.clone().oneshot(
            Request::builder()
                .uri(&query)
                .header("host", "issuer.example.test")
                .body(Body::empty())
                .unwrap(),
        )
    };
    let response = send().await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let redirect = url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
    let code = redirect
        .query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned();
    let LeaseAcquire::Acquired(record) = state
        .codes
        .acquire_lease("", &code, "inspect", now, now + 30)
        .await
        .unwrap()
    else {
        panic!("issued code must exist");
    };
    assert_eq!(record.user_id, "user:alice");
    assert_eq!(record.credential_epoch, Some(0));
    assert_eq!(
        state
            .clients
            .get("", "client")
            .await
            .unwrap()
            .unwrap()
            .authority_revision,
        1
    );
    state
        .users
        .set_status("", "user:alice", UserStatus::Disabled, now + 1)
        .await
        .unwrap();
    let response = send().await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let redirect = url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
    assert!(redirect
        .query_pairs()
        .any(|(key, value)| key == "error" && value == "access_denied"));
    assert!(!redirect.query_pairs().any(|(key, _)| key == "code"));
    assert_eq!(
        state
            .clients
            .get("", "client")
            .await
            .unwrap()
            .unwrap()
            .authority_revision,
        1
    );
    pool.close().await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
