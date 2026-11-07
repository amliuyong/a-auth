use super::{database, tenant};
use agent_auth_http::{
    adapters::postgres::{PostgresStore, PostgresUsersStore, UserAuthorityKey},
    attribute_namespace::{
        AttributeNamespaceStore, BeginNamespaceChange, BeginNamespaceChangeOutcome,
        NamespaceChangeKind, NamespaceChangeOutcome, NamespaceMigrationPhase,
        NamespaceOperationCheckpoint,
    },
    federation_attributes::{
        FederationAttributeMappingsStore, FederationAttributeOwnerPurgeOutcome,
        FederationAttributeReconciliationOutcome, FederationAttributeReconciliationRequest,
        MappingChange, MappingChangeOutcome, MappingMode, MappingSpec,
    },
    ports::{FederationConfigStore, PutAttrOutcome, UsersStore},
    state::{
        AttributeNamespaceStoreImpl, FederationAttributeMappingsStoreImpl,
        FederationConfigStoreImpl, UsersStoreImpl,
    },
    AppState,
};
use std::{collections::BTreeSet, sync::Arc};
use tokio::sync::Barrier;

const NAMESPACE: &str = "https://resource.example.test/attributes";
const ISSUER: &str = "https://identity.example.test";
const USER: &str = "federated\0canonical";

fn state(store: PostgresStore) -> AppState {
    let mut state = AppState::dev("issuer.example.test");
    state.users = Arc::new(UsersStoreImpl::Postgres(PostgresUsersStore::new(
        store.clone(),
        UserAuthorityKey::new([0x57; 32]).unwrap(),
    )));
    state.attribute_namespaces = Arc::new(AttributeNamespaceStoreImpl::Postgres(store.clone()));
    state.federation_config = Arc::new(FederationConfigStoreImpl::Postgres(store.clone()));
    state.federation_attribute_mappings =
        Arc::new(FederationAttributeMappingsStoreImpl::Postgres(store));
    state
}

async fn initialize(state: &AppState, tenant: &str) {
    state
        .users
        .create_or_get_by_id(tenant, USER, 100)
        .await
        .unwrap();
    let BeginNamespaceChangeOutcome::Started(registration) = state
        .attribute_namespaces
        .begin_change(
            tenant,
            BeginNamespaceChange {
                canonical_namespace: NAMESPACE.into(),
                exact_audiences: BTreeSet::from([NAMESPACE.into()]),
                expected_revision: 0,
                operation_id: "register".into(),
                kind: NamespaceChangeKind::Upsert,
            },
        )
        .await
        .unwrap()
    else {
        panic!("namespace registration");
    };
    let revision = registration.operation.as_ref().unwrap().revision;
    let NamespaceChangeOutcome::Updated(registration) = state
        .attribute_namespaces
        .checkpoint(
            tenant,
            NAMESPACE,
            "register",
            NamespaceOperationCheckpoint {
                expected_revision: revision,
                phase: NamespaceMigrationPhase::Migrating,
                cursor: None,
                scan_complete: true,
                started_mutation: false,
                inflight_user_id: None,
                users_scanned: 0,
                users_completed: 0,
                conflict_count: 0,
                conflict_user_ids: vec![],
            },
        )
        .await
        .unwrap()
    else {
        panic!("namespace checkpoint");
    };
    assert!(matches!(
        state
            .attribute_namespaces
            .activate(
                tenant,
                NAMESPACE,
                "register",
                registration.operation.as_ref().unwrap().revision,
            )
            .await
            .unwrap(),
        NamespaceChangeOutcome::Updated(_)
    ));
    assert!(matches!(
        state
            .federation_attribute_mappings
            .change(
                tenant,
                "primary",
                ISSUER,
                MappingChange::Create {
                    mapping_id: "fm_department".into(),
                    expected_registry_revision: 0,
                    spec: MappingSpec {
                        source_claim: "department".into(),
                        target_namespace: NAMESPACE.into(),
                        target_key: "department".into(),
                        mode: MappingMode::CopyString,
                    },
                },
            )
            .await
            .unwrap(),
        MappingChangeOutcome::Applied(_)
    ));
}

fn request(tenant: &str, operation: &str, value: &str) -> FederationAttributeReconciliationRequest {
    FederationAttributeReconciliationRequest {
        operation_id: operation.into(),
        logical_tenant_id: tenant.into(),
        storage_tenant_id: tenant.into(),
        upstream_idp_id: "primary".into(),
        upstream_issuer: ISSUER.into(),
        user_id: USER.into(),
        verified_claims: serde_json::json!({"department": value}),
    }
}

#[tokio::test]
async fn postgres_attribute_authority_serializes_replica_writes_and_namespace_changes() {
    let states = [state(database().await), state(database().await)];
    let tenant = tenant();
    initialize(&states[0], &tenant).await;
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let (state, tenant, barrier) = (states[index % 2].clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            state
                .put_user_attributes_authorized(
                    &tenant,
                    USER,
                    NAMESPACE,
                    std::collections::BTreeMap::from([("role".into(), format!("role-{index}"))]),
                    0,
                )
                .await
                .unwrap()
                .outcome
        }));
    }
    let mut stored = 0;
    for task in tasks {
        match task.await.unwrap() {
            PutAttrOutcome::Ok { revision: 1 } => stored += 1,
            PutAttrOutcome::RevisionConflict { current: 1 } => {}
            other => panic!("unexpected authorized attribute write: {other:?}"),
        }
    }
    assert_eq!(stored, 1);
    let before = states[0]
        .users
        .get_by_id(&tenant, USER)
        .await
        .unwrap()
        .unwrap();
    let registration = states[0]
        .attribute_namespaces
        .get(&tenant, NAMESPACE)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        states[1]
            .attribute_namespaces
            .begin_change(
                &tenant,
                BeginNamespaceChange {
                    canonical_namespace: NAMESPACE.into(),
                    exact_audiences: BTreeSet::new(),
                    expected_revision: registration.revision,
                    operation_id: "retire".into(),
                    kind: NamespaceChangeKind::Delete,
                },
            )
            .await
            .unwrap(),
        BeginNamespaceChangeOutcome::Started(_)
    ));
    assert_eq!(
        states[0]
            .put_user_attributes_authorized(
                &tenant,
                USER,
                NAMESPACE,
                std::collections::BTreeMap::new(),
                1,
            )
            .await
            .unwrap()
            .outcome,
        PutAttrOutcome::NamespaceBlocked
    );
    assert_eq!(
        states[1].users.get_by_id(&tenant, USER).await.unwrap(),
        Some(before)
    );
    let mut foreign = states[0].clone();
    foreign.attribute_namespaces =
        Arc::new(AttributeNamespaceStoreImpl::Postgres(database().await));
    assert!(foreign
        .put_user_attributes_authorized(
            &tenant,
            USER,
            "https://unbound.example.test/attributes",
            std::collections::BTreeMap::new(),
            0,
        )
        .await
        .is_err());
}

#[tokio::test]
async fn postgres_federation_authority_reconciles_and_purges_once_across_independent_states() {
    let states = [state(database().await), state(database().await)];
    let tenant = tenant();
    initialize(&states[0], &tenant).await;
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let (state, tenant, barrier) = (states[index % 2].clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            state
                .reconcile_federated_attributes(request(
                    &tenant,
                    &format!("flow-{index}"),
                    "finance",
                ))
                .await
                .unwrap()
        }));
    }
    let mut changed = 0;
    for task in tasks {
        let FederationAttributeReconciliationOutcome::Applied {
            user,
            changed: mutation,
            ..
        } = task.await.unwrap()
        else {
            panic!("reconciliation must apply");
        };
        changed += usize::from(mutation);
        assert_eq!(user.attributes_generation, 1);
        assert_eq!(user.attributes[NAMESPACE].kv["department"], "finance");
    }
    assert_eq!(changed, 1);
    assert!(matches!(
        states[0]
            .federation_attribute_mappings
            .change(
                &tenant,
                "primary",
                ISSUER,
                MappingChange::SetEnabled {
                    mapping_id: "fm_department".into(),
                    expected_registry_revision: 1,
                    expected_mapping_revision: 1,
                    enabled: false,
                },
            )
            .await
            .unwrap(),
        MappingChangeOutcome::Applied(_)
    ));
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let (state, tenant, barrier) = (states[index % 2].clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            state
                .purge_stale_federated_attribute_owner(
                    &tenant,
                    &tenant,
                    USER,
                    NAMESPACE,
                    "department",
                    1,
                )
                .await
                .unwrap()
        }));
    }
    let mut purged = 0;
    for task in tasks {
        match task.await.unwrap() {
            FederationAttributeOwnerPurgeOutcome::Purged { user, .. } => {
                purged += 1;
                assert_eq!(user.attributes_generation, 2);
                assert!(user.attributes[NAMESPACE].kv.is_empty());
                assert!(user.attributes[NAMESPACE].federation_owners.is_empty());
            }
            FederationAttributeOwnerPurgeOutcome::RevisionConflict { current: 2 } => {}
            other => panic!("unexpected owner purge: {other:?}"),
        }
    }
    assert_eq!(purged, 1);
}

#[tokio::test]
async fn postgres_federation_authority_rejects_mixed_pools_and_preserves_user_on_write_failure() {
    let base = database().await;
    let state = state(base);
    let tenant = tenant();
    initialize(&state, &tenant).await;
    let mut foreign = state.clone();
    foreign.attribute_namespaces =
        Arc::new(AttributeNamespaceStoreImpl::Postgres(database().await));
    assert!(foreign
        .reconcile_federated_attributes(request(&tenant, "foreign", "finance"))
        .await
        .is_err());
    let before = state.users.get_by_id(&tenant, USER).await.unwrap().unwrap();
    assert_eq!(before.attributes_generation, 0);
    let url = std::env::var("A_AUTH_TEST_DATABASE_URL").expect("dedicated PostgreSQL fixture");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap_or_else(|_| panic!("database fixture unavailable"));
    let name = format!("test_fed_{:032x}", rand::random::<u128>());
    let tenant_hex: String = tenant
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    sqlx::query(&format!(
        "ALTER TABLE a_auth.users ADD CONSTRAINT {name} \
         CHECK (tenant <> decode('{tenant_hex}', 'hex') OR strpos(record, 'reject-write') = 0)"
    ))
    .execute(&pool)
    .await
    .unwrap();
    assert!(state
        .reconcile_federated_attributes(request(&tenant, "rejected", "reject-write"))
        .await
        .is_err());
    assert_eq!(
        state.users.get_by_id(&tenant, USER).await.unwrap().unwrap(),
        before
    );
    sqlx::query(&format!("ALTER TABLE a_auth.users DROP CONSTRAINT {name}"))
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    assert!(matches!(
        state
            .reconcile_federated_attributes(request(&tenant, "retry", "finance"))
            .await
            .unwrap(),
        FederationAttributeReconciliationOutcome::Applied { changed: true, .. }
    ));
}

#[tokio::test]
async fn postgres_federation_admin_http_fences_config_and_mapping_and_rejects_rebound_identity() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    // Isolate the fixed self-hosted default tenant. The remaining development
    // adapters do not establish production startup or native acceptance.
    let (base, pool, admin, name, url) = super::ssf_contracts::isolated_database().await;
    let replica = state(PostgresStore::connect(&url, 8).await.unwrap());
    let (replica_router, _) = agent_auth_http::build_router(replica);
    let state = state(base);
    initialize(&state, "").await;
    let (router, _) = agent_auth_http::build_router(state.clone());
    let config = serde_json::json!({
        "tenant_id": "default",
        "upstream_idp_id": "configured",
        "upstream_issuer": "https://identity.example.com",
        "client_id": "test-rp",
        "client_secret_ref": "fixture/oidc-client",
        "authorization_endpoint": "https://identity.example.com/authorize",
        "token_endpoint": "https://identity.example.com/token",
        "jwks_uri": "https://identity.example.com/jwks",
        "scopes": ["openid", "profile"],
        "strong_acr_values": []
    });
    let request = |method: &str, path: &str, body: serde_json::Value| {
        Request::builder()
            .method(method)
            .uri(path)
            .header("host", "issuer.example.test")
            .header("authorization", "Bearer dev-admin-token-not-for-prod")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let send = |method: &str, path: &str, body: serde_json::Value| {
        router.clone().oneshot(request(method, path, body))
    };
    assert_eq!(
        send("PUT", "/admin/federation", config.clone())
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        send(
            "POST",
            "/admin/federation/default/configured/attribute-mappings",
            serde_json::json!({
                "expected_registry_revision": 0,
                "mode": "copy_string",
                "source_claim": "department",
                "target_namespace": NAMESPACE,
                "target_key": "department"
            }),
        )
        .await
        .unwrap()
        .status(),
        StatusCode::CREATED
    );
    let before = state
        .federation_config
        .get("default", "configured")
        .await
        .unwrap()
        .unwrap();
    let mut rebound = config.clone();
    rebound["upstream_issuer"] = "https://replacement.example.com".into();
    assert_eq!(
        send("PUT", "/admin/federation", rebound)
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        send(
            "DELETE",
            "/admin/federation/default/configured",
            serde_json::Value::Null
        )
        .await
        .unwrap()
        .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        state
            .federation_config
            .get("default", "configured")
            .await
            .unwrap(),
        Some(before.clone())
    );
    for index in 0..16 {
        let idp = format!("race-{index}");
        let mut initial = config.clone();
        initial["upstream_idp_id"] = idp.clone().into();
        assert_eq!(
            send("PUT", "/admin/federation", initial.clone())
                .await
                .unwrap()
                .status(),
            StatusCode::CREATED
        );
        initial["upstream_issuer"] = "https://replacement.example.com".into();
        let config_write = send("PUT", "/admin/federation", initial);
        let path = format!("/admin/federation/default/{idp}/attribute-mappings");
        let mapping_write = replica_router.clone().oneshot(request(
            "POST",
            &path,
            serde_json::json!({
                "expected_registry_revision": 0,
                "mode": "copy_string",
                "source_claim": "department",
                "target_namespace": NAMESPACE,
                "target_key": format!("department-{index}")
            }),
        ));
        let (config_result, mapping_result) = tokio::join!(config_write, mapping_write);
        for status in [
            config_result.unwrap().status(),
            mapping_result.unwrap().status(),
        ] {
            assert!(
                matches!(status, StatusCode::CREATED | StatusCode::CONFLICT),
                "unexpected competing mutation status: {status}"
            );
        }
        let stored = state
            .federation_config
            .get("default", &idp)
            .await
            .unwrap()
            .unwrap();
        if let Some(registry) = state
            .federation_attribute_mappings
            .get_registry("default", &idp)
            .await
            .unwrap()
        {
            assert_eq!(registry.upstream_issuer, stored.upstream_issuer);
        }
    }
    let tamper = "UPDATE a_auth.federation_configs SET record = jsonb_set(record, '{tenant_id}', \
         '\"foreign\"'::jsonb) WHERE tenant = 'default' AND upstream_idp_id = 'configured'";
    assert!(sqlx::query(tamper).execute(&pool).await.is_err());
    // The database is unique to this test. Bypass its physical CHECK only to
    // prove that runtime decoding also rejects corrupt restored authority.
    sqlx::query("ALTER TABLE a_auth.federation_configs DROP CONSTRAINT federation_configs_check")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(tamper).execute(&pool).await.unwrap();
    assert!(state
        .federation_config
        .get("default", "configured")
        .await
        .is_err());
    assert!(state
        .federation_config
        .list_by_tenant("default")
        .await
        .is_err());
    sqlx::query(
        "UPDATE a_auth.federation_configs SET record = $1 \
         WHERE tenant = 'default' AND upstream_idp_id = 'configured'",
    )
    .bind(sqlx::types::Json(before))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "ALTER TABLE a_auth.federation_configs ADD CONSTRAINT federation_configs_check \
         CHECK (record->>'tenant_id' = tenant)",
    )
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
