use agent_auth_http::adapters::memory_federation_attributes::MemoryFederationAttributeMappingsStore;
use agent_auth_http::federation_attributes::{
    AttributeMapping, FederationAttributeMappingsStore, FederationAttributeReconciliationOutcome,
    FederationAttributeReconciliationRequest, MappingChange, MappingChangeOutcome,
    MappingEvaluation, MappingMode, MappingSpec, MappingValidationError,
};
use agent_auth_http::ports::UsersStore;
use agent_auth_http::security_event::{SecurityEventOutcome, SecurityEventStore};
use agent_auth_http::state::FederationAttributeMappingsStoreImpl;
use agent_auth_http::{build_router, AppState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

const HOST: &str = "localhost";
const ADMIN: &str = "dev-admin-token-not-for-prod";
const TENANT: &str = "default";
const IDP: &str = "okta";
const ISSUER: &str = "https://okta.example.com";
const CANONICAL: &str = "https://resources.example.com/finance";

fn admin_auth() -> String {
    format!("Bearer {ADMIN}")
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap()
}

async fn register_idp(router: &axum::Router) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/admin/federation")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "tenant_id": TENANT,
                        "upstream_idp_id": IDP,
                        "upstream_issuer": ISSUER,
                        "client_id": "as-rp",
                        "client_secret_ref": "secretsmanager:fed/okta",
                        "authorization_endpoint": "https://okta.example.com/authorize",
                        "token_endpoint": "https://okta.example.com/token",
                        "jwks_uri": "https://okta.example.com/jwks",
                        "scopes": ["openid", "profile"],
                        "strong_acr_values": []
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

async fn register_namespace(router: &axum::Router) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/admin/attribute-namespaces")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "canonical_namespace": CANONICAL,
                        "exact_audiences": [CANONICAL],
                        "expected_revision": 0,
                        "operation_id": "op-register-finance"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let mut registration = body_json(response).await;

    for _ in 0..8 {
        let Some(revision) = registration["operation"]["revision"].as_u64() else {
            return;
        };
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/attribute-namespaces/advance")
                    .header("host", HOST)
                    .header("authorization", admin_auth())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "canonical_namespace": CANONICAL,
                            "operation_id": "op-register-finance",
                            "expected_operation_revision": revision
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        registration = body_json(response).await;
    }
    panic!("namespace registration did not converge: {registration:?}");
}

#[test]
fn bounded_mapping_modes_use_only_exact_top_level_string_claims() {
    let copy = AttributeMapping {
        mapping_id: "fm_department".to_string(),
        revision: 1,
        enabled: true,
        source_claim: "department.name".to_string(),
        target_namespace: "https://resources.example.com/finance".to_string(),
        target_key: "department".to_string(),
        mode: MappingMode::CopyString,
    };
    let membership = AttributeMapping {
        mapping_id: "fm_finance_admin".to_string(),
        revision: 1,
        enabled: true,
        source_claim: "groups".to_string(),
        target_namespace: "https://resources.example.com/finance".to_string(),
        target_key: "role".to_string(),
        mode: MappingMode::ExactMembership {
            source_value: "finance-admin".to_string(),
            target_value: "admin".to_string(),
        },
    };

    let exact_top_level = serde_json::json!({
        "department.name": "treasury",
        "department": {"name": "must-not-be-traversed"},
        "groups": ["staff", "finance-admin"]
    });
    assert_eq!(
        copy.evaluate(&exact_top_level),
        MappingEvaluation::Present("treasury".to_string())
    );
    assert_eq!(
        membership.evaluate(&exact_top_level),
        MappingEvaluation::Present("admin".to_string())
    );

    let nested_only = serde_json::json!({
        "department": {"name": "treasury"},
        "groups": ["finance-admin", 7]
    });
    assert_eq!(copy.evaluate(&nested_only), MappingEvaluation::Absent);
    assert_eq!(membership.evaluate(&nested_only), MappingEvaluation::Absent);

    assert_eq!(
        membership.evaluate(&serde_json::json!({"groups": "finance-admin"})),
        MappingEvaluation::Present("admin".to_string())
    );
    assert_eq!(
        membership.evaluate(&serde_json::json!({"groups": ["finance-admins"]})),
        MappingEvaluation::Absent
    );
}

fn finance_role_spec() -> MappingSpec {
    MappingSpec {
        source_claim: "groups".to_string(),
        target_namespace: "https://resources.example.com/finance".to_string(),
        target_key: "role".to_string(),
        mode: MappingMode::ExactMembership {
            source_value: "finance-admin".to_string(),
            target_value: "admin".to_string(),
        },
    }
}

#[tokio::test]
async fn mapping_authority_is_tenant_unique_revisioned_and_never_reuses_ids() {
    let store = MemoryFederationAttributeMappingsStore::default();

    let created_a = store
        .change(
            "tenant-a",
            "idp-a",
            "https://idp-a.example.com",
            MappingChange::Create {
                mapping_id: "fm_a".to_string(),
                expected_registry_revision: 0,
                spec: finance_role_spec(),
            },
        )
        .await
        .unwrap();
    let MappingChangeOutcome::Applied(registry_a) = created_a else {
        panic!("first mapping must be created");
    };
    assert_eq!(registry_a.revision, 1);
    assert_eq!(registry_a.mappings[0].revision, 1);

    assert!(matches!(
        store
            .change(
                "tenant-b",
                "idp-a",
                "https://idp-a.example.com",
                MappingChange::Create {
                    mapping_id: "fm_same_target_other_tenant".to_string(),
                    expected_registry_revision: 0,
                    spec: finance_role_spec(),
                },
            )
            .await
            .unwrap(),
        MappingChangeOutcome::Applied(_)
    ));

    assert_eq!(
        store
            .change(
                "tenant-a",
                "idp-b",
                "https://idp-b.example.com",
                MappingChange::Create {
                    mapping_id: "fm_b".to_string(),
                    expected_registry_revision: 0,
                    spec: finance_role_spec(),
                },
            )
            .await
            .unwrap(),
        MappingChangeOutcome::TargetConflict
    );

    let disabled_a = store
        .change(
            "tenant-a",
            "idp-a",
            "https://idp-a.example.com",
            MappingChange::SetEnabled {
                mapping_id: "fm_a".to_string(),
                expected_registry_revision: 1,
                expected_mapping_revision: 1,
                enabled: false,
            },
        )
        .await
        .unwrap();
    let MappingChangeOutcome::Applied(registry_a) = disabled_a else {
        panic!("disable must apply");
    };
    assert_eq!(registry_a.revision, 2);
    assert_eq!(registry_a.mappings[0].revision, 2);
    assert!(!registry_a.mappings[0].enabled);

    let created_b = store
        .change(
            "tenant-a",
            "idp-b",
            "https://idp-b.example.com",
            MappingChange::Create {
                mapping_id: "fm_b".to_string(),
                expected_registry_revision: 0,
                spec: finance_role_spec(),
            },
        )
        .await
        .unwrap();
    assert!(matches!(created_b, MappingChangeOutcome::Applied(_)));

    assert_eq!(
        store
            .change(
                "tenant-a",
                "idp-a",
                "https://idp-a.example.com",
                MappingChange::SetEnabled {
                    mapping_id: "fm_a".to_string(),
                    expected_registry_revision: 2,
                    expected_mapping_revision: 2,
                    enabled: true,
                },
            )
            .await
            .unwrap(),
        MappingChangeOutcome::TargetConflict
    );

    let deleted_b = store
        .change(
            "tenant-a",
            "idp-b",
            "https://idp-b.example.com",
            MappingChange::Delete {
                mapping_id: "fm_b".to_string(),
                expected_registry_revision: 1,
                expected_mapping_revision: 1,
            },
        )
        .await
        .unwrap();
    assert!(matches!(deleted_b, MappingChangeOutcome::Applied(_)));

    assert_eq!(
        store
            .change(
                "tenant-a",
                "idp-b",
                "https://idp-b.example.com",
                MappingChange::Create {
                    mapping_id: "fm_b".to_string(),
                    expected_registry_revision: 2,
                    spec: finance_role_spec(),
                },
            )
            .await
            .unwrap(),
        MappingChangeOutcome::MappingIdRetired
    );
}

#[tokio::test]
async fn empty_mapping_registry_rebinds_to_a_recreated_idp_issuer() {
    let store = MemoryFederationAttributeMappingsStore::default();

    let created = store
        .change(
            "tenant-a",
            "idp-a",
            "https://old-idp.example.com",
            MappingChange::Create {
                mapping_id: "fm_old".to_string(),
                expected_registry_revision: 0,
                spec: finance_role_spec(),
            },
        )
        .await
        .unwrap();
    assert!(matches!(created, MappingChangeOutcome::Applied(_)));

    let deleted = store
        .change(
            "tenant-a",
            "idp-a",
            "https://old-idp.example.com",
            MappingChange::Delete {
                mapping_id: "fm_old".to_string(),
                expected_registry_revision: 1,
                expected_mapping_revision: 1,
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        deleted,
        MappingChangeOutcome::Applied(ref registry)
            if registry.revision == 2 && registry.mappings.is_empty()
    ));

    let rebound = store
        .change(
            "tenant-a",
            "idp-a",
            "https://new-idp.example.com",
            MappingChange::Create {
                mapping_id: "fm_new".to_string(),
                expected_registry_revision: 2,
                spec: finance_role_spec(),
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        rebound,
        MappingChangeOutcome::Applied(ref registry)
            if registry.revision == 3
                && registry.upstream_issuer == "https://new-idp.example.com"
                && registry.mappings[0].mapping_id == "fm_new"
    ));
}

#[tokio::test]
async fn mapping_authority_governance_is_tenant_scoped_and_cleans_all_row_types() {
    let store = MemoryFederationAttributeMappingsStore::default();
    for (tenant, idp, mapping_id, key) in [
        ("tenant-a", "idp-a", "fm_a", "role-a"),
        ("tenant-b", "idp-b", "fm_b", "role-b"),
    ] {
        let mut spec = finance_role_spec();
        spec.target_key = key.to_string();
        assert!(matches!(
            store
                .change(
                    tenant,
                    idp,
                    &format!("https://{idp}.example.com"),
                    MappingChange::Create {
                        mapping_id: mapping_id.to_string(),
                        expected_registry_revision: 0,
                        spec,
                    },
                )
                .await
                .unwrap(),
            MappingChangeOutcome::Applied(_)
        ));
    }

    let registries = store.list_by_tenant("tenant-a").await.unwrap();
    assert_eq!(registries.len(), 1);
    assert_eq!(registries[0].upstream_idp_id, "idp-a");
    assert_eq!(
        store
            .governance_count_all_by_tenant("tenant-a")
            .await
            .unwrap(),
        3
    );

    assert_eq!(store.delete_all_by_tenant("tenant-a").await.unwrap(), 3);
    assert_eq!(
        store
            .governance_count_all_by_tenant("tenant-a")
            .await
            .unwrap(),
        0
    );
    assert!(store.list_by_tenant("tenant-a").await.unwrap().is_empty());
    assert_eq!(
        store
            .governance_count_all_by_tenant("tenant-b")
            .await
            .unwrap(),
        3
    );
    assert_eq!(
        store
            .get_registry("tenant-b", "idp-b")
            .await
            .unwrap()
            .unwrap()
            .mappings[0]
            .mapping_id,
        "fm_b"
    );
}

#[tokio::test]
async fn mapping_authority_rejects_reserved_targets_and_the_thirty_third_mapping() {
    let store = MemoryFederationAttributeMappingsStore::default();
    let mut reserved = finance_role_spec();
    reserved.target_key = "sub".to_string();
    assert_eq!(
        store
            .change(
                "tenant-a",
                "idp-a",
                "https://idp-a.example.com",
                MappingChange::Create {
                    mapping_id: "fm_reserved".to_string(),
                    expected_registry_revision: 0,
                    spec: reserved,
                },
            )
            .await
            .unwrap(),
        MappingChangeOutcome::Invalid(MappingValidationError::ReservedTargetKey)
    );

    for index in 0..32 {
        let mut spec = finance_role_spec();
        spec.target_key = format!("role-{index}");
        assert!(matches!(
            store
                .change(
                    "tenant-a",
                    "idp-a",
                    "https://idp-a.example.com",
                    MappingChange::Create {
                        mapping_id: format!("fm_{index}"),
                        expected_registry_revision: index,
                        spec,
                    },
                )
                .await
                .unwrap(),
            MappingChangeOutcome::Applied(_)
        ));
    }

    let mut thirty_third = finance_role_spec();
    thirty_third.target_key = "role-32".to_string();
    assert_eq!(
        store
            .change(
                "tenant-a",
                "idp-a",
                "https://idp-a.example.com",
                MappingChange::Create {
                    mapping_id: "fm_32".to_string(),
                    expected_registry_revision: 32,
                    spec: thirty_third,
                },
            )
            .await
            .unwrap(),
        MappingChangeOutcome::LimitExceeded
    );
}

#[tokio::test]
async fn tenant_admin_creates_and_lists_mapping_only_for_registered_canonical_namespace() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state);
    register_idp(&router).await;
    register_namespace(&router).await;

    let create = |target_namespace: &'static str, expected_registry_revision: u64| {
        let router = router.clone();
        async move {
            router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!(
                            "/admin/federation/{TENANT}/{IDP}/attribute-mappings"
                        ))
                        .header("host", HOST)
                        .header("authorization", admin_auth())
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::json!({
                                "expected_registry_revision": expected_registry_revision,
                                "mode": "copy_string",
                                "source_claim": "department",
                                "target_namespace": target_namespace,
                                "target_key": "department"
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap()
        }
    };

    let response = create(CANONICAL, 0).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = body_json(response).await;
    assert_eq!(created["registry_revision"], 1);
    assert_eq!(created["mapping"]["revision"], 1);
    assert_eq!(created["mapping"]["enabled"], true);
    assert_eq!(created["mapping"]["mode"], "copy_string");
    assert_eq!(created["mapping"]["source_claim"], "department");
    assert_eq!(created["mapping"]["target_namespace"], CANONICAL);
    assert_eq!(created["mapping"]["target_key"], "department");
    assert!(
        created["mapping"]["mapping_id"]
            .as_str()
            .unwrap()
            .starts_with("fm_"),
        "mapping id must be server-issued"
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/admin/federation/{TENANT}/{IDP}/attribute-mappings"
                ))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let listed = body_json(response).await;
    assert_eq!(listed["registry_revision"], 1);
    assert_eq!(listed["mappings"].as_array().unwrap().len(), 1);
    assert_eq!(
        listed["mappings"][0]["mapping_id"],
        created["mapping"]["mapping_id"]
    );

    let response = create("https://resources.example.com/unregistered", 1).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/admin/federation/{TENANT}/{IDP}/attribute-mappings"
                ))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let unchanged = body_json(response).await;
    assert_eq!(unchanged["registry_revision"], 1);
    assert_eq!(unchanged["mappings"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn tenant_admin_updates_and_deletes_mapping_with_revision_and_idp_guards() {
    let state = AppState::dev(HOST);
    let observed_state = state.clone();
    let (router, _) = build_router(state);
    register_idp(&router).await;
    register_namespace(&router).await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/admin/federation/{TENANT}/{IDP}/attribute-mappings"
                ))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "expected_registry_revision": 0,
                        "mode": "copy_string",
                        "source_claim": "department",
                        "target_namespace": CANONICAL,
                        "target_key": "department"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = body_json(response).await;
    let mapping_id = created["mapping"]["mapping_id"].as_str().unwrap();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/federation/{TENANT}/{IDP}"))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::CONFLICT,
        "an IdP with mappings cannot be deleted"
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/admin/federation/{TENANT}/{IDP}/attribute-mappings/{mapping_id}"
                ))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "expected_registry_revision": 1,
                        "expected_mapping_revision": 1,
                        "enabled": false,
                        "mode": "exact_membership",
                        "source_claim": "groups",
                        "source_value": "SECRET_SOURCE_VALUE_213",
                        "target_namespace": CANONICAL,
                        "target_key": "role",
                        "target_value": "SECRET_TARGET_VALUE_213"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let updated = body_json(response).await;
    assert_eq!(updated["registry_revision"], 2);
    assert_eq!(updated["mapping"]["revision"], 2);
    assert_eq!(updated["mapping"]["enabled"], false);
    assert_eq!(updated["mapping"]["mode"], "exact_membership");
    assert_eq!(updated["mapping"]["source_claim"], "groups");
    assert_eq!(
        updated["mapping"]["source_value"],
        "SECRET_SOURCE_VALUE_213"
    );
    assert_eq!(updated["mapping"]["target_key"], "role");
    assert_eq!(
        updated["mapping"]["target_value"],
        "SECRET_TARGET_VALUE_213"
    );

    let stale_delete = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/admin/federation/{TENANT}/{IDP}/attribute-mappings/{mapping_id}?expected_registry_revision=1&expected_mapping_revision=1"
                ))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stale_delete.status(), StatusCode::CONFLICT);

    let deleted = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/admin/federation/{TENANT}/{IDP}/attribute-mappings/{mapping_id}?expected_registry_revision=2&expected_mapping_revision=2"
                ))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::OK);
    let deleted = body_json(deleted).await;
    assert_eq!(deleted["registry_revision"], 3);
    assert!(deleted["mappings"].as_array().unwrap().is_empty());

    let response = router
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/federation/{TENANT}/{IDP}"))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let events = observed_state
        .security_events
        .list_by_tenant(TENANT, 0, i64::MAX, 1_000)
        .await
        .unwrap();
    let mapping_events: Vec<_> = events
        .iter()
        .filter(|stored| {
            stored
                .event
                .action
                .starts_with("federation.attribute_mapping.")
        })
        .collect();
    assert_eq!(mapping_events.len(), 4);
    for (action, outcome, revision, target_key) in [
        (
            "federation.attribute_mapping.create",
            SecurityEventOutcome::Success,
            1,
            "department",
        ),
        (
            "federation.attribute_mapping.update",
            SecurityEventOutcome::Success,
            2,
            "role",
        ),
        (
            "federation.attribute_mapping.delete",
            SecurityEventOutcome::Denied,
            1,
            "role",
        ),
        (
            "federation.attribute_mapping.delete",
            SecurityEventOutcome::Success,
            2,
            "role",
        ),
    ] {
        assert!(mapping_events.iter().any(|stored| {
            stored.event.action == action
                && stored.event.outcome == outcome
                && stored.event.subject.id() == mapping_id
                && stored.event.correlation.upstream_idp_id.as_deref() == Some(IDP)
                && stored.event.correlation.mapping_id.as_deref() == Some(mapping_id)
                && stored.event.correlation.mapping_revision == Some(revision)
                && stored.event.correlation.target_namespace.as_deref() == Some(CANONICAL)
                && stored.event.correlation.target_key.as_deref() == Some(target_key)
        }));
    }
    let serialized = serde_json::to_string(&events).unwrap();
    assert!(!serialized.contains("SECRET_SOURCE_VALUE_213"));
    assert!(!serialized.contains("SECRET_TARGET_VALUE_213"));
}

#[tokio::test]
async fn saas_mapping_surfaces_return_not_found_before_extractors() {
    let mut state = AppState::dev(HOST);
    state.form = agent_auth_discovery::Form::Saas {
        zone: "example.test".into(),
        control_host: "control.example.test".into(),
    };
    let (router, _) = build_router(state);

    for (method, uri, body) in [
        (
            "GET",
            "/admin/federation/default/okta/attribute-mappings",
            "",
        ),
        (
            "POST",
            "/admin/federation/default/okta/attribute-mappings",
            "{",
        ),
        (
            "PUT",
            "/admin/federation/default/okta/attribute-mappings/fm_one",
            "{",
        ),
        (
            "DELETE",
            "/admin/federation/default/okta/attribute-mappings/fm_one",
            "",
        ),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("host", HOST)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {uri}");
    }
}

#[tokio::test]
async fn idp_issuer_cannot_change_while_attribute_mappings_exist() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state);
    register_idp(&router).await;
    register_namespace(&router).await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/admin/federation/{TENANT}/{IDP}/attribute-mappings"
                ))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "expected_registry_revision": 0,
                        "mode": "copy_string",
                        "source_claim": "department",
                        "target_namespace": CANONICAL,
                        "target_key": "department"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/admin/federation")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "tenant_id": TENANT,
                        "upstream_idp_id": IDP,
                        "upstream_issuer": "https://replacement.example.com",
                        "client_id": "as-rp",
                        "client_secret_ref": "secretsmanager:fed/okta",
                        "authorization_endpoint": "https://replacement.example.com/authorize",
                        "token_endpoint": "https://replacement.example.com/token",
                        "jwks_uri": "https://replacement.example.com/jwks",
                        "scopes": ["openid", "profile"],
                        "strong_acr_values": []
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/admin/federation/{TENANT}"))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let listed = body_json(response).await;
    assert_eq!(listed["idps"][0]["upstream_issuer"], ISSUER);
}

#[tokio::test]
async fn reconciliation_replaces_stale_owned_keys_with_current_mapping_provenance() {
    let state = AppState::dev(HOST);
    let observed_state = state.clone();
    let (router, _) = build_router(state);
    register_namespace(&router).await;
    observed_state
        .users
        .create_or_get_by_id("", "user:federated", 1)
        .await
        .unwrap();

    let created = observed_state
        .federation_attribute_mappings
        .change(
            TENANT,
            IDP,
            ISSUER,
            MappingChange::Create {
                mapping_id: "fm_department".to_string(),
                expected_registry_revision: 0,
                spec: MappingSpec {
                    source_claim: "department".to_string(),
                    target_namespace: CANONICAL.to_string(),
                    target_key: "department".to_string(),
                    mode: MappingMode::CopyString,
                },
            },
        )
        .await
        .unwrap();
    assert!(matches!(created, MappingChangeOutcome::Applied(_)));

    let applied = observed_state
        .reconcile_federated_attributes(FederationAttributeReconciliationRequest {
            operation_id: "flow-department-1".to_string(),
            logical_tenant_id: TENANT.to_string(),
            storage_tenant_id: String::new(),
            upstream_idp_id: IDP.to_string(),
            upstream_issuer: ISSUER.to_string(),
            user_id: "user:federated".to_string(),
            verified_claims: serde_json::json!({"department": "treasury"}),
        })
        .await
        .unwrap();
    let FederationAttributeReconciliationOutcome::Applied {
        user,
        registry_revision,
        changed,
        ..
    } = applied
    else {
        panic!("reconciliation must apply");
    };
    assert!(changed);
    assert_eq!(registry_revision, 1);
    assert_eq!(user.attributes_generation, 1);
    assert_eq!(user.attributes[CANONICAL].kv["department"], "treasury");
    assert_eq!(
        user.attributes[CANONICAL].federation_owners["department"].mapping_revision,
        1
    );

    let updated = observed_state
        .federation_attribute_mappings
        .change(
            TENANT,
            IDP,
            ISSUER,
            MappingChange::Update {
                mapping_id: "fm_department".to_string(),
                expected_registry_revision: 1,
                expected_mapping_revision: 1,
                enabled: true,
                spec: MappingSpec {
                    source_claim: "division".to_string(),
                    target_namespace: CANONICAL.to_string(),
                    target_key: "division".to_string(),
                    mode: MappingMode::CopyString,
                },
            },
        )
        .await
        .unwrap();
    assert!(matches!(updated, MappingChangeOutcome::Applied(_)));

    let applied = observed_state
        .reconcile_federated_attributes(FederationAttributeReconciliationRequest {
            operation_id: "flow-department-2".to_string(),
            logical_tenant_id: TENANT.to_string(),
            storage_tenant_id: String::new(),
            upstream_idp_id: IDP.to_string(),
            upstream_issuer: ISSUER.to_string(),
            user_id: "user:federated".to_string(),
            verified_claims: serde_json::json!({"division": "finance"}),
        })
        .await
        .unwrap();
    let FederationAttributeReconciliationOutcome::Applied {
        user,
        registry_revision,
        changed,
        ..
    } = applied
    else {
        panic!("updated reconciliation must apply");
    };
    assert!(changed);
    assert_eq!(registry_revision, 2);
    assert_eq!(user.attributes_generation, 2);
    assert!(!user.attributes[CANONICAL].kv.contains_key("department"));
    assert_eq!(user.attributes[CANONICAL].kv["division"], "finance");
    let owner = &user.attributes[CANONICAL].federation_owners["division"];
    assert_eq!(owner.mapping_id, "fm_department");
    assert_eq!(owner.mapping_revision, 2);
}

#[tokio::test]
async fn reconciliation_handles_repeat_changed_missing_and_wrong_type_without_cross_idp_loss() {
    const OTHER_IDP: &str = "entra";
    const OTHER_ISSUER: &str = "https://entra.example.com";

    let state = AppState::dev(HOST);
    let observed_state = state.clone();
    let (router, _) = build_router(state);
    register_namespace(&router).await;
    observed_state
        .users
        .create_or_get_by_id("", "user:semantic-matrix", 1)
        .await
        .unwrap();
    let mut admin_values = std::collections::BTreeMap::new();
    admin_values.insert("note".to_string(), "keep-admin".to_string());
    observed_state
        .users
        .put_attributes("", "user:semantic-matrix", CANONICAL, admin_values, 0)
        .await
        .unwrap();

    for (mapping_id, expected_registry_revision, spec) in [
        (
            "fm_department",
            0,
            MappingSpec {
                source_claim: "department".to_string(),
                target_namespace: CANONICAL.to_string(),
                target_key: "department".to_string(),
                mode: MappingMode::CopyString,
            },
        ),
        (
            "fm_role",
            1,
            MappingSpec {
                source_claim: "groups".to_string(),
                target_namespace: CANONICAL.to_string(),
                target_key: "role".to_string(),
                mode: MappingMode::ExactMembership {
                    source_value: "finance-admin".to_string(),
                    target_value: "admin".to_string(),
                },
            },
        ),
    ] {
        assert!(matches!(
            observed_state
                .federation_attribute_mappings
                .change(
                    TENANT,
                    IDP,
                    ISSUER,
                    MappingChange::Create {
                        mapping_id: mapping_id.to_string(),
                        expected_registry_revision,
                        spec,
                    },
                )
                .await
                .unwrap(),
            MappingChangeOutcome::Applied(_)
        ));
    }
    assert!(matches!(
        observed_state
            .federation_attribute_mappings
            .change(
                TENANT,
                OTHER_IDP,
                OTHER_ISSUER,
                MappingChange::Create {
                    mapping_id: "fm_cost_center".to_string(),
                    expected_registry_revision: 0,
                    spec: MappingSpec {
                        source_claim: "cost_center".to_string(),
                        target_namespace: CANONICAL.to_string(),
                        target_key: "cost_center".to_string(),
                        mode: MappingMode::CopyString,
                    },
                },
            )
            .await
            .unwrap(),
        MappingChangeOutcome::Applied(_)
    ));

    let other_idp = observed_state
        .reconcile_federated_attributes(FederationAttributeReconciliationRequest {
            operation_id: "flow-other-idp".to_string(),
            logical_tenant_id: TENANT.to_string(),
            storage_tenant_id: String::new(),
            upstream_idp_id: OTHER_IDP.to_string(),
            upstream_issuer: OTHER_ISSUER.to_string(),
            user_id: "user:semantic-matrix".to_string(),
            verified_claims: serde_json::json!({"cost_center": "cc-42"}),
        })
        .await
        .unwrap();
    assert!(matches!(
        other_idp,
        FederationAttributeReconciliationOutcome::Applied { changed: true, .. }
    ));

    let first = observed_state
        .reconcile_federated_attributes(FederationAttributeReconciliationRequest {
            operation_id: "flow-first".to_string(),
            logical_tenant_id: TENANT.to_string(),
            storage_tenant_id: String::new(),
            upstream_idp_id: IDP.to_string(),
            upstream_issuer: ISSUER.to_string(),
            user_id: "user:semantic-matrix".to_string(),
            verified_claims: serde_json::json!({
                "department": "treasury",
                "groups": ["staff", "finance-admin"]
            }),
        })
        .await
        .unwrap();
    let FederationAttributeReconciliationOutcome::Applied { user, changed, .. } = first else {
        panic!("first reconciliation must apply");
    };
    assert!(changed);
    assert_eq!(user.attributes_generation, 3);
    assert_eq!(user.attributes[CANONICAL].kv["note"], "keep-admin");
    assert_eq!(user.attributes[CANONICAL].kv["cost_center"], "cc-42");
    assert_eq!(user.attributes[CANONICAL].kv["department"], "treasury");
    assert_eq!(user.attributes[CANONICAL].kv["role"], "admin");

    let repeat = observed_state
        .reconcile_federated_attributes(FederationAttributeReconciliationRequest {
            operation_id: "flow-repeat".to_string(),
            logical_tenant_id: TENANT.to_string(),
            storage_tenant_id: String::new(),
            upstream_idp_id: IDP.to_string(),
            upstream_issuer: ISSUER.to_string(),
            user_id: "user:semantic-matrix".to_string(),
            verified_claims: serde_json::json!({
                "department": "treasury",
                "groups": ["staff", "finance-admin"]
            }),
        })
        .await
        .unwrap();
    let FederationAttributeReconciliationOutcome::Applied { user, changed, .. } = repeat else {
        panic!("repeat reconciliation must apply");
    };
    assert!(!changed);
    assert_eq!(user.attributes_generation, 3);

    let changed_and_missing = observed_state
        .reconcile_federated_attributes(FederationAttributeReconciliationRequest {
            operation_id: "flow-changed-missing".to_string(),
            logical_tenant_id: TENANT.to_string(),
            storage_tenant_id: String::new(),
            upstream_idp_id: IDP.to_string(),
            upstream_issuer: ISSUER.to_string(),
            user_id: "user:semantic-matrix".to_string(),
            verified_claims: serde_json::json!({"department": "finance"}),
        })
        .await
        .unwrap();
    let FederationAttributeReconciliationOutcome::Applied { user, changed, .. } =
        changed_and_missing
    else {
        panic!("changed reconciliation must apply");
    };
    assert!(changed);
    assert_eq!(user.attributes_generation, 4);
    assert_eq!(user.attributes[CANONICAL].kv["department"], "finance");
    assert!(!user.attributes[CANONICAL].kv.contains_key("role"));
    assert_eq!(user.attributes[CANONICAL].kv["note"], "keep-admin");
    assert_eq!(user.attributes[CANONICAL].kv["cost_center"], "cc-42");

    let wrong_types = observed_state
        .reconcile_federated_attributes(FederationAttributeReconciliationRequest {
            operation_id: "flow-wrong-types".to_string(),
            logical_tenant_id: TENANT.to_string(),
            storage_tenant_id: String::new(),
            upstream_idp_id: IDP.to_string(),
            upstream_issuer: ISSUER.to_string(),
            user_id: "user:semantic-matrix".to_string(),
            verified_claims: serde_json::json!({
                "department": {"name": "finance"},
                "groups": ["finance-admin", 7]
            }),
        })
        .await
        .unwrap();
    let FederationAttributeReconciliationOutcome::Applied { user, changed, .. } = wrong_types
    else {
        panic!("wrong-type reconciliation must remove owned values");
    };
    assert!(changed);
    assert_eq!(user.attributes_generation, 5);
    assert!(!user.attributes[CANONICAL].kv.contains_key("department"));
    assert!(!user.attributes[CANONICAL].kv.contains_key("role"));
    assert_eq!(user.attributes[CANONICAL].kv["note"], "keep-admin");
    assert_eq!(user.attributes[CANONICAL].kv["cost_center"], "cc-42");
    assert_eq!(
        user.attributes[CANONICAL].federation_owners["cost_center"].upstream_idp_id,
        OTHER_IDP
    );
}

#[tokio::test]
async fn reconciliation_never_mutates_disabled_or_tombstoned_users() {
    let state = AppState::dev(HOST);
    let observed_state = state.clone();
    let (router, _) = build_router(state);
    register_namespace(&router).await;
    observed_state
        .federation_attribute_mappings
        .change(
            TENANT,
            IDP,
            ISSUER,
            MappingChange::Create {
                mapping_id: "fm_department".to_string(),
                expected_registry_revision: 0,
                spec: MappingSpec {
                    source_claim: "department".to_string(),
                    target_namespace: CANONICAL.to_string(),
                    target_key: "department".to_string(),
                    mode: MappingMode::CopyString,
                },
            },
        )
        .await
        .unwrap();

    for (user_id, status, expected) in [
        (
            "user:disabled-mapping",
            agent_auth_http::ports::UserStatus::Disabled,
            FederationAttributeReconciliationOutcome::UserDisabled,
        ),
        (
            "user:tombstoned-mapping",
            agent_auth_http::ports::UserStatus::Tombstoned,
            FederationAttributeReconciliationOutcome::UserTombstoned,
        ),
    ] {
        observed_state
            .users
            .create_or_get_by_id("", user_id, 1)
            .await
            .unwrap();
        observed_state
            .users
            .set_status("", user_id, status, 2)
            .await
            .unwrap();
        let outcome = observed_state
            .reconcile_federated_attributes(FederationAttributeReconciliationRequest {
                operation_id: format!("flow-{user_id}"),
                logical_tenant_id: TENANT.to_string(),
                storage_tenant_id: String::new(),
                upstream_idp_id: IDP.to_string(),
                upstream_issuer: ISSUER.to_string(),
                user_id: user_id.to_string(),
                verified_claims: serde_json::json!({"department": "treasury"}),
            })
            .await
            .unwrap();
        assert_eq!(outcome, expected);
        let user = observed_state
            .users
            .get_by_id("", user_id)
            .await
            .unwrap()
            .unwrap();
        assert!(user.attributes.is_empty());
        assert_eq!(user.attributes_generation, 0);
    }
}

#[tokio::test]
async fn tenant_admin_can_purge_only_a_stale_federation_owner() {
    let state = AppState::dev(HOST);
    let observed_state = state.clone();
    let (router, _) = build_router(state);
    register_namespace(&router).await;
    observed_state
        .users
        .create_or_get_by_id("", "user:stale-owner", 1)
        .await
        .unwrap();
    observed_state
        .federation_attribute_mappings
        .change(
            TENANT,
            IDP,
            ISSUER,
            MappingChange::Create {
                mapping_id: "fm_department".to_string(),
                expected_registry_revision: 0,
                spec: MappingSpec {
                    source_claim: "department".to_string(),
                    target_namespace: CANONICAL.to_string(),
                    target_key: "department".to_string(),
                    mode: MappingMode::CopyString,
                },
            },
        )
        .await
        .unwrap();
    observed_state
        .reconcile_federated_attributes(FederationAttributeReconciliationRequest {
            operation_id: "flow-stale-owner".to_string(),
            logical_tenant_id: TENANT.to_string(),
            storage_tenant_id: String::new(),
            upstream_idp_id: IDP.to_string(),
            upstream_issuer: ISSUER.to_string(),
            user_id: "user:stale-owner".to_string(),
            verified_claims: serde_json::json!({"department": "treasury"}),
        })
        .await
        .unwrap();

    let active = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/admin/users/user:stale-owner/attributes/federation-owner?namespace={CANONICAL}&key=department"
                ))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("if-match", "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(active.status(), StatusCode::CONFLICT);

    observed_state
        .federation_attribute_mappings
        .change(
            TENANT,
            IDP,
            ISSUER,
            MappingChange::SetEnabled {
                mapping_id: "fm_department".to_string(),
                expected_registry_revision: 1,
                expected_mapping_revision: 1,
                enabled: false,
            },
        )
        .await
        .unwrap();

    let stale_revision = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/admin/users/user:stale-owner/attributes/federation-owner?namespace={CANONICAL}&key=department"
                ))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("if-match", "0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stale_revision.status(), StatusCode::CONFLICT);

    let purged = router
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/admin/users/user:stale-owner/attributes/federation-owner?namespace={CANONICAL}&key=department"
                ))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("if-match", "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(purged.status(), StatusCode::OK);
    let body = body_json(purged).await;
    assert_eq!(body["revision"], 2);
    let user = observed_state
        .users
        .get_by_id("", "user:stale-owner")
        .await
        .unwrap()
        .unwrap();
    assert!(!user.attributes[CANONICAL].kv.contains_key("department"));
    assert!(!user.attributes[CANONICAL]
        .federation_owners
        .contains_key("department"));

    let events = observed_state
        .security_events
        .list_by_tenant(TENANT, 0, i64::MAX, 100)
        .await
        .unwrap();
    let purged = events
        .iter()
        .find(|stored| {
            stored.event.action == "federation.attribute_owner.purge"
                && stored.event.outcome == SecurityEventOutcome::Success
        })
        .expect("successful stale owner purge must be audited");
    assert_eq!(purged.event.subject.id(), "user:stale-owner");
    assert_eq!(
        purged.event.correlation.mapping_id.as_deref(),
        Some("fm_department")
    );
    assert_eq!(purged.event.correlation.mapping_revision, Some(1));
    assert_eq!(
        purged.event.correlation.target_namespace.as_deref(),
        Some(CANONICAL)
    );
    assert_eq!(
        purged.event.correlation.target_key.as_deref(),
        Some("department")
    );
    assert!(purged.event.correlation.old_value_summary.is_some());
    assert!(purged.event.correlation.new_value_summary.is_some());
    assert_ne!(
        purged.event.correlation.old_value_summary,
        purged.event.correlation.new_value_summary
    );
    assert!(
        !serde_json::to_string(&purged.event)
            .unwrap()
            .contains("treasury"),
        "purge audit must not expose the removed attribute value"
    );
}

#[tokio::test]
async fn reconciliation_audits_ownership_denial_without_exposing_values() {
    let state = AppState::dev(HOST);
    let observed_state = state.clone();
    let (router, _) = build_router(state);
    register_namespace(&router).await;
    observed_state
        .users
        .create_or_get_by_id("", "user:ownership-conflict", 1)
        .await
        .unwrap();
    let mut admin_values = std::collections::BTreeMap::new();
    admin_values.insert("department".to_string(), "manual-value".to_string());
    observed_state
        .users
        .put_attributes("", "user:ownership-conflict", CANONICAL, admin_values, 0)
        .await
        .unwrap();
    observed_state
        .federation_attribute_mappings
        .change(
            TENANT,
            IDP,
            ISSUER,
            MappingChange::Create {
                mapping_id: "fm_department".to_string(),
                expected_registry_revision: 0,
                spec: MappingSpec {
                    source_claim: "department".to_string(),
                    target_namespace: CANONICAL.to_string(),
                    target_key: "department".to_string(),
                    mode: MappingMode::CopyString,
                },
            },
        )
        .await
        .unwrap();

    let outcome = observed_state
        .reconcile_federated_attributes(FederationAttributeReconciliationRequest {
            operation_id: "flow-ownership-conflict".to_string(),
            logical_tenant_id: TENANT.to_string(),
            storage_tenant_id: String::new(),
            upstream_idp_id: IDP.to_string(),
            upstream_issuer: ISSUER.to_string(),
            user_id: "user:ownership-conflict".to_string(),
            verified_claims: serde_json::json!({"department": "treasury"}),
        })
        .await
        .unwrap();
    assert_eq!(
        outcome,
        FederationAttributeReconciliationOutcome::OwnershipConflict {
            namespace: CANONICAL.to_string(),
            key: "department".to_string(),
        }
    );
    let user = observed_state
        .users
        .get_by_id("", "user:ownership-conflict")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.attributes_generation, 1);
    assert_eq!(user.attributes[CANONICAL].kv["department"], "manual-value");

    let events = observed_state
        .security_events
        .list_by_tenant(TENANT, 0, i64::MAX, 100)
        .await
        .unwrap();
    let denied = events
        .iter()
        .find(|stored| {
            stored.event.action == "federation.attribute_reconciliation"
                && stored.event.outcome == SecurityEventOutcome::Denied
        })
        .expect("ownership conflict must be audited");
    let event = serde_json::to_value(&denied.event).unwrap();
    assert_eq!(event["correlation"]["upstream_idp_id"], IDP);
    assert_eq!(event["correlation"]["mapping_id"], "fm_department");
    assert_eq!(event["correlation"]["mapping_revision"], 1);
    assert_eq!(event["correlation"]["target_namespace"], CANONICAL);
    assert_eq!(event["correlation"]["target_key"], "department");
    assert_ne!(
        event["correlation"]["old_value_summary"],
        event["correlation"]["new_value_summary"]
    );
    let serialized = event.to_string();
    assert!(!serialized.contains("manual-value"));
    assert!(!serialized.contains("treasury"));
}

#[tokio::test]
async fn reconciliation_audits_mapping_authority_failure() {
    let mut state = AppState::dev(HOST);
    state.federation_attribute_mappings = Arc::new(FederationAttributeMappingsStoreImpl::Disabled);
    state
        .users
        .create_or_get_by_id("", "user:authority-failure", 1)
        .await
        .unwrap();

    let error = state
        .reconcile_federated_attributes(FederationAttributeReconciliationRequest {
            operation_id: "flow-authority-failure".to_string(),
            logical_tenant_id: TENANT.to_string(),
            storage_tenant_id: String::new(),
            upstream_idp_id: IDP.to_string(),
            upstream_issuer: ISSUER.to_string(),
            user_id: "user:authority-failure".to_string(),
            verified_claims: serde_json::json!({"department": "must-not-be-logged"}),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        agent_auth_http::ports::StoreError::Permanent(_)
    ));

    let events = state
        .security_events
        .list_by_tenant(TENANT, 0, i64::MAX, 100)
        .await
        .unwrap();
    let failure = events
        .iter()
        .find(|stored| {
            stored.event.action == "federation.attribute_reconciliation"
                && stored.event.outcome == SecurityEventOutcome::Failure
        })
        .expect("mapping authority failure must be audited");
    let event = serde_json::to_value(&failure.event).unwrap();
    assert_eq!(event["subject"]["id"], "user:authority-failure");
    assert_eq!(event["correlation"]["upstream_idp_id"], IDP);
    assert!(event["correlation"]["operation_id"]
        .as_str()
        .is_some_and(|value| value.starts_with("far_")));
    assert!(event["correlation"].get("mapping_id").is_none());
    assert!(!event.to_string().contains("must-not-be-logged"));
}
