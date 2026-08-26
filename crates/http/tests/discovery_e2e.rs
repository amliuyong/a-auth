//! 进程内 e2e:发现面双文档(spec 000 C1.1/C1.4/C1.6a)。
//!
//! 验证:OIDC(`/.well-known/openid-configuration`)与 OAuth(`/.well-known/oauth-authorization-server`)
//! 是**两份独立文档**(C1.1,不共用同一 JSON);两者 issuer 一致且 = 按请求 Host 派生(C1.6a);
//! OIDC 独有 OIDC-only 字段(userinfo/id_token 相关),OAuth 文档不含。

use agent_auth_http::{build_router, AppState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::collections::BTreeSet;
use tower::ServiceExt;

const HOST: &str = "localhost";
const EMA_JWKS_URI: &str = "https://login.example.com/acme/discovery/keys";

async fn app() -> axum::Router {
    let (r, _) = build_router(AppState::dev(HOST));
    r
}

async fn get_json(router: &axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    get_json_host(router, path, HOST).await
}

// 带指定 Host 取 discovery(SaaS Host 路由测试用:issuer 按入站 Host 派生 C1.6a/C10.20)。
async fn get_json_host(
    router: &axum::Router,
    path: &str,
    host: &str,
) -> (StatusCode, serde_json::Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("host", host)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let st = resp.status();
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        st,
        serde_json::from_slice(&b).unwrap_or(serde_json::json!({})),
    )
}

#[tokio::test]
async fn discovery_responses_bind_the_live_deployment_commit() {
    let deployment_commit = "a".repeat(40);
    let mut state = AppState::dev(HOST);
    state.deployment_commit = deployment_commit.clone();
    let (router, _) = build_router(state);

    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("host", HOST)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-agent-auth-deployment-commit")
                .and_then(|value| value.to_str().ok()),
            Some(deployment_commit.as_str()),
            "{path} must bind conformance evidence to the live runtime commit",
        );
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-cache"),
            "{path} must require caches to revalidate deployment provenance",
        );
    }
}

fn configure_ema(state: &mut AppState) {
    let raw = serde_json::json!([{
        "tenant": "default",
        "policy": {
            "policy_id": "test-enterprise-idp",
            "trusted_issuer": "https://login.example.com/acme/v2.0",
            "issuer_tenant": "acme",
            "jwks_uri": EMA_JWKS_URI,
            "allowed_algorithms": ["ES256"],
            "authenticated_client_id": "ema-client",
            "assertion_client_id": "enterprise-mcp-client",
            "resources": [{
                "resource": "https://mcp.example.com",
                "scopes": ["mcp:read"]
            }],
            "max_assertion_lifetime_secs": 300,
            "allowed_clock_skew_secs": 30
        }
    }])
    .to_string();
    state.ema_policies = std::sync::Arc::new(
        agent_auth_http::ema_flow::parse_tenant_policies(Some(&raw), &state.form, &[]).unwrap(),
    );
}

#[tokio::test]
async fn openapi_document_is_downloadable() {
    let router = app().await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-disposition")
            .and_then(|value| value.to_str().ok()),
        Some("attachment; filename=\"agent-auth-openapi.json\"")
    );
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(document["openapi"], "3.1.0");
    assert_eq!(document["info"]["title"], "Agent Auth");
    assert!(document["paths"]["/authorize"].is_object());
    assert!(document["paths"]["/openapi.json"].is_object());
    let authorize_params = document["paths"]["/authorize"]["get"]["parameters"]
        .as_array()
        .expect("/authorize parameters");
    for credential in ["client_secret", "client_assertion_type", "client_assertion"] {
        assert!(
            !authorize_params
                .iter()
                .any(|parameter| parameter["name"] == credential),
            "GET /authorize OpenAPI 不得暴露客户端凭据参数 {credential}"
        );
    }
    for (schema, field) in [
        ("ClientView", "last_used_at"),
        ("UserView", "last_login_at"),
    ] {
        assert!(
            document["components"]["schemas"][schema]["required"]
                .as_array()
                .is_some_and(|required| required.iter().any(|value| value == field)),
            "{schema}.{field} 必须作为 required nullable 字段出现在 OpenAPI"
        );
    }
}

#[tokio::test]
async fn client_management_schema_exposes_dpop_but_keeps_rotation_and_validity_immutable() {
    let router = app().await;
    let (status, document) = get_json(&router, "/openapi.json").await;
    assert_eq!(status, StatusCode::OK);

    for schema in [
        "AdminClientCreate",
        "ClientPatch",
        "ClientPut",
        "ClientView",
        "RegisterRequest",
        "RegisterResponse",
    ] {
        let properties = document["components"]["schemas"][schema]["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{schema} properties"));
        assert!(
            properties.contains_key("require_dpop"),
            "{schema} must expose the mutable DPoP policy"
        );
        assert!(
            !properties.contains_key("refresh_rotation"),
            "{schema} must not expose a control that disables mandatory refresh rotation"
        );
        assert!(
            !properties.contains_key("token_validity_secs"),
            "{schema} must not expose a per-client token lifetime extension"
        );
    }

    let expected_update_fields = BTreeSet::from([
        "application_type",
        "confirm_downgrade",
        "default_resource",
        "jwks",
        "jwks_uri",
        "post_logout_redirect_uris",
        "redirect_mode",
        "redirect_uris",
        "require_dpop",
        "token_endpoint_auth_method",
        "token_endpoint_auth_signing_alg",
    ]);
    for schema in ["ClientPatch", "ClientPut"] {
        let actual = document["components"]["schemas"][schema]["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{schema} properties"))
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            actual, expected_update_fields,
            "{schema} fields changed; audit every new mutable field against C4.7 before updating this closed set"
        );
    }
}

// C1.1:两份文档都可取、均 200、issuer 一致且 = 按 Host 派生。
#[tokio::test]
async fn both_discovery_docs_served_with_consistent_issuer() {
    let router = app().await;
    let (st_oidc, oidc) = get_json(&router, "/.well-known/openid-configuration").await;
    let (st_oauth, oauth) = get_json(&router, "/.well-known/oauth-authorization-server").await;
    assert_eq!(st_oidc, StatusCode::OK, "OIDC discovery 应 200");
    assert_eq!(st_oauth, StatusCode::OK, "OAuth discovery 应 200");
    let want_iss = format!("https://{HOST}");
    assert_eq!(
        oidc["issuer"], want_iss,
        "OIDC issuer = 按 Host 派生(C1.6a)"
    );
    assert_eq!(
        oauth["issuer"], want_iss,
        "OAuth issuer = 按 Host 派生(C1.6a)"
    );
    assert_eq!(oidc["issuer"], oauth["issuer"], "两文档 issuer MUST 一致");
    let want_registration = format!("{want_iss}/register");
    assert_eq!(
        oidc["registration_endpoint"], want_registration,
        "OIDC discovery MUST 宣告同源 DCR endpoint"
    );
    assert_eq!(
        oauth["registration_endpoint"], want_registration,
        "OAuth metadata MUST 宣告同源 DCR endpoint"
    );
    assert_eq!(
        oidc["registration_endpoint"], oauth["registration_endpoint"],
        "两文档 registration_endpoint MUST 逐值相等"
    );
    assert_eq!(
        oidc["acr_values_supported"],
        serde_json::json!([
            agent_auth_authn::assurance::BASELINE_ACR,
            agent_auth_authn::assurance::STRONG_ACR
        ])
    );
    assert!(
        oauth.get("acr_values_supported").is_none(),
        "OAuth AS metadata must not contain OIDC-only ACR metadata"
    );
}

// C1.1:两份是**独立文档**——OIDC 含 OIDC-only 字段,OAuth 文档不含(不共用同一 JSON)。
#[tokio::test]
async fn oidc_and_oauth_docs_are_distinct() {
    let router = app().await;
    let (_, oidc) = get_json(&router, "/.well-known/openid-configuration").await;
    let (_, oauth) = get_json(&router, "/.well-known/oauth-authorization-server").await;

    // OIDC 独有:userinfo_endpoint(默认 audience 指向它,§1)+ id_token 签名算法宣告。
    assert!(
        oidc.get("userinfo_endpoint").is_some(),
        "OIDC 文档 MUST 含 userinfo_endpoint"
    );
    assert!(
        oidc.get("id_token_signing_alg_values_supported").is_some(),
        "OIDC 文档 MUST 含 id_token_signing_alg_values_supported"
    );
    // OAuth(RFC 8414)不是 OIDC provider,不宣告 OIDC-only 的 userinfo/id_token 字段。
    assert!(
        oauth.get("userinfo_endpoint").is_none(),
        "OAuth 文档 MUST NOT 含 userinfo_endpoint(非 OIDC provider)"
    );
    assert!(
        oauth.get("id_token_signing_alg_values_supported").is_none(),
        "OAuth 文档 MUST NOT 含 id_token 签名算法宣告"
    );
    // 两者不是同一份 JSON(至少字段集有别)。
    assert_ne!(
        oidc, oauth,
        "两份 discovery MUST 是独立文档,不共用同一 JSON"
    );
}

// C1.1:通过公开 HTTP seam 固定两份 metadata 的闭合字段契约与 revocation phase gate。
#[tokio::test]
async fn discovery_documents_match_c1_1_closed_field_contract_across_phases() {
    const P0_SHARED_FIELDS: &[&str] = &[
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "registration_endpoint",
        "jwks_uri",
        "code_challenge_methods_supported",
        "grant_types_supported",
        "response_types_supported",
        "authorization_response_iss_parameter_supported",
        "token_endpoint_auth_methods_supported",
        "token_endpoint_auth_signing_alg_values_supported",
    ];
    const P0_OIDC_ONLY_FIELDS: &[&str] = &[
        "subject_types_supported",
        "id_token_signing_alg_values_supported",
        "userinfo_endpoint",
        "claims_supported",
        "acr_values_supported",
        "request_parameter_supported",
        "request_uri_parameter_supported",
    ];
    const OIDC_REQUIRED_FIELDS: &[&str] = &[
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "response_types_supported",
        "subject_types_supported",
        "id_token_signing_alg_values_supported",
    ];

    for phase in [agent_auth_http::Phase::P0, agent_auth_http::Phase::P1] {
        let mut state = AppState::dev(HOST);
        state.phase = phase;
        let (router, _) = build_router(state);
        let (oidc_status, oidc) = get_json(&router, "/.well-known/openid-configuration").await;
        let (oauth_status, oauth) =
            get_json(&router, "/.well-known/oauth-authorization-server").await;

        assert_eq!(oidc_status, StatusCode::OK);
        assert_eq!(oauth_status, StatusCode::OK);
        assert_ne!(oidc, oauth, "{phase:?}:两份 metadata MUST 独立");

        let mut expected_oidc_fields: BTreeSet<&str> = P0_SHARED_FIELDS.iter().copied().collect();
        expected_oidc_fields.extend(P0_OIDC_ONLY_FIELDS.iter().copied());
        let mut expected_oauth_fields: BTreeSet<&str> = P0_SHARED_FIELDS.iter().copied().collect();
        if phase == agent_auth_http::Phase::P1 {
            expected_oidc_fields.extend([
                "introspection_endpoint",
                "revocation_endpoint",
                "end_session_endpoint",
                "revocation_endpoint_auth_methods_supported",
                "revocation_endpoint_auth_signing_alg_values_supported",
            ]);
            expected_oauth_fields.extend([
                "revocation_endpoint",
                "revocation_endpoint_auth_methods_supported",
                "revocation_endpoint_auth_signing_alg_values_supported",
            ]);
        }
        let actual_oidc_fields: BTreeSet<&str> = oidc
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let actual_oauth_fields: BTreeSet<&str> = oauth
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            actual_oidc_fields, expected_oidc_fields,
            "{phase:?}:OIDC metadata 字段集合 MUST 与闭列精确相等"
        );
        assert_eq!(
            actual_oauth_fields, expected_oauth_fields,
            "{phase:?}:OAuth metadata 字段集合 MUST 与闭列精确相等"
        );
        for (field, value) in oidc.as_object().unwrap() {
            assert!(!value.is_null(), "{phase:?}:OIDC 字段 {field} MUST 非 null");
        }
        for (field, value) in oauth.as_object().unwrap() {
            assert!(
                !value.is_null(),
                "{phase:?}:OAuth 字段 {field} MUST 非 null"
            );
        }

        for field in P0_SHARED_FIELDS {
            assert!(
                oidc.get(field).is_some() && oauth.get(field).is_some(),
                "{phase:?}:共享字段 {field} MUST 在两份文档中存在"
            );
            assert_eq!(
                oidc.get(field),
                oauth.get(field),
                "{phase:?}:共享字段 {field} MUST 逐值相等"
            );
        }
        for field in P0_OIDC_ONLY_FIELDS {
            assert!(
                oidc.get(field).is_some(),
                "{phase:?}:OIDC 文档缺少专有字段 {field}"
            );
            assert!(
                oauth.get(field).is_none(),
                "{phase:?}:OAuth metadata MUST NOT 含 OIDC 专有字段 {field}"
            );
        }
        for field in OIDC_REQUIRED_FIELDS {
            assert!(
                oidc.get(field).is_some(),
                "{phase:?}:OIDC REQUIRED 闭列缺少 {field}"
            );
        }

        let issuer = format!("https://{HOST}");
        assert_eq!(
            oidc["registration_endpoint"],
            format!("{issuer}/register"),
            "{phase:?}:OIDC registration_endpoint MUST 同源"
        );
        assert_eq!(
            oauth["registration_endpoint"],
            format!("{issuer}/register"),
            "{phase:?}:OAuth registration_endpoint MUST 同源"
        );

        if phase == agent_auth_http::Phase::P0 {
            for field in [
                "revocation_endpoint",
                "revocation_endpoint_auth_methods_supported",
            ] {
                assert!(
                    oidc.get(field).is_none() && oauth.get(field).is_none(),
                    "P0 MUST NOT 宣告 {field}"
                );
            }
        } else {
            assert_eq!(
                oidc["revocation_endpoint"],
                format!("{issuer}/revoke"),
                "P1 OIDC revocation_endpoint MUST 同源"
            );
            assert_eq!(
                oidc["revocation_endpoint"], oauth["revocation_endpoint"],
                "P1 两份 revocation_endpoint MUST 逐值相等"
            );
            assert_eq!(
                oidc["revocation_endpoint_auth_methods_supported"],
                oauth["revocation_endpoint_auth_methods_supported"],
                "P1 两份 revocation auth method 集合 MUST 逐值相等"
            );
            assert_eq!(
                oidc["revocation_endpoint_auth_methods_supported"],
                serde_json::json!([
                    "none",
                    "client_secret_basic",
                    "client_secret_post",
                    "private_key_jwt"
                ]),
                "P1 revocation auth method 集合 MUST 精确等于当前可执行 registered-client capability"
            );
        }
    }
}

// C13.1:EMA 默认关闭时不宣告 profile/JWT bearer grant，且请求仍按未知 grant 拒绝。
#[tokio::test]
async fn ema_feature_off_is_absent_from_metadata_and_rejects_jwt_bearer_grant() {
    let router = app().await;
    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        let (_, metadata) = get_json(&router, path).await;
        assert!(
            metadata
                .get("authorization_grant_profiles_supported")
                .is_none(),
            "{path} must not advertise EMA while disabled"
        );
        assert!(
            !metadata["grant_types_supported"]
                .as_array()
                .unwrap()
                .iter()
                .any(|grant| grant == "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            "{path} must not advertise the JWT bearer grant while EMA is disabled"
        );
    }

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer\
                     &assertion=header.payload.signature",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn ema_feature_on_is_announced_by_both_http_metadata_documents() {
    let mut state = AppState::dev(HOST);
    state.phase = agent_auth_discovery::Phase::P2;
    state.ema_enabled = true;
    configure_ema(&mut state);
    let observed_state = state.clone();
    let (router, _) = build_router(state);

    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        let (status, metadata) = get_json(&router, path).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            metadata["authorization_grant_profiles_supported"],
            serde_json::json!(["urn:ietf:params:oauth:grant-profile:id-jag"])
        );
        assert!(metadata["grant_types_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|grant| grant == "urn:ietf:params:oauth:grant-type:jwt-bearer"));
    }
    assert_eq!(
        observed_state.jwks_fetcher_calls(EMA_JWKS_URI).await,
        Some(0),
        "discovery must not synchronously fetch the configured external JWKS"
    );
    assert_eq!(
        observed_state.jwks_fetcher_fresh_calls(EMA_JWKS_URI).await,
        Some(0),
        "discovery must not synchronously force-refresh the configured external JWKS"
    );
}

#[tokio::test]
async fn ema_advertisement_and_grant_are_scoped_to_the_configured_tenant() {
    use agent_auth_discovery::Form;

    let mut state = AppState::dev("t1.aws.example.com");
    state.form = Form::Saas {
        zone: "aws.example.com".into(),
        control_host: "c.aws.example.com".into(),
    };
    state.tenant_partitioning = true;
    state.saas_tenants = std::sync::Arc::new(vec!["t1".into(), "t2".into()]);
    state.phase = agent_auth_discovery::Phase::P2;
    state.ema_enabled = true;
    let raw = serde_json::json!([{
        "tenant": "t1",
        "policy": {
            "policy_id": "test-enterprise-idp",
            "trusted_issuer": "https://login.example.com/acme/v2.0",
            "issuer_tenant": "acme",
            "jwks_uri": "https://login.example.com/acme/discovery/keys",
            "allowed_algorithms": ["ES256"],
            "authenticated_client_id": "ema-client",
            "assertion_client_id": "enterprise-mcp-client",
            "resources": [{
                "resource": "https://mcp.example.com",
                "scopes": ["mcp:read"]
            }],
            "max_assertion_lifetime_secs": 300,
            "allowed_clock_skew_secs": 30
        }
    }])
    .to_string();
    state.ema_policies = std::sync::Arc::new(
        agent_auth_http::ema_flow::parse_tenant_policies(
            Some(&raw),
            &state.form,
            &["t1".into(), "t2".into()],
        )
        .unwrap(),
    );
    let (router, _) = build_router(state);

    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        let (t1_status, t1) = get_json_host(&router, path, "t1.aws.example.com").await;
        assert_eq!(t1_status, StatusCode::OK, "{path} must serve tenant t1");
        assert_eq!(
            t1["authorization_grant_profiles_supported"],
            serde_json::json!(["urn:ietf:params:oauth:grant-profile:id-jag"])
        );

        let (t2_status, t2) = get_json_host(&router, path, "t2.aws.example.com").await;
        assert_eq!(t2_status, StatusCode::OK, "{path} must serve tenant t2");
        assert!(
            t2.get("authorization_grant_profiles_supported").is_none(),
            "{path} must not advertise a profile without a tenant policy"
        );
        assert!(!t2["grant_types_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|grant| grant == "urn:ietf:params:oauth:grant-type:jwt-bearer"));
    }

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", "t2.aws.example.com")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer\
                     &assertion=header.payload.signature",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"],
        "unsupported_grant_type"
    );
}

#[tokio::test]
async fn ema_flag_without_each_required_dependency_is_not_announced() {
    let mut valid = AppState::dev(HOST);
    valid.phase = agent_auth_discovery::Phase::P2;
    valid.ema_enabled = true;
    configure_ema(&mut valid);

    let mut no_policy = valid.clone();
    no_policy.ema_policies = std::sync::Arc::new(Vec::new());
    let mut no_replay = valid.clone();
    no_replay.replay_store = None;
    let mut no_jti_mapping = valid.clone();
    no_jti_mapping.jti_store = None;
    let mut too_early = valid.clone();
    too_early.phase = agent_auth_discovery::Phase::P1;
    let mut saas_without_partitioning = valid;
    saas_without_partitioning.form = agent_auth_discovery::Form::Saas {
        zone: "aws.example.com".into(),
        control_host: "c.aws.example.com".into(),
    };
    saas_without_partitioning.saas_tenants = std::sync::Arc::new(vec!["t1".into()]);
    saas_without_partitioning.tenant_partitioning = false;

    for (state, host, missing_dependency) in [
        (no_policy, HOST, "tenant policy"),
        (no_replay, HOST, "replay store"),
        (no_jti_mapping, HOST, "JTI mapping store"),
        (too_early, HOST, "P2 phase"),
        (
            saas_without_partitioning,
            "t1.aws.example.com",
            "SaaS tenant partitioning",
        ),
    ] {
        let (router, _) = build_router(state);
        for path in [
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
        ] {
            let (status, metadata) = get_json_host(&router, path, host).await;
            assert_eq!(status, StatusCode::OK);
            assert!(
                metadata
                    .get("authorization_grant_profiles_supported")
                    .is_none(),
                "{path} must not advertise EMA without {missing_dependency}"
            );
            assert!(
                !metadata["grant_types_supported"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|grant| grant == "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                "{path} must not advertise the JWT bearer grant without {missing_dependency}"
            );
        }
    }
}

// C1.4:两份文档都宣告 RFC 9207 authorization_response_iss_parameter_supported=true
// (与 authorize 实际回带 iss 一致,公理 1:元数据如实)。
#[tokio::test]
async fn both_docs_announce_iss_parameter_supported() {
    let router = app().await;
    let (_, oidc) = get_json(&router, "/.well-known/openid-configuration").await;
    let (_, oauth) = get_json(&router, "/.well-known/oauth-authorization-server").await;
    assert_eq!(
        oidc["authorization_response_iss_parameter_supported"], true,
        "OIDC MUST 宣告 iss 参数支持(RFC 9207)"
    );
    assert_eq!(
        oauth["authorization_response_iss_parameter_supported"], true,
        "OAuth MUST 宣告 iss 参数支持(RFC 9207)"
    );
}

// spec 020 §2.7/§2.8(C10.20 + C1.1b):SaaS 形态下 discovery **按入站 Host 路由到该租户 issuer**,
// 逐租户 issuer 的 discovery 宣告一致(issuer=该 Host + subject_types_supported 宣告)、租户间独立;
// 控制面 Host(c.aws)MUST NOT 返回租户 discovery。
#[tokio::test]
async fn saas_discovery_routes_per_tenant_and_control_plane_rejected() {
    use agent_auth_discovery::Form;
    use agent_auth_http::SubjectType;
    use std::collections::BTreeMap;
    // Form::Saas:zone=aws.example.com,control_host=c.aws.example.com。
    let mut state = AppState::dev("t1.aws.example.com");
    state.form = Form::Saas {
        zone: "aws.example.com".into(),
        control_host: "c.aws.example.com".into(),
    };
    state.tenant_partitioning = true;
    state.saas_tenants = std::sync::Arc::new(vec!["t1".to_string(), "t3".to_string()]);
    state.phase = agent_auth_discovery::Phase::P2;
    state.tenant_subject_types =
        std::sync::Arc::new(BTreeMap::from([("t3".to_string(), SubjectType::Public)]));
    let (router, _) = build_router(state);

    // t1:issuer=https://t1.aws.example.com + 宣告 subject_types_supported。
    let (st1, d1) = get_json_host(
        &router,
        "/.well-known/openid-configuration",
        "t1.aws.example.com",
    )
    .await;
    assert_eq!(st1, StatusCode::OK, "t1 discovery 应 200");
    assert_eq!(
        d1["issuer"], "https://t1.aws.example.com",
        "Host=t1 → issuer 路由到 t1(C10.20)"
    );
    assert!(
        d1["subject_types_supported"].is_array(),
        "逐租户 discovery MUST 宣告 subject_types_supported(C1.1b)"
    );
    assert_eq!(
        d1["subject_types_supported"],
        serde_json::json!(["pairwise"]),
        "未显式覆盖的 SaaS tenant 必须使用 pairwise 隐私默认"
    );
    // t1 的所有端点 URL 都在 t1 issuer 下(不串到别的租户/控制面)。
    assert!(
        d1["token_endpoint"]
            .as_str()
            .unwrap()
            .starts_with("https://t1.aws.example.com/"),
        "t1 端点 URL MUST 在 t1 issuer 下"
    );

    // t3:同一部署的显式 public profile 必须与 discovery/签发口径一致。
    let (st2, d2) = get_json_host(
        &router,
        "/.well-known/openid-configuration",
        "t3.aws.example.com",
    )
    .await;
    assert_eq!(st2, StatusCode::OK, "t3 discovery 应 200");
    assert_eq!(
        d2["issuer"], "https://t3.aws.example.com",
        "Host=t3 → issuer 路由到 t3"
    );
    assert_eq!(
        d2["subject_types_supported"],
        serde_json::json!(["public"]),
        "t3 显式 public profile 必须由 discovery 如实宣告"
    );
    // 租户间独立:t1 与 t2 的 issuer 不同(不相互串)。
    assert_ne!(
        d1["issuer"], d2["issuer"],
        "租户间 issuer MUST 独立(C10.20)"
    );

    // 控制面 Host c.aws → discovery MUST NOT 返回租户文档(不是任何租户 issuer,C10.20)。
    let (st_c, _) = get_json_host(
        &router,
        "/.well-known/openid-configuration",
        "c.aws.example.com",
    )
    .await;
    assert_ne!(
        st_c,
        StatusCode::OK,
        "控制面 Host c.aws MUST NOT 返回租户 discovery(不签租户 token,C10.20)"
    );

    // 控制面 Host 也必须在任何签发逻辑前被 Host/issuer 边界拒绝，不能仅隐藏 discovery。
    let token_body = "grant_type=client_credentials&client_id=service-client\
                      &client_secret=not-used&resource=https%3A%2F%2Frs.example.com";
    let token_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", "c.aws.example.com")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(token_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        token_response.status(),
        StatusCode::BAD_REQUEST,
        "控制面 Host MUST 在 token 签发前 fail closed"
    );
    let body = axum::body::to_bytes(token_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["error"], "invalid_request");
    assert!(
        error.get("access_token").is_none(),
        "控制面 Host 拒绝响应不得包含 access token"
    );

    // 相同 P2 请求在合法 tenant Host 下必须越过 Host 门控并到达 client 认证。
    let tenant_response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", "t1.aws.example.com")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(token_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(tenant_response.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(tenant_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let tenant_error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        tenant_error["error"], "invalid_client",
        "合法 tenant Host 必须越过 Host 门控并到达 client 认证"
    );
    assert!(tenant_error.get("access_token").is_none());
}
