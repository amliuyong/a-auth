use agent_auth_http::{build_router, AppState};
use agent_auth_http::{
    ports::{FederationConfigStore, OidcMetadata, PlatformJwk, Signer},
    state::OidcMetadataFetcherImpl,
};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use serde_json::{json, Value};
use tower::ServiceExt;

const DISCOVERY: &str = "https://idp.example.com/tenant/.well-known/openid-configuration";
const JWKS: &str = "https://idp.example.com/tenant/keys";

fn config(id: &str) -> Value {
    json!({
        "tenant_id": "default",
        "upstream_idp_id": id,
        "upstream_issuer": "https://idp.example.com/tenant",
        "client_id": "registered-rp",
        "client_secret_ref": "agent-auth/federation/controlled",
        "authorization_endpoint": "https://idp.example.com/tenant/authorize",
        "token_endpoint": "https://idp.example.com/tenant/token",
        "jwks_uri": JWKS,
        "scopes": ["openid"],
        "strong_acr_values": []
    })
}

fn metadata() -> OidcMetadata {
    let params = config("controlled");
    OidcMetadata {
        issuer: params["upstream_issuer"].as_str().map(String::from),
        authorization_endpoint: params["authorization_endpoint"].as_str().map(String::from),
        token_endpoint: params["token_endpoint"].as_str().map(String::from),
        jwks_uri: params["jwks_uri"].as_str().map(String::from),
    }
}

// Without the AWS feature this dispatch enum has just its Memory variant.
#[allow(clippy::infallible_destructuring_match)]
fn fetcher(state: &AppState) -> &agent_auth_http::adapters::memory::MemoryOidcMetadataFetcher {
    match state.oidc_metadata_fetcher.as_ref() {
        OidcMetadataFetcherImpl::Memory(fetcher) => fetcher,
        #[cfg(feature = "aws")]
        _ => panic!("controlled tests require the memory adapter"),
    }
}

async fn request(
    router: &axum::Router,
    method: &str,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    request_as(
        router,
        method,
        path,
        body,
        "localhost",
        Some("dev-admin-token-not-for-prod"),
    )
    .await
}

async fn request_as(
    router: &axum::Router,
    method: &str,
    path: &str,
    body: Value,
    host: &str,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", host)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = router
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn current_provider_list_and_diagnostics_are_bound_to_authenticated_saas_tenant() {
    use agent_auth_http::admin_credentials::{
        AdminCredentialOwner, AdminCredentialRecord, AdminCredentialResolver, AdminCredentialSet,
        MemoryAdminCredentialStore,
    };
    use std::{collections::HashMap, sync::Arc, time::Duration};

    let mut state = AppState::dev("t1.aws.example.com");
    state.form = agent_auth_discovery::Form::Saas {
        zone: "aws.example.com".into(),
        control_host: "c.aws.example.com".into(),
    };
    state.tenant_partitioning = true;
    state.saas_tenants = Arc::new(vec!["t1".into(), "t3".into()]);
    let now = agent_auth_http::current_unix_secs();
    let store = MemoryAdminCredentialStore::default();
    let platform_reference = "memory:platform";
    store.put_set(
        platform_reference,
        &AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            AdminCredentialRecord::explicit(
                "platform-v1",
                "platform-test-admin",
                now - 60,
                now - 60,
                now + 86_400,
            ),
        ),
        now,
    );
    let mut references = HashMap::new();
    for (tenant, token) in [("t1", "t1-test-admin-token"), ("t3", "t3-test-admin-token")] {
        let reference = format!("memory:tenant:{tenant}");
        references.insert(tenant.into(), reference.clone());
        store.put_set(
            &reference,
            &AdminCredentialSet::single(
                AdminCredentialOwner::tenant(tenant),
                AdminCredentialRecord::explicit(
                    format!("{tenant}-v1"),
                    token,
                    now - 60,
                    now - 60,
                    now + 86_400,
                ),
            ),
            now,
        );
    }
    state.admin_credentials = Arc::new(AdminCredentialResolver::memory(
        Some(platform_reference.into()),
        references,
        store,
        Duration::ZERO,
    ));
    let (router, _) = build_router(state.clone());
    for (tenant, token) in [("t1", "t1-test-admin-token"), ("t3", "t3-test-admin-token")] {
        let host = format!("{tenant}.aws.example.com");
        let mut payload = config(&format!("{tenant}-provider"));
        payload["tenant_id"] = json!(tenant);
        payload["client_secret_ref"] = json!(format!("agent-auth/federation/{tenant}/controlled"));
        assert_eq!(
            request_as(
                &router,
                "PUT",
                "/admin/federation",
                payload,
                &host,
                Some(token)
            )
            .await
            .0,
            StatusCode::CREATED
        );
        let (status, result) = request_as(
            &router,
            "GET",
            "/admin/federation?tenant_id=other",
            Value::Null,
            &host,
            Some(token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(result["tenant_id"], tenant);
        assert_eq!(result["total"], 1);
        assert_eq!(
            result["idps"][0]["upstream_idp_id"],
            format!("{tenant}-provider")
        );
        assert!(!result.to_string().contains("client_secret_ref"));
    }
    for reference in [
        "agent-auth/federation/t3/controlled",
        "agent-auth/federation/shared",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:agent-auth/federation/t3/controlled-ABCDEF",
        "arn:aws:ssm:us-east-1:123456789012:secret:agent-auth/federation/t1/controlled",
    ] {
        let mut payload = config("t1-provider");
        payload["tenant_id"] = json!("t1");
        payload["client_secret_ref"] = json!(reference);
        let (status, result) = request_as(
            &router, "PUT", "/admin/federation", payload, "t1.aws.example.com", Some("t1-test-admin-token"),
        ).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(result["field"], "client_secret_ref");
    }
    for (path, host, token, expected) in [
        (
            "/admin/federation",
            "t1.aws.example.com",
            None,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/admin/federation",
            "t3.aws.example.com",
            Some("t1-test-admin-token"),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/admin/federation/t3",
            "t1.aws.example.com",
            Some("t1-test-admin-token"),
            StatusCode::FORBIDDEN,
        ),
        (
            "/admin/federation/t3/t3-provider/checks",
            "t1.aws.example.com",
            Some("t1-test-admin-token"),
            StatusCode::FORBIDDEN,
        ),
    ] {
        assert_eq!(
            request_as(&router, "GET", path, Value::Null, host, token)
                .await
                .0,
            expected,
            "{path} {host}"
        );
    }
    assert_eq!(fetcher(&state).calls(DISCOVERY).await, 0);
    let (status, result) = request_as(
        &router,
        "GET",
        "/admin/federation/t1/t1-provider/checks",
        Value::Null,
        "t1.aws.example.com",
        Some("t1-test-admin-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["format"]["status"], "PASS");
    assert_eq!(result["discovery"]["status"], "UNKNOWN");
    assert_eq!(fetcher(&state).calls(DISCOVERY).await, 1);
    // Full ARN references retain the same tenant-owned name contract.
    let mut payload = config("t1-provider");
    payload["tenant_id"] = json!("t1");
    payload["client_secret_ref"] = json!("arn:aws:secretsmanager:us-east-1:123456789012:secret:agent-auth/federation/t1/controlled-ABCDEF");
    assert_eq!(
        request_as(
            &router,
            "PUT",
            "/admin/federation",
            payload,
            "t1.aws.example.com",
            Some("t1-test-admin-token"),
        )
        .await
        .0,
        StatusCode::CREATED
    );
    // Imported/legacy rows are checked too, before any diagnostic network call.
    let mut legacy = state
        .federation_config
        .get("t1", "t1-provider")
        .await
        .unwrap()
        .unwrap();
    legacy.oidc.as_mut().unwrap().client_secret_ref = "agent-auth/federation/t3/controlled".into();
    state.federation_config.put(legacy).await.unwrap();
    let (_, result) = request_as(
        &router,
        "GET",
        "/admin/federation/t1/t1-provider/checks",
        Value::Null,
        "t1.aws.example.com",
        Some("t1-test-admin-token"),
    )
    .await;
    assert_eq!(result["format"]["status"], "FAIL");
    assert_eq!(result["format"]["field"], "client_secret_ref");
    assert_eq!(result["discovery"]["status"], "NOT_RUN");
    assert_eq!(fetcher(&state).calls(DISCOVERY).await, 1);
}

#[tokio::test]
async fn checks_report_format_separately_from_unavailable_discovery_and_real_login() {
    let (router, _) = build_router(AppState::dev("localhost"));
    let (status, body) = request(&router, "PUT", "/admin/federation", config("controlled")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = request(
        &router,
        "GET",
        "/admin/federation/default/controlled/checks",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["format"]["status"], "PASS");
    assert_eq!(body["discovery"]["status"], "UNKNOWN");
    assert_eq!(body["jwks"]["status"], "NOT_RUN");
    assert_eq!(body["login"]["status"], "NOT_RUN");
}

#[tokio::test]
async fn metadata_and_jwks_failures_are_separate_and_never_change_trust() {
    let state = AppState::dev("localhost");
    let (router, _) = build_router(state.clone());
    assert_eq!(
        request(&router, "PUT", "/admin/federation", config("controlled"))
            .await
            .0,
        StatusCode::CREATED
    );
    let before = state
        .federation_config
        .get("default", "controlled")
        .await
        .unwrap()
        .unwrap();
    let path = "/admin/federation/default/controlled/checks";
    // Remote metadata cannot substitute issuer, endpoints or a JWKS trust.
    for field in [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
    ] {
        let mut document = config("controlled");
        document["issuer"] = document["upstream_issuer"].clone();
        document[field] = json!("https://untrusted.example.com");
        let parsed: OidcMetadata = serde_json::from_value(document).unwrap();
        fetcher(&state).set(DISCOVERY.into(), Ok(parsed)).await;
        let (status, result) = request(&router, "GET", path, Value::Null).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(result["discovery"]["status"], "FAIL");
        assert_eq!(result["discovery"]["field"], field);
        assert_eq!(result["jwks"]["status"], "NOT_RUN");
        assert_eq!(state.jwks_fetcher_fresh_calls(JWKS).await, Some(0));
    }
    fetcher(&state).set(DISCOVERY.into(), Ok(metadata())).await;
    let (_, result) = request(&router, "GET", path, Value::Null).await;
    assert_eq!(result["discovery"]["status"], "PASS");
    assert_eq!(result["jwks"]["status"], "FAIL");
    // Invalid RSA material must not pass merely because a document has a key.
    state
        .jwks_fetcher_set_fresh(
            JWKS,
            vec![PlatformJwk {
                n: "invalid".into(),
                e: "AQAB".into(),
                ..Default::default()
            }],
        )
        .await;
    assert_eq!(
        request(&router, "GET", path, Value::Null).await.1["jwks"]["status"],
        "FAIL"
    );
    let key = state.signer.public_rsa_jwks().await.unwrap().remove(0);
    state
        .jwks_fetcher_set_fresh(
            JWKS,
            vec![PlatformJwk {
                kty: Some("RSA".into()),
                n: key.n,
                e: key.e,
                alg: Some("RS256".into()),
                ..Default::default()
            }],
        )
        .await;
    let (_, result) = request(&router, "GET", path, Value::Null).await;
    for field in ["format", "discovery", "jwks"] {
        assert_eq!(result[field]["status"], "PASS");
    }
    assert_eq!(result["login"]["status"], "NOT_RUN");
    let rendered = result.to_string();
    assert!(!rendered.contains("agent-auth/federation/controlled"));
    assert!(!rendered.contains("untrusted.example.com"));
    assert_eq!(
        state
            .federation_config
            .get("default", "controlled")
            .await
            .unwrap()
            .unwrap(),
        before
    );
}

#[tokio::test]
async fn authentication_tenant_and_url_guards_precede_network_checks() {
    let state = AppState::dev("localhost");
    let (router, _) = build_router(state.clone());
    assert_eq!(
        request(&router, "PUT", "/admin/federation", config("controlled"))
            .await
            .0,
        StatusCode::CREATED
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/federation/default/controlled/checks")
                .header("host", "localhost")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        request(
            &router,
            "GET",
            "/admin/federation/other/controlled/checks",
            Value::Null
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &router,
            "GET",
            "/admin/federation/default/missing/checks",
            Value::Null
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(fetcher(&state).calls(DISCOVERY).await, 0);
    for (field, value) in [
        ("client_id", json!("")),
        ("client_secret_ref", json!(" ")),
        ("scopes", json!([])),
        ("strong_acr_values", json!(["untrusted value with spaces"])),
    ] {
        let mut invalid = config("invalid");
        invalid[field] = value;
        let (status, body) = request(&router, "PUT", "/admin/federation", invalid).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["field"], field);
    }
    for field in [
        "upstream_issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
    ] {
        for url in [
            "https://127.0.0.1/metadata",
            "https://2130706433/metadata",
            "https://[fec0::1]/metadata",
            "https://[2001:db8::1]/metadata",
            "https://test.lambda-url.us-east-1.on.aws/",
            "https://test.LAMBDA-URL.us-east-1.on.aws./",
            "https://idp.example.com:8443",
            "https://user:secret@idp.example.com",
        ] {
            let mut invalid = config("invalid");
            invalid[field] = json!(url);
            let (status, body) = request(&router, "PUT", "/admin/federation", invalid).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{field} {body}");
            assert_eq!(body["field"], field);
        }
    }
    assert_eq!(fetcher(&state).calls(DISCOVERY).await, 0);
    // Also guard a legacy/directly stored config before any network adapter.
    let mut stored = state
        .federation_config
        .get("default", "controlled")
        .await
        .unwrap()
        .unwrap();
    stored.oidc.as_mut().unwrap().jwks_uri = "https://test.lambda-url.us-east-1.on.aws/".into();
    state.federation_config.put(stored).await.unwrap();
    let (_, body) = request(
        &router,
        "GET",
        "/admin/federation/default/controlled/checks",
        Value::Null,
    )
    .await;
    assert_eq!(body["format"]["status"], "FAIL");
    assert_eq!(body["format"]["field"], "jwks_uri");
    assert_eq!(body["discovery"]["status"], "NOT_RUN");
    assert_eq!(fetcher(&state).calls(DISCOVERY).await, 0);
}

#[tokio::test]
async fn changed_config_cannot_receive_a_stale_diagnostic_result() {
    let state = AppState::dev("localhost");
    let (router, _) = build_router(state.clone());
    assert_eq!(
        request(&router, "PUT", "/admin/federation", config("controlled"))
            .await
            .0,
        StatusCode::CREATED
    );
    fetcher(&state).set(DISCOVERY.into(), Ok(metadata())).await;
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let resume = std::sync::Arc::new(tokio::sync::Notify::new());
    fetcher(&state)
        .pause_once(started.clone(), resume.clone())
        .await;
    let task = tokio::spawn(async move {
        request(
            &router,
            "GET",
            "/admin/federation/default/controlled/checks",
            Value::Null,
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), started.notified())
        .await
        .unwrap();
    let mut current = state
        .federation_config
        .get("default", "controlled")
        .await
        .unwrap()
        .unwrap();
    current.oidc.as_mut().unwrap().client_id = "replacement-rp".into();
    state.federation_config.put(current).await.unwrap();
    resume.notify_one();
    assert_eq!(task.await.unwrap().0, StatusCode::CONFLICT);
}
