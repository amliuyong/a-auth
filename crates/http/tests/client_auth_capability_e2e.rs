//! Issue #13: advertised client authentication methods must be executable.
//!
//! The public seam is the real HTTP router: discovery, DCR/Admin admission,
//! token authentication, and revocation authentication must agree.

use agent_auth_http::ports::{ClientRecord, ClientStore, CodeRecord, CodeStore};
use agent_auth_http::security_event::{
    SecurityEventCategory, SecurityEventOutcome, SecurityEventStore,
};
use agent_auth_http::{build_router, current_unix_secs, AppState, Phase};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use tower::ServiceExt;

const HOST: &str = "localhost";
const ADMIN: &str = "dev-admin-token-not-for-prod";
const METHODS: [&str; 4] = [
    "none",
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt",
];
const VERIFIER: &str = "0123456789012345678901234567890123456789abc";
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

async fn request(
    router: &axum::Router,
    method: &str,
    path: &str,
    content_type: Option<&str>,
    authorization: Option<String>,
    body: impl Into<Body>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", HOST);
    if let Some(content_type) = content_type {
        request = request.header("content-type", content_type);
    }
    if let Some(authorization) = authorization {
        request = request.header("authorization", authorization);
    }
    router
        .clone()
        .oneshot(request.body(body.into()).unwrap())
        .await
        .unwrap()
}

fn basic(client_id: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
}

fn inline_es256_jwks() -> serde_json::Value {
    let signing_key = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
    let point = signing_key.verifying_key().to_encoded_point(false);
    serde_json::json!({
        "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "kid": "capability-key",
            "use": "sig",
            "alg": "ES256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap())
        }]
    })
}

fn private_key_jwt_registration(redirect_uri: &str) -> serde_json::Value {
    serde_json::json!({
        "redirect_uris": [redirect_uri],
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_signing_alg": "ES256",
        "jwks": inline_es256_jwks()
    })
}

fn private_key_assertion(client_id: &str, audience: &str, jti: &str, seed: [u8; 32]) -> String {
    let now = current_unix_secs();
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "JWT",
        "kid": "capability-key"
    });
    let claims = serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + 120,
        "jti": jti
    });
    let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signing_key = SigningKey::from_bytes(&seed.into()).unwrap();
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

async fn seed_code(state: &AppState, code: &str, client_id: &str) {
    state
        .codes
        .put(
            "",
            CodeRecord {
                code: code.to_string(),
                client_id: client_id.to_string(),
                cimd_snapshot: None,
                redirect_uri: "https://client.example.com/expected".to_string(),
                code_challenge: agent_auth_client::s256_challenge(VERIFIER),
                resources: vec![],
                user_id: "alice".to_string(),
                scope: vec![],
                expires_at: current_unix_secs() + 300,
                authz_session_id: None,
                nonce: None,
                auth_time: current_unix_secs(),
                authorization_details: vec![],
                acr: None,
                amr: vec![],
                credential_epoch: Some(0),
                password_credential_version: None,
            },
        )
        .await
        .unwrap();
}

fn presented_auth(
    method: &str,
    client_id: &str,
    audience: &str,
    jti: &str,
) -> (Vec<(String, String)>, Option<String>) {
    let secret = match client_id {
        "basic-client" => "basic-secret",
        "post-client" => "post-secret",
        _ => "substitute-secret",
    };
    match method {
        "none" => (vec![("client_id".to_string(), client_id.to_string())], None),
        "client_secret_basic" => (vec![], Some(basic(client_id, secret))),
        "client_secret_post" => (
            vec![
                ("client_id".to_string(), client_id.to_string()),
                ("client_secret".to_string(), secret.to_string()),
            ],
            None,
        ),
        "private_key_jwt" => (
            vec![
                (
                    "client_assertion_type".to_string(),
                    ASSERTION_TYPE.to_string(),
                ),
                (
                    "client_assertion".to_string(),
                    private_key_assertion(client_id, audience, jti, [7u8; 32]),
                ),
            ],
            None,
        ),
        _ => panic!("unsupported presented authentication method"),
    }
}

async fn p1_router_with_state() -> (axum::Router, AppState) {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P1;
    for mut client in [
        ClientRecord {
            client_id: "public-client".to_string(),
            token_endpoint_auth_method: "none".to_string(),
            ..Default::default()
        },
        ClientRecord {
            client_id: "basic-client".to_string(),
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            client_secret: Some("basic-secret".to_string()),
            ..Default::default()
        },
        ClientRecord {
            client_id: "post-client".to_string(),
            token_endpoint_auth_method: "client_secret_post".to_string(),
            client_secret: Some("post-secret".to_string()),
            ..Default::default()
        },
        ClientRecord {
            client_id: "private-client".to_string(),
            token_endpoint_auth_method: "private_key_jwt".to_string(),
            jwks: Some(serde_json::from_value(inline_es256_jwks()).unwrap()),
            token_endpoint_auth_signing_alg: Some("ES256".to_string()),
            ..Default::default()
        },
    ] {
        client.redirect_uris = vec!["https://client.example.com/expected".to_string()];
        state.clients.put("", client).await.unwrap();
    }
    for (code, client_id) in [
        ("valid-none", "public-client"),
        ("invalid-none", "public-client"),
        ("valid-basic", "basic-client"),
        ("invalid-basic", "basic-client"),
        ("valid-post", "post-client"),
        ("invalid-post", "post-client"),
        ("valid-private", "private-client"),
        ("invalid-private", "private-client"),
    ] {
        seed_code(&state, code, client_id).await;
    }
    let router = build_router(state.clone()).0;
    (router, state)
}

async fn p1_router() -> axum::Router {
    p1_router_with_state().await.0
}

#[tokio::test]
async fn metadata_exactly_matches_registered_client_auth_capabilities() {
    let router = p1_router().await;
    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        let response = request(&router, "GET", path, None, None, Body::empty()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let metadata = response_json(response).await;
        assert_eq!(
            metadata["token_endpoint_auth_methods_supported"],
            serde_json::json!(METHODS),
            "{path} must advertise every executable registered-client method and no others"
        );
    }

    let response = request(
        &router,
        "GET",
        "/.well-known/openid-configuration",
        None,
        None,
        Body::empty(),
    )
    .await;
    let metadata = response_json(response).await;
    assert_eq!(
        metadata["revocation_endpoint_auth_methods_supported"],
        serde_json::json!(METHODS),
        "revocation metadata must match the methods accepted by /revoke"
    );
    let response = request(
        &router,
        "GET",
        "/.well-known/oauth-authorization-server",
        None,
        None,
        Body::empty(),
    )
    .await;
    let metadata = response_json(response).await;
    assert_eq!(
        metadata["revocation_endpoint_auth_methods_supported"],
        serde_json::json!(METHODS),
        "OAuth authorization-server metadata must expose truthful revocation authentication"
    );
}

#[tokio::test]
async fn token_metadata_keeps_workload_methods_endpoint_specific_and_phase_gated() {
    let cases = [
        (
            Phase::P2,
            false,
            vec![
                "none",
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt",
                "workload_oidc_jwt",
                "aws_sigv4_caller_identity",
                "spiffe_jwt_svid",
            ],
        ),
        (
            Phase::P3,
            true,
            vec![
                "none",
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt",
                "workload_oidc_jwt",
                "aws_sigv4_caller_identity",
                "spiffe_jwt_svid",
                "spiffe_svid_mtls",
            ],
        ),
    ];

    for (phase, mtls_svid_enabled, token_methods) in cases {
        let mut state = AppState::dev(HOST);
        state.phase = phase;
        state.mtls_svid_enabled = mtls_svid_enabled;
        let router = build_router(state).0;

        for path in [
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
        ] {
            let response = request(&router, "GET", path, None, None, Body::empty()).await;
            assert_eq!(response.status(), StatusCode::OK);
            let metadata = response_json(response).await;
            assert_eq!(
                metadata["token_endpoint_auth_methods_supported"],
                serde_json::json!(token_methods),
                "{path} must preserve the complete phase-specific token projection"
            );
            assert_eq!(
                metadata["revocation_endpoint_auth_methods_supported"],
                serde_json::json!(METHODS),
                "workload-only token methods must not leak into revocation metadata"
            );
        }
    }
}

#[tokio::test]
async fn dcr_and_admin_admit_only_executable_registered_client_methods() {
    let router = p1_router().await;
    let response = request(
        &router,
        "GET",
        "/admin/clients",
        None,
        Some(format!("Bearer {ADMIN}")),
        Body::empty(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let admin_capabilities = response_json(response).await;
    assert_eq!(
        admin_capabilities["registered_client_auth_methods_supported"],
        serde_json::json!(METHODS),
        "Admin UI options must come from the server-owned executable registry"
    );

    for method in METHODS {
        let body = if method == "private_key_jwt" {
            private_key_jwt_registration("https://client.example.com/callback")
        } else {
            serde_json::json!({
                "redirect_uris": ["https://client.example.com/callback"],
                "token_endpoint_auth_method": method
            })
        };
        for (path, authorization) in [
            ("/register", None),
            ("/admin/clients", Some(format!("Bearer {ADMIN}"))),
        ] {
            let response = request(
                &router,
                "POST",
                path,
                Some("application/json"),
                authorization,
                body.to_string(),
            )
            .await;
            assert_eq!(
                response.status(),
                StatusCode::CREATED,
                "{path} must accept advertised method {method}"
            );
        }
    }

    for path in ["/register", "/admin/clients"] {
        let body = serde_json::json!({
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "private_key_jwt"
        });
        let authorization = (path == "/admin/clients").then(|| format!("Bearer {ADMIN}"));
        let response = request(
            &router,
            "POST",
            path,
            Some("application/json"),
            authorization,
            body.to_string(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{path} must reject private_key_jwt without key metadata"
        );
    }

    let response = request(
        &router,
        "POST",
        "/register",
        Some("application/json"),
        None,
        serde_json::json!({
            "redirect_uris": ["https://self-service.example.com/callback"],
            "token_endpoint_auth_method": "none"
        })
        .to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let registered = response_json(response).await;
    let client_id = registered["client_id"].as_str().unwrap();
    let reg_token = registered["registration_access_token"].as_str().unwrap();

    let conflicting_sources = serde_json::json!({
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_signing_alg": "ES256",
        "jwks": inline_es256_jwks(),
        "jwks_uri": "https://keys.example.com/jwks"
    })
    .to_string();
    let response = request(
        &router,
        "PATCH",
        &format!("/register/{client_id}"),
        Some("application/json"),
        Some(format!("Bearer {reg_token}")),
        conflicting_sources.clone(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "RFC 7592 PATCH must reject conflicting private_key_jwt trust anchors"
    );
    let response = request(
        &router,
        "PATCH",
        "/admin/clients/public-client",
        Some("application/json"),
        Some(format!("Bearer {ADMIN}")),
        conflicting_sources,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Admin PATCH must reject conflicting private_key_jwt trust anchors"
    );

    for method in ["PATCH", "PUT"] {
        let body = if method == "PATCH" {
            serde_json::json!({
                "token_endpoint_auth_method": "private_key_jwt",
                "token_endpoint_auth_signing_alg": "ES256",
                "jwks": inline_es256_jwks()
            })
        } else {
            private_key_jwt_registration("https://self-service.example.com/callback")
        };
        let response = request(
            &router,
            method,
            &format!("/register/{client_id}"),
            Some("application/json"),
            Some(format!("Bearer {reg_token}")),
            body.to_string(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "RFC 7592 {method} must accept private_key_jwt with valid key metadata"
        );
    }

    let response = request(
        &router,
        "PATCH",
        &format!("/register/{client_id}"),
        Some("application/json"),
        Some(format!("Bearer {reg_token}")),
        serde_json::json!({
            "token_endpoint_auth_method": "none",
            "confirm_downgrade": true
        })
        .to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = request(
        &router,
        "PATCH",
        &format!("/register/{client_id}"),
        Some("application/json"),
        Some(format!("Bearer {reg_token}")),
        serde_json::json!({ "token_endpoint_auth_method": "private_key_jwt" }).to_string(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "RFC 7592 must reject private_key_jwt without key metadata"
    );

    for method in ["PATCH", "PUT"] {
        let mut body = if method == "PATCH" {
            serde_json::json!({
                "token_endpoint_auth_method": "private_key_jwt",
                "token_endpoint_auth_signing_alg": "ES256",
                "jwks": inline_es256_jwks()
            })
        } else {
            private_key_jwt_registration("https://client.example.com/callback")
        };
        if method == "PUT" {
            body["confirm_downgrade"] = serde_json::Value::Bool(true);
        }
        let response = request(
            &router,
            method,
            "/admin/clients/public-client",
            Some("application/json"),
            Some(format!("Bearer {ADMIN}")),
            body.to_string(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Admin {method} must accept private_key_jwt with valid key metadata"
        );
    }
}

#[tokio::test]
async fn invalid_private_key_jwt_records_remain_visible_editable_and_fail_closed() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P1;
    let router = build_router(state.clone()).0;

    let response = request(
        &router,
        "POST",
        "/register",
        Some("application/json"),
        None,
        serde_json::json!({
            "redirect_uris": ["https://legacy.example.com/callback"],
            "token_endpoint_auth_method": "none"
        })
        .to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let registered = response_json(response).await;
    let client_id = registered["client_id"].as_str().unwrap().to_string();
    let reg_token = registered["registration_access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let mut legacy = state.clients.get("", &client_id).await.unwrap().unwrap();
    legacy.token_endpoint_auth_method = "private_key_jwt".to_string();
    state.clients.put("", legacy).await.unwrap();

    let response = request(
        &router,
        "GET",
        &format!("/register/{client_id}"),
        None,
        Some(format!("Bearer {reg_token}")),
        Body::empty(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let registration = response_json(response).await;
    assert_eq!(
        registration["token_endpoint_auth_method"],
        "private_key_jwt"
    );

    let response = request(
        &router,
        "PATCH",
        &format!("/register/{client_id}"),
        Some("application/json"),
        Some(format!("Bearer {reg_token}")),
        serde_json::json!({
            "redirect_uris": ["https://legacy.example.com/new-callback"],
            "confirm_downgrade": true
        })
        .to_string(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "an unrelated edit must not brick a persisted record with missing key metadata"
    );
    assert_eq!(
        state
            .clients
            .get("", &client_id)
            .await
            .unwrap()
            .unwrap()
            .token_endpoint_auth_method,
        "private_key_jwt"
    );

    let response = request(
        &router,
        "POST",
        "/revoke",
        Some("application/x-www-form-urlencoded"),
        None,
        serde_urlencoded::to_string([
            ("token", "missing.0"),
            ("client_assertion_type", ASSERTION_TYPE),
            (
                "client_assertion",
                private_key_assertion(
                    &client_id,
                    "https://localhost/revoke",
                    "invalid-persisted-record",
                    [7u8; 32],
                )
                .as_str(),
            ),
        ])
        .unwrap(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "a persisted private_key_jwt record with invalid key metadata must fail closed"
    );

    let response = request(
        &router,
        "PATCH",
        &format!("/register/{client_id}"),
        Some("application/json"),
        Some(format!("Bearer {reg_token}")),
        serde_json::json!({
            "token_endpoint_auth_method": "none",
            "confirm_downgrade": true
        })
        .to_string(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "invalid persisted records must be able to migrate to a valid method"
    );

    let response = request(
        &router,
        "PATCH",
        &format!("/register/{client_id}"),
        Some("application/json"),
        Some(format!("Bearer {reg_token}")),
        serde_json::json!({
            "token_endpoint_auth_method": "private_key_jwt"
        })
        .to_string(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "a migrated record must not re-enter private_key_jwt without key metadata"
    );

    state
        .clients
        .put(
            "",
            ClientRecord {
                client_id: "legacy-admin-client".to_string(),
                redirect_uris: vec!["https://legacy-admin.example.com/callback".to_string()],
                token_endpoint_auth_method: "private_key_jwt".to_string(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let response = request(
        &router,
        "PUT",
        "/admin/clients/legacy-admin-client",
        Some("application/json"),
        Some(format!("Bearer {ADMIN}")),
        serde_json::json!({
            "redirect_uris": ["https://legacy-admin.example.com/callback"],
            "token_endpoint_auth_method": "none",
            "confirm_downgrade": true
        })
        .to_string(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Admin PUT must also support migration away from a legacy method"
    );
}

#[tokio::test]
async fn every_advertised_token_method_has_positive_and_negative_authentication() {
    let (router, state) = p1_router_with_state().await;
    let valid_private_assertion = private_key_assertion(
        "private-client",
        "https://localhost/token",
        "capability-token-valid",
        [7u8; 32],
    );
    let invalid_private_assertion = private_key_assertion(
        "private-client",
        "https://localhost/token",
        "capability-token-invalid",
        [8u8; 32],
    );
    let cases = vec![
        (
            "none",
            format!(
                "grant_type=authorization_code&code=valid-none&client_id=public-client&redirect_uri=https%3A%2F%2Fclient.example.com%2Fexpected&code_verifier={VERIFIER}"
            ),
            None,
            format!(
                "grant_type=authorization_code&code=invalid-none&client_id=public-client&client_secret=unexpected&redirect_uri=https%3A%2F%2Fclient.example.com%2Fexpected&code_verifier={VERIFIER}"
            ),
            None,
        ),
        (
            "client_secret_basic",
            format!(
                "grant_type=authorization_code&code=valid-basic&redirect_uri=https%3A%2F%2Fclient.example.com%2Fexpected&code_verifier={VERIFIER}"
            ),
            Some(basic("basic-client", "basic-secret")),
            format!(
                "grant_type=authorization_code&code=invalid-basic&redirect_uri=https%3A%2F%2Fclient.example.com%2Fexpected&code_verifier={VERIFIER}"
            ),
            Some(basic("basic-client", "wrong")),
        ),
        (
            "client_secret_post",
            format!(
                "grant_type=authorization_code&code=valid-post&client_id=post-client&client_secret=post-secret&redirect_uri=https%3A%2F%2Fclient.example.com%2Fexpected&code_verifier={VERIFIER}"
            ),
            None,
            format!(
                "grant_type=authorization_code&code=invalid-post&client_id=post-client&client_secret=wrong&redirect_uri=https%3A%2F%2Fclient.example.com%2Fexpected&code_verifier={VERIFIER}"
            ),
            None,
        ),
        (
            "private_key_jwt",
            serde_urlencoded::to_string([
                ("grant_type", "authorization_code"),
                ("code", "valid-private"),
                ("redirect_uri", "https://client.example.com/expected"),
                ("code_verifier", VERIFIER),
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", valid_private_assertion.as_str()),
            ])
            .unwrap(),
            None,
            serde_urlencoded::to_string([
                ("grant_type", "authorization_code"),
                ("code", "invalid-private"),
                ("redirect_uri", "https://client.example.com/expected"),
                ("code_verifier", VERIFIER),
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", invalid_private_assertion.as_str()),
            ])
            .unwrap(),
            None,
        ),
    ];

    for (method, valid_body, valid_auth, invalid_body, invalid_auth) in cases {
        let accepted = request(
            &router,
            "POST",
            "/token",
            Some("application/x-www-form-urlencoded"),
            valid_auth,
            valid_body.clone(),
        )
        .await;
        assert_eq!(
            accepted.status(),
            StatusCode::OK,
            "{method} must complete the advertised token path"
        );
        let accepted_body = response_json(accepted).await;
        assert!(
            accepted_body["access_token"]
                .as_str()
                .is_some_and(|token| !token.is_empty()),
            "{method} valid credentials must issue an access token"
        );

        let rejected = request(
            &router,
            "POST",
            "/token",
            Some("application/x-www-form-urlencoded"),
            invalid_auth,
            invalid_body.clone(),
        )
        .await;
        assert_eq!(
            rejected.status(),
            StatusCode::UNAUTHORIZED,
            "{method} invalid credentials must be rejected"
        );
        let rejected_body = response_json(rejected).await;
        assert_eq!(
            rejected_body["error"], "invalid_client",
            "{method} invalid credentials must fail at client authentication"
        );
    }
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    let failures = events
        .iter()
        .filter(|stored| {
            stored.event.category == SecurityEventCategory::Authentication
                && stored.event.action == "authentication.client"
                && stored.event.outcome == SecurityEventOutcome::Denied
        })
        .collect::<Vec<_>>();
    assert_eq!(failures.len(), METHODS.len());
    assert!(failures.iter().all(|stored| {
        let event = serde_json::to_value(&stored.event).unwrap();
        event["actor"]["kind"] == "system"
            && event["actor"]["id"] == "anonymous"
            && event["subject"]["kind"] == "client"
            && event["subject"]["id"] == event["correlation"]["client_id"]
    }));
}

#[tokio::test]
async fn every_advertised_revocation_method_has_positive_and_negative_authentication() {
    let router = p1_router().await;
    let valid_private_assertion = private_key_assertion(
        "private-client",
        "https://localhost/revoke",
        "capability-revoke-valid",
        [7u8; 32],
    );
    let invalid_private_assertion = private_key_assertion(
        "private-client",
        "https://localhost/revoke",
        "capability-revoke-invalid",
        [8u8; 32],
    );
    let cases = vec![
        (
            "none",
            "token=missing.0&client_id=public-client".to_string(),
            None,
            "token=missing.0&client_id=public-client&client_secret=unexpected".to_string(),
            None,
        ),
        (
            "client_secret_basic",
            "token=missing.0".to_string(),
            Some(basic("basic-client", "basic-secret")),
            "token=missing.0".to_string(),
            Some(basic("basic-client", "wrong")),
        ),
        (
            "client_secret_post",
            "token=missing.0&client_id=post-client&client_secret=post-secret".to_string(),
            None,
            "token=missing.0&client_id=post-client&client_secret=wrong".to_string(),
            None,
        ),
        (
            "private_key_jwt",
            serde_urlencoded::to_string([
                ("token", "missing.0"),
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", valid_private_assertion.as_str()),
            ])
            .unwrap(),
            None,
            serde_urlencoded::to_string([
                ("token", "missing.0"),
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", invalid_private_assertion.as_str()),
            ])
            .unwrap(),
            None,
        ),
    ];

    for (method, valid_body, valid_auth, invalid_body, invalid_auth) in cases {
        let accepted = request(
            &router,
            "POST",
            "/revoke",
            Some("application/x-www-form-urlencoded"),
            valid_auth,
            valid_body,
        )
        .await;
        assert_eq!(
            accepted.status(),
            StatusCode::OK,
            "{method} must authenticate at /revoke"
        );

        let rejected = request(
            &router,
            "POST",
            "/revoke",
            Some("application/x-www-form-urlencoded"),
            invalid_auth,
            invalid_body,
        )
        .await;
        assert_eq!(
            rejected.status(),
            StatusCode::UNAUTHORIZED,
            "{method} invalid credentials must be rejected by /revoke"
        );
    }
}

#[tokio::test]
async fn registered_auth_method_cannot_be_substituted_at_token_or_revoke() {
    let (router, state) = p1_router_with_state().await;
    let registered_clients = [
        ("none", "public-client"),
        ("client_secret_basic", "basic-client"),
        ("client_secret_post", "post-client"),
        ("private_key_jwt", "private-client"),
    ];

    for (endpoint, audience) in [
        ("/token", "https://localhost/token"),
        ("/revoke", "https://localhost/revoke"),
    ] {
        for (registered_method, client_id) in registered_clients {
            for presented_method in METHODS {
                if presented_method == registered_method {
                    continue;
                }

                let case = format!(
                    "{}-{}-as-{}",
                    endpoint.trim_start_matches('/'),
                    registered_method,
                    presented_method
                );
                let (mut fields, authorization) =
                    presented_auth(presented_method, client_id, audience, &case);
                if endpoint == "/token" {
                    let code = format!("substitution-{case}");
                    seed_code(&state, &code, client_id).await;
                    fields.extend([
                        ("grant_type".to_string(), "authorization_code".to_string()),
                        ("code".to_string(), code),
                        (
                            "redirect_uri".to_string(),
                            "https://client.example.com/expected".to_string(),
                        ),
                        ("code_verifier".to_string(), VERIFIER.to_string()),
                    ]);
                } else {
                    fields.push(("token".to_string(), "missing.0".to_string()));
                }

                let response = request(
                    &router,
                    "POST",
                    endpoint,
                    Some("application/x-www-form-urlencoded"),
                    authorization,
                    serde_urlencoded::to_string(fields).unwrap(),
                )
                .await;
                assert_eq!(
                    response.status(),
                    StatusCode::UNAUTHORIZED,
                    "{endpoint} must reject {presented_method} for a {registered_method} client"
                );
                assert_eq!(
                    response_json(response).await["error"],
                    "invalid_client",
                    "{endpoint} method substitution must fail at client authentication"
                );
            }
        }
    }
}
