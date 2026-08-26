//! Issue #14: RFC 7523 private_key_jwt through the real HTTP router.

use agent_auth_http::adapters::memory::MemorySigner;
use agent_auth_http::ports::{
    ClientRecord, ClientStore, CodeRecord, CodeStore, PlatformJwk, RegisteredClientJwks, Signer,
};
use agent_auth_http::{build_router, current_unix_secs, AppState, Phase};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use tower::ServiceExt;

const HOST: &str = "localhost";
const VERIFIER: &str = "0123456789012345678901234567890123456789abc";
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

fn inline_es256_jwks() -> serde_json::Value {
    serde_json::json!({ "keys": [es256_jwk([7u8; 32], "client-key-1")] })
}

fn es256_jwk(seed: [u8; 32], kid: &str) -> serde_json::Value {
    let signing_key = SigningKey::from_bytes(&seed.into()).unwrap();
    let point = signing_key.verifying_key().to_encoded_point(false);
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "kid": kid,
        "use": "sig",
        "alg": "ES256",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap())
    })
}

fn es256_platform_jwk() -> PlatformJwk {
    let signing_key = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
    let point = signing_key.verifying_key().to_encoded_point(false);
    PlatformJwk {
        kid: Some("client-key-1".to_string()),
        kty: Some("EC".to_string()),
        n: String::new(),
        e: String::new(),
        crv: Some("P-256".to_string()),
        x: Some(URL_SAFE_NO_PAD.encode(point.x().unwrap())),
        y: Some(URL_SAFE_NO_PAD.encode(point.y().unwrap())),
        alg: Some("ES256".to_string()),
    }
}

fn es256_assertion(client_id: &str, audience: &str, jti: &str, now: i64) -> String {
    es256_assertion_with(
        client_id,
        client_id,
        audience,
        jti,
        now,
        now,
        now + 120,
        "client-key-1",
        "ES256",
    )
}

#[allow(clippy::too_many_arguments)]
fn es256_assertion_with(
    issuer: &str,
    subject: &str,
    audience: &str,
    jti: &str,
    iat: i64,
    nbf: i64,
    exp: i64,
    kid: &str,
    alg: &str,
) -> String {
    es256_assertion_with_seed(
        [7u8; 32], issuer, subject, audience, jti, iat, nbf, exp, kid, alg,
    )
}

#[allow(clippy::too_many_arguments)]
fn es256_assertion_with_seed(
    seed: [u8; 32],
    issuer: &str,
    subject: &str,
    audience: &str,
    jti: &str,
    iat: i64,
    nbf: i64,
    exp: i64,
    kid: &str,
    alg: &str,
) -> String {
    let signing_key = SigningKey::from_bytes(&seed.into()).unwrap();
    let header = serde_json::json!({
        "alg": alg,
        "typ": "JWT",
        "kid": kid
    });
    let claims = serde_json::json!({
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "iat": iat,
        "nbf": nbf,
        "exp": exp,
        "jti": jti
    });
    let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

async fn rs256_material() -> (MemorySigner, serde_json::Value) {
    let signer = MemorySigner::dev();
    let jwk = signer.public_rsa_jwks().await.unwrap().remove(0);
    let jwks = serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "kid": jwk.kid,
            "use": "sig",
            "alg": "RS256",
            "n": jwk.n,
            "e": jwk.e
        }]
    });
    (signer, jwks)
}

async fn rs256_jwks_without_kid() -> serde_json::Value {
    let (_, mut jwks) = rs256_material().await;
    jwks["keys"][0].as_object_mut().unwrap().remove("kid");
    jwks
}

async fn rs256_assertion(
    signer: &MemorySigner,
    client_id: &str,
    audience: &str,
    jti: &str,
    now: i64,
) -> String {
    let kid = signer.active_rsa_kid().await.unwrap();
    let header = serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": kid });
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
    let (_, signature) = signer.sign_rs256(signing_input.as_bytes()).await.unwrap();
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

async fn seed_code(state: &AppState, client_id: &str, code: &str) {
    state
        .codes
        .put(
            "",
            CodeRecord {
                code: code.to_string(),
                client_id: client_id.to_string(),
                cimd_snapshot: None,
                redirect_uri: "https://client.example.com/callback".to_string(),
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

fn token_body(code: &str, assertion: &str, client_id: Option<&str>) -> String {
    let mut values = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", "https://client.example.com/callback"),
        ("code_verifier", VERIFIER),
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", assertion),
    ];
    if let Some(client_id) = client_id {
        values.push(("client_id", client_id));
    }
    serde_urlencoded::to_string(values).unwrap()
}

async fn request(
    router: &axum::Router,
    method: &str,
    path: &str,
    content_type: Option<&str>,
    body: impl Into<Body>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", HOST);
    if let Some(content_type) = content_type {
        request = request.header("content-type", content_type);
    }
    router
        .clone()
        .oneshot(request.body(body.into()).unwrap())
        .await
        .unwrap()
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn dcr_accepts_valid_inline_jwks() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P1;
    let router = build_router(state).0;

    let response = request(
        &router,
        "POST",
        "/register",
        Some("application/json"),
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "jwks": inline_es256_jwks()
        })
        .to_string(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "a valid inline public JWKS must be accepted"
    );
    let registered = response_json(response).await;
    assert_eq!(registered["token_endpoint_auth_method"], "private_key_jwt");
}

#[tokio::test]
async fn dcr_accepts_oidf_rs256_jwks_without_kid_for_client_secret_basic() {
    let state = AppState::dev(HOST);
    let router = build_router(state.clone()).0;
    let response = request(
        &router,
        "POST",
        "/register",
        Some("application/json"),
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/callback"],
            "client_name": "OIDF Conformance Test Suite",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "contacts": ["ops@example.com"],
            "token_endpoint_auth_method": "client_secret_basic",
            "jwks": rs256_jwks_without_kid().await
        })
        .to_string(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "RFC 7517 kid is optional and RFC 7591 jwks is valid general client metadata"
    );
    let registered = response_json(response).await;
    assert_eq!(
        registered["token_endpoint_auth_method"],
        "client_secret_basic"
    );
    assert!(registered["client_secret"]
        .as_str()
        .is_some_and(|secret| !secret.is_empty()));
    assert!(
        registered["jwks"]["keys"][0].get("kid").is_none(),
        "an absent kid must remain absent in the DCR response"
    );
    assert!(registered.get("token_endpoint_auth_signing_alg").is_none());

    let client_id = registered["client_id"].as_str().unwrap();
    let persisted = state.clients.get("", client_id).await.unwrap().unwrap();
    let key = &persisted.jwks.unwrap().keys[0];
    assert!(key.kid.is_empty());
    assert_eq!(key.kty, "RSA");
    assert_eq!(key.alg, "RS256");
}

#[tokio::test]
async fn dcr_rejects_private_key_jwt_without_kid_as_client_metadata_error() {
    let state = AppState::dev(HOST);
    let router = build_router(state).0;
    let response = request(
        &router,
        "POST",
        "/register",
        Some("application/json"),
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "RS256",
            "jwks": rs256_jwks_without_kid().await
        })
        .to_string(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "private_key_jwt still requires a unique non-empty kid, but must not fail JSON extraction"
    );
    let error = response_json(response).await;
    assert_eq!(error["error"], "invalid_client_metadata");
    assert!(error["error_description"]
        .as_str()
        .is_some_and(|description| description.contains("kid")));
}

#[tokio::test]
async fn general_jwks_uri_patch_preserves_and_put_replaces() {
    let state = AppState::dev(HOST);
    let router = build_router(state.clone()).0;
    let jwks_uri = "https://keys.example.com/client.jwks";
    let response = request(
        &router,
        "POST",
        "/register",
        Some("application/json"),
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "client_secret_basic",
            "jwks_uri": jwks_uri
        })
        .to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let registered = response_json(response).await;
    assert_eq!(registered["jwks_uri"], jwks_uri);
    let client_id = registered["client_id"].as_str().unwrap();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/clients/{client_id}"))
                .header("host", HOST)
                .header("authorization", "Bearer dev-admin-token-not-for-prod")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "token_endpoint_auth_method": "client_secret_basic"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let stored = state.clients.get("", client_id).await.unwrap().unwrap();
    assert_eq!(stored.jwks_uri.as_deref(), Some(jwks_uri));
    assert!(stored.jwks.is_none());
    assert!(stored.token_endpoint_auth_signing_alg.is_none());

    let response = router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/admin/clients/{client_id}"))
                .header("host", HOST)
                .header("authorization", "Bearer dev-admin-token-not-for-prod")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "redirect_uris": ["https://client.example.com/callback"],
                        "token_endpoint_auth_method": "client_secret_basic"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let stored = state.clients.get("", client_id).await.unwrap().unwrap();
    assert!(
        stored.jwks.is_none() && stored.jwks_uri.is_none(),
        "Admin PUT must clear omitted general key metadata"
    );
    assert!(stored.token_endpoint_auth_signing_alg.is_none());
}

#[tokio::test]
async fn token_accepts_valid_private_key_jwt_assertion() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P1;
    let router = build_router(state.clone()).0;

    let response = request(
        &router,
        "POST",
        "/register",
        Some("application/json"),
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "jwks": inline_es256_jwks()
        })
        .to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let registered = response_json(response).await;
    let client_id = registered["client_id"].as_str().unwrap();

    seed_code(&state, client_id, "private-jwt-code").await;

    let assertion = es256_assertion(
        client_id,
        "https://localhost/token",
        "valid-token-assertion",
        current_unix_secs(),
    );
    let body = token_body("private-jwt-code", &assertion, None);
    let response = request(
        &router,
        "POST",
        "/token",
        Some("application/x-www-form-urlencoded"),
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let token = response_json(response).await;
    assert!(token["access_token"]
        .as_str()
        .is_some_and(|jwt| !jwt.is_empty()));
}

#[tokio::test]
async fn private_key_jwt_completes_code_flow_without_pkce() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P1;
    let router = build_router(state).0;

    let response = request(
        &router,
        "POST",
        "/register",
        Some("application/json"),
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "jwks": inline_es256_jwks()
        })
        .to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let registered = response_json(response).await;
    let client_id = registered["client_id"].as_str().unwrap();

    let authorize_query = serde_urlencoded::to_string([
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", "https://client.example.com/callback"),
        ("scope", "openid"),
        ("login_user", "alice"),
    ])
    .unwrap();
    let authorization = request(
        &router,
        "GET",
        &format!("/authorize?{authorize_query}"),
        None,
        Body::empty(),
    )
    .await;
    assert_eq!(authorization.status(), StatusCode::SEE_OTHER);
    let location = authorization
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let code = location
        .split_once('?')
        .unwrap()
        .1
        .split('&')
        .find_map(|pair| pair.strip_prefix("code="))
        .unwrap();

    let assertion = es256_assertion(
        client_id,
        "https://localhost/token",
        "no-pkce-token-assertion",
        current_unix_secs(),
    );
    let body = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", "https://client.example.com/callback"),
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", assertion.as_str()),
    ])
    .unwrap();
    let response = request(
        &router,
        "POST",
        "/token",
        Some("application/x-www-form-urlencoded"),
        body,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response_json(response).await["access_token"]
        .as_str()
        .is_some_and(|jwt| !jwt.is_empty()));
}

#[tokio::test]
async fn token_rejects_invalid_assertions_and_replay() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P1;
    let router = build_router(state.clone()).0;
    let response = request(
        &router,
        "POST",
        "/register",
        Some("application/json"),
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "jwks": inline_es256_jwks()
        })
        .to_string(),
    )
    .await;
    let registered = response_json(response).await;
    let client_id = registered["client_id"].as_str().unwrap();
    seed_code(&state, client_id, "invalid-assertion-code").await;

    let now = current_unix_secs();
    let invalid = [
        (
            "wrong audience",
            es256_assertion(
                client_id,
                "https://localhost/introspect",
                "wrong-audience",
                now,
            ),
            None,
        ),
        (
            "wrong client",
            es256_assertion(
                "different-client",
                "https://localhost/token",
                "wrong-client",
                now,
            ),
            Some(client_id),
        ),
        (
            "expired",
            es256_assertion_with(
                client_id,
                client_id,
                "https://localhost/token",
                "expired",
                now - 1_000,
                now - 1_000,
                now - 900,
                "client-key-1",
                "ES256",
            ),
            None,
        ),
        (
            "unknown key",
            es256_assertion_with(
                client_id,
                client_id,
                "https://localhost/token",
                "unknown-key",
                now,
                now,
                now + 120,
                "unregistered-key",
                "ES256",
            ),
            None,
        ),
        (
            "algorithm confusion",
            es256_assertion_with(
                client_id,
                client_id,
                "https://localhost/token",
                "algorithm-confusion",
                now,
                now,
                now + 120,
                "client-key-1",
                "RS256",
            ),
            None,
        ),
    ];
    for (case, assertion, form_client_id) in invalid {
        let response = request(
            &router,
            "POST",
            "/token",
            Some("application/x-www-form-urlencoded"),
            token_body("invalid-assertion-code", &assertion, form_client_id),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{case} must be rejected"
        );
    }

    seed_code(&state, client_id, "replay-code-1").await;
    seed_code(&state, client_id, "replay-code-2").await;
    let assertion = es256_assertion(
        client_id,
        "https://localhost/token",
        "one-time-jti",
        current_unix_secs(),
    );
    let first = request(
        &router,
        "POST",
        "/token",
        Some("application/x-www-form-urlencoded"),
        token_body("replay-code-1", &assertion, None),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let replay = request(
        &router,
        "POST",
        "/token",
        Some("application/x-www-form-urlencoded"),
        token_body("replay-code-2", &assertion, None),
    )
    .await;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn discovery_advertises_private_key_jwt_with_signing_algorithms() {
    let router = build_router(AppState::dev(HOST)).0;

    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        let response = request(&router, "GET", path, None, Body::empty()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let metadata = response_json(response).await;
        assert!(metadata["token_endpoint_auth_methods_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|method| method == "private_key_jwt"));
        assert_eq!(
            metadata["token_endpoint_auth_signing_alg_values_supported"],
            serde_json::json!(["RS256", "ES256"])
        );
        assert_eq!(
            metadata["revocation_endpoint_auth_signing_alg_values_supported"],
            serde_json::json!(["RS256", "ES256"])
        );
    }
}

#[tokio::test]
async fn revocation_accepts_endpoint_bound_private_key_jwt() {
    let state = AppState::dev(HOST);
    let router = build_router(state).0;
    let response = request(
        &router,
        "POST",
        "/register",
        Some("application/json"),
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "jwks": inline_es256_jwks()
        })
        .to_string(),
    )
    .await;
    let registered = response_json(response).await;
    let client_id = registered["client_id"].as_str().unwrap();
    let assertion = es256_assertion(
        client_id,
        "https://localhost/revoke",
        "revocation-assertion",
        current_unix_secs(),
    );
    let body = serde_urlencoded::to_string([
        ("token", "unknown-token"),
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", assertion.as_str()),
    ])
    .unwrap();
    let response = request(
        &router,
        "POST",
        "/revoke",
        Some("application/x-www-form-urlencoded"),
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn introspection_accepts_endpoint_bound_private_key_jwt() {
    let state = AppState::dev(HOST);
    let router = build_router(state.clone()).0;
    let response = request(
        &router,
        "POST",
        "/register",
        Some("application/json"),
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "jwks": inline_es256_jwks()
        })
        .to_string(),
    )
    .await;
    let registered = response_json(response).await;
    let client_id = registered["client_id"].as_str().unwrap();
    let mut client = state.clients.get("", client_id).await.unwrap().unwrap();
    client.introspect_enabled = true;
    client.resource_ids = vec!["https://rs.example.com".to_string()];
    state.clients.put("", client).await.unwrap();

    let assertion = es256_assertion(
        client_id,
        "https://localhost/introspect",
        "introspection-assertion",
        current_unix_secs(),
    );
    let body = serde_urlencoded::to_string([
        ("token", "not-a-token"),
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", assertion.as_str()),
    ])
    .unwrap();
    let response = request(
        &router,
        "POST",
        "/introspect",
        Some("application/x-www-form-urlencoded"),
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await,
        serde_json::json!({ "active": false })
    );
}

#[tokio::test]
async fn par_accepts_endpoint_bound_private_key_jwt() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P3;
    let router = build_router(state).0;
    let response = request(
        &router,
        "POST",
        "/register",
        Some("application/json"),
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "jwks": inline_es256_jwks()
        })
        .to_string(),
    )
    .await;
    let registered = response_json(response).await;
    let client_id = registered["client_id"].as_str().unwrap();
    let assertion = es256_assertion(
        client_id,
        "https://localhost/par",
        "par-assertion",
        current_unix_secs(),
    );
    let challenge = agent_auth_client::s256_challenge(VERIFIER);
    let body = serde_urlencoded::to_string([
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", "https://client.example.com/callback"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", assertion.as_str()),
    ])
    .unwrap();
    let response = request(
        &router,
        "POST",
        "/par",
        Some("application/x-www-form-urlencoded"),
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert!(response_json(response).await["request_uri"]
        .as_str()
        .is_some_and(|uri| uri.starts_with("urn:ietf:params:oauth:request_uri:")));
}

#[tokio::test]
async fn refresh_accepts_a_fresh_private_key_jwt_assertion() {
    let state = AppState::dev(HOST);
    let router = build_router(state.clone()).0;
    let response = request(
        &router,
        "POST",
        "/register",
        Some("application/json"),
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "jwks": inline_es256_jwks()
        })
        .to_string(),
    )
    .await;
    let registered = response_json(response).await;
    let client_id = registered["client_id"].as_str().unwrap();
    seed_code(&state, client_id, "refresh-seed-code").await;

    let first_assertion = es256_assertion(
        client_id,
        "https://localhost/token",
        "code-exchange-jti",
        current_unix_secs(),
    );
    let response = request(
        &router,
        "POST",
        "/token",
        Some("application/x-www-form-urlencoded"),
        token_body("refresh-seed-code", &first_assertion, None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let refresh_token = response_json(response).await["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();

    let refresh_assertion = es256_assertion(
        client_id,
        "https://localhost/token",
        "refresh-rotation-jti",
        current_unix_secs(),
    );
    let body = serde_urlencoded::to_string([
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token.as_str()),
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", refresh_assertion.as_str()),
    ])
    .unwrap();
    let response = request(
        &router,
        "POST",
        "/token",
        Some("application/x-www-form-urlencoded"),
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn ciba_ping_uses_endpoint_bound_private_key_jwt_at_both_authentication_steps() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P3;
    state.ciba_ping_push_enabled = true;
    let user_id = state.seed_user("alice@example.com", 1_000).await;
    let router = build_router(state.clone()).0;

    let response = request(
        &router,
        "POST",
        "/register",
        Some("application/json"),
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "jwks": inline_es256_jwks(),
            "backchannel_token_delivery_mode": "ping",
            "backchannel_client_notification_endpoint": "https://client.example.com/ciba/notify"
        })
        .to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let registered = response_json(response).await;
    let client_id = registered["client_id"].as_str().unwrap();

    let assertion = es256_assertion(
        client_id,
        "https://localhost/bc-authorize",
        "ciba-authorize-jti",
        current_unix_secs(),
    );
    let body = serde_urlencoded::to_string([
        ("client_id", client_id),
        ("scope", "openid"),
        ("login_hint", "alice@example.com"),
        (
            "client_notification_token",
            "0123456789abcdef0123456789abcdef",
        ),
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", assertion.as_str()),
    ])
    .unwrap();
    let response = request(
        &router,
        "POST",
        "/bc-authorize",
        Some("application/x-www-form-urlencoded"),
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let auth_req_id = response_json(response).await["auth_req_id"]
        .as_str()
        .unwrap()
        .to_string();

    agent_auth_http::ciba_flow::approve_by_auth_req_id(&state, "", &auth_req_id, &user_id, true)
        .await
        .unwrap();

    let assertion = es256_assertion(
        client_id,
        "https://localhost/token",
        "ciba-token-jti",
        current_unix_secs(),
    );
    let body = serde_urlencoded::to_string([
        ("grant_type", "urn:openid:params:grant-type:ciba"),
        ("auth_req_id", auth_req_id.as_str()),
        ("client_id", client_id),
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", assertion.as_str()),
    ])
    .unwrap();
    let response = request(
        &router,
        "POST",
        "/token",
        Some("application/x-www-form-urlencoded"),
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response_json(response).await["access_token"]
        .as_str()
        .is_some_and(|token| !token.is_empty()));
}

#[tokio::test]
async fn prm_post_accepts_private_key_jwt_without_putting_the_assertion_in_the_url() {
    let state = AppState::dev(HOST);
    let router = build_router(state.clone()).0;
    let response = request(
        &router,
        "POST",
        "/register",
        Some("application/json"),
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "jwks": inline_es256_jwks()
        })
        .to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let registered = response_json(response).await;
    let client_id = registered["client_id"].as_str().unwrap();
    let mut client = state.clients.get("", client_id).await.unwrap().unwrap();
    client.introspect_enabled = true;
    client.resource_ids = vec!["https://rs.example.com".to_string()];
    state.clients.put("", client).await.unwrap();

    let assertion = es256_assertion(
        client_id,
        "https://localhost/rs/prm",
        "prm-jti",
        current_unix_secs(),
    );
    let body = serde_urlencoded::to_string([
        ("resource", "https://rs.example.com"),
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", assertion.as_str()),
    ])
    .unwrap();
    let response = request(
        &router,
        "POST",
        "/rs/prm",
        Some("application/x-www-form-urlencoded"),
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await["resource"],
        "https://rs.example.com"
    );
}

#[tokio::test]
async fn session_post_endpoints_accept_private_key_jwt_without_query_credentials() {
    let state = AppState::dev(HOST);
    let router = build_router(state.clone()).0;
    let response = request(
        &router,
        "POST",
        "/register",
        Some("application/json"),
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "jwks": inline_es256_jwks()
        })
        .to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let registered = response_json(response).await;
    let client_id = registered["client_id"].as_str().unwrap();
    let (session_id, _) = agent_auth_http::authz_session::create_session(
        &state,
        "",
        client_id,
        agent_auth_authn::authz_session::AuthzState::PendingConsent,
        current_unix_secs(),
    )
    .await
    .unwrap();

    let list_assertion = es256_assertion(
        client_id,
        "https://localhost/sessions",
        "session-list-jti",
        current_unix_secs(),
    );
    let body = serde_urlencoded::to_string([
        ("client_id", "me"),
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", list_assertion.as_str()),
    ])
    .unwrap();
    let response = request(
        &router,
        "POST",
        "/sessions",
        Some("application/x-www-form-urlencoded"),
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await["sessions"],
        serde_json::json!([session_id])
    );

    let detail_assertion = es256_assertion(
        client_id,
        "https://localhost/sessions",
        "session-detail-jti",
        current_unix_secs(),
    );
    let body = serde_urlencoded::to_string([
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", detail_assertion.as_str()),
    ])
    .unwrap();
    let response = request(
        &router,
        "POST",
        &format!("/sessions/{session_id}"),
        Some("application/x-www-form-urlencoded"),
        body,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "detail endpoint must reject an assertion bound to the list endpoint"
    );

    let detail_assertion = es256_assertion(
        client_id,
        &format!("https://localhost/sessions/{session_id}"),
        "session-detail-correct-audience-jti",
        current_unix_secs(),
    );
    let body = serde_urlencoded::to_string([
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", detail_assertion.as_str()),
    ])
    .unwrap();
    let response = request(
        &router,
        "POST",
        &format!("/sessions/{session_id}"),
        Some("application/x-www-form-urlencoded"),
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await["session_id"], session_id);
}

#[tokio::test]
async fn admin_migration_away_from_private_key_jwt_preserves_general_key_metadata() {
    let state = AppState::dev(HOST);
    let jwks: RegisteredClientJwks = serde_json::from_value(inline_es256_jwks()).unwrap();
    state
        .clients
        .put(
            "",
            ClientRecord {
                client_id: "private-admin-client".to_string(),
                redirect_uris: vec!["https://client.example.com/callback".to_string()],
                token_endpoint_auth_method: "private_key_jwt".to_string(),
                jwks: Some(jwks.clone()),
                token_endpoint_auth_signing_alg: Some("ES256".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let router = build_router(state.clone()).0;
    let response = router
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/admin/clients/private-admin-client")
                .header("host", HOST)
                .header("authorization", "Bearer dev-admin-token-not-for-prod")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "token_endpoint_auth_method": "none",
                        "confirm_downgrade": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let stored = state
        .clients
        .get("", "private-admin-client")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.token_endpoint_auth_method, "none");
    assert_eq!(stored.jwks, Some(jwks));
    assert!(stored.jwks_uri.is_none());
    assert!(stored.token_endpoint_auth_signing_alg.is_none());
}

#[tokio::test]
async fn missing_replay_store_disables_admission_and_discovery_and_fails_existing_clients_closed() {
    let mut state = AppState::dev(HOST);
    state.replay_store = None;
    state
        .clients
        .put(
            "",
            ClientRecord {
                client_id: "persisted-private-client".to_string(),
                redirect_uris: vec!["https://client.example.com/callback".to_string()],
                token_endpoint_auth_method: "private_key_jwt".to_string(),
                jwks: Some(serde_json::from_value(inline_es256_jwks()).unwrap()),
                token_endpoint_auth_signing_alg: Some("ES256".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    seed_code(
        &state,
        "persisted-private-client",
        "missing-replay-store-code",
    )
    .await;
    let router = build_router(state).0;

    let response = request(
        &router,
        "GET",
        "/.well-known/openid-configuration",
        None,
        Body::empty(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let metadata = response_json(response).await;
    assert!(!metadata["token_endpoint_auth_methods_supported"]
        .as_array()
        .unwrap()
        .iter()
        .any(|method| method == "private_key_jwt"));
    assert!(metadata
        .get("token_endpoint_auth_signing_alg_values_supported")
        .is_none());

    let response = request(
        &router,
        "POST",
        "/register",
        Some("application/json"),
        serde_json::json!({
            "redirect_uris": ["https://new.example.com/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "jwks": inline_es256_jwks()
        })
        .to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let assertion = es256_assertion(
        "persisted-private-client",
        "https://localhost/token",
        "missing-replay-store-jti",
        current_unix_secs(),
    );
    let response = request(
        &router,
        "POST",
        "/token",
        Some("application/x-www-form-urlencoded"),
        token_body("missing-replay-store-code", &assertion, None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn token_accepts_private_key_jwt_from_registered_jwks_uri() {
    const JWKS_URI: &str = "https://keys.client.example.com/oauth/jwks";

    let state = AppState::dev(HOST);
    state
        .jwks_fetcher_set(JWKS_URI, vec![es256_platform_jwk()])
        .await;
    let router = build_router(state.clone()).0;
    let response = request(
        &router,
        "POST",
        "/register",
        Some("application/json"),
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "jwks_uri": JWKS_URI
        })
        .to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let registered = response_json(response).await;
    let client_id = registered["client_id"].as_str().unwrap();
    seed_code(&state, client_id, "jwks-uri-code").await;

    let assertion = es256_assertion(
        client_id,
        "https://localhost/token",
        "jwks-uri-jti",
        current_unix_secs(),
    );
    let response = request(
        &router,
        "POST",
        "/token",
        Some("application/x-www-form-urlencoded"),
        token_body("jwks-uri-code", &assertion, None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn token_accepts_rs256_private_key_jwt() {
    let state = AppState::dev(HOST);
    let router = build_router(state.clone()).0;
    let (signer, jwks) = rs256_material().await;
    let response = request(
        &router,
        "POST",
        "/register",
        Some("application/json"),
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "RS256",
            "jwks": jwks
        })
        .to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let registered = response_json(response).await;
    let client_id = registered["client_id"].as_str().unwrap();
    seed_code(&state, client_id, "rs256-code").await;

    let assertion = rs256_assertion(
        &signer,
        client_id,
        "https://localhost/token",
        "rs256-jti",
        current_unix_secs(),
    )
    .await;
    let response = request(
        &router,
        "POST",
        "/token",
        Some("application/x-www-form-urlencoded"),
        token_body("rs256-code", &assertion, None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn inline_key_rotation_accepts_overlap_then_rejects_the_removed_key() {
    let old_key = es256_jwk([7u8; 32], "old-key");
    let new_key = es256_jwk([8u8; 32], "new-key");
    let state = AppState::dev(HOST);
    let router = build_router(state.clone()).0;
    let response = request(
        &router,
        "POST",
        "/register",
        Some("application/json"),
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "jwks": { "keys": [old_key, new_key.clone()] }
        })
        .to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let registered = response_json(response).await;
    let client_id = registered["client_id"].as_str().unwrap().to_string();
    let now = current_unix_secs();

    for (code, seed, kid, jti) in [
        ("old-overlap-code", [7u8; 32], "old-key", "old-overlap-jti"),
        ("new-overlap-code", [8u8; 32], "new-key", "new-overlap-jti"),
    ] {
        seed_code(&state, &client_id, code).await;
        let assertion = es256_assertion_with_seed(
            seed,
            &client_id,
            &client_id,
            "https://localhost/token",
            jti,
            now,
            now,
            now + 120,
            kid,
            "ES256",
        );
        let response = request(
            &router,
            "POST",
            "/token",
            Some("application/x-www-form-urlencoded"),
            token_body(code, &assertion, None),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{kid} must work in overlap"
        );
    }

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/clients/{client_id}"))
                .header("host", HOST)
                .header("authorization", "Bearer dev-admin-token-not-for-prod")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "jwks": { "keys": [new_key] } }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    seed_code(&state, &client_id, "old-removed-code").await;
    let assertion = es256_assertion_with_seed(
        [7u8; 32],
        &client_id,
        &client_id,
        "https://localhost/token",
        "old-removed-jti",
        now,
        now,
        now + 120,
        "old-key",
        "ES256",
    );
    let response = request(
        &router,
        "POST",
        "/token",
        Some("application/x-www-form-urlencoded"),
        token_body("old-removed-code", &assertion, None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
