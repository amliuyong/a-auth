use agent_auth_client::s256_challenge;
use agent_auth_http::cimd::{
    CimdHttpResponse, CimdResolver, CimdTrustPolicy, MemoryCimdHttpClient,
};
use agent_auth_http::ports::AuthzSessionStore;
use agent_auth_http::security_event::{
    SecurityEventCategory, SecurityEventOutcome, SecurityEventStore,
};
use agent_auth_http::{build_router, AppState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use std::collections::HashMap;
use std::sync::Arc;
use tower::ServiceExt;

const HOST: &str = "localhost";
const CLIENT_ID: &str = "https://client.example.com/oauth/client.json";
const REDIRECT: &str = "https://app.example.com/callback";
const QUERY_REDIRECT: &str = "https://app.example.com/callback?channel=mcp";

fn document(client_id: &str, redirect_uris: &[&str]) -> Vec<u8> {
    named_document(client_id, "Example MCP Client", redirect_uris)
}

fn named_document(client_id: &str, client_name: &str, redirect_uris: &[&str]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "client_id": client_id,
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": "none"
    }))
    .unwrap()
}

fn es256_jwk(seed: [u8; 32]) -> serde_json::Value {
    let signing_key = SigningKey::from_bytes(&seed.into()).unwrap();
    let point = signing_key.verifying_key().to_encoded_point(false);
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "kid": "cimd-key-1",
        "use": "sig",
        "alg": "ES256",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap())
    })
}

fn private_key_document(client_id: &str, seed: [u8; 32]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "client_id": client_id,
        "client_name": "Example Confidential MCP Client",
        "redirect_uris": [REDIRECT],
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_signing_alg": "ES256",
        "jwks": { "keys": [es256_jwk(seed)] }
    }))
    .unwrap()
}

fn client_assertion(seed: [u8; 32], jti: &str) -> String {
    let now = agent_auth_http::current_unix_secs();
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "JWT",
        "kid": "cimd-key-1"
    });
    let claims = serde_json::json!({
        "iss": CLIENT_ID,
        "sub": CLIENT_ID,
        "aud": "https://localhost/token",
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

fn http_response(body: Vec<u8>, cache_control: &str) -> CimdHttpResponse {
    CimdHttpResponse {
        status: 200,
        body,
        cache_control: Some(cache_control.to_string()),
        ..Default::default()
    }
}

fn resolver(client: Arc<MemoryCimdHttpClient>) -> Arc<CimdResolver> {
    Arc::new(
        CimdResolver::new(
            true,
            CimdTrustPolicy::new(vec!["client.example.com".to_string()], HashMap::new()).unwrap(),
            client,
        )
        .unwrap(),
    )
}

fn form(pairs: &[(&str, &str)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or_else(|_| serde_json::json!({}))
}

fn query_param(location: &str, key: &str) -> Option<String> {
    url::Url::parse(location)
        .ok()?
        .query_pairs()
        .find_map(|(name, value)| (name == key).then(|| value.into_owned()))
}

async fn authorize(
    router: &axum::Router,
    client_id: &str,
    redirect_uri: &str,
    verifier: &str,
    cookie: Option<&str>,
) -> axum::response::Response {
    let challenge = s256_challenge(verifier);
    let query = form(&[
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
        ("scope", "openid"),
        ("login_user", "alice"),
    ]);
    let mut request = Request::builder()
        .uri(format!("/authorize?{query}"))
        .header("host", HOST);
    if let Some(cookie) = cookie {
        request = request.header("cookie", format!("__Host-agent_auth_session={cookie}"));
    }
    router
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn authorize_without_placeholder(
    router: &axum::Router,
    client_id: &str,
    redirect_uri: &str,
    verifier: &str,
) -> axum::response::Response {
    let challenge = s256_challenge(verifier);
    let query = form(&[
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
        ("scope", "openid"),
    ]);
    router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/authorize?{query}"))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn exchange_code(
    router: &axum::Router,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> axum::response::Response {
    let body = form(&[
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("code", code),
        ("code_verifier", verifier),
    ]);
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn exchange_code_with_assertion(
    router: &axum::Router,
    code: &str,
    verifier: &str,
    assertion: &str,
) -> axum::response::Response {
    let body = form(&[
        ("grant_type", "authorization_code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT),
        ("code", code),
        ("code_verifier", verifier),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", assertion),
    ]);
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn refresh(
    router: &axum::Router,
    client_id: &str,
    refresh_token: &str,
) -> axum::response::Response {
    let body = form(&[
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("refresh_token", refresh_token),
    ]);
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn refresh_with_assertion(
    router: &axum::Router,
    refresh_token: &str,
    assertion: &str,
) -> axum::response::Response {
    let body = form(&[
        ("grant_type", "refresh_token"),
        ("client_id", CLIENT_ID),
        ("refresh_token", refresh_token),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", assertion),
    ]);
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

fn set_cookie_value(response: &axum::response::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .find_map(|value| {
            let value = value.to_str().ok()?;
            let rest = value.strip_prefix(&format!("{name}="))?;
            Some(rest.split(';').next().unwrap_or("").to_string())
        })
}

async fn login_session(router: &axum::Router, email: &str) -> String {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login/magic-link")
                .header("host", HOST)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email": email, "authorize_query": ""}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let nonce = set_cookie_value(&response, "__Host-agent_auth_login_nonce").unwrap();
    let body = body_json(response).await;
    let link = body["dev_link"].as_str().unwrap();
    let callback = link.split_once("/login/callback").unwrap().1;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/login/callback{callback}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_login_nonce={nonce}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    set_cookie_value(&response, "__Host-agent_auth_session").unwrap()
}

#[tokio::test]
async fn pre_registered_url_client_has_priority_over_cimd() {
    let client = Arc::new(MemoryCimdHttpClient::default());
    let mut state = AppState::dev(HOST);
    state.cimd = resolver(client.clone());
    state.seed_dev_client(CLIENT_ID, REDIRECT, None).await;
    let (router, _) = build_router(state.clone());

    let response = authorize(
        &router,
        CLIENT_ID,
        REDIRECT,
        "0123456789012345678901234567890123456789abc",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(client.request_count(CLIENT_ID).await, 0);
}

#[tokio::test]
async fn cimd_confidential_client_cannot_omit_pkce() {
    let client = Arc::new(MemoryCimdHttpClient::default());
    client
        .set(
            CLIENT_ID,
            http_response(private_key_document(CLIENT_ID, [7u8; 32]), "max-age=120"),
        )
        .await;
    let mut state = AppState::dev(HOST);
    state.cimd = resolver(client);
    let router = build_router(state).0;
    let query = form(&[
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT),
        ("scope", "openid"),
        ("login_user", "alice"),
    ]);
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/authorize?{query}"))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "CIMD snapshots cannot receive the current-client PKCE exemption"
    );
}

#[tokio::test]
async fn cimd_exact_loopback_redirect_is_not_treated_as_dcr_web() {
    const LOOPBACK_REDIRECT: &str = "http://127.0.0.1:43123/callback";

    let client = Arc::new(MemoryCimdHttpClient::default());
    client
        .set(
            CLIENT_ID,
            http_response(document(CLIENT_ID, &[LOOPBACK_REDIRECT]), "max-age=120"),
        )
        .await;
    let mut state = AppState::dev(HOST);
    state.cimd = resolver(client);
    let (router, _) = build_router(state);
    let verifier = "0123456789012345678901234567890123456789abc";

    let response = authorize(&router, CLIENT_ID, LOOPBACK_REDIRECT, verifier, None).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let code = query_param(location, "code").expect("authorization code");

    let response = exchange_code(&router, CLIENT_ID, LOOPBACK_REDIRECT, &code, verifier).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn cimd_redirect_query_is_preserved_when_authorization_params_are_appended() {
    let client = Arc::new(MemoryCimdHttpClient::default());
    client
        .set(
            CLIENT_ID,
            http_response(document(CLIENT_ID, &[QUERY_REDIRECT]), "max-age=120"),
        )
        .await;
    let mut state = AppState::dev(HOST);
    state.cimd = resolver(client);
    state.seed_dev_user("query-redirect@example.com").await;
    let (router, _) = build_router(state);
    let verifier = "0123456789012345678901234567890123456789abc";

    let response = authorize(&router, CLIENT_ID, QUERY_REDIRECT, verifier, None).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(query_param(location, "channel").as_deref(), Some("mcp"));
    let code = query_param(location, "code").expect("authorization code");

    let response = exchange_code(&router, CLIENT_ID, QUERY_REDIRECT, &code, verifier).await;
    assert_eq!(response.status(), StatusCode::OK);

    let session = login_session(&router, "query-redirect@example.com").await;
    let response = authorize(&router, CLIENT_ID, QUERY_REDIRECT, verifier, Some(&session)).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let consent_location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let consent_query = url::Url::parse(consent_location)
        .unwrap()
        .query()
        .unwrap()
        .to_string();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/consent/context?{consent_query}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let context = body_json(response).await;
    let csrf = context["csrf_token"].as_str().unwrap();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/consent/decision")
                .header("host", HOST)
                .header("content-type", "application/json")
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::from(
                    serde_json::json!({
                        "decision": "approve",
                        "csrf": csrf,
                        "authorize_query": consent_query
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let result = body_json(response).await;
    let redirect = result["redirect"].as_str().unwrap();
    assert_eq!(query_param(redirect, "channel").as_deref(), Some("mcp"));
    let code = query_param(redirect, "code").expect("consent authorization code");
    let response = exchange_code(&router, CLIENT_ID, QUERY_REDIRECT, &code, verifier).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn cimd_consent_continuation_issues_at_most_one_code() {
    let client = Arc::new(MemoryCimdHttpClient::default());
    client
        .set(
            CLIENT_ID,
            http_response(document(CLIENT_ID, &[REDIRECT]), "max-age=120"),
        )
        .await;
    let mut state = AppState::dev(HOST);
    state.cimd = resolver(client);
    state.seed_dev_user("cimd-replay@example.com").await;
    let (router, _) = build_router(state.clone());
    let verifier = "0123456789012345678901234567890123456789abc";
    let session = login_session(&router, "cimd-replay@example.com").await;

    let response = authorize(&router, CLIENT_ID, REDIRECT, verifier, Some(&session)).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let consent_location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let consent_query = url::Url::parse(consent_location)
        .unwrap()
        .query()
        .unwrap()
        .to_string();
    let authz_session_id =
        query_param(consent_location, "authz_session_id").expect("authorization session id");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/consent/context?{consent_query}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let context = body_json(response).await;
    let csrf = context["csrf_token"].as_str().unwrap();
    let decision = serde_json::json!({
        "decision": "approve",
        "csrf": csrf,
        "authorize_query": consent_query
    })
    .to_string();
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/consent/decision")
            .header("host", HOST)
            .header("content-type", "application/json")
            .header("cookie", format!("__Host-agent_auth_session={session}"))
            .body(Body::from(decision.clone()))
            .unwrap()
    };

    let (first, second) = tokio::join!(
        router.clone().oneshot(request()),
        router.clone().oneshot(request())
    );
    let responses = [first.unwrap(), second.unwrap()];
    assert_eq!(
        responses
            .iter()
            .filter(|response| response.status() == StatusCode::OK)
            .count(),
        1
    );
    assert_eq!(
        responses
            .iter()
            .filter(|response| response.status() == StatusCode::BAD_REQUEST)
            .count(),
        1
    );
    let mut code = None;
    for response in responses {
        if response.status() == StatusCode::OK {
            let result = body_json(response).await;
            code = query_param(result["redirect"].as_str().unwrap(), "code");
        }
    }
    let code = code.expect("exactly one authorization code");

    let replay = router.clone().oneshot(request()).await.unwrap();
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    let stale_context = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/consent/context?{consent_query}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stale_context.status(), StatusCode::BAD_REQUEST);
    let authz_session = state
        .authz_sessions
        .get("", &authz_session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(authz_session.state, "code_issued_awaiting_exchange");

    let response = exchange_code(&router, CLIENT_ID, REDIRECT, &code, verifier).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn cimd_code_token_and_refresh_use_the_authorize_snapshot() {
    let client = Arc::new(MemoryCimdHttpClient::default());
    client
        .set_sequence(
            CLIENT_ID,
            vec![
                Ok(http_response(document(CLIENT_ID, &[REDIRECT]), "no-store")),
                Ok(http_response(
                    document(CLIENT_ID, &["https://changed.example.com/callback"]),
                    "no-store",
                )),
            ],
        )
        .await;
    let mut state = AppState::dev(HOST);
    state.cimd = resolver(client.clone());
    let (router, _) = build_router(state.clone());
    let verifier = "0123456789012345678901234567890123456789abc";

    let response = authorize(&router, CLIENT_ID, REDIRECT, verifier, None).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let code = query_param(location, "code").expect("authorization code");

    let response = exchange_code(&router, CLIENT_ID, REDIRECT, &code, verifier).await;
    assert_eq!(response.status(), StatusCode::OK);
    let token = body_json(response).await;
    let refresh_token = token["refresh_token"].as_str().unwrap();

    let response = refresh(&router, CLIENT_ID, refresh_token).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        client.request_count(CLIENT_ID).await,
        1,
        "token and refresh must not re-fetch mutable CIMD metadata"
    );
}

#[tokio::test]
async fn cimd_private_key_jwt_uses_only_the_inline_snapshot_keys() {
    let client = Arc::new(MemoryCimdHttpClient::default());
    client
        .set_sequence(
            CLIENT_ID,
            vec![
                Ok(http_response(
                    private_key_document(CLIENT_ID, [7u8; 32]),
                    "no-store",
                )),
                Ok(http_response(
                    private_key_document(CLIENT_ID, [9u8; 32]),
                    "no-store",
                )),
            ],
        )
        .await;
    let mut state = AppState::dev(HOST);
    state.cimd = resolver(client.clone());
    let (router, _) = build_router(state.clone());
    let verifier = "0123456789012345678901234567890123456789abc";

    let response = authorize(&router, CLIENT_ID, REDIRECT, verifier, None).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let code = query_param(location, "code").expect("authorization code");

    let response = exchange_code_with_assertion(
        &router,
        &code,
        verifier,
        &client_assertion([9u8; 32], "cimd-code-invalid-jti"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = exchange_code_with_assertion(
        &router,
        &code,
        verifier,
        &client_assertion([7u8; 32], "cimd-code-jti"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let token = body_json(response).await;
    let refresh_token = token["refresh_token"].as_str().unwrap();

    let response = refresh_with_assertion(
        &router,
        refresh_token,
        &client_assertion([9u8; 32], "cimd-refresh-invalid-jti"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = refresh_with_assertion(
        &router,
        refresh_token,
        &client_assertion([7u8; 32], "cimd-refresh-jti"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        client.request_count(CLIENT_ID).await,
        1,
        "token and refresh must use only the authorization-time inline JWKS"
    );
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    let auth_failures = events
        .iter()
        .filter(|stored| {
            stored.event.category == SecurityEventCategory::Authentication
                && stored.event.action == "authentication.client"
                && stored.event.outcome == SecurityEventOutcome::Denied
        })
        .map(|stored| serde_json::to_value(&stored.event).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(auth_failures.len(), 2);
    assert!(auth_failures.iter().all(|event| {
        event["subject"]["id"] == "cimd-host:client.example.com"
            && event["correlation"]["client_id"] == "cimd-host:client.example.com"
            && !event.to_string().contains(CLIENT_ID)
    }));
}

#[tokio::test]
async fn cimd_par_authentication_failure_audit_redacts_the_url() {
    let client = Arc::new(MemoryCimdHttpClient::default());
    client
        .set(
            CLIENT_ID,
            http_response(document(CLIENT_ID, &[REDIRECT]), "max-age=120"),
        )
        .await;
    let mut state = AppState::dev(HOST);
    state.phase = agent_auth_http::Phase::P3;
    state.cimd = resolver(client);
    let (router, _) = build_router(state.clone());
    let challenge = s256_challenge("0123456789012345678901234567890123456789abc");
    let body = form(&[
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
        ("scope", "openid"),
        ("client_secret", "must-not-be-accepted"),
    ]);
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/par")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    let failure = events
        .iter()
        .find(|stored| stored.event.action == "authentication.client")
        .map(|stored| serde_json::to_value(&stored.event).unwrap())
        .expect("PAR client authentication failure event");
    assert_eq!(failure["subject"]["id"], "cimd-host:client.example.com");
    assert_eq!(
        failure["correlation"]["client_id"],
        "cimd-host:client.example.com"
    );
    assert!(!failure.to_string().contains(CLIENT_ID));
}

#[tokio::test]
async fn exact_client_id_and_redirect_mismatches_are_rejected() {
    let mismatch_client = Arc::new(MemoryCimdHttpClient::default());
    mismatch_client
        .set(
            CLIENT_ID,
            http_response(
                document("https://client.example.com/oauth/other.json", &[REDIRECT]),
                "no-store",
            ),
        )
        .await;
    let mut state = AppState::dev(HOST);
    state.cimd = resolver(mismatch_client);
    let (router, _) = build_router(state);
    let response = authorize(
        &router,
        CLIENT_ID,
        REDIRECT,
        "0123456789012345678901234567890123456789abc",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let redirect_client = Arc::new(MemoryCimdHttpClient::default());
    redirect_client
        .set(
            CLIENT_ID,
            http_response(
                document(CLIENT_ID, &["https://other.example.com/callback"]),
                "no-store",
            ),
        )
        .await;
    let mut state = AppState::dev(HOST);
    state.cimd = resolver(redirect_client);
    let (router, _) = build_router(state);
    let response = authorize(
        &router,
        CLIENT_ID,
        REDIRECT,
        "0123456789012345678901234567890123456789abc",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn consent_rejects_cimd_mutation_during_authorization() {
    let client = Arc::new(MemoryCimdHttpClient::default());
    client
        .set_sequence(
            CLIENT_ID,
            vec![
                Ok(http_response(document(CLIENT_ID, &[REDIRECT]), "no-store")),
                Ok(http_response(
                    document(CLIENT_ID, &["https://changed.example.com/callback"]),
                    "no-store",
                )),
            ],
        )
        .await;
    let mut state = AppState::dev(HOST);
    state.cimd = resolver(client.clone());
    state.seed_dev_user("cimd-user@example.com").await;
    let (router, _) = build_router(state.clone());
    let session = login_session(&router, "cimd-user@example.com").await;

    let response = authorize(
        &router,
        CLIENT_ID,
        REDIRECT,
        "0123456789012345678901234567890123456789abc",
        Some(&session),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let authz_session_id =
        query_param(location, "authz_session_id").expect("authorization session id");
    let authz_session = state
        .authz_sessions
        .get("", &authz_session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        authz_session.client_id, "cimd-host:client.example.com",
        "authorization-session observability must not persist the CIMD URL path"
    );
    let query = url::Url::parse(location)
        .unwrap()
        .query()
        .unwrap()
        .to_string();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/consent/context?{query}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(client.request_count(CLIENT_ID).await, 2);
}

#[tokio::test]
async fn authorize_rejects_cimd_mutation_while_the_user_logs_in() {
    let client = Arc::new(MemoryCimdHttpClient::default());
    client
        .set_sequence(
            CLIENT_ID,
            vec![
                Ok(http_response(
                    named_document(CLIENT_ID, "Original Client", &[REDIRECT]),
                    "no-store",
                )),
                Ok(http_response(
                    named_document(CLIENT_ID, "Changed Client", &[REDIRECT]),
                    "no-store",
                )),
            ],
        )
        .await;
    let mut state = AppState::dev(HOST);
    state.cimd = resolver(client.clone());
    state.seed_dev_user("cimd-login@example.com").await;
    let (router, _) = build_router(state);

    let response = authorize_without_placeholder(
        &router,
        CLIENT_ID,
        REDIRECT,
        "0123456789012345678901234567890123456789abc",
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let login_location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(
        url::Url::parse(login_location).unwrap().path(),
        "/login",
        "an unauthenticated CIMD flow must first bind its login continuation"
    );
    let continuation = url::Url::parse(login_location)
        .unwrap()
        .query()
        .unwrap()
        .to_string();
    let session = login_session(&router, "cimd-login@example.com").await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/authorize?{continuation}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(client.request_count(CLIENT_ID).await, 2);
}

#[tokio::test]
async fn authorize_reuses_a_valid_cimd_login_continuation() {
    let client = Arc::new(MemoryCimdHttpClient::default());
    client
        .set(
            CLIENT_ID,
            http_response(document(CLIENT_ID, &[REDIRECT]), "no-store"),
        )
        .await;
    let mut state = AppState::dev(HOST);
    state.cimd = resolver(client.clone());
    state.seed_dev_user("cimd-login-stable@example.com").await;
    let (router, _) = build_router(state.clone());

    let response = authorize_without_placeholder(
        &router,
        CLIENT_ID,
        REDIRECT,
        "0123456789012345678901234567890123456789abc",
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let login_location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let original_session_id =
        query_param(login_location, "authz_session_id").expect("authorization session id");
    let continuation = url::Url::parse(login_location)
        .unwrap()
        .query()
        .unwrap()
        .to_string();
    let session = login_session(&router, "cimd-login-stable@example.com").await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/authorize?{continuation}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let consent_location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(
        url::Url::parse(consent_location).unwrap().path(),
        "/consent"
    );
    assert_eq!(
        query_param(consent_location, "authz_session_id").as_deref(),
        Some(original_session_id.as_str())
    );
    let authz_session = state
        .authz_sessions
        .get("", &original_session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(authz_session.state, "pending_consent");
    assert_eq!(client.request_count(CLIENT_ID).await, 2);
}

#[tokio::test]
async fn discovery_advertises_cimd_only_when_tenant_policy_is_active() {
    let disabled = build_router(AppState::dev(HOST)).0;
    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        let response = disabled
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
        assert_eq!(response.status(), StatusCode::OK, "{path} must be served");
        let metadata = body_json(response).await;
        assert!(metadata
            .get("client_id_metadata_document_supported")
            .is_none());
    }

    let client = Arc::new(MemoryCimdHttpClient::default());
    let mut state = AppState::dev(HOST);
    state.cimd = resolver(client.clone());
    state.phase = agent_auth_http::Phase::P0;
    let p0 = build_router(state.clone()).0;
    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        let response = p0
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
        assert_eq!(response.status(), StatusCode::OK, "{path} must be served");
        let metadata = body_json(response).await;
        assert!(metadata
            .get("client_id_metadata_document_supported")
            .is_none());
    }
    let response = authorize(
        &p0,
        CLIENT_ID,
        REDIRECT,
        "0123456789012345678901234567890123456789abc",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        client.request_count(CLIENT_ID).await,
        0,
        "P0 must not execute the P1 CIMD resolver"
    );

    state.phase = agent_auth_http::Phase::P1;
    let enabled = build_router(state).0;
    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        let response = enabled
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
        assert_eq!(response.status(), StatusCode::OK, "{path} must be served");
        let metadata = body_json(response).await;
        assert_eq!(
            metadata["client_id_metadata_document_supported"],
            serde_json::Value::Bool(true)
        );
    }

    let mut tenant_domains = HashMap::new();
    tenant_domains.insert("t1".to_string(), vec!["client.example.com".to_string()]);
    let mut tenant_state = AppState::dev("t1.aws.example.com");
    tenant_state.form = agent_auth_discovery::Form::Saas {
        zone: "aws.example.com".to_string(),
        control_host: "c.aws.example.com".to_string(),
    };
    tenant_state.tenant_partitioning = true;
    tenant_state.saas_tenants = Arc::new(vec!["t1".to_string(), "t2".to_string()]);
    tenant_state.phase = agent_auth_http::Phase::P1;
    tenant_state.cimd = Arc::new(
        CimdResolver::new(
            true,
            CimdTrustPolicy::new(Vec::new(), tenant_domains).unwrap(),
            client,
        )
        .unwrap(),
    );
    let tenant_router = build_router(tenant_state).0;
    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        for (host, expected) in [
            ("t1.aws.example.com", Some(serde_json::Value::Bool(true))),
            ("t2.aws.example.com", None),
        ] {
            let response = tenant_router
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
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "{path} must be served for {host}"
            );
            let metadata = body_json(response).await;
            assert_eq!(
                metadata
                    .get("client_id_metadata_document_supported")
                    .cloned(),
                expected,
                "{path} CIMD advertisement must be isolated by tenant policy for {host}"
            );
        }
    }
}
