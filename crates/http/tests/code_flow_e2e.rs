//! 进程内 code flow 端到端集成测试(无 AWS,内存适配器)。
//!
//! 走完整 P0 链:seed client → `GET /authorize`(PKCE)拿 code → `POST /token` 换 JWT
//! → 用 `/jwks.json` 公钥**独立验签**该 JWT(p256 verifier)。验证 000/002/006/001/005[a]
//! 的纯逻辑经 HTTP handler 编排后端到端成立。真机版(KMS/DynamoDB)见 e2e 脚本。

use agent_auth_client::s256_challenge;
use agent_auth_http::{
    build_router,
    ports::{CodeRecord, CodeStore, GraceStore},
    security_event::{SecurityEventOutcome, SecurityEventStore},
    state::ClientStoreImpl,
    AppState,
};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use tower::ServiceExt; // oneshot
use url::Url;

const HOST: &str = "localhost";
const CLIENT: &str = "test-client";
const REDIRECT: &str = "https://app.example.com/cb";
const CONFIDENTIAL_SECRET: &str = "test-confidential-secret";

async fn app() -> axum::Router {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let (router, _) = build_router(state);
    router
}

async fn confidential_state() -> AppState {
    use agent_auth_http::ports::{ClientRecord, ClientStore};

    let state = AppState::dev(HOST);
    ClientStore::put(
        state.clients.as_ref(),
        "",
        ClientRecord {
            client_id: CLIENT.into(),
            redirect_uris: vec![REDIRECT.into()],
            token_endpoint_auth_method: "client_secret_basic".into(),
            client_secret: Some(CONFIDENTIAL_SECRET.into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    state
}

async fn confidential_app() -> axum::Router {
    let state = confidential_state().await;
    let (router, _) = build_router(state);
    router
}

// 从 302 Location 里取 query 参数。
fn query_param(location: &str, key: &str) -> Option<String> {
    let q = location.split('?').nth(1)?;
    q.split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")).map(|v| v.to_string()))
}

// GET authorize,返回 302 的 Location。
async fn get_redirect(router: &axum::Router, uri: &str) -> String {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    resp.headers()
        .get("location")
        .expect("authorize 应回跳")
        .to_str()
        .unwrap()
        .to_string()
}

async fn confidential_code(router: &axum::Router) -> (String, &'static str) {
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
    );
    let location = get_redirect(router, &authz).await;
    (query_param(&location, "code").unwrap(), verifier)
}

async fn confidential_code_without_pkce(router: &axum::Router) -> String {
    let authorization = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &scope=openid&login_user=alice"
    );
    let location = get_redirect(router, &authorization).await;
    query_param(&location, "code").unwrap()
}

#[tokio::test]
async fn authorize_allows_confidential_client_without_pkce() {
    let router = confidential_app().await;
    assert!(!confidential_code_without_pkce(&router).await.is_empty());
}

#[tokio::test]
async fn authorize_accepts_form_post() {
    let router = confidential_app().await;
    let form = format!(
        "response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &scope=openid&login_user=alice"
    );
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/authorize")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();

    if !response.status().is_redirection() {
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        panic!(
            "POST /authorize returned {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }
    let location = response.headers()["location"].to_str().unwrap();
    assert!(query_param(location, "code").is_some(), "{location}");
}

#[tokio::test]
async fn authorize_missing_response_type_redirects_protocol_error() {
    let router = confidential_app().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/authorize?client_id={CLIENT}&redirect_uri={REDIRECT}&scope=openid&state=s"
                ))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(response.status().is_redirection());
    let location = response.headers()["location"].to_str().unwrap();
    assert_eq!(
        query_param(location, "error").as_deref(),
        Some("invalid_request")
    );
    assert_eq!(query_param(location, "state").as_deref(), Some("s"));
}

#[tokio::test]
async fn authorize_echoes_state_byte_for_byte_with_reserved_and_unicode_characters() {
    let router = app().await;
    let state = "opaque /?&=%+雪";
    let encoded_state: String = url::form_urlencoded::byte_serialize(state.as_bytes()).collect();
    let challenge = s256_challenge("0123456789012345678901234567890123456789abc");
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
                     &scope=openid&state={encoded_state}&login_user=alice\
                     &code_challenge={challenge}&code_challenge_method=S256"
                ))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()["location"].to_str().unwrap();
    let redirected = Url::parse(location).unwrap();
    let echoed = redirected
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()));
    assert_eq!(echoed.as_deref(), Some(state));
}

#[tokio::test]
async fn authorize_without_state_omits_state_from_redirect() {
    let router = app().await;
    let challenge = s256_challenge("0123456789012345678901234567890123456789abc");
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
                     &scope=openid&login_user=alice\
                     &code_challenge={challenge}&code_challenge_method=S256"
                ))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()["location"].to_str().unwrap();
    let redirected = Url::parse(location).unwrap();
    assert!(
        redirected.query_pairs().all(|(key, _)| key != "state"),
        "state must be absent when the request omits it"
    );
}

#[tokio::test]
async fn authorize_protocol_errors_never_redirect_to_unregistered_uri() {
    let router = confidential_app().await;
    for query in [
        format!("client_id={CLIENT}&redirect_uri=https://attacker.example/cb&scope=openid&state=s"),
        format!(
            "response_type=code&client_id={CLIENT}\
             &redirect_uri=https://attacker.example/cb&request=eyJhbGciOiJub25lIn0.e30."
        ),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/authorize?{query}"))
                    .header("host", HOST)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get("location").is_none());
    }
}

#[tokio::test]
async fn authorize_rejects_unsupported_request_object() {
    let router = confidential_app().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
                     &scope=openid&state=s&login_user=alice&request=eyJhbGciOiJub25lIn0.e30."
                ))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(response.status().is_redirection());
    let location = response.headers()["location"].to_str().unwrap();
    assert_eq!(
        query_param(location, "error").as_deref(),
        Some("request_not_supported")
    );
    assert_eq!(query_param(location, "state").as_deref(), Some("s"));
}

#[tokio::test]
async fn authorize_rejects_unsupported_request_uri() {
    let router = confidential_app().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
                     &scope=openid&state=s&login_user=alice\
                     &request_uri=https%3A%2F%2Fclient.example.com%2Frequest.jwt"
                ))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(response.status().is_redirection());
    let location = response.headers()["location"].to_str().unwrap();
    assert_eq!(
        query_param(location, "error").as_deref(),
        Some("request_uri_not_supported")
    );
    assert_eq!(query_param(location, "state").as_deref(), Some("s"));
}

#[tokio::test]
async fn authorize_confidential_pkce_exemption_requires_both_parameters_absent() {
    let router = confidential_app().await;
    for malformed in [
        "code_challenge_method=S256",
        "code_challenge=&code_challenge_method=S256",
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
                         &scope=openid&login_user=alice&{malformed}"
                    ))
                    .header("host", HOST)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "malformed PKCE tuple must not receive the confidential exemption: {malformed}"
        );
    }
}

#[tokio::test]
async fn authorize_rejects_pkce_less_private_key_jwt_when_runtime_capability_is_off() {
    use agent_auth_http::ports::{ClientRecord, ClientStore};

    let mut state = AppState::dev(HOST);
    state.replay_store = None;
    state
        .clients
        .put(
            "",
            ClientRecord {
                client_id: "inactive-private-key-client".into(),
                redirect_uris: vec![REDIRECT.into()],
                token_endpoint_auth_method: "private_key_jwt".into(),
                client_type: Some("confidential".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let router = build_router(state).0;
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/authorize?response_type=code&client_id=inactive-private-key-client\
                     &redirect_uri={REDIRECT}&scope=openid&login_user=alice"
                ))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "a runtime-disabled auth method must not qualify for no-PKCE authorization"
    );
}

async fn confidential_exchange_without_pkce(
    router: &axum::Router,
    code: &str,
    secret: &str,
) -> axum::response::Response {
    let credentials = STANDARD.encode(format!("{CLIENT}:{secret}"));
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .header("authorization", format!("Basic {credentials}"))
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT}"
                )))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn token_allows_authenticated_confidential_code_without_pkce() {
    let router = confidential_app().await;
    let code = confidential_code_without_pkce(&router).await;
    let response = confidential_exchange_without_pkce(&router, &code, CONFIDENTIAL_SECRET).await;

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn token_requires_authentication_for_pkce_less_code_without_consuming_it() {
    let router = confidential_app().await;
    let code = confidential_code_without_pkce(&router).await;

    let rejected = confidential_exchange_without_pkce(&router, &code, "wrong-secret").await;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        rejected
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok()),
        Some("Basic realm=\"token\"")
    );

    let retry = confidential_exchange_without_pkce(&router, &code, CONFIDENTIAL_SECRET).await;
    assert_eq!(
        retry.status(),
        StatusCode::OK,
        "failed authentication must not consume a PKCE-less confidential code"
    );
}

#[tokio::test]
async fn token_success_response_disables_caching() {
    let router = confidential_app().await;
    let code = confidential_code_without_pkce(&router).await;
    let response = confidential_exchange_without_pkce(&router, &code, CONFIDENTIAL_SECRET).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
}

#[tokio::test]
async fn expired_authorization_code_is_rejected_without_ttl_gc() {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let verifier = "expired-code-verifier-012345678901234567890123";
    let code = "expired-authorization-code";
    CodeStore::put(
        state.codes.as_ref(),
        "",
        CodeRecord {
            code: code.into(),
            client_id: CLIENT.into(),
            cimd_snapshot: None,
            redirect_uri: REDIRECT.into(),
            code_challenge: s256_challenge(verifier),
            resources: Vec::new(),
            user_id: "alice".into(),
            scope: vec!["openid".into()],
            expires_at: 1,
            authz_session_id: None,
            nonce: None,
            auth_time: 1,
            authorization_details: Vec::new(),
            acr: None,
            amr: Vec::new(),
            credential_epoch: Some(0),
            password_credential_version: None,
        },
    )
    .await
    .unwrap();
    let router = build_router(state).0;

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&code_verifier={verifier}\
                     &redirect_uri={REDIRECT}&client_id={CLIENT}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn confidential_code_replay_requires_valid_client_secret_before_revocation() {
    let router = confidential_app().await;
    let code = confidential_code_without_pkce(&router).await;
    let first = confidential_exchange_without_pkce(&router, &code, CONFIDENTIAL_SECRET).await;
    assert_eq!(first.status(), StatusCode::OK);
    let body = axum::body::to_bytes(first.into_body(), usize::MAX)
        .await
        .unwrap();
    let token_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let access_token = token_response["access_token"].as_str().unwrap();

    let invalid_secret = confidential_exchange_without_pkce(&router, &code, "wrong-secret").await;
    assert_eq!(invalid_secret.status(), StatusCode::UNAUTHORIZED);
    let before_authenticated_replay = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header("host", HOST)
                .header("authorization", format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        before_authenticated_replay.status(),
        StatusCode::OK,
        "an invalid client secret must not revoke the original token"
    );

    let authenticated_replay =
        confidential_exchange_without_pkce(&router, &code, CONFIDENTIAL_SECRET).await;
    assert_eq!(authenticated_replay.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(authenticated_replay.into_body(), usize::MAX)
        .await
        .unwrap();
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["error"], "invalid_grant");

    let after_authenticated_replay = router
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header("host", HOST)
                .header("authorization", format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        after_authenticated_replay.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn client_secret_post_completes_code_flow_without_pkce() {
    use agent_auth_http::ports::{ClientRecord, ClientStore};

    let state = AppState::dev(HOST);
    state
        .clients
        .put(
            "",
            ClientRecord {
                client_id: "post-client".into(),
                redirect_uris: vec![REDIRECT.into()],
                token_endpoint_auth_method: "client_secret_post".into(),
                client_secret: Some(CONFIDENTIAL_SECRET.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let router = build_router(state).0;
    let location = get_redirect(
        &router,
        &format!(
            "/authorize?response_type=code&client_id=post-client&redirect_uri={REDIRECT}\
             &scope=openid&login_user=alice"
        ),
    )
    .await;
    let code = query_param(&location, "code").unwrap();
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT}\
                     &client_id=post-client&client_secret={CONFIDENTIAL_SECRET}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn token_rejects_pkce_less_code_after_client_downgrade_without_consuming_it() {
    use agent_auth_http::ports::{ClientRecord, ClientStore};

    let state = confidential_state().await;
    let router = build_router(state.clone()).0;
    let code = confidential_code_without_pkce(&router).await;
    state
        .clients
        .put(
            "",
            ClientRecord {
                client_id: CLIENT.into(),
                redirect_uris: vec![REDIRECT.into()],
                token_endpoint_auth_method: "none".into(),
                client_type: Some("public".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let downgraded = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT}\
                     &client_id={CLIENT}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(downgraded.status(), StatusCode::BAD_REQUEST);

    state
        .clients
        .put(
            "",
            ClientRecord {
                client_id: CLIENT.into(),
                redirect_uris: vec![REDIRECT.into()],
                token_endpoint_auth_method: "client_secret_basic".into(),
                client_secret: Some(CONFIDENTIAL_SECRET.into()),
                client_type: Some("confidential".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let recovered = confidential_exchange_without_pkce(&router, &code, CONFIDENTIAL_SECRET).await;
    assert_eq!(
        recovered.status(),
        StatusCode::OK,
        "a pre-auth downgrade rejection must release the code lease"
    );
}

#[tokio::test]
async fn token_rejects_pkce_code_after_client_becomes_workload_without_consuming_it() {
    use agent_auth_http::ports::{ClientRecord, ClientStore};

    let state = confidential_state().await;
    let router = build_router(state.clone()).0;
    let (code, verifier) = confidential_code(&router).await;
    state
        .clients
        .put(
            "",
            ClientRecord {
                client_id: CLIENT.into(),
                redirect_uris: vec![REDIRECT.into()],
                token_endpoint_auth_method: "client_secret_basic".into(),
                client_secret: Some(CONFIDENTIAL_SECRET.into()),
                client_type: Some("workload".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let workload = confidential_exchange(&router, &code, verifier, CLIENT, None).await;
    assert_eq!(workload.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        workload
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok()),
        Some("Basic realm=\"token\"")
    );

    state
        .clients
        .put(
            "",
            ClientRecord {
                client_id: CLIENT.into(),
                redirect_uris: vec![REDIRECT.into()],
                token_endpoint_auth_method: "client_secret_basic".into(),
                client_secret: Some(CONFIDENTIAL_SECRET.into()),
                client_type: Some("confidential".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let recovered = confidential_exchange(&router, &code, verifier, CLIENT, None).await;
    assert_eq!(
        recovered.status(),
        StatusCode::OK,
        "a pre-auth workload rejection must release the code lease"
    );
}

async fn confidential_exchange(
    router: &axum::Router,
    code: &str,
    verifier: &str,
    basic_client_id: &str,
    form_client_id: Option<&str>,
) -> axum::response::Response {
    confidential_exchange_with_secret(
        router,
        code,
        verifier,
        basic_client_id,
        CONFIDENTIAL_SECRET,
        form_client_id,
    )
    .await
}

async fn confidential_exchange_with_secret(
    router: &axum::Router,
    code: &str,
    verifier: &str,
    basic_client_id: &str,
    secret: &str,
    form_client_id: Option<&str>,
) -> axum::response::Response {
    let mut form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}"
    );
    if let Some(client_id) = form_client_id {
        form.push_str("&client_id=");
        form.push_str(client_id);
    }
    let credentials = STANDARD.encode(format!("{basic_client_id}:{secret}"));
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .header("authorization", format!("Basic {credentials}"))
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn token_rejects_any_verifier_when_authorization_omitted_pkce() {
    for verifier in ["", "0123456789012345678901234567890123456789abc"] {
        let router = confidential_app().await;
        let code = confidential_code_without_pkce(&router).await;
        let response = confidential_exchange(&router, &code, verifier, CLIENT, None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            error["error"], "invalid_request",
            "a supplied verifier without an authorization challenge is malformed"
        );
    }
}

#[tokio::test]
async fn confidential_client_that_sent_challenge_must_supply_matching_verifier() {
    let router = confidential_app().await;
    let (missing_code, _) = confidential_code(&router).await;
    let missing =
        confidential_exchange_without_pkce(&router, &missing_code, CONFIDENTIAL_SECRET).await;
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    let missing_body = axum::body::to_bytes(missing.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&missing_body).unwrap()["error"],
        "invalid_request"
    );

    let (wrong_code, _) = confidential_code(&router).await;
    let wrong = confidential_exchange(
        &router,
        &wrong_code,
        "wrong-verifier-0987654321-zyxwvutsrqponmlkj",
        CLIENT,
        None,
    )
    .await;
    assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
    let wrong_body = axum::body::to_bytes(wrong.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&wrong_body).unwrap()["error"],
        "invalid_grant"
    );
}

async fn confidential_refresh_token(router: &axum::Router) -> String {
    let (code, verifier) = confidential_code(router).await;
    let response = confidential_exchange(router, &code, verifier, CLIENT, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice::<serde_json::Value>(&body).unwrap()["refresh_token"]
        .as_str()
        .expect("confidential code flow should issue refresh token")
        .to_string()
}

async fn confidential_refresh_exchange(
    router: &axum::Router,
    refresh_token: &str,
    basic_client_id: &str,
    form_client_id: Option<&str>,
) -> axum::response::Response {
    let mut form = format!("grant_type=refresh_token&refresh_token={refresh_token}");
    if let Some(client_id) = form_client_id {
        form.push_str("&client_id=");
        form.push_str(client_id);
    }
    let credentials = STANDARD.encode(format!("{basic_client_id}:{CONFIDENTIAL_SECRET}"));
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .header("authorization", format!("Basic {credentials}"))
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn exchange_response(
    router: &axum::Router,
    code: &str,
    verifier: &str,
) -> axum::response::Response {
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap()
}

// POST token 兑换,返回 access_token。
async fn exchange_token(router: &axum::Router, code: &str, verifier: &str) -> String {
    let resp = exchange_response(router, code, verifier).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let tok: serde_json::Value = serde_json::from_slice(&body).unwrap();
    tok["access_token"].as_str().unwrap().to_string()
}

async fn exhaust_client_rate_limit(state: &AppState, client_id: &str) {
    use agent_auth_http::ports::RateLimitStore;

    let rate_limit = state.rate_limit.as_ref().expect("dev rate-limit store");
    rate_limit.delete(client_id).await.unwrap();
    assert!(
        rate_limit
            .try_consume(client_id, i64::MAX / 4, 1.0, 0.0, 1.0)
            .await
            .unwrap()
            .allowed,
        "test setup must consume the only token in a future-dated bucket"
    );
    assert!(
        agent_auth_http::ratelimit_gate::check(state, "", client_id)
            .await
            .is_some(),
        "the production client gate must observe the exhausted bucket"
    );
}

async fn assert_client_rate_limited(response: axum::response::Response) {
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|value| value > 0),
        "per-client throttling must advertise a positive Retry-After"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "temporarily_unavailable");
}

#[tokio::test]
async fn token_form_rejection_is_oauth_json_and_disables_caching() {
    let router = app().await;
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("client_id=test-client"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["error"], "invalid_request");
}

#[tokio::test]
async fn code_flow_uses_grant_authority_when_refresh_persistence_fails() {
    use agent_auth_http::state::RefreshStoreImpl;

    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let router = build_router(state.clone()).0;
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let location = get_redirect(
        &router,
        &format!(
            "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
             &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
        ),
    )
    .await;
    let code = query_param(&location, "code").unwrap();
    match state.refresh.as_ref() {
        RefreshStoreImpl::Memory(store) => store.fail_next_create(),
        #[cfg(feature = "aws")]
        RefreshStoreImpl::Dynamo(_) => panic!("test requires memory refresh store"),
    }

    let response = exchange_response(&router, &code, verifier).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let token_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(token_response["refresh_token"].is_null());
    let access_token = token_response["access_token"].as_str().unwrap();

    let replay = exchange_response(&router, &code, verifier).await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    let userinfo = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header("host", HOST)
                .header("authorization", format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        userinfo.status(),
        StatusCode::UNAUTHORIZED,
        "Grant-only fallback must remain revocable on code replay"
    );
}

#[tokio::test]
async fn code_flow_suppresses_tokens_when_all_authority_persistence_fails() {
    use agent_auth_http::state::{GrantStoreImpl, RefreshStoreImpl};

    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let router = build_router(state.clone()).0;
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let location = get_redirect(
        &router,
        &format!(
            "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
             &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
        ),
    )
    .await;
    let code = query_param(&location, "code").unwrap();
    match state.refresh.as_ref() {
        RefreshStoreImpl::Memory(store) => store.fail_next_create(),
        #[cfg(feature = "aws")]
        RefreshStoreImpl::Dynamo(_) => panic!("test requires memory refresh store"),
    }
    match state.grants.as_ref() {
        GrantStoreImpl::Memory(store) => store.fail_next_put(),
        #[cfg(feature = "aws")]
        GrantStoreImpl::Dynamo(_) => panic!("test requires memory Grant store"),
    }

    let response = exchange_response(&router, &code, verifier).await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["error"], "server_error");
    assert!(error.get("access_token").is_none());
}

#[tokio::test]
async fn full_code_flow_issues_verifiable_es256_jwt() {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let (router, _) = build_router(state.clone());

    // PKCE:verifier → S256 challenge。
    let verifier = "0123456789012345678901234567890123456789abc"; // 43 字符,合法
    let challenge = s256_challenge(verifier);

    // 1. GET /authorize(带 login_user 占位,P0 未接真实登录)。
    let authz_uri = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&state=xyz&login_user=alice"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&authz_uri)
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "authorize 应 302 回跳"
    );
    let location = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(location.starts_with(REDIRECT));
    assert_eq!(
        query_param(&location, "state").as_deref(),
        Some("xyz"),
        "state 逐字节 echo"
    );
    // RFC 9207(C1.4 mix-up 防护):授权响应 MUST 回带 iss = 按请求 Host 派生的 issuer(percent-encoded)。
    let iss_raw = query_param(&location, "iss").expect("authorize 回跳 MUST 带 iss(RFC 9207,C1.4)");
    // pct_encode(https://localhost) → https%3A%2F%2Flocalhost;解码 %3A/%2F 后比对。
    let iss_decoded = iss_raw.replace("%3A", ":").replace("%2F", "/");
    assert_eq!(
        iss_decoded,
        format!("https://{HOST}"),
        "iss 应 = 按 Host 派生的 issuer(RFC 9207 mix-up 防护)"
    );
    let code = query_param(&location, "code").expect("回跳应带 code");

    // 2. POST /token(code + verifier)。
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "token 兑换应 200");
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let tok: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let jwt = tok["access_token"].as_str().expect("含 access_token");
    assert_eq!(tok["token_type"], "Bearer");

    // 3. 拉 /jwks.json 公钥。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/jwks.json")
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Cache-Control max-age(C10.16)。
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap(),
        "max-age=300"
    );
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let jwks: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let jwk = &jwks["keys"][0];

    // 4. 用 JWKS 公钥独立验签 JWT(p256 verifier)。
    verify_jwt_with_jwk(jwt, jwk);

    // 5. 校验 claim:aud 单元素、alg=ES256、iss 正确。
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    assert_eq!(header["alg"], "ES256", "access token 恒 ES256(C10.15a)");
    assert_eq!(header["typ"], "at+jwt");
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(claims["iss"], format!("https://{HOST}"));
    // 无 resource + 无 default_resource → aud = <issuer>/userinfo(C2.8)。
    assert_eq!(
        claims["aud"],
        serde_json::json!([format!("https://{HOST}/userinfo")])
    );
    assert_eq!(claims["client_id"], CLIENT);
    assert_eq!(
        claims["https://a-auth.com/c"]["sub_type"], "user",
        "authorization_code access token must classify its subject as user"
    );
    assert!(state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 500)
        .await
        .unwrap()
        .iter()
        .any(|stored| {
            stored.event.action == "grant.create"
                && stored.event.outcome == SecurityEventOutcome::Success
        }));
}

#[tokio::test]
async fn confidential_code_flow_accepts_client_id_from_basic_auth() {
    let router = confidential_app().await;
    let (code, verifier) = confidential_code(&router).await;

    let response = confidential_exchange(&router, &code, verifier, CLIENT, None).await;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "client_secret_basic token request may omit form client_id"
    );
}

#[tokio::test]
async fn previous_activation_code_and_refresh_fail_with_region_ownership() {
    use agent_auth_http::region::{
        MemoryRegionControlStore, RegionAdmission, RegionControlRecord, RegionControlStoreImpl,
        RegionRuntime,
    };

    let control = MemoryRegionControlStore::with_record(RegionControlRecord {
        active: true,
        activation_not_before: 0,
        revision: 1,
    });
    let region =
        RegionRuntime::controlled("us-east-1", RegionControlStoreImpl::Memory(control.clone()))
            .unwrap();
    assert_eq!(
        region
            .admit(agent_auth_http::current_unix_secs())
            .await
            .unwrap(),
        RegionAdmission::Active
    );

    let mut state = confidential_state().await;
    state.region = region;
    let (router, _) = build_router(state);
    let (code, verifier) = confidential_code(&router).await;
    let refresh_token = confidential_refresh_token(&router).await;

    let quiescence_not_before = agent_auth_http::current_unix_secs() + 330;
    control
        .set(Some(RegionControlRecord {
            active: true,
            activation_not_before: quiescence_not_before,
            revision: 2,
        }))
        .await;

    let quiescing_code_response =
        confidential_exchange(&router, &code, verifier, CLIENT, None).await;
    assert_eq!(
        quiescing_code_response.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let retry_after = quiescing_code_response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .expect("quiescing Region must advertise Retry-After");
    assert!((1..=300).contains(&retry_after));
    let quiescing_code_body = axum::body::to_bytes(quiescing_code_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let quiescing_code_error: serde_json::Value =
        serde_json::from_slice(&quiescing_code_body).unwrap();
    assert_eq!(quiescing_code_error["error"], "region_inactive");
    assert!(quiescing_code_error.get("access_token").is_none());

    let quiescing_refresh_response =
        confidential_refresh_exchange(&router, &refresh_token, CLIENT, None).await;
    assert_eq!(
        quiescing_refresh_response.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let quiescing_refresh_body =
        axum::body::to_bytes(quiescing_refresh_response.into_body(), usize::MAX)
            .await
            .unwrap();
    let quiescing_refresh_error: serde_json::Value =
        serde_json::from_slice(&quiescing_refresh_body).unwrap();
    assert_eq!(quiescing_refresh_error["error"], "region_inactive");
    assert!(quiescing_refresh_error.get("access_token").is_none());

    control
        .set(Some(RegionControlRecord {
            active: true,
            activation_not_before: 0,
            revision: 3,
        }))
        .await;

    let code_response = confidential_exchange(&router, &code, verifier, CLIENT, None).await;
    assert_eq!(code_response.status(), StatusCode::BAD_REQUEST);
    let code_body = axum::body::to_bytes(code_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let code_error: serde_json::Value = serde_json::from_slice(&code_body).unwrap();
    assert_eq!(
        code_error["error_description"],
        "authorization code belongs to another Region"
    );

    let refresh_response =
        confidential_refresh_exchange(&router, &refresh_token, CLIENT, None).await;
    assert_eq!(refresh_response.status(), StatusCode::BAD_REQUEST);
    let refresh_body = axum::body::to_bytes(refresh_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let refresh_error: serde_json::Value = serde_json::from_slice(&refresh_body).unwrap();
    assert_eq!(
        refresh_error["error_description"],
        "refresh_token belongs to another Region"
    );

    let (current_code, current_verifier) = confidential_code(&router).await;
    let current_response =
        confidential_exchange(&router, &current_code, current_verifier, CLIENT, None).await;
    assert_eq!(
        current_response.status(),
        StatusCode::OK,
        "the client must complete a new authorization under the current activation"
    );
}

#[tokio::test]
async fn token_rejects_mismatched_basic_and_form_client_ids_without_consuming_code() {
    use agent_auth_http::ports::RateLimitStore;

    let state = confidential_state().await;
    let router = build_router(state.clone()).0;
    let (code, verifier) = confidential_code(&router).await;

    exhaust_client_rate_limit(&state, "other-client").await;
    let mismatch =
        confidential_exchange(&router, &code, verifier, "other-client", Some(CLIENT)).await;
    assert_eq!(
        mismatch.status(),
        StatusCode::UNAUTHORIZED,
        "identity conflict must be rejected before the request-controlled form client can select an exhausted bucket"
    );
    assert_eq!(
        mismatch
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok()),
        Some("Basic realm=\"token\"")
    );
    let body = axum::body::to_bytes(mismatch.into_body(), usize::MAX)
        .await
        .unwrap();
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["error"], "invalid_client");

    state
        .rate_limit
        .as_ref()
        .unwrap()
        .delete("other-client")
        .await
        .unwrap();
    let retry = confidential_exchange(&router, &code, verifier, CLIENT, None).await;
    assert_eq!(
        retry.status(),
        StatusCode::OK,
        "client identity mismatch must not consume the authorization code"
    );
}

#[tokio::test]
async fn token_rejects_malformed_basic_with_challenge_without_consuming_code() {
    let router = confidential_app().await;
    let (code, verifier) = confidential_code(&router).await;
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}"
    );

    let malformed = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("authorization", "Basic !!!not-base64!!!")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        malformed
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok()),
        Some("Basic realm=\"token\"")
    );

    let retry = confidential_exchange(&router, &code, verifier, CLIENT, None).await;
    assert_eq!(
        retry.status(),
        StatusCode::OK,
        "malformed Basic credentials must not consume the authorization code"
    );
}

#[tokio::test]
async fn token_wrong_basic_secret_releases_acquired_code_lease() {
    let router = confidential_app().await;
    let (code, verifier) = confidential_code(&router).await;

    let rejected =
        confidential_exchange_with_secret(&router, &code, verifier, CLIENT, "wrong-secret", None)
            .await;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        rejected
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok()),
        Some("Basic realm=\"token\"")
    );

    let retry = confidential_exchange(&router, &code, verifier, CLIENT, None).await;
    assert_eq!(
        retry.status(),
        StatusCode::OK,
        "authentication failure after lease acquisition must release the code lease"
    );
}

#[tokio::test]
async fn authorization_code_kms_transient_releases_lease_without_consuming() {
    use agent_auth_http::adapters::memory::MemorySigner;
    use agent_auth_http::state::SignerImpl;

    let mut state = AppState::dev(HOST);
    let isolated_signer =
        std::sync::Arc::new(SignerImpl::Memory(MemorySigner::from_seed([79; 32])));
    state.signer = isolated_signer.clone();
    state.tenant_keys = std::sync::Arc::new(
        agent_auth_http::tenant_keys::TenantKeyService::shared(isolated_signer),
    );
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let router = build_router(state.clone()).0;
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let location = get_redirect(
        &router,
        &format!(
            "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
             &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
        ),
    )
    .await;
    let code = query_param(&location, "code").unwrap();
    let SignerImpl::Memory(signer) = state.signer.as_ref() else {
        panic!("dev state must use MemorySigner");
    };
    signer.fail_next_es256(true);

    let response = exchange_response(&router, &code, verifier).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|value| value > 0),
        "transient signing failure must advertise a positive Retry-After"
    );
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["error"], "temporarily_unavailable");
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());

    assert_eq!(
        exchange_response(&router, &code, verifier).await.status(),
        StatusCode::OK,
        "the same code must remain retryable after a transient signer failure"
    );
}

#[tokio::test]
async fn authorization_code_finalize_failure_keeps_lease_until_expiry_then_retries() {
    use agent_auth_http::ports::{CodeStore, LeaseAcquire};
    use agent_auth_http::state::{CodeStoreImpl, SignerImpl};

    let mut state = AppState::dev(HOST);
    let isolated_signer = std::sync::Arc::new(SignerImpl::Memory(
        agent_auth_http::adapters::memory::MemorySigner::from_seed([80; 32]),
    ));
    state.signer = isolated_signer.clone();
    state.tenant_keys = std::sync::Arc::new(
        agent_auth_http::tenant_keys::TenantKeyService::shared(isolated_signer),
    );
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let router = build_router(state.clone()).0;
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let location = get_redirect(
        &router,
        &format!(
            "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
             &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
        ),
    )
    .await;
    let code = query_param(&location, "code").unwrap();
    let codes = match state.codes.as_ref() {
        CodeStoreImpl::Memory(codes) => codes,
        #[cfg(feature = "aws")]
        CodeStoreImpl::Dynamo(_) => panic!("test requires memory code store"),
    };
    let SignerImpl::Memory(signer) = state.signer.as_ref() else {
        panic!("dev state must use MemorySigner");
    };
    codes.fail_next_finalize();
    let sign_count_before = signer.es256_sign_count();

    let response = exchange_response(&router, &code, verifier).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["error"], "temporarily_unavailable");
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
    let signed_once = signer.es256_sign_count();
    assert_eq!(signed_once, sign_count_before + 1);

    assert_eq!(
        exchange_response(&router, &code, verifier).await.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "the unexpired finalize-failure lease must block duplicate signing"
    );
    assert_eq!(
        signer.es256_sign_count(),
        signed_once,
        "a locked retry must not invoke the signer again"
    );

    let now = agent_auth_http::current_unix_secs();
    let reclaim_at = now + 31;
    assert!(matches!(
        state
            .codes
            .acquire_lease("", &code, "expiry-probe", reclaim_at, reclaim_at + 30)
            .await
            .unwrap(),
        LeaseAcquire::Acquired(_)
    ));
    state
        .codes
        .release_lease("", &code, "expiry-probe", reclaim_at)
        .await
        .unwrap();
    assert_eq!(
        exchange_response(&router, &code, verifier).await.status(),
        StatusCode::OK,
        "an unconsumed code must retry successfully after lease expiry"
    );
}

#[tokio::test]
async fn token_basic_unknown_and_tombstoned_clients_return_challenge() {
    use agent_auth_http::ports::ClientStore;

    let deleted_state = confidential_state().await;
    let (deleted_router, _) = build_router(deleted_state.clone());
    let (deleted_code, deleted_verifier) = confidential_code(&deleted_router).await;
    deleted_state.clients.delete("", CLIENT).await.unwrap();
    let unknown = confidential_exchange(
        &deleted_router,
        &deleted_code,
        deleted_verifier,
        CLIENT,
        None,
    )
    .await;
    assert_eq!(unknown.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        unknown
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok()),
        Some("Basic realm=\"token\"")
    );

    let tombstoned_state = confidential_state().await;
    let (tombstoned_router, _) = build_router(tombstoned_state.clone());
    let (tombstoned_code, tombstoned_verifier) = confidential_code(&tombstoned_router).await;
    assert!(tombstoned_state
        .clients
        .convert_to_tombstone("", CLIENT, 1, None, 0)
        .await
        .unwrap());
    let tombstoned = confidential_exchange(
        &tombstoned_router,
        &tombstoned_code,
        tombstoned_verifier,
        CLIENT,
        None,
    )
    .await;
    assert_eq!(tombstoned.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        tombstoned
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok()),
        Some("Basic realm=\"token\"")
    );
}

#[tokio::test]
async fn refresh_rejects_mismatched_basic_and_form_client_identity() {
    use agent_auth_http::ports::RateLimitStore;

    let state = confidential_state().await;
    let router = build_router(state.clone()).0;
    let refresh_token = confidential_refresh_token(&router).await;

    exhaust_client_rate_limit(&state, "other-client").await;
    let wrong_basic =
        confidential_refresh_exchange(&router, &refresh_token, "other-client", None).await;
    assert_eq!(wrong_basic.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        wrong_basic
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok()),
        Some("Basic realm=\"token\"")
    );
    let body = axum::body::to_bytes(wrong_basic.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "invalid_client");

    let conflicting_form =
        confidential_refresh_exchange(&router, &refresh_token, CLIENT, Some("other-client")).await;
    assert_eq!(conflicting_form.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(conflicting_form.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "invalid_client");

    state
        .rate_limit
        .as_ref()
        .unwrap()
        .delete("other-client")
        .await
        .unwrap();
    let valid = confidential_refresh_exchange(&router, &refresh_token, CLIENT, None).await;
    assert_eq!(
        valid.status(),
        StatusCode::OK,
        "identity mismatch must not rotate or revoke the refresh family"
    );
}

#[tokio::test]
async fn refresh_authenticated_cross_client_returns_invalid_grant() {
    use agent_auth_http::ports::{ClientRecord, ClientStore};

    const OTHER_CLIENT: &str = "other-client";
    const OTHER_SECRET: &str = "other-confidential-secret";

    let state = confidential_state().await;
    state
        .clients
        .put(
            "",
            ClientRecord {
                client_id: OTHER_CLIENT.into(),
                redirect_uris: vec!["https://other.example.com/cb".into()],
                token_endpoint_auth_method: "client_secret_basic".into(),
                client_secret: Some(OTHER_SECRET.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let router = build_router(state).0;
    let refresh_token = confidential_refresh_token(&router).await;
    let credentials = STANDARD.encode(format!("{OTHER_CLIENT}:{OTHER_SECRET}"));

    let cross_client = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .header("authorization", format!("Basic {credentials}"))
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={refresh_token}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(cross_client.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(cross_client.into_body(), usize::MAX)
        .await
        .unwrap();
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["error"], "invalid_grant");

    let owner = confidential_refresh_exchange(&router, &refresh_token, CLIENT, None).await;
    assert_eq!(
        owner.status(),
        StatusCode::OK,
        "cross-client rejection must not rotate or revoke the refresh family"
    );
}

fn verify_jwt_with_jwk(jwt: &str, jwk: &serde_json::Value) {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let parts: Vec<&str> = jwt.split('.').collect();
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();

    let x = URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap();
    let y = URL_SAFE_NO_PAD.decode(jwk["y"].as_str().unwrap()).unwrap();
    let mut sec1 = vec![0x04u8];
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let vk = VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let sig = Signature::from_slice(&sig_bytes).unwrap();
    assert!(
        vk.verify(signing_input.as_bytes(), &sig).is_ok(),
        "JWKS 公钥应能验证 JWT 签名"
    );
    assert_eq!(jwk["alg"], "ES256");
    assert_eq!(jwk["kty"], "EC");
}

#[tokio::test]
async fn token_rejects_wrong_pkce_verifier() {
    let router = app().await;
    let challenge = s256_challenge("0123456789012345678901234567890123456789abc");
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&authz)
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let loc = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let code = query_param(&loc, "code").unwrap();

    // 用错误 verifier 兑换 → invalid_grant。
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier=WRONGwrongWRONGwrongWRONGwrongWRONGwrong123&redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "错误 PKCE verifier 应拒"
    );
}

#[tokio::test]
async fn authorize_rejects_missing_pkce() {
    let router = app().await;
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}&scope=openid&login_user=alice"
    );
    let resp = router
        .oneshot(
            Request::builder()
                .uri(&authz)
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "缺 PKCE challenge 应拒(C4.1)"
    );
}

#[tokio::test]
async fn authorize_rejects_unknown_explicit_client_type_without_pkce() {
    use agent_auth_http::ports::{ClientRecord, ClientStore};

    let state = AppState::dev(HOST);
    state
        .clients
        .put(
            "",
            ClientRecord {
                client_id: "invalid-type-client".into(),
                redirect_uris: vec![REDIRECT.into()],
                token_endpoint_auth_method: "client_secret_basic".into(),
                client_secret: Some(CONFIDENTIAL_SECRET.into()),
                client_type: Some("invalid".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let router = build_router(state).0;
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/authorize?response_type=code&client_id=invalid-type-client\
                     &redirect_uri={REDIRECT}&scope=openid&login_user=alice"
                ))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "an unknown explicit client type must not receive the confidential PKCE exemption"
    );
}

// spec 006 Task 2.2:只做 authorization code + PKCE,MUST 拒 implicit(response_type=token)/
// hybrid(code token / code id_token)——不签出前端通道 token(无 PKCE 保护、URL 片段泄露面)。
#[tokio::test]
async fn authorize_rejects_implicit_and_hybrid_response_types() {
    let router = app().await;
    for rt in [
        "token",
        "id_token",
        "code token",
        "code id_token",
        "id_token token",
    ] {
        let encoded = rt.replace(' ', "%20");
        let authz = format!(
            "/authorize?response_type={encoded}&client_id={CLIENT}&redirect_uri={REDIRECT}\
             &scope=openid&code_challenge=abc&code_challenge_method=S256&login_user=alice"
        );
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&authz)
                    .header("host", HOST)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "response_type={rt:?} 应拒 unsupported_response_type(只做 code+PKCE)"
        );
    }
}

const DCR_CODE_FLOW_REDIRECT: &str = "http://127.0.0.1:49152/cb";

async fn dcr_code_flow_tokens(
    id_token_alg: Option<&str>,
    user: &str,
    nonce: Option<&str>,
) -> (axum::Router, String, serde_json::Value) {
    use agent_auth_http::ports::ClientStore;

    let state = AppState::dev(HOST);
    let clients = state.clients.clone();
    let (router, _) = build_router(state);

    let mut registration = serde_json::json!({
        "redirect_uris": [DCR_CODE_FLOW_REDIRECT],
        "application_type": "native",
        "token_endpoint_auth_method": "none"
    });
    if let Some(alg) = id_token_alg {
        registration["id_token_signed_response_alg"] = serde_json::json!(alg);
    }
    let (status, registered) = register(&router, registration).await;
    assert_eq!(status, StatusCode::CREATED, "DCR 注册应成功");
    let client_id = registered["client_id"]
        .as_str()
        .expect("DCR 响应应返回 client_id")
        .to_string();
    let persisted = ClientStore::get(clients.as_ref(), "", &client_id)
        .await
        .unwrap()
        .expect("DCR client 应持久化");
    assert_eq!(
        persisted.id_token_signed_response_alg.as_deref(),
        id_token_alg,
        "DCR 必须持久化 per-client ID token 算法选择"
    );

    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let nonce_query = nonce
        .map(|value| {
            let encoded: String = url::form_urlencoded::byte_serialize(value.as_bytes()).collect();
            format!("&nonce={encoded}")
        })
        .unwrap_or_default();
    let authorization = format!(
        "/authorize?response_type=code&client_id={client_id}&redirect_uri={DCR_CODE_FLOW_REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid\
         &login_user={user}{nonce_query}"
    );
    let location = get_redirect(&router, &authorization).await;
    let code = query_param(&location, "code").expect("DCR client 应能获取 code");
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={DCR_CODE_FLOW_REDIRECT}&client_id={client_id}"
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        router,
        client_id,
        serde_json::from_slice(&body).expect("token response 应为 JSON"),
    )
}

// spec 001 C2.6/C2.7/C2.9:openid scope 的 code flow 返回 id_token;DCR 默认 RS256 签、
// aud=client_id、nonce echo、auth_time 存在;同一响应的 access token 仍固定 ES256;
// 用 /jwks.json 的 RSA 公钥独立验签。
#[tokio::test]
async fn dcr_default_rs256_id_token_keeps_access_token_es256() {
    let nonce = "n-._~:/?@[]!$&'()*+,;= % + 雪";
    let (router, client_id, tok) = dcr_code_flow_tokens(None, "alice", Some(nonce)).await;
    let id_token = tok["id_token"]
        .as_str()
        .expect("openid scope 应返回 id_token");
    let access_token = tok["access_token"]
        .as_str()
        .expect("code flow 应返回 access token");

    // header:alg=RS256、typ=JWT(非 at+jwt)、有 kid。
    let parts: Vec<&str> = id_token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    assert_eq!(header["alg"], "RS256", "id_token 默认 RS256(C2.7)");
    assert_eq!(header["typ"], "JWT", "id_token typ 非 at+jwt");
    let kid = header["kid"].as_str().unwrap().to_string();

    // claims:iss、aud=client_id、nonce echo、auth_time 存在、sub 存在。
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(claims["iss"], format!("https://{HOST}"));
    assert_eq!(
        claims["aud"], client_id,
        "id_token aud=client_id(C2.6,单值)"
    );
    assert_eq!(claims["nonce"], nonce, "nonce 逐字节 echo(C2.9)");
    assert!(claims["auth_time"].is_i64(), "id_token 含 auth_time(C2.7)");
    assert!(claims["sub"].is_string(), "id_token 含 sub");

    let access_header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(access_token.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        access_header["alg"], "ES256",
        "默认 RS256 ID token 不得改变 access token 的固定 ES256 算法"
    );
    assert_eq!(access_header["typ"], "at+jwt");

    // 真实 RS 只接受 typ=at+jwt 的 access token，必须拒绝 typ=JWT 的 ID token。
    let rejected = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/rs/attributes")
                .header("host", HOST)
                .header("authorization", format!("Bearer {id_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        rejected.status(),
        StatusCode::UNAUTHORIZED,
        "RS 不得把 ID token 当作访问凭证(C2.6)"
    );

    // 从 /jwks.json 取 RSA 公钥(kty=RSA),用 workload::verify_rs256 独立验签。
    let jresp = router
        .oneshot(
            Request::builder()
                .uri("/jwks.json")
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let jbody = axum::body::to_bytes(jresp.into_body(), usize::MAX)
        .await
        .unwrap();
    let jwks: serde_json::Value = serde_json::from_slice(&jbody).unwrap();
    let rsa_jwk = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kty"] == "RSA")
        .expect("JWKS 应含 RSA 公钥(id_token 验签)");
    assert_eq!(rsa_jwk["kid"], kid, "id_token kid 应命中 JWKS RSA key");
    let n = rsa_jwk["n"].as_str().unwrap();
    let e = rsa_jwk["e"].as_str().unwrap();
    let v = agent_auth_workload::verify_rs256(id_token, n, e, Some(&kid))
        .expect("RSA 公钥应能验证 id_token 签名");
    assert_eq!(v.claims["aud"], client_id);
}

// spec 001 C2.7:DCR 客户端显式请求 ES256 时 ID token 使用 ES256；
// access token 的算法仍固定为 ES256，不受 ID token 的 per-client 选择影响。
#[tokio::test]
async fn dcr_es256_id_token_keeps_access_token_es256() {
    let (router, client_id, tokens) = dcr_code_flow_tokens(Some("ES256"), "es256-user", None).await;
    let id_token = tokens["id_token"]
        .as_str()
        .expect("openid code flow 应返回 ID token");
    let access_token = tokens["access_token"]
        .as_str()
        .expect("code flow 应返回 access token");

    let id_header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(id_token.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        id_header["alg"], "ES256",
        "client 的 id_token_signed_response_alg=ES256 必须生效"
    );
    assert_eq!(id_header["typ"], "JWT");

    let access_header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(access_token.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        access_header["alg"], "ES256",
        "access token 算法不得被 ID token 的 per-client 算法选择改变"
    );
    assert_eq!(access_header["typ"], "at+jwt");

    let jwks_response = router
        .oneshot(
            Request::builder()
                .uri("/jwks.json")
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let jwks_body = axum::body::to_bytes(jwks_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let jwks: serde_json::Value = serde_json::from_slice(&jwks_body).unwrap();
    for (label, token, header, expected_claim, expected_value) in [
        ("ID token", id_token, &id_header, "aud", client_id.as_str()),
        (
            "access token",
            access_token,
            &access_header,
            "client_id",
            client_id.as_str(),
        ),
    ] {
        let kid = header["kid"]
            .as_str()
            .unwrap_or_else(|| panic!("{label} header 应含 kid"));
        let ec_jwk = jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|key| key["kty"] == "EC" && key["kid"] == kid)
            .unwrap_or_else(|| panic!("{label} kid 应命中公开 JWKS EC key"));
        let verified = agent_auth_workload::verify_es256(
            token,
            ec_jwk["x"].as_str().unwrap(),
            ec_jwk["y"].as_str().unwrap(),
            Some(kid),
        )
        .unwrap_or_else(|error| panic!("公开 JWKS 应能独立验证 {label}: {error:?}"));
        assert_eq!(
            verified.claims[expected_claim], expected_value,
            "{label} 独立验签后的 {expected_claim} 必须匹配 DCR client"
        );
    }
}

// id_token 不含 openid scope 时不签发。
#[tokio::test]
async fn code_flow_no_id_token_without_openid() {
    let router = app().await;
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=profile&login_user=alice"
    );
    let loc = get_redirect(&router, &authz).await;
    let code = query_param(&loc, "code").unwrap();
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let tok: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        tok.get("id_token").is_none(),
        "无 openid scope 不应返回 id_token"
    );
}

// C2.8/C2.5b/006 4.2/6.1:多 resource 按**部署阶段**门控——P0 拒(单值绑定)、P1+ 接受(多值集合)。
#[tokio::test]
async fn authorize_multi_resource_phase_gated() {
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let two = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice\
         &resource=https://mcp.a.example.com&resource=https://mcp.b.example.com"
    );
    let three = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice\
         &resource=https://mcp.a.example.com&resource=https://mcp.b.example.com\
         &resource=https://mcp.c.example.com"
    );
    let one = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice\
         &resource=https://mcp.a.example.com"
    );
    let get = |router: axum::Router, uri: String| async move {
        router
            .oneshot(
                Request::builder()
                    .uri(&uri)
                    .header("host", HOST)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    };

    // --- P0 部署:单 resource 放行、多 resource 拒(400,C2.8/006 4.2)---
    let mut p0 = AppState::dev(HOST);
    p0.phase = agent_auth_http::Phase::P0;
    p0.seed_dev_client(CLIENT, REDIRECT, None).await;
    let (r0, _) = build_router(p0);
    assert_eq!(
        get(r0.clone(), one.clone()).await,
        StatusCode::SEE_OTHER,
        "P0 单 resource 应放行"
    );
    assert_eq!(
        get(r0.clone(), two.clone()).await,
        StatusCode::BAD_REQUEST,
        "P0 两个 resource 应拒(单值绑定,C2.8)"
    );
    assert_eq!(
        get(r0, three.clone()).await,
        StatusCode::BAD_REQUEST,
        "P0 三个 resource 也应拒，不能只特判 len == 2"
    );

    // --- P1+ 部署(dev 默认 P1):多 resource **接受**(集合写 code,token 侧收窄,C2.5b)---
    let router = app().await; // dev = P1
    assert_eq!(
        get(router.clone(), one).await,
        StatusCode::SEE_OTHER,
        "P1 单 resource 应放行"
    );
    assert_eq!(
        get(router.clone(), two).await,
        StatusCode::SEE_OTHER,
        "P1+ 两个 resource 应接受(C2.5b 集合绑定,token 侧收窄单值)"
    );
    assert_eq!(
        get(router, three).await,
        StatusCode::SEE_OTHER,
        "P1+ 三个 resource 应接受，作为 P0 拒绝的阶段对照"
    );
}

// C2.5b/006 6.1:P1+ 多 resource authorize → code 存集合 → token 选其一收窄 → aud=所选(单值)。
#[tokio::test]
async fn multi_resource_authorize_token_narrows_to_one() {
    const RA: &str = "https://mcp.a.example.com";
    const RB: &str = "https://mcp.b.example.com";
    let router = app().await; // dev = P1,允许多 resource
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    // authorize 带两 resource → 接受(303),code 绑定 {RA, RB}。
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice\
         &resource={RA}&resource={RB}"
    );
    let loc = get_redirect(&router, &authz).await;
    let code = query_param(&loc, "code").expect("多 resource authorize 应签 code");

    // token 选 RB(∈ 授权集合)→ aud=[RB](收窄到单值,C2.5b)。
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}&resource={RB}"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "token 选授权集合内 resource 应 200"
    );
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let tok: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let jwt = tok["access_token"].as_str().unwrap();
    let claims: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        claims["aud"],
        serde_json::json!([RB]),
        "多 resource 授权 + token 选 RB → aud=[RB](收窄单值,C2.5b)"
    );

    // token 选**不在**授权集合的 resource → 拒(resource ∉ authorize 集合)。
    let authz2 = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice\
         &resource={RA}&resource={RB}"
    );
    let loc2 = get_redirect(&router, &authz2).await;
    let code2 = query_param(&loc2, "code").unwrap();
    let form2 = format!(
        "grant_type=authorization_code&code={code2}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}&resource=https://mcp.c.evil.com"
    );
    let resp2 = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form2))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::BAD_REQUEST,
        "token 选授权集合外 resource 应拒(authorize↔token 绑定)"
    );
}

// C4.4b/C4.6(002 §5.2):redirect_mode=prefix 接线——confidential client 前缀 callback 放行;
// public client 配 prefix → authorize 拒,且入站 URI 仍受注册 host 边界约束。
// 独立、版本化的 prefix host allowlist 由 #198 跟踪,本测试不宣称覆盖该策略。
#[tokio::test]
async fn authorize_prefix_mode_confidential_only() {
    use agent_auth_http::ports::{ClientRecord, ClientStore};
    let pfx_host = "https://bedrock-agentcore.us-east-1.amazonaws.com";
    let mk_client = |id: &str, method: &str, ctype: Option<&str>| ClientRecord {
        client_id: id.into(),
        redirect_uris: vec![format!("{pfx_host}/identities/*")],
        application_type: None,
        token_endpoint_auth_method: method.into(),
        client_secret: (method != "none").then(|| "s3cret".into()),
        client_secret_credentials: Default::default(),
        jwks: None,
        jwks_uri: None,
        token_endpoint_auth_signing_alg: None,
        default_resource: None,
        introspect_enabled: false,
        resource_ids: vec![],
        post_logout_redirect_uris: vec![],
        reg_token_hash: None,
        registration_token_credentials: Default::default(),
        client_type: ctype.map(String::from),
        id_token_signed_response_alg: None,
        oidc_sector_identifier: None,
        allowed_resources: vec![],
        allowed_scopes: vec![],
        redirect_mode: Some("prefix".into()),
        created_at: 0,
        last_used_day: None,
        authority_revision: 0,
        tombstoned_at: None,
        backchannel_token_delivery_mode: None,
        backchannel_client_notification_endpoint: None,
        require_dpop: false,
        prm_domains: vec![],
    };
    let state = AppState::dev(HOST);
    let _ = ClientStore::put(
        &*state.clients,
        "",
        mk_client("conf-pfx", "client_secret_basic", Some("confidential")),
    )
    .await;
    let _ = ClientStore::put(
        &*state.clients,
        "",
        mk_client("pub-pfx", "none", Some("public")),
    )
    .await;
    let mut default_exact = mk_client(
        "conf-default-exact",
        "client_secret_basic",
        Some("confidential"),
    );
    default_exact.redirect_mode = None;
    let _ = ClientStore::put(&*state.clients, "", default_exact).await;
    let (router, _) = build_router(state);

    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let cb = format!("{pfx_host}/identities/uuid-abc-123");
    let cb_enc = cb.replace(':', "%3A").replace('/', "%2F");

    // confidential + prefix:前缀下单层 callback → authorize 放行(303)。
    let authz_conf = format!(
        "/authorize?response_type=code&client_id=conf-pfx&redirect_uri={cb_enc}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
    );
    let st_conf = get_status(&router, &authz_conf).await;
    assert_eq!(
        st_conf,
        StatusCode::SEE_OTHER,
        "confidential + prefix 前缀 callback 应放行(C4.4b)"
    );

    // public + prefix:C4.6 拒(prefix 仅授 confidential)。
    let authz_pub = format!(
        "/authorize?response_type=code&client_id=pub-pfx&redirect_uri={cb_enc}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
    );
    let st_pub = get_status(&router, &authz_pub).await;
    assert_eq!(
        st_pub,
        StatusCode::BAD_REQUEST,
        "public + prefix 应拒(C4.6:prefix 仅授 confidential)"
    );

    // prefix 缺省关闭:相同 wildcard 注册值在 exact 模式下不得接受展开后的 callback。
    let authz_default_exact = format!(
        "/authorize?response_type=code&client_id=conf-default-exact&redirect_uri={cb_enc}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
    );
    assert_eq!(
        get_status(&router, &authz_default_exact).await,
        StatusCode::BAD_REQUEST,
        "未显式启用 prefix 时 MUST 保持 exact,不得展开 wildcard"
    );

    // host allowlist:即使是 confidential + prefix,也只能匹配注册 URI 的 host/path 前缀。
    let unallowlisted = "https://evil.example.com/identities/uuid-abc-123"
        .replace(':', "%3A")
        .replace('/', "%2F");
    let authz_unallowlisted = format!(
        "/authorize?response_type=code&client_id=conf-pfx&redirect_uri={unallowlisted}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
    );
    assert_eq!(
        get_status(&router, &authz_unallowlisted).await,
        StatusCode::BAD_REQUEST,
        "prefix 模式 MUST 拒绝未注册 host"
    );
}

// GET authorize,返回 status(不取 body)。
async fn get_status(router: &axum::Router, uri: &str) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

// C2.8 case②(006 Task 8.2):client 注册 default_resource + /authorize 带该 resource,
// /token **省略** resource → aud = 该 RS(非 /userinfo)。端到端坐实 default_resource 经 HTTP 通路生效
// (纯逻辑优先级三用例在 protocol::resource UT 全覆盖;此处验编排通路)。
#[tokio::test]
async fn token_omit_resource_with_default_resource_aud_is_rs() {
    const DR: &str = "https://mcp.default.example.com";
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, Some(DR)).await; // 注册 default_resource
    let (router, _) = build_router(state);

    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    // authorize 带 resource=DR(与 default 一致;声明进 code 集合)。
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&state=s&login_user=alice\
         &resource={DR}"
    );
    let location = get_redirect(&router, &authz).await;
    let code = query_param(&location, "code").expect("回跳带 code");

    // token **省略** resource → 期望 aud = DR(default_resource,非 /userinfo)。
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "token 兑换应 200");
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let tok: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let jwt = tok["access_token"].as_str().expect("含 access_token");
    let claims: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        claims["aud"],
        serde_json::json!([DR]),
        "省略 resource + 有 default_resource → aud=该 RS(C2.8 case②),非 /userinfo"
    );
}

// C2.8 case③ / 006 §8.3:authorize **未带** resource,但 /token 却传 resource → 拒
// (authorize↔token 绑定:token 侧不得凭空引入未在 authorize 声明的 resource;授权集合为空 → 任何
//  显式 resource 都 ∉ 集合 → invalid_target)。
#[tokio::test]
async fn token_resource_without_authorize_resource_rejected() {
    const RS: &str = "https://mcp.unbound.example.com";
    let router = app().await; // CLIENT 无 default_resource
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    // authorize **不带** resource → code 绑定空集合(纯 OIDC)。
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
    );
    let loc = get_redirect(&router, &authz).await;
    let code = query_param(&loc, "code").expect("回跳带 code");

    // token 却传 resource=RS(authorize 从未声明)→ 期望 400 invalid_target。
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}&resource={RS}"
    );
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "authorize 未带 resource 但 token 传 resource → 拒(authorize↔token 绑定,C2.8 case③)"
    );
}

// C2.11:aud=<issuer>/userinfo 的 token 调 /userinfo 通过、返回 sub。
#[tokio::test]
async fn userinfo_accepts_userinfo_aud_token() {
    let router = app().await;
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    // 无 resource + client 无 default → aud=<issuer>/userinfo。
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
    );
    let loc = get_redirect(&router, &authz).await;
    let code = query_param(&loc, "code").unwrap();
    let jwt = exchange_token(&router, &code, verifier).await;

    // 调 /userinfo。
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header("host", HOST)
                .header("authorization", format!("Bearer {jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "aud=/userinfo 的 token 应通过"
    );
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let ui: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(ui["sub"], "alice");
}

#[tokio::test]
async fn userinfo_accepts_post_header_bearer_token() {
    let router = app().await;
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
    );
    let location = get_redirect(&router, &authz).await;
    let code = query_param(&location, "code").unwrap();
    let access_token = exchange_token(&router, &code, verifier).await;

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/userinfo")
                .header("host", HOST)
                .header("authorization", format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let userinfo: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(userinfo["sub"], "alice");
}

#[tokio::test]
async fn userinfo_bearer_scheme_is_case_insensitive() {
    let router = app().await;
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
    );
    let location = get_redirect(&router, &authz).await;
    let code = query_param(&location, "code").unwrap();
    let access_token = exchange_token(&router, &code, verifier).await;

    let response = router
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header("host", HOST)
                .header("authorization", format!("bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn userinfo_accepts_post_form_bearer_token() {
    let router = app().await;
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
    );
    let location = get_redirect(&router, &authz).await;
    let code = query_param(&location, "code").unwrap();
    let access_token = exchange_token(&router, &code, verifier).await;

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/userinfo")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("access_token={access_token}")))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let userinfo: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(userinfo["sub"], "alice");
}

#[tokio::test]
async fn userinfo_rejects_multiple_bearer_token_transport_methods() {
    let router = app().await;
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
    );
    let location = get_redirect(&router, &authz).await;
    let code = query_param(&location, "code").unwrap();
    let access_token = exchange_token(&router, &code, verifier).await;

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/userinfo")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .header("authorization", format!("Bearer {access_token}"))
                .body(Body::from(format!("access_token={access_token}")))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers()["www-authenticate"]
        .to_str()
        .unwrap()
        .contains(r#"error="invalid_request""#));
}

#[tokio::test]
async fn userinfo_rejects_invalid_token_across_all_transport_methods() {
    let router = app().await;
    let requests = [
        Request::builder()
            .uri("/userinfo")
            .header("host", HOST)
            .header("authorization", "Bearer not-a-token")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri("/userinfo")
            .header("host", HOST)
            .header("authorization", "Bearer not-a-token")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri("/userinfo")
            .header("host", HOST)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("access_token=not-a-token"))
            .unwrap(),
    ];
    for request in requests {
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

// C2.11:aud=某 MCP RS 的 token 调 /userinfo → 403(aud 隔离)。
#[tokio::test]
async fn userinfo_rejects_mcp_rs_aud_token() {
    let state = AppState::dev(HOST);
    // client 注册 default_resource = 某 MCP RS;省略 resource → aud=该 RS。
    use agent_auth_http::ports::{ClientRecord, ClientStore};
    // 直接用 seed 变体注入带 default_resource 的 client。
    let rs = "https://mcp.rs.example.com";
    let _ = ClientStore::put(
        &*state.clients,
        "",
        ClientRecord {
            client_id: CLIENT.into(),
            redirect_uris: vec![REDIRECT.into()],
            application_type: None,
            token_endpoint_auth_method: "none".into(),
            client_secret: None,
            client_secret_credentials: Default::default(),
            jwks: None,
            jwks_uri: None,
            token_endpoint_auth_signing_alg: None,
            default_resource: Some(rs.into()),
            introspect_enabled: false,
            resource_ids: vec![],
            post_logout_redirect_uris: vec![],
            reg_token_hash: None,
            registration_token_credentials: Default::default(),
            client_type: None,
            id_token_signed_response_alg: None,
            oidc_sector_identifier: None,
            allowed_resources: vec![],
            allowed_scopes: vec![],
            redirect_mode: None,
            created_at: 0,
            last_used_day: None,
            authority_revision: 0,
            tombstoned_at: None,
            backchannel_token_delivery_mode: None,
            backchannel_client_notification_endpoint: None,
            require_dpop: false,
            prm_domains: vec![],
        },
    )
    .await;
    let (router, _) = build_router(state);

    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    // authorize 绑定该 RS(resource=rs),token 省略继承 → aud=rs。
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&resource={rs}&login_user=alice"
    );
    let loc = get_redirect(&router, &authz).await;
    let code = query_param(&loc, "code").unwrap();
    let jwt = exchange_token(&router, &code, verifier).await;

    // 该 token aud=rs,调 /userinfo → 403。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header("host", HOST)
                .header("authorization", format!("Bearer {jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "aud=MCP RS 的 token 调 /userinfo 应 403(C2.11)"
    );
    let post_header = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/userinfo")
                .header("host", HOST)
                .header("authorization", format!("Bearer {jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(post_header.status(), StatusCode::FORBIDDEN);
    let post_form = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/userinfo")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("access_token={jwt}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(post_form.status(), StatusCode::FORBIDDEN);
}

// 取一个含 refresh_token 的 token 响应(走完整 code flow)。
async fn code_flow_token_json(router: &axum::Router, user: &str) -> serde_json::Value {
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user={user}"
    );
    let loc = get_redirect(router, &authz).await;
    let code = query_param(&loc, "code").unwrap();
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn refresh_exchange(router: &axum::Router, refresh: &str) -> (StatusCode, serde_json::Value) {
    refresh_exchange_res(router, refresh, None).await
}

async fn refresh_http_response(router: &axum::Router, refresh: &str) -> axum::response::Response {
    let form = format!("grant_type=refresh_token&refresh_token={refresh}&client_id={CLIENT}");
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn refresh_exchange_for_client(
    router: &axum::Router,
    refresh: &str,
    client_id: &str,
) -> (StatusCode, serde_json::Value) {
    let form = format!("grant_type=refresh_token&refresh_token={refresh}&client_id={client_id}");
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&body).unwrap_or(serde_json::json!({})),
    )
}

// 带可选 resource 的 refresh 兑换(resource 变会改宽限窗指纹 → 按复用处理)。
async fn refresh_exchange_res(
    router: &axum::Router,
    refresh: &str,
    resource: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let res = resource
        .map(|r| format!("&resource={r}"))
        .unwrap_or_default();
    let form = format!("grant_type=refresh_token&refresh_token={refresh}&client_id={CLIENT}{res}");
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    let st = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        st,
        serde_json::from_slice(&body).unwrap_or(serde_json::json!({})),
    )
}

#[tokio::test]
async fn authorization_code_rate_limit_uses_bound_client_and_releases_lease() {
    use agent_auth_http::ports::RateLimitStore;

    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let router = build_router(state.clone()).0;
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let location = get_redirect(
        &router,
        &format!(
            "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
             &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
        ),
    )
    .await;
    let code = query_param(&location, "code").unwrap();

    exhaust_client_rate_limit(&state, CLIENT).await;
    assert_client_rate_limited(exchange_response(&router, &code, verifier).await).await;

    state
        .rate_limit
        .as_ref()
        .unwrap()
        .delete(CLIENT)
        .await
        .unwrap();
    assert_eq!(
        exchange_response(&router, &code, verifier).await.status(),
        StatusCode::OK,
        "a throttled authorization code must retain a retryable released lease"
    );
}

#[tokio::test]
async fn authorization_code_rate_limit_release_failure_is_not_reported_as_429() {
    use agent_auth_http::state::CodeStoreImpl;

    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let router = build_router(state.clone()).0;
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let location = get_redirect(
        &router,
        &format!(
            "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
             &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
        ),
    )
    .await;
    let code = query_param(&location, "code").unwrap();

    exhaust_client_rate_limit(&state, CLIENT).await;
    let codes = match state.codes.as_ref() {
        CodeStoreImpl::Memory(codes) => codes,
        #[cfg(feature = "aws")]
        CodeStoreImpl::Dynamo(_) => panic!("test requires memory code store"),
    };
    codes.fail_next_release_lease();

    let response = exchange_response(&router, &code, verifier).await;
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a failed lease release must not promise ordinary 429 retryability"
    );
    assert!(response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|value| value > 0));
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "temporarily_unavailable");
}

#[tokio::test]
async fn authorization_code_rate_limit_permanent_release_failure_is_server_error() {
    use agent_auth_http::state::CodeStoreImpl;

    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let router = build_router(state.clone()).0;
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let location = get_redirect(
        &router,
        &format!(
            "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
             &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
        ),
    )
    .await;
    let code = query_param(&location, "code").unwrap();

    exhaust_client_rate_limit(&state, CLIENT).await;
    let codes = match state.codes.as_ref() {
        CodeStoreImpl::Memory(codes) => codes,
        #[cfg(feature = "aws")]
        CodeStoreImpl::Dynamo(_) => panic!("test requires memory code store"),
    };
    codes.fail_next_release_lease_permanently();

    let response = exchange_response(&router, &code, verifier).await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        response.headers().get("retry-after").is_none(),
        "permanent storage failures must not advertise automatic retry timing"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "server_error");
}

#[tokio::test]
async fn refresh_rate_limit_uses_family_client_without_rotating() {
    use agent_auth_http::ports::{GraceStore, RateLimitStore, RefreshStore};

    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let router = build_router(state.clone()).0;
    let token = code_flow_token_json(&router, "rate-limited-refresh-user").await;
    let refresh = token["refresh_token"].as_str().unwrap();
    let (family_id, presented_version) = refresh
        .rsplit_once('.')
        .and_then(|(family_id, version)| {
            version
                .parse::<u64>()
                .ok()
                .map(|version| (family_id, version))
        })
        .expect("refresh token uses family.version encoding");

    exhaust_client_rate_limit(&state, CLIENT).await;
    let limited = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={refresh}&client_id={CLIENT}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_client_rate_limited(limited).await;
    assert_eq!(
        state
            .refresh
            .get("", family_id)
            .await
            .unwrap()
            .expect("refresh family")
            .current_version,
        presented_version,
        "throttling must not rotate the refresh family"
    );
    assert!(
        state
            .grace
            .as_ref()
            .expect("dev grace store")
            .get(family_id, presented_version)
            .await
            .unwrap()
            .is_none(),
        "throttling must not create a grace replay entry"
    );

    state
        .rate_limit
        .as_ref()
        .unwrap()
        .delete(CLIENT)
        .await
        .unwrap();
    assert_eq!(
        refresh_exchange(&router, refresh).await.0,
        StatusCode::OK,
        "a throttled refresh must remain at the presented family version"
    );
}

// C3:code flow 返回 refresh_token;refresh grant rotation 换新 access + 新 refresh。
#[tokio::test]
async fn refresh_rotation_issues_new_tokens() {
    use agent_auth_http::ports::ClientStore;

    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let (router, _) = build_router(state.clone());
    let tok = code_flow_token_json(&router, "alice").await;
    let refresh = tok["refresh_token"]
        .as_str()
        .expect("code flow 应返回 refresh_token");
    let (family_id, version) = refresh
        .rsplit_once('.')
        .expect("refresh handle 应包含服务端 family 与 version");
    assert_eq!(version, "0", "新 family 从 version 0 开始");
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(family_id)
            .expect("dev refresh family id 应是 canonical base64url")
            .len(),
        24,
        "refresh family id 应是 24-byte opaque 引用,而不是自包含用户/client claims"
    );
    assert!(
        !family_id.is_empty()
            && !refresh.contains("alice")
            && !refresh.contains(CLIENT)
            && refresh.split('.').count() == 2,
        "refresh 应是无用户/client/JWT claims 的 opaque server-state handle"
    );
    let second = code_flow_token_json(&router, "alice-second").await;
    let second_family_id = second["refresh_token"]
        .as_str()
        .expect("第二条 code flow 应返回 refresh_token")
        .rsplit_once('.')
        .expect("第二条 refresh handle 应包含 family 与 version")
        .0;
    assert_ne!(
        second_family_id, family_id,
        "不同 family 必须得到不同的 24-byte opaque 引用"
    );

    let mut client = state.clients.get("", CLIENT).await.unwrap().unwrap();
    client.last_used_day = None;
    ClientStore::put(state.clients.as_ref(), "", client)
        .await
        .unwrap();
    let unknown = format!("{family_id}-unknown.0");
    let (unknown_status, _) = refresh_exchange(&router, &unknown).await;
    assert_eq!(
        unknown_status,
        StatusCode::BAD_REQUEST,
        "格式合法但没有服务端 family state 的 refresh handle 必须拒绝"
    );
    assert_eq!(
        state
            .clients
            .get("", CLIENT)
            .await
            .unwrap()
            .unwrap()
            .last_used_day,
        None,
        "refresh 签发失败不得推进 client 活动"
    );

    let (st, r) = refresh_exchange(&router, refresh).await;
    assert_eq!(st, StatusCode::OK, "refresh rotation 应成功");
    assert!(
        r["access_token"].as_str().is_some(),
        "refresh 应换出新 access"
    );
    let access_header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(
                r["access_token"]
                    .as_str()
                    .unwrap()
                    .split('.')
                    .next()
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        access_header["alg"], "ES256",
        "refresh rotation 签出的 access token 必须保持 ES256"
    );
    assert_eq!(access_header["typ"], "at+jwt");
    let new_refresh = r["refresh_token"]
        .as_str()
        .expect("refresh 应轮换出新 refresh");
    assert_ne!(new_refresh, refresh, "refresh 每次 rotation 必换新值");
    assert_eq!(
        new_refresh.rsplit_once('.').unwrap(),
        (family_id, "1"),
        "rotation 只推进同一服务端 family 的版本"
    );
    assert!(
        state
            .clients
            .get("", CLIENT)
            .await
            .unwrap()
            .unwrap()
            .last_used_day
            .is_some(),
        "成功 refresh rotation 必须推进 client 活动"
    );
}

#[tokio::test]
async fn refresh_kms_transient_releases_lease_without_rotating_and_returns_retry_after() {
    use agent_auth_http::adapters::memory::MemorySigner;
    use agent_auth_http::ports::RefreshStore;
    use agent_auth_http::state::SignerImpl;

    let mut state = AppState::dev(HOST);
    let isolated_signer =
        std::sync::Arc::new(SignerImpl::Memory(MemorySigner::from_seed([81; 32])));
    state.signer = isolated_signer.clone();
    state.tenant_keys = std::sync::Arc::new(
        agent_auth_http::tenant_keys::TenantKeyService::shared(isolated_signer),
    );
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let (router, _) = build_router(state.clone());
    let tokens = code_flow_token_json(&router, "refresh-kms-transient").await;
    let refresh = tokens["refresh_token"].as_str().unwrap().to_string();
    let (family_id, _) = refresh.rsplit_once('.').unwrap();
    let SignerImpl::Memory(signer) = state.signer.as_ref() else {
        panic!("dev state must use MemorySigner");
    };
    signer.fail_next_es256(true);

    let response = refresh_http_response(&router, &refresh).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let retry_after = response
        .headers()
        .get("retry-after")
        .expect("KMS transient refresh failure must include Retry-After")
        .to_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!(retry_after > 0);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["error"], "temporarily_unavailable");
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
    assert_eq!(
        state
            .refresh
            .get("", family_id)
            .await
            .unwrap()
            .unwrap()
            .current_version,
        0,
        "transient signing failure must not rotate the family"
    );

    let (retry_status, retry_body) = refresh_exchange(&router, &refresh).await;
    assert_eq!(retry_status, StatusCode::OK, "{retry_body:?}");
    assert_eq!(
        retry_body["refresh_token"]
            .as_str()
            .unwrap()
            .rsplit_once('.')
            .unwrap(),
        (family_id, "1"),
        "released lease must allow the same handle to retry successfully"
    );
}

#[tokio::test]
async fn refresh_finalize_failure_keeps_version_and_blocks_resign_until_lease_expiry() {
    use agent_auth_http::adapters::memory::MemorySigner;
    use agent_auth_http::ports::{GraceStore, RefreshLeaseAcquire, RefreshStore};
    use agent_auth_http::state::{RefreshStoreImpl, SignerImpl};

    let mut state = AppState::dev(HOST);
    let isolated_signer =
        std::sync::Arc::new(SignerImpl::Memory(MemorySigner::from_seed([82; 32])));
    state.signer = isolated_signer.clone();
    state.tenant_keys = std::sync::Arc::new(
        agent_auth_http::tenant_keys::TenantKeyService::shared(isolated_signer),
    );
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let (router, _) = build_router(state.clone());
    let tokens = code_flow_token_json(&router, "refresh-finalize-failure").await;
    let refresh = tokens["refresh_token"].as_str().unwrap().to_string();
    let (family_id, _) = refresh.rsplit_once('.').unwrap();
    let refresh_store = match state.refresh.as_ref() {
        RefreshStoreImpl::Memory(store) => store,
        #[cfg(feature = "aws")]
        RefreshStoreImpl::Dynamo(_) => panic!("test requires memory refresh store"),
    };
    let SignerImpl::Memory(signer) = state.signer.as_ref() else {
        panic!("dev state must use MemorySigner");
    };
    refresh_store.fail_next_finalize(true);
    let sign_count_before = signer.es256_sign_count();

    let response = refresh_http_response(&router, &refresh).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get("retry-after").is_some());
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["error"], "temporarily_unavailable");
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
    assert_eq!(
        state
            .refresh
            .get("", family_id)
            .await
            .unwrap()
            .unwrap()
            .current_version,
        0
    );
    assert!(
        state
            .grace
            .as_ref()
            .unwrap()
            .get(family_id, 0)
            .await
            .unwrap()
            .is_none(),
        "failed finalize must not write a grace response"
    );
    let signed_once = signer.es256_sign_count();
    assert_eq!(signed_once, sign_count_before + 1);

    let retry = refresh_http_response(&router, &refresh).await;
    assert_eq!(retry.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(retry.headers().get("retry-after").is_some());
    assert_eq!(
        signer.es256_sign_count(),
        signed_once,
        "an unexpired finalize-failure lease must block duplicate signing"
    );

    let now = agent_auth_http::current_unix_secs();
    let reclaim_at = now + 31;
    assert_eq!(
        state
            .refresh
            .acquire_lease(
                "",
                family_id,
                0,
                "expiry-probe",
                reclaim_at,
                reclaim_at + 30,
            )
            .await
            .unwrap(),
        RefreshLeaseAcquire::Acquired
    );
    assert!(state
        .refresh
        .release_lease("", family_id, 0, "expiry-probe")
        .await
        .unwrap());

    let (retry_status, retry_body) = refresh_exchange(&router, &refresh).await;
    assert_eq!(
        retry_status,
        StatusCode::OK,
        "the unchanged refresh handle must retry successfully after lease expiry: {retry_body}"
    );
    assert_eq!(
        retry_body["refresh_token"]
            .as_str()
            .unwrap()
            .rsplit_once('.')
            .unwrap(),
        (family_id, "1")
    );
    assert_eq!(
        signer.es256_sign_count(),
        signed_once + 1,
        "only the post-expiry retry may invoke the signer again"
    );
}

// spec 001 C3.3:public client 且无 DPoP 时，refresh grace cache 的有效窗口不得超过 5 秒。
#[tokio::test]
async fn public_bearer_refresh_grace_never_exceeds_five_seconds() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    assert!(
        state.grace_window_secs <= 5,
        "public bearer refresh grace 配置不得超过 5 秒"
    );
    let grace = state
        .grace
        .as_ref()
        .expect("dev 应启用 grace store")
        .clone();
    let (router, _) = build_router(state);

    let tokens = code_flow_token_json(&router, "public-grace-user").await;
    let refresh = tokens["refresh_token"]
        .as_str()
        .expect("code flow 应返回 refresh token")
        .to_string();
    let family_id = refresh.rsplit_once('.').unwrap().0.to_string();

    let started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let (status, first_response) = refresh_exchange(&router, &refresh).await;
    assert_eq!(status, StatusCode::OK);
    let rotated_refresh = first_response["refresh_token"]
        .as_str()
        .expect("首次 refresh rotation 应返回新 refresh token")
        .to_string();
    let completed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let cached = grace
        .get(&family_id, 0)
        .await
        .unwrap()
        .expect("首次 refresh rotation 应缓存 public bearer 响应");

    assert_eq!(cached.client_id, CLIENT);
    assert!(
        cached.dpop_jkt.is_none(),
        "该 public client 未绑定 DPoP，必须走短 grace window"
    );
    assert!(
        cached.expires_at >= started_at && cached.expires_at <= completed_at + 5,
        "public bearer grace cache 的实际剩余有效期必须在 0..=5 秒内"
    );

    let (replay_status, replay_response) = refresh_exchange(&router, &refresh).await;
    assert_eq!(
        replay_status,
        StatusCode::OK,
        "public bearer refresh 在 grace 截止前必须命中缓存"
    );
    assert_eq!(
        replay_response["access_token"], first_response["access_token"],
        "grace 命中必须返回缓存的同一 access token"
    );
    assert_eq!(
        replay_response["refresh_token"], first_response["refresh_token"],
        "grace 命中必须返回缓存的同一 rotated refresh token"
    );

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let wait_secs = cached.expires_at.saturating_sub(now) as u64 + 1;
    tokio::time::sleep(std::time::Duration::from_secs(wait_secs)).await;

    let (expired_status, _) = refresh_exchange(&router, &refresh).await;
    assert_eq!(
        expired_status,
        StatusCode::BAD_REQUEST,
        "public bearer refresh 越过 5 秒 grace 截止后必须拒绝旧 token"
    );
    let (family_status, _) = refresh_exchange(&router, &rotated_refresh).await;
    assert_eq!(
        family_status,
        StatusCode::BAD_REQUEST,
        "窗外复用检测必须吊销 rotated refresh 所在 family"
    );
}

// C3.6(spec 001 §4.3):多 resource 授权 {RA,RB} → 用 refresh 为 RA 下采样 rotation 后,
// 新 refresh MUST 仍绑定**整个集合**,故之后 MUST 仍能用新 refresh 为 RB 换 token(不被收窄成 RA)。
#[tokio::test]
async fn refresh_rotation_preserves_full_resource_set() {
    const RA: &str = "https://mcp.a.example.com";
    const RB: &str = "https://mcp.b.example.com";
    let router = app().await; // dev = P1,允许多 resource
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);

    // 1. authorize 带两 resource → code 绑定 {RA, RB};token 选 RA 换 access + refresh。
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice\
         &resource={RA}&resource={RB}"
    );
    let loc = get_redirect(&router, &authz).await;
    let code = query_param(&loc, "code").expect("多 resource authorize 应签 code");
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}&resource={RA}"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let tok: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let refresh = tok["refresh_token"].as_str().expect("应返回 refresh");

    // 2. 用 refresh 为 RA 下采样 rotation → 新 refresh(aud=[RA])。
    let (st, r1) = refresh_exchange_res(&router, refresh, Some(RA)).await;
    assert_eq!(st, StatusCode::OK, "为 RA refresh 应成功");
    let aud1: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(
                r1["access_token"]
                    .as_str()
                    .unwrap()
                    .split('.')
                    .nth(1)
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        aud1["aud"],
        serde_json::json!([RA]),
        "为 RA 下采样 → aud=[RA]"
    );
    let refresh2 = r1["refresh_token"]
        .as_str()
        .expect("rotation 应换新 refresh");

    // 3. 关键断言(C3.6):新 refresh 仍绑定整个集合 → 能为 RB 换 token(未被收窄成 RA)。
    let (st2, r2) = refresh_exchange_res(&router, refresh2, Some(RB)).await;
    assert_eq!(
        st2,
        StatusCode::OK,
        "新 refresh MUST 仍能为 RB 换 token(rotation 保整个集合,C3.6)"
    );
    let aud2: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(
                r2["access_token"]
                    .as_str()
                    .unwrap()
                    .split('.')
                    .nth(1)
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        aud2["aud"],
        serde_json::json!([RB]),
        "为 RB 下采样 → aud=[RB](证明集合未被上次 RA 下采样收窄)"
    );
}

// 带可选 scope 的 refresh 兑换(RFC 6749 §6 下采样)。
async fn refresh_exchange_scope(
    router: &axum::Router,
    refresh: &str,
    scope: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let sc = scope
        .map(|s| format!("&scope={}", s.replace(' ', "%20")))
        .unwrap_or_default();
    let form = format!("grant_type=refresh_token&refresh_token={refresh}&client_id={CLIENT}{sc}");
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    let st = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        st,
        serde_json::from_slice(&body).unwrap_or(serde_json::json!({})),
    )
}

// spec 006 §3.3 / RFC 6749 §6 / DESIGN §1:156:refresh scope 下采样(交集签发)。
// 授权 scope={openid profile};下采样到 {openid}→签出窄 token;超集 {openid admin}→invalid_scope;
// 不带 scope→继承全集;**C3.6:下采样后不带 scope 再 refresh MUST 仍返回全集**(family.scope 未被收窄)。
#[tokio::test]
async fn refresh_scope_downscope_and_preserves_full_set() {
    let router = app().await;
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    // authorize scope = "openid profile"(空格 URL 编码 %20)。
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid%20profile&login_user=alice"
    );
    let loc = get_redirect(&router, &authz).await;
    let code = query_param(&loc, "code").unwrap();
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let tok: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let refresh = tok["refresh_token"].as_str().expect("应返回 refresh");

    // 取 access token scope claim 的 helper。
    let scope_of = |at: &str| -> String {
        let c: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(at.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        c["scope"].as_str().unwrap_or("").to_string()
    };

    // 1. 下采样到 {openid} 子集 → 成功,签出 token 的 scope claim = "openid"(收窄)。
    let (st, r1) = refresh_exchange_scope(&router, refresh, Some("openid")).await;
    assert_eq!(st, StatusCode::OK, "子集下采样应成功: {r1}");
    assert_eq!(
        scope_of(r1["access_token"].as_str().unwrap()),
        "openid",
        "签发 scope 应收窄到请求子集"
    );
    assert_eq!(r1["scope"], "openid", "响应 scope 字段亦收窄");
    let refresh2 = r1["refresh_token"].as_str().unwrap();

    // 2. 超集 {openid admin}(admin 未授权)→ invalid_scope(RFC 6749 §6,不静默丢弃)。
    let (st2, r2) = refresh_exchange_scope(&router, refresh2, Some("openid admin")).await;
    assert_eq!(st2, StatusCode::BAD_REQUEST, "超集应拒: {r2}");
    assert_eq!(r2["error"], "invalid_scope");

    // 3. C3.6 铁律:下采样后**不带 scope** 再 refresh → 仍返回全集(family.scope 未被上次收窄)。
    //    用 refresh2(step 1 rotation 出的;step 2 失败不消费版本)。
    let (st3, r3) = refresh_exchange_scope(&router, refresh2, None).await;
    assert_eq!(st3, StatusCode::OK, "不带 scope 应成功: {r3}");
    let full = scope_of(r3["access_token"].as_str().unwrap());
    let mut parts: Vec<&str> = full.split(' ').collect();
    parts.sort_unstable();
    assert_eq!(
        parts,
        vec!["openid", "profile"],
        "C3.6:下采样后不带 scope 再 refresh MUST 仍继承全集(family.scope 未被收窄)"
    );
}

// spec 010 §4 / C8.5a / RFC 9396:RAR 发行 —— authorize 带 authorization_details(内建词汇表)→
// 签入 token 顶层 claim + Grant per_resource → **refresh 换发保留 RAR(不静默剥离,DESIGN §5.2:510)**。
#[tokio::test]
async fn rar_issuance_and_refresh_preserves() {
    // P2 state(RAR 属 P2)。
    let mut state = AppState::dev(HOST);
    state.phase = agent_auth_http::Phase::P2;
    let rs = "https://mcp.kb.example.com";
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let (router, _) = build_router(state);

    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    // authorization_details:内建词汇表,locations 指向 RS(URL 编码 JSON)。
    let rar = format!(
        r#"[{{"type":"agent_auth_rar_v1","locations":["{rs}"],"resource_subset":["{rs}/2026/"],"max_records":100}}]"#
    );
    let rar_enc = rar
        .replace('{', "%7B")
        .replace('}', "%7D")
        .replace('[', "%5B")
        .replace(']', "%5D")
        .replace('"', "%22")
        .replace(':', "%3A")
        .replace(',', "%2C")
        .replace('/', "%2F");
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice\
         &resource={rs}&authorization_details={rar_enc}"
    );
    let loc = get_redirect(&router, &authz).await;
    let code = query_param(&loc, "code").expect("带 RAR 的 authorize 应签 code");
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}&resource={rs}"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let tok: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let at = tok["access_token"].as_str().expect("应签 access token");

    // 断言 token 顶层带 authorization_details(RFC 9068/9396 §7)。
    let claims: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(at.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    let ad = claims["authorization_details"]
        .as_array()
        .expect("token 应带 authorization_details");
    assert_eq!(ad.len(), 1, "本 aud 归属一条 RAR");
    assert_eq!(ad[0]["type"], "agent_auth_rar_v1");
    assert_eq!(ad[0]["max_records"], 100);

    // **BLOCKER 验证:refresh 换发保留 RAR(不静默剥离 → 防续期扩权,DESIGN §5.2:510)。**
    let refresh = tok["refresh_token"].as_str().expect("应返回 refresh");
    let (st, r1) = refresh_exchange_res(&router, refresh, Some(rs)).await;
    assert_eq!(st, StatusCode::OK, "refresh 应成功: {r1}");
    let at2 = r1["access_token"].as_str().unwrap();
    let claims2: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(at2.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    let ad2 = claims2["authorization_details"]
        .as_array()
        .expect("refresh 换发的 token MUST 仍带 RAR(不静默剥离)");
    assert_eq!(
        ad2[0]["max_records"], 100,
        "refresh 保留源 Grant 的 RAR 约束"
    );
}

// C8.5a fail-closed:authorize 带**未知 type / 词汇表外约束字段**的 authorization_details → 拒(400)。
#[tokio::test]
async fn rar_admission_rejects_unknown() {
    let mut state = AppState::dev(HOST);
    state.phase = agent_auth_http::Phase::P2;
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let (router, _) = build_router(state);
    let challenge = s256_challenge("0123456789012345678901234567890123456789abc");
    // 未知 type → invalid_authorization_details(准入拒)。
    let bad = "%5B%7B%22type%22%3A%22custom_v9%22%7D%5D"; // [{"type":"custom_v9"}]
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice\
         &authorization_details={bad}"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&authz)
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // 准入不合规 → 400(非回跳 code)。
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "未知 RAR type 应拒 400"
    );
}

// C3.1:refresh 复用检测——旧(已轮换)refresh 再用 → family 全链吊销,后续新 refresh 也失效。
// 用**宽限窗关闭**的 state(grace=None,生产 fail-closed 姿态)证明纯复用检测:非当前版本一律拒。
#[tokio::test]
async fn refresh_reuse_detection_revokes_family() {
    let mut state = AppState::dev(HOST);
    state.grace = None; // 关宽限窗 → 任何非当前版本都是复用(fail-closed)
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let (router, _) = build_router(state);
    let tok = code_flow_token_json(&router, "bob").await;
    let r0 = tok["refresh_token"].as_str().unwrap().to_string();

    // 用 r0 换出 r1(rotation)。
    let (st1, resp1) = refresh_exchange(&router, &r0).await;
    assert_eq!(st1, StatusCode::OK);
    let r1 = resp1["refresh_token"].as_str().unwrap().to_string();

    // 复用旧的 r0(已轮换)+ 宽限窗关 → 复用检测 → 400 + family 吊销。
    let (st_reuse, _) = refresh_exchange(&router, &r0).await;
    assert_eq!(
        st_reuse,
        StatusCode::BAD_REQUEST,
        "宽限窗关时复用旧 refresh 应被拒(C3.1)"
    );

    // family 已吊销:连合法的 r1 也失效(全链吊销)。
    let (st_r1, _) = refresh_exchange(&router, &r1).await;
    assert_eq!(
        st_r1,
        StatusCode::BAD_REQUEST,
        "复用检测后 family 全链吊销,r1 也失效"
    );
}

// C3.1 原子 rotation:无 grace 时并发消费同一当前版本,至多一个请求能签出下一版本。
// 随后的旧值复用必须吊销整个 family,包括唯一赢家拿到的新 refresh。
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_refresh_rotation_has_single_winner_then_reuse_revokes_family() {
    use agent_auth_http::state::RefreshStoreImpl;

    const CONCURRENT_REQUESTS: usize = 8;
    let mut state = AppState::dev(HOST);
    state.grace = None;
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let (router, _) = build_router(state.clone());
    let tokens = code_flow_token_json(&router, "atomic-refresh-user").await;
    let original = tokens["refresh_token"]
        .as_str()
        .expect("code flow 应返回 refresh")
        .to_string();
    match state.refresh.as_ref() {
        RefreshStoreImpl::Memory(store) => {
            store
                .synchronize_next_lease_acquisitions(CONCURRENT_REQUESTS)
                .await;
        }
        #[cfg(feature = "aws")]
        RefreshStoreImpl::Dynamo(_) => panic!("test requires memory refresh store"),
    }

    let mut handles = Vec::new();
    for _ in 0..CONCURRENT_REQUESTS {
        let router = router.clone();
        let refresh = original.clone();
        handles.push(tokio::spawn(async move {
            refresh_exchange(&router, &refresh).await
        }));
    }

    let mut winners = Vec::new();
    for handle in handles {
        let (status, body) = handle.await.unwrap();
        match status {
            StatusCode::OK => winners.push(
                body["refresh_token"]
                    .as_str()
                    .expect("成功 rotation 必须返回新 refresh")
                    .to_string(),
            ),
            StatusCode::BAD_REQUEST | StatusCode::SERVICE_UNAVAILABLE => {}
            other => panic!("并发 rotation 返回非预期状态 {other}: {body}"),
        }
    }
    assert_eq!(
        winners.len(),
        1,
        "原子 rotation 必须保证同一 family/version 至多一组新 token"
    );

    let (reuse_status, _) = refresh_exchange(&router, &original).await;
    assert_eq!(
        reuse_status,
        StatusCode::BAD_REQUEST,
        "赢家产生后再次复用旧 refresh 必须触发 family 吊销"
    );
    let (winner_status, _) = refresh_exchange(&router, &winners[0]).await;
    assert_eq!(
        winner_status,
        StatusCode::BAD_REQUEST,
        "旧值复用后唯一赢家的新 refresh 也必须因全链吊销而失效"
    );
}

// C3.2:宽限窗内**同指纹**重试同一(已轮换)refresh → 返回缓存的同一组结果(不吊销、不再签)。
#[tokio::test]
async fn grace_window_same_request_returns_cached() {
    let router = app().await; // dev():grace 开、窗 5s
    let tok = code_flow_token_json(&router, "carol").await;
    let r0 = tok["refresh_token"].as_str().unwrap().to_string();

    // 首次:r0 → r1(缓存 v0 结果)。
    let (st1, resp1) = refresh_exchange(&router, &r0).await;
    assert_eq!(st1, StatusCode::OK);
    let r1 = resp1["refresh_token"].as_str().unwrap().to_string();
    let access1 = resp1["access_token"].as_str().unwrap().to_string();

    // 宽限窗内同请求重试 r0 → 命中缓存,返回同一组结果(access/refresh 逐字节相同)。
    let (st2, resp2) = refresh_exchange(&router, &r0).await;
    assert_eq!(st2, StatusCode::OK, "宽限窗内同指纹重试应返回缓存(C3.2)");
    assert_eq!(
        resp2["access_token"].as_str().unwrap(),
        access1,
        "宽限窗命中应重放同一 access token"
    );
    assert_eq!(
        resp2["refresh_token"].as_str().unwrap(),
        r1,
        "宽限窗命中应重放同一 refresh token(非再签一组)"
    );

    // family 未被吊销:r1 仍能正常 rotation。
    let (st3, _) = refresh_exchange(&router, &r1).await;
    assert_eq!(st3, StatusCode::OK, "宽限窗命中不吊销 family,r1 仍有效");
}

// C3.2:宽限窗内重放旧 refresh 时,scope/resource 任一请求指纹维度变化都按复用处理,
// 拒绝本次请求并吊销已轮换出的新 refresh。
#[tokio::test]
async fn grace_window_request_fingerprint_mismatch_revokes_family() {
    const RA: &str = "https://mcp.a.example.com";
    const RB: &str = "https://mcp.b.example.com";
    let router = app().await;
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);

    // scope mismatch:首次 refresh 省略 scope 并继承完整集合,随后用同一旧 token
    // 显式请求逐字相同的完整集合。参数存在性变化也必须改变冻结指纹。
    let scope_authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256\
         &scope=openid%20profile&login_user=grace-scope"
    );
    let scope_loc = get_redirect(&router, &scope_authz).await;
    let scope_code = query_param(&scope_loc, "code").expect("scope flow 应签 code");
    let scope_form = format!(
        "grant_type=authorization_code&code={scope_code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    let scope_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(scope_form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(scope_resp.status(), StatusCode::OK);
    let scope_body = axum::body::to_bytes(scope_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let scope_tokens: serde_json::Value = serde_json::from_slice(&scope_body).unwrap();
    let scope_r0 = scope_tokens["refresh_token"]
        .as_str()
        .expect("scope flow 应返回 refresh");
    let (scope_first_status, scope_first) = refresh_exchange_scope(&router, scope_r0, None).await;
    assert_eq!(scope_first_status, StatusCode::OK);
    let scope_r1 = scope_first["refresh_token"]
        .as_str()
        .expect("scope rotation 应返回新 refresh");

    let (scope_replay_status, scope_replay) =
        refresh_exchange_scope(&router, scope_r0, Some("openid profile")).await;
    assert_eq!(scope_replay_status, StatusCode::BAD_REQUEST);
    assert_eq!(scope_replay["error"], "invalid_grant");
    assert!(scope_replay.get("access_token").is_none());
    assert!(scope_replay.get("refresh_token").is_none());
    let (scope_family_status, _) = refresh_exchange(&router, scope_r1).await;
    assert_eq!(
        scope_family_status,
        StatusCode::BAD_REQUEST,
        "scope 指纹不符的旧 refresh 重放必须吊销 rotated family"
    );

    // resource mismatch:两个 resource 都在授权集合,因此拒绝只能来自 grace 指纹不符。
    let resource_authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid\
         &login_user=grace-resource&resource={RA}&resource={RB}"
    );
    let resource_loc = get_redirect(&router, &resource_authz).await;
    let resource_code = query_param(&resource_loc, "code").expect("multi-resource flow 应签 code");
    let resource_form = format!(
        "grant_type=authorization_code&code={resource_code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}&resource={RA}"
    );
    let resource_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(resource_form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resource_resp.status(), StatusCode::OK);
    let resource_body = axum::body::to_bytes(resource_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let resource_tokens: serde_json::Value = serde_json::from_slice(&resource_body).unwrap();
    let resource_r0 = resource_tokens["refresh_token"]
        .as_str()
        .expect("resource flow 应返回 refresh");
    let (resource_first_status, resource_first) =
        refresh_exchange_res(&router, resource_r0, Some(RA)).await;
    assert_eq!(resource_first_status, StatusCode::OK);
    let resource_r1 = resource_first["refresh_token"]
        .as_str()
        .expect("resource rotation 应返回新 refresh");

    let (resource_replay_status, resource_replay) =
        refresh_exchange_res(&router, resource_r0, Some(RB)).await;
    assert_eq!(resource_replay_status, StatusCode::BAD_REQUEST);
    assert_eq!(resource_replay["error"], "invalid_grant");
    assert!(resource_replay.get("access_token").is_none());
    assert!(resource_replay.get("refresh_token").is_none());
    let (resource_family_status, _) = refresh_exchange_res(&router, resource_r1, Some(RA)).await;
    assert_eq!(
        resource_family_status,
        StatusCode::BAD_REQUEST,
        "resource 指纹不符的旧 refresh 重放必须吊销 rotated family"
    );
}

// C3.2:application/x-www-form-urlencoded is decoded once by the HTTP extractor.
// Fingerprint canonicalization must not decode the parsed values again, or the
// distinct scope sets {"a%20b"} and {"a", "b"} collapse to the same input.
#[tokio::test]
async fn grace_window_wire_values_are_decoded_exactly_once() {
    let router = app().await;
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256\
         &scope=a%2520b%20a%20b&login_user=grace-single-decode"
    );
    let loc = get_redirect(&router, &authz).await;
    let code = query_param(&loc, "code").expect("authorize should issue a code");
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let tokens: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let refresh_r0 = tokens["refresh_token"]
        .as_str()
        .expect("code flow should return a refresh token");

    // Wire a%2520b is decoded once by Form into the single scope value a%20b.
    let (first_status, first) = refresh_exchange_scope(&router, refresh_r0, Some("a%2520b")).await;
    assert_eq!(first_status, StatusCode::OK);
    let refresh_r1 = first["refresh_token"]
        .as_str()
        .expect("rotation should return a refresh token");

    // Wire a%20b is decoded once by Form into two scope values: a and b.
    let (replay_status, replay) = refresh_exchange_scope(&router, refresh_r0, Some("a%20b")).await;
    assert_eq!(replay_status, StatusCode::BAD_REQUEST);
    assert_eq!(replay["error"], "invalid_grant");
    assert!(replay.get("access_token").is_none());
    assert!(replay.get("refresh_token").is_none());
    assert!(replay.get("id_token").is_none());

    let (family_status, family_body) = refresh_exchange(&router, refresh_r1).await;
    assert_eq!(
        family_status,
        StatusCode::BAD_REQUEST,
        "a different parsed scope set must revoke the rotated family: {family_body}"
    );
}

// C3.2: a refresh family created from a PKCE code flow carries the immutable
// originating challenge into every grace fingerprint. Authority drift must not
// let an old refresh token reuse the cached response.
#[tokio::test]
async fn grace_window_origin_pkce_challenge_is_bound() {
    use agent_auth_http::ports::RefreshStore;
    use agent_auth_http::state::RefreshStoreImpl;

    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let router = build_router(state.clone()).0;
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256\
         &scope=openid&login_user=grace-pkce-origin"
    );
    let loc = get_redirect(&router, &authz).await;
    let code = query_param(&loc, "code").expect("authorize should issue a code");
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let tokens: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let refresh_r0 = tokens["refresh_token"]
        .as_str()
        .expect("code flow should return a refresh token");
    let family_id = refresh_r0
        .rsplit_once('.')
        .expect("refresh token should carry family and version")
        .0;
    let family = RefreshStore::get(state.refresh.as_ref(), "", family_id)
        .await
        .unwrap()
        .expect("refresh family should exist");
    assert_eq!(
        family.pkce_code_challenge.as_deref(),
        Some(challenge.as_str()),
        "code exchange must persist the verified originating challenge"
    );

    let (first_status, first) = refresh_exchange(&router, refresh_r0).await;
    assert_eq!(first_status, StatusCode::OK);
    let refresh_r1 = first["refresh_token"]
        .as_str()
        .expect("rotation should return a refresh token");

    match state.refresh.as_ref() {
        RefreshStoreImpl::Memory(store) => {
            store
                .replace_pkce_code_challenge_for_test(
                    "",
                    family_id,
                    Some("different-origin-challenge".to_string()),
                )
                .await;
        }
        #[cfg(feature = "aws")]
        RefreshStoreImpl::Dynamo(_) => panic!("test requires memory refresh store"),
    }

    let (replay_status, replay) = refresh_exchange(&router, refresh_r0).await;
    assert_eq!(replay_status, StatusCode::BAD_REQUEST);
    assert_eq!(replay["error"], "invalid_grant");
    assert!(replay.get("access_token").is_none());
    assert!(replay.get("refresh_token").is_none());
    assert!(replay.get("id_token").is_none());
    let (family_status, _) = refresh_exchange(&router, refresh_r1).await;
    assert_eq!(
        family_status,
        StatusCode::BAD_REQUEST,
        "origin challenge drift must revoke the rotated family"
    );
}

// C3.2:已轮换 refresh 的 grace identity 还绑定原 client_id。另一个已注册 client
// 即使自身认证有效,重放旧 token 也必须按 reuse 吊销原 family,不得只拒绝本次请求。
#[tokio::test]
async fn grace_window_client_identity_mismatch_revokes_family() {
    const OTHER_CLIENT: &str = "grace-other-client";
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    state
        .seed_dev_client(OTHER_CLIENT, "https://other.example.com/cb", None)
        .await;
    let router = build_router(state).0;

    let tokens = code_flow_token_json(&router, "grace-client").await;
    let refresh_r0 = tokens["refresh_token"]
        .as_str()
        .expect("code flow 应返回 refresh");
    let (current_status, current_body) =
        refresh_exchange_for_client(&router, refresh_r0, OTHER_CLIENT).await;
    assert_eq!(current_status, StatusCode::BAD_REQUEST);
    assert_eq!(current_body["error"], "invalid_grant");
    assert!(current_body.get("access_token").is_none());
    assert!(current_body.get("refresh_token").is_none());
    assert!(current_body.get("id_token").is_none());

    let (first_status, first_tokens) = refresh_exchange(&router, refresh_r0).await;
    assert_eq!(first_status, StatusCode::OK);
    let refresh_r1 = first_tokens["refresh_token"]
        .as_str()
        .expect("rotation 应返回新 refresh");

    let (replay_status, replay_body) =
        refresh_exchange_for_client(&router, refresh_r0, OTHER_CLIENT).await;
    assert_eq!(replay_status, StatusCode::BAD_REQUEST);
    assert_eq!(replay_body["error"], "invalid_grant");
    assert!(replay_body.get("access_token").is_none());
    assert!(replay_body.get("refresh_token").is_none());
    assert!(replay_body.get("id_token").is_none());

    let (rotated_status, rotated_body) = refresh_exchange(&router, refresh_r1).await;
    assert_eq!(
        rotated_status,
        StatusCode::BAD_REQUEST,
        "另一已认证 client 重放旧 refresh 必须吊销 rotated family: {rotated_body}"
    );
    assert_eq!(rotated_body["error"], "invalid_grant");
}

// C3.2/C3.5:复用检测只有在 refresh family 吊销与 grace 清理均成功后才可报告
// invalid_grant。存储变更失败返回无 token 的 fail-closed 错误(transient=503,
// permanent=500),不得谎称 family 已完成吊销。
#[tokio::test]
async fn grace_window_reuse_cleanup_failures_are_retriable() {
    use agent_auth_http::state::{GraceStoreImpl, RefreshStoreImpl};

    const OTHER_CLIENT: &str = "grace-cleanup-other";
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    state
        .seed_dev_client(OTHER_CLIENT, "https://cleanup.example.com/cb", None)
        .await;
    let router = build_router(state.clone()).0;

    let tokens = code_flow_token_json(&router, "grace-cleanup").await;
    let refresh_r0 = tokens["refresh_token"]
        .as_str()
        .expect("code flow 应返回 refresh");
    let (family_id, version_r0) = refresh_r0
        .rsplit_once('.')
        .map(|(family_id, version)| (family_id, version.parse::<u64>().unwrap()))
        .expect("refresh 应包含 family 与 version");
    let (first_status, first_tokens) = refresh_exchange(&router, refresh_r0).await;
    assert_eq!(first_status, StatusCode::OK);
    let refresh_r1 = first_tokens["refresh_token"]
        .as_str()
        .expect("rotation 应返回新 refresh");

    match state.refresh.as_ref() {
        RefreshStoreImpl::Memory(store) => store.fail_next_revoke(true),
        #[cfg(feature = "aws")]
        RefreshStoreImpl::Dynamo(_) => panic!("test requires memory refresh store"),
    }
    let (revoke_failure_status, revoke_failure) =
        refresh_exchange_for_client(&router, refresh_r0, OTHER_CLIENT).await;
    assert_eq!(revoke_failure_status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(revoke_failure["error"], "temporarily_unavailable");
    assert!(revoke_failure.get("access_token").is_none());
    assert!(revoke_failure.get("refresh_token").is_none());
    assert!(revoke_failure.get("id_token").is_none());
    assert!(
        state
            .grace
            .as_ref()
            .expect("test requires grace store")
            .get(family_id, version_r0)
            .await
            .unwrap()
            .is_none(),
        "即使 revoke 失败也必须独立尝试并完成 grace 删除"
    );

    let (retry_status, retry_tokens) = refresh_exchange(&router, refresh_r1).await;
    assert_eq!(
        retry_status,
        StatusCode::OK,
        "revoke 持久化失败不得谎称 family 已吊销"
    );
    let refresh_r2 = retry_tokens["refresh_token"]
        .as_str()
        .expect("retry rotation 应返回新 refresh");
    let (_, version_r1) = refresh_r1
        .rsplit_once('.')
        .map(|(family_id, version)| (family_id, version.parse::<u64>().unwrap()))
        .expect("refresh 应包含 family 与 version");
    assert!(
        state
            .grace
            .as_ref()
            .expect("test requires grace store")
            .get(family_id, version_r1)
            .await
            .unwrap()
            .is_some(),
        "第二次 rotation 应建立 r1 grace entry"
    );

    match state.grace.as_deref() {
        Some(GraceStoreImpl::Memory(store)) => store.fail_next_delete_family(true),
        #[cfg(feature = "aws")]
        Some(GraceStoreImpl::Dynamo(_)) => panic!("test requires memory grace store"),
        None => panic!("test requires grace store"),
    }
    let (delete_failure_status, delete_failure) =
        refresh_exchange_for_client(&router, refresh_r1, OTHER_CLIENT).await;
    assert_eq!(delete_failure_status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(delete_failure["error"], "temporarily_unavailable");
    assert!(delete_failure.get("access_token").is_none());
    assert!(delete_failure.get("refresh_token").is_none());
    assert!(delete_failure.get("id_token").is_none());
    assert!(
        state
            .grace
            .as_ref()
            .expect("test requires grace store")
            .get(family_id, version_r1)
            .await
            .unwrap()
            .is_some(),
        "注入的 grace delete 失败必须保留条目以证明后续重试会清理"
    );

    let (revoked_status, revoked_body) = refresh_exchange(&router, refresh_r2).await;
    assert_eq!(revoked_status, StatusCode::BAD_REQUEST);
    assert_eq!(revoked_body["error"], "invalid_grant");
    assert!(revoked_body.get("access_token").is_none());
    assert!(revoked_body.get("refresh_token").is_none());
    assert!(revoked_body.get("id_token").is_none());
    assert!(
        state
            .grace
            .as_ref()
            .expect("test requires grace store")
            .get(family_id, version_r1)
            .await
            .unwrap()
            .is_none(),
        "AlreadyRevoked 请求必须重试并完成 grace 删除"
    );

    let permanent_tokens = code_flow_token_json(&router, "grace-cleanup-permanent").await;
    let permanent_r0 = permanent_tokens["refresh_token"]
        .as_str()
        .expect("code flow 应返回 refresh");
    let (permanent_family_id, permanent_version_r0) = permanent_r0
        .rsplit_once('.')
        .map(|(family_id, version)| (family_id, version.parse::<u64>().unwrap()))
        .expect("refresh 应包含 family 与 version");
    let (permanent_first_status, permanent_first) = refresh_exchange(&router, permanent_r0).await;
    assert_eq!(permanent_first_status, StatusCode::OK);
    let permanent_r1 = permanent_first["refresh_token"]
        .as_str()
        .expect("rotation 应返回新 refresh");

    match state.refresh.as_ref() {
        RefreshStoreImpl::Memory(store) => store.fail_next_revoke(false),
        #[cfg(feature = "aws")]
        RefreshStoreImpl::Dynamo(_) => panic!("test requires memory refresh store"),
    }
    let (permanent_revoke_status, permanent_revoke) =
        refresh_exchange_for_client(&router, permanent_r0, OTHER_CLIENT).await;
    assert_eq!(permanent_revoke_status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(permanent_revoke["error"], "server_error");
    assert!(permanent_revoke.get("access_token").is_none());
    assert!(permanent_revoke.get("refresh_token").is_none());
    assert!(permanent_revoke.get("id_token").is_none());
    assert!(
        state
            .grace
            .as_ref()
            .expect("test requires grace store")
            .get(permanent_family_id, permanent_version_r0)
            .await
            .unwrap()
            .is_none(),
        "permanent revoke 失败时仍必须独立完成 grace 删除"
    );

    let (permanent_retry_status, permanent_retry) = refresh_exchange(&router, permanent_r1).await;
    assert_eq!(permanent_retry_status, StatusCode::OK);
    let permanent_r2 = permanent_retry["refresh_token"]
        .as_str()
        .expect("retry rotation 应返回新 refresh");
    let permanent_version_r1 = permanent_r1
        .rsplit_once('.')
        .and_then(|(_, version)| version.parse::<u64>().ok())
        .expect("refresh 应包含 version");

    match state.grace.as_deref() {
        Some(GraceStoreImpl::Memory(store)) => store.fail_next_delete_family(false),
        #[cfg(feature = "aws")]
        Some(GraceStoreImpl::Dynamo(_)) => panic!("test requires memory grace store"),
        None => panic!("test requires grace store"),
    }
    let (permanent_delete_status, permanent_delete) =
        refresh_exchange_for_client(&router, permanent_r1, OTHER_CLIENT).await;
    assert_eq!(permanent_delete_status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(permanent_delete["error"], "server_error");
    assert!(permanent_delete.get("access_token").is_none());
    assert!(permanent_delete.get("refresh_token").is_none());
    assert!(permanent_delete.get("id_token").is_none());
    assert!(
        state
            .grace
            .as_ref()
            .expect("test requires grace store")
            .get(permanent_family_id, permanent_version_r1)
            .await
            .unwrap()
            .is_some(),
        "permanent grace delete 失败必须保留条目供后续重试"
    );

    let (permanent_revoked_status, permanent_revoked) =
        refresh_exchange(&router, permanent_r2).await;
    assert_eq!(permanent_revoked_status, StatusCode::BAD_REQUEST);
    assert_eq!(permanent_revoked["error"], "invalid_grant");
    assert!(permanent_revoked.get("access_token").is_none());
    assert!(permanent_revoked.get("refresh_token").is_none());
    assert!(permanent_revoked.get("id_token").is_none());
    assert!(
        state
            .grace
            .as_ref()
            .expect("test requires grace store")
            .get(permanent_family_id, permanent_version_r1)
            .await
            .unwrap()
            .is_none(),
        "permanent delete 失败后 AlreadyRevoked 请求必须完成重试清理"
    );
}

// C3.2 并发(评审 codex HIGH-1 / Kiro F1):N 个并发同指纹 r0 请求 → 至多一组新 token 签发,
// family MUST NOT 被误吊销(旧实现 CAS-false 直接 revoke 会误登出);落败者拿缓存重放或可重试 503,
// 无一返回 400 invalid_grant。之后 family 仍活(r0 窗内重放仍 200)。
#[tokio::test]
async fn concurrent_same_refresh_does_not_revoke_family() {
    let router = app().await; // grace 开
    let tok = code_flow_token_json(&router, "erin").await;
    let r0 = tok["refresh_token"].as_str().unwrap().to_string();

    // 并发 8 个同 r0(同指纹)。
    let mut handles = Vec::new();
    for _ in 0..8 {
        let router = router.clone();
        let r0 = r0.clone();
        handles.push(tokio::spawn(
            async move { refresh_exchange(&router, &r0).await },
        ));
    }
    let mut ok = 0;
    let mut retryable = 0;
    let mut bad = 0;
    let mut access_tokens = std::collections::HashSet::new();
    for h in handles {
        let (st, body) = h.await.unwrap();
        match st {
            StatusCode::OK => {
                ok += 1;
                access_tokens.insert(body["access_token"].as_str().unwrap().to_string());
            }
            StatusCode::SERVICE_UNAVAILABLE => retryable += 1,
            StatusCode::BAD_REQUEST => bad += 1,
            _ => {}
        }
    }
    assert_eq!(
        bad, 0,
        "并发同指纹续期 MUST NOT 触发 invalid_grant 吊销(误登出)"
    );
    assert!(ok >= 1, "至少一个成功");
    assert_eq!(
        ok + retryable,
        8,
        "落败者应是缓存重放(200)或可重试 503,不吊销"
    );
    // 所有 200 响应的 access token 必须是**同一个**(缓存重放,非各签各的)。
    assert_eq!(
        access_tokens.len(),
        1,
        "并发只应产出一组 token(其余重放同一组),不得各拿不同 token"
    );

    // family 仍活:窗内重放 r0 仍 200(未被误吊销)。
    let (st_after, _) = refresh_exchange(&router, &r0).await;
    assert_eq!(
        st_after,
        StatusCode::OK,
        "并发后 family 未被误吊销,r0 窗内重放仍命中"
    );
}

// C3.5:窗外(过期)重试旧 refresh → 按复用处理 → 全链吊销 + 条件删宽限缓存;此后 r1 也失效。
// 用 grace_window_secs=0(缓存项即刻过期)确定性触发"窗外"路径,免 sleep。
#[tokio::test]
async fn grace_expired_treated_as_reuse_and_revokes() {
    let mut state = AppState::dev(HOST);
    state.grace_window_secs = 0; // 缓存项 expires_at=now,判定即过期 → 窗外
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let grace = state
        .grace
        .as_ref()
        .expect("dev 应启用 grace store")
        .clone();
    let (router, _) = build_router(state);
    let tok = code_flow_token_json(&router, "dave").await;
    let r0 = tok["refresh_token"].as_str().unwrap().to_string();
    let family_id = r0.rsplit_once('.').unwrap().0.to_string();

    // r0 → r1(缓存 v0,但 expires_at=now → 立即过期)。
    let (st1, resp1) = refresh_exchange(&router, &r0).await;
    assert_eq!(st1, StatusCode::OK);
    let r1 = resp1["refresh_token"].as_str().unwrap().to_string();
    let mut sibling = grace
        .get(&family_id, 0)
        .await
        .unwrap()
        .expect("reuse 检测前应存在 family grace cache");
    sibling.version = 99;
    grace.put(sibling).await.unwrap();
    assert!(
        grace.get(&family_id, 0).await.unwrap().is_some(),
        "reuse 检测前应存在 family grace cache"
    );
    assert!(
        grace.get(&family_id, 99).await.unwrap().is_some(),
        "测试应预置同 family 的第二个 grace cache 版本"
    );

    // 复用 r0:缓存存在但已过期(窗外)→ 按复用处理 → 400 + family 吊销 + 删缓存(C3.5)。
    let (st_reuse, _) = refresh_exchange(&router, &r0).await;
    assert_eq!(
        st_reuse,
        StatusCode::BAD_REQUEST,
        "窗外重试旧 refresh 应按复用处理(C3.5)"
    );
    assert!(
        grace.get(&family_id, 0).await.unwrap().is_none(),
        "reuse detection 必须删除该 family 的原始 grace cache"
    );
    assert!(
        grace.get(&family_id, 99).await.unwrap().is_none(),
        "reuse detection 必须删除该 family 的全部 grace cache 版本"
    );

    // family 已吊销:r1 也失效(全链吊销)。
    let (st_r1, _) = refresh_exchange(&router, &r1).await;
    assert_eq!(st_r1, StatusCode::BAD_REQUEST, "吊销后 r1 失效");
}

// C3.5:/revoke 吊销 family 后 MUST 删宽限缓存——之后窗内重放旧 refresh 不再命中(family 已吊销)。
#[tokio::test]
async fn revoke_deletes_grace_cache() {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let grace = state
        .grace
        .as_ref()
        .expect("dev 应启用 grace store")
        .clone();
    let (router, _) = build_router(state);
    let tok = code_flow_token_json(&router, "frank").await;
    let r0 = tok["refresh_token"].as_str().unwrap().to_string();
    let family_id = r0.rsplit_once('.').unwrap().0.to_string();

    // r0 → r1(缓存 v0)。
    let (st1, _) = refresh_exchange(&router, &r0).await;
    assert_eq!(st1, StatusCode::OK);
    let mut sibling = grace
        .get(&family_id, 0)
        .await
        .unwrap()
        .expect("revoke 前应存在 family grace cache");
    sibling.version = 99;
    grace.put(sibling).await.unwrap();
    assert!(
        grace.get(&family_id, 0).await.unwrap().is_some(),
        "revoke 前应存在 family grace cache"
    );
    assert!(
        grace.get(&family_id, 99).await.unwrap().is_some(),
        "测试应预置同 family 的第二个 grace cache 版本"
    );

    // 确认此刻窗内重放 r0 命中缓存(200)。
    let (st_hit, _) = refresh_exchange(&router, &r0).await;
    assert_eq!(st_hit, StatusCode::OK, "吊销前窗内重放 r0 命中缓存");

    // /revoke 吊销该 family(用 r1 或 r0 的 family 部分;public client 用 client_id 认证)。
    let revoke_form = format!("token={r0}&client_id={CLIENT}");
    let rv = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/revoke")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(revoke_form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rv.status(), StatusCode::OK, "/revoke 幂等 200");

    // 吊销后窗内重放 r0:family 已吊销 → AlreadyRevoked 分支(不查缓存)→ 400;缓存也已删(C3.5)。
    let (st_after, _) = refresh_exchange(&router, &r0).await;
    assert_eq!(
        st_after,
        StatusCode::BAD_REQUEST,
        "吊销后窗内重放不得再命中缓存(C3.5:缓存已条件删)"
    );
    assert!(
        grace.get(&family_id, 0).await.unwrap().is_none(),
        "/revoke 必须删除该 family 的原始 grace cache"
    );
    assert!(
        grace.get(&family_id, 99).await.unwrap().is_none(),
        "/revoke 必须删除该 family 的全部 grace cache 版本"
    );
}

// C4 DCR:注册一个 client → 用返回的 client_id 走完整 code flow(端到端证明铸造可用)。
#[tokio::test]
async fn dcr_register_then_code_flow() {
    // 不 seed,直接注册(dev() dcr_mode=Open)。
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state);

    let reg_body = serde_json::json!({
        "redirect_uris": ["http://127.0.0.1:49152/cb"],
        "application_type": "native",
        "token_endpoint_auth_method": "none"
    });
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("host", HOST)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&reg_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "DCR 注册应 201");
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let reg: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let cid = reg["client_id"].as_str().unwrap().to_string();
    assert!(cid.starts_with("c_"), "client_id 应随机铸造");
    assert!(
        reg["registration_access_token"].as_str().is_some(),
        "含 registration_access_token"
    );
    assert_eq!(
        reg["registration_client_uri"].as_str(),
        Some(format!("https://{HOST}/register/{cid}").as_str()),
        "RFC 7592 registration_client_uri 必须是服务端给出的 fully qualified URL"
    );

    // 用铸造的 client_id 走 authorize + token。
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id={cid}&redirect_uri=http://127.0.0.1:54321/cb\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=bob"
    );
    let loc = get_redirect(&router, &authz).await;
    let code = query_param(&loc, "code").expect("注册的 client 应能拿 code");

    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri=http://127.0.0.1:54321/cb&client_id={cid}"
    );
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "铸造的 client 应能换 token");
}

#[tokio::test]
async fn dcr_invalid_host_is_rejected_before_client_is_persisted() {
    use agent_auth_http::ports::ClientStore;

    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());
    let reg_body = serde_json::json!({
        "redirect_uris": ["http://127.0.0.1:49152/cb"],
        "application_type": "native",
        "token_endpoint_auth_method": "none"
    });
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("host", "attacker.example")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&reg_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["error"], "invalid_client_metadata");
    assert!(
        ClientStore::list(&*state.clients, "")
            .await
            .unwrap()
            .is_empty(),
        "invalid issuer host must not leave a persisted dynamic client"
    );
}

async fn seed_initial_access_token(state: &AppState, one_time: bool) -> String {
    seed_initial_access_token_for_tenant(state, "", "test", one_time, 30).await
}

async fn seed_initial_access_token_for_tenant(
    state: &AppState,
    tenant: &str,
    token_label: &str,
    one_time: bool,
    rate_limit_per_minute: u32,
) -> String {
    use agent_auth_http::ports::InitialAccessTokenStore;
    let now = agent_auth_http::current_unix_secs();
    let token_id = format!("iat_{}", state.region.issue_id(token_label));
    let secret = "valid-iat-1";
    let record = agent_auth_http::credential::InitialAccessTokenRecord {
        token_id: token_id.clone(),
        credential: agent_auth_http::credential::new_credential_record(
            &state.server_secret,
            agent_auth_http::credential::CredentialKind::InitialAccessToken,
            tenant,
            token_id.clone(),
            "test-owner".to_string(),
            secret,
            now,
            now + 3_600,
            "test".to_string(),
            None,
        ),
        scopes: vec!["dcr:register".to_string()],
        rate_limit_per_minute,
        one_time,
        used_at: None,
        version: 1,
    };
    assert!(state
        .initial_access_tokens
        .put_new(tenant, record)
        .await
        .unwrap());
    format!("{token_id}.{secret}")
}

// C4.3/§3.2:initial_access_token 档缺票 → 401 invalid_token(收紧档不被匿名绕过)。
#[tokio::test]
async fn dcr_initial_access_token_missing_ticket_rejected() {
    use agent_auth_http::state::DcrMode;
    let mut state = AppState::dev(HOST);
    state.dcr_mode = DcrMode::InitialAccessToken;
    let _ = seed_initial_access_token(&state, false).await;
    let (router, _) = build_router(state);
    let reg_body = serde_json::json!({
        "redirect_uris": ["http://127.0.0.1/cb"],
        "application_type": "native"
    });
    // 无 Authorization 头 → 401。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("host", HOST)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&reg_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "initial_access_token 档缺票应 401"
    );
    assert!(
        resp.headers()
            .get("www-authenticate")
            .map(|v| v.to_str().unwrap().contains("invalid_token"))
            .unwrap_or(false),
        "应带 WWW-Authenticate: Bearer error=invalid_token(RFC 6750)"
    );
    // 错误票据 → 401。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("host", HOST)
                .header("content-type", "application/json")
                .header("authorization", "Bearer wrong-iat")
                .body(Body::from(serde_json::to_vec(&reg_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "错误票据应 401");
}

// C4.3/§3.2:initial_access_token 档带有效票 → 注册成功(201)。
#[tokio::test]
async fn dcr_initial_access_token_valid_ticket_succeeds() {
    use agent_auth_http::state::DcrMode;
    let mut state = AppState::dev(HOST);
    state.dcr_mode = DcrMode::InitialAccessToken;
    let token = seed_initial_access_token(&state, false).await;
    let (router, _) = build_router(state);
    let reg_body = serde_json::json!({
        "redirect_uris": ["http://127.0.0.1/cb"],
        "application_type": "native"
    });
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("host", HOST)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&reg_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "带有效 initial access token 应注册成功"
    );
}

#[tokio::test]
async fn dcr_rejects_initial_access_token_from_previous_regional_activation() {
    use agent_auth_http::region::{
        MemoryRegionControlStore, RegionAdmission, RegionControlRecord, RegionControlStoreImpl,
        RegionRuntime,
    };
    use agent_auth_http::state::DcrMode;

    let control = MemoryRegionControlStore::with_record(RegionControlRecord {
        active: true,
        activation_not_before: 0,
        revision: 1,
    });
    let region =
        RegionRuntime::controlled("us-east-1", RegionControlStoreImpl::Memory(control.clone()))
            .unwrap();
    assert_eq!(
        region
            .admit(agent_auth_http::current_unix_secs())
            .await
            .unwrap(),
        RegionAdmission::Active
    );

    let mut state = AppState::dev(HOST);
    state.dcr_mode = DcrMode::InitialAccessToken;
    state.region = region;
    let token = seed_initial_access_token(&state, false).await;
    control
        .set(Some(RegionControlRecord {
            active: true,
            activation_not_before: 0,
            revision: 2,
        }))
        .await;

    let (router, _) = build_router(state);
    let reg_body = serde_json::json!({ "redirect_uris": ["http://127.0.0.1/cb"] });
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("host", HOST)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&reg_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// C4.3/§3.2:software_statement 档 P0 未实现 → 501(fail-closed,不静默放行)。
#[tokio::test]
async fn dcr_software_statement_not_implemented() {
    use agent_auth_http::state::DcrMode;
    let mut state = AppState::dev(HOST);
    state.dcr_mode = DcrMode::SoftwareStatement;
    let (router, _) = build_router(state);
    let reg_body = serde_json::json!({
        "redirect_uris": ["http://127.0.0.1/cb"],
        "application_type": "native"
    });
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("host", HOST)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&reg_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_IMPLEMENTED,
        "software_statement 档 P0 应 501"
    );
}

// C10.1:同一 code 并发兑换,恰好一个成功(两阶段 lease:一个占 lease→finalize,其余 Locked/已消费)。
#[tokio::test]
async fn concurrent_same_code_only_one_succeeds() {
    let router = app().await;
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
    );
    let loc = get_redirect(&router, &authz).await;
    let code = query_param(&loc, "code").unwrap();

    // 并发 8 个同 code 兑换。
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    let mut handles = Vec::new();
    for _ in 0..8 {
        let r = router.clone();
        let f = form.clone();
        handles.push(tokio::spawn(async move {
            let resp = r
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/token")
                        .header("host", HOST)
                        .header("content-type", "application/x-www-form-urlencoded")
                        .body(Body::from(f))
                        .unwrap(),
                )
                .await
                .unwrap();
            resp.status()
        }));
    }
    let mut ok = 0;
    for h in handles {
        if h.await.unwrap() == StatusCode::OK {
            ok += 1;
        }
    }
    assert_eq!(
        ok, 1,
        "同 code 并发兑换必须恰好一个成功(两阶段 lease + 一次性消费)"
    );
}

#[tokio::test]
async fn replay_between_finalize_and_authority_writes_suppresses_first_response() {
    use agent_auth_http::ports::{GrantStore, RefreshStore};
    use agent_auth_http::state::RefreshStoreImpl;

    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let router = build_router(state.clone()).0;
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let location = get_redirect(
        &router,
        &format!(
            "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
             &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
        ),
    )
    .await;
    let code = query_param(&location, "code").unwrap();
    let (create_started, resume_create) = match state.refresh.as_ref() {
        RefreshStoreImpl::Memory(store) => store.pause_next_create().await,
        #[cfg(feature = "aws")]
        RefreshStoreImpl::Dynamo(_) => panic!("test requires memory refresh store"),
    };

    let first_router = router.clone();
    let first_code = code.clone();
    let first =
        tokio::spawn(async move { exchange_response(&first_router, &first_code, verifier).await });
    create_started.notified().await;

    let replay = exchange_response(&router, &code, verifier).await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    resume_create.notify_one();

    let first_response = first.await.unwrap();
    assert_eq!(
        first_response.status(),
        StatusCode::BAD_REQUEST,
        "the original request must suppress its token response after a concurrent replay"
    );
    let grants = state.grants.list_by_user("", "alice").await.unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].status, agent_auth_grant::GrantStatus::Revoked);
    let family = state
        .refresh
        .get("", &grants[0].grant_id)
        .await
        .unwrap()
        .expect("the resumed first request creates its family before final replay cleanup");
    assert!(family.revoked);
}

#[tokio::test]
async fn authenticated_code_replay_revokes_even_when_client_bucket_is_exhausted() {
    use agent_auth_http::ports::RateLimitStore;

    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let router = build_router(state.clone()).0;
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let location = get_redirect(
        &router,
        &format!(
            "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
             &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
        ),
    )
    .await;
    let code = query_param(&location, "code").unwrap();
    let access_token = exchange_token(&router, &code, verifier).await;

    let rate_limit = state.rate_limit.as_ref().unwrap();
    rate_limit.delete(CLIENT).await.unwrap();
    let future_now = agent_auth_http::current_unix_secs() + 60;
    assert!(
        rate_limit
            .try_consume(CLIENT, future_now, 60.0, 10.0, 60.0)
            .await
            .unwrap()
            .allowed
    );
    assert!(
        agent_auth_http::ratelimit_gate::check(&state, "", CLIENT)
            .await
            .is_some(),
        "test setup must exhaust the ordinary client token bucket"
    );

    let replay = exchange_response(&router, &code, verifier).await;
    assert_eq!(
        replay.status(),
        StatusCode::BAD_REQUEST,
        "authenticated replay cleanup must bypass ordinary issuance throttling"
    );
    let userinfo = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header("host", HOST)
                .header("authorization", format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(userinfo.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_reuses_consumed_code_rejected() {
    let router = app().await;
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&authz)
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let loc = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let code = query_param(&loc, "code").unwrap();
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}&redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    // 第一次成功。
    let r1 = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::OK);
    let body = axum::body::to_bytes(r1.into_body(), usize::MAX)
        .await
        .unwrap();
    let token_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let access_token = token_response["access_token"].as_str().unwrap().to_string();
    let refresh_token = token_response["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();

    // A consumed code alone is not enough to revoke the original result. The
    // replay request must still prove the client identity bound to that code.
    let wrong_client = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&code_verifier={verifier}\
                     &redirect_uri={REDIRECT}&client_id=wrong-client"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_client.status(), StatusCode::BAD_REQUEST);
    let before_authenticated_replay = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header("host", HOST)
                .header("authorization", format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        before_authenticated_replay.status(),
        StatusCode::OK,
        "an unauthenticated replay must not revoke the original token"
    );

    let wrong_redirect = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&code_verifier={verifier}\
                     &redirect_uri=https://attacker.example/cb&client_id={CLIENT}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_redirect.status(), StatusCode::BAD_REQUEST);

    let wrong_verifier = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&code_verifier=wrong-verifier\
                     &redirect_uri={REDIRECT}&client_id={CLIENT}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_verifier.status(), StatusCode::BAD_REQUEST);
    let before_bound_replay = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header("host", HOST)
                .header("authorization", format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        before_bound_replay.status(),
        StatusCode::OK,
        "a replay without the redirect/PKCE binding must not revoke the original token"
    );

    // 第二次同 code → invalid_grant(一次性消费)。
    let r2 = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::BAD_REQUEST, "code 重放应拒");
    assert_eq!(r2.headers()["cache-control"], "no-store");
    assert_eq!(r2.headers()["pragma"], "no-cache");
    let body = axum::body::to_bytes(r2.into_body(), usize::MAX)
        .await
        .unwrap();
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let description = error["error_description"].as_str().unwrap();
    assert!(
        description
            .bytes()
            .all(|byte| matches!(byte, 0x20..=0x21 | 0x23..=0x5b | 0x5d..=0x7e)),
        "RFC 6749 error_description contains a disallowed character: {description:?}"
    );

    let refresh = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={refresh_token}&client_id={CLIENT}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        refresh.status(),
        StatusCode::BAD_REQUEST,
        "authorization code replay must revoke the refresh family"
    );

    let userinfo = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header("host", HOST)
                .header("authorization", format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        userinfo.status(),
        StatusCode::UNAUTHORIZED,
        "authorization code replay must revoke tokens issued from that code"
    );
    let userinfo_post_header = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/userinfo")
                .header("host", HOST)
                .header("authorization", format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(userinfo_post_header.status(), StatusCode::UNAUTHORIZED);
    let userinfo_post_form = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/userinfo")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("access_token={access_token}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(userinfo_post_form.status(), StatusCode::UNAUTHORIZED);
}

// id_token payload 的 sub(base64url decode 中段)。
fn id_token_sub(id_token: &str) -> String {
    let payload = id_token.split('.').nth(1).unwrap();
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    claims["sub"].as_str().unwrap().to_string()
}

// 走一遍 code flow(带 scope/resource),返回完整 token JSON。
async fn pairwise_flow(
    router: &axum::Router,
    scope: &str,
    resource: Option<&str>,
) -> serde_json::Value {
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let res = resource
        .map(|r| format!("&resource={r}"))
        .unwrap_or_default();
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope={scope}&login_user=alice{res}"
    );
    let loc = get_redirect(router, &authz).await;
    let code = query_param(&loc, "code").unwrap();
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

// C2.11 / §2.8:pairwise 形态下 id_token.sub == /userinfo.sub(同 OIDC sector),且都 != 明文 user_id。
#[tokio::test]
async fn pairwise_id_token_sub_matches_userinfo_and_hides_user_id() {
    let mut state = AppState::dev(HOST);
    state.subject_type = agent_auth_http::SubjectType::Pairwise;
    // 单 host redirect → oidc_sector 可解析(= "app.example.com")。
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let (router, _) = build_router(state);

    // openid、无 resource → aud=<issuer>/userinfo,签 id_token。
    let tok = pairwise_flow(&router, "openid", None).await;
    let id_token = tok["id_token"].as_str().expect("openid 应返回 id_token");
    let access = tok["access_token"].as_str().unwrap();
    let id_sub = id_token_sub(id_token);

    // pairwise sub 不是明文 user_id(§2.8:HMAC 派生、假名)。
    assert_ne!(
        id_sub, "alice",
        "pairwise 下 id_token.sub 不得是明文 user_id"
    );

    // 调 /userinfo(用同一 access token,aud=/userinfo),其 sub 必与 id_token.sub 一致(C2.11)。
    let ui_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header("host", HOST)
                .header("authorization", format!("Bearer {access}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ui_resp.status(), StatusCode::OK);
    let ui_body = axum::body::to_bytes(ui_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let ui: serde_json::Value = serde_json::from_slice(&ui_body).unwrap();
    assert_eq!(
        ui["sub"].as_str().unwrap(),
        id_sub,
        "C2.11:/userinfo.sub 必等于 id_token.sub(同 OIDC sector)"
    );
}

async fn tenant_subject_code_flow(
    router: &axum::Router,
    host: &str,
    client_id: &str,
) -> serde_json::Value {
    let verifier = format!("0123456789012345678901234567890123456789{client_id}");
    let challenge = s256_challenge(&verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(authz)
                .header("host", host)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()["location"].to_str().unwrap();
    let code = query_param(location, "code").unwrap();
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}&client_id={client_id}"
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", host)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn saas_code_flow_uses_the_request_tenant_subject_profile() {
    use agent_auth_discovery::Form;
    use agent_auth_http::ports::{ClientRecord, ClientStore};
    use agent_auth_http::SubjectType;
    use std::collections::BTreeMap;

    let mut state = AppState::dev("t1.aws.example.com");
    state.form = Form::Saas {
        zone: "aws.example.com".into(),
        control_host: "c.aws.example.com".into(),
    };
    state.tenant_partitioning = true;
    state.saas_tenants = std::sync::Arc::new(vec!["t1".into(), "t3".into()]);
    state.tenant_subject_types =
        std::sync::Arc::new(BTreeMap::from([("t3".into(), SubjectType::Public)]));
    for (tenant, client_id) in [("t1", "tenant-t1-client"), ("t3", "tenant-t3-client")] {
        ClientStore::put(
            state.clients.as_ref(),
            tenant,
            ClientRecord {
                client_id: client_id.into(),
                redirect_uris: vec![REDIRECT.into()],
                application_type: Some("web".into()),
                token_endpoint_auth_method: "none".into(),
                oidc_sector_identifier: Some("app.example.com".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
    let (router, _) = build_router(state);

    let t1 = tenant_subject_code_flow(&router, "t1.aws.example.com", "tenant-t1-client").await;
    let t3 = tenant_subject_code_flow(&router, "t3.aws.example.com", "tenant-t3-client").await;
    let t1_sub = id_token_sub(t1["id_token"].as_str().unwrap());
    let t3_sub = id_token_sub(t3["id_token"].as_str().unwrap());

    assert_ne!(t1_sub, "alice", "t1 must keep the pairwise privacy default");
    assert_eq!(t3_sub, "alice", "t3 must use its explicit public profile");
    assert_ne!(
        t1_sub, t3_sub,
        "tenant profiles must change issued subjects"
    );
}

#[tokio::test]
async fn saas_host_routes_code_grant_and_refresh_to_one_tenant_partition() {
    use agent_auth_discovery::Form;
    use agent_auth_http::ports::{ClientRecord, ClientStore, GrantStore, RefreshStore};

    let client_id = "tenant-code-client";
    let mut state = AppState::dev("t1.aws.example.com");
    state.form = Form::Saas {
        zone: "aws.example.com".into(),
        control_host: "c.aws.example.com".into(),
    };
    state.tenant_partitioning = true;
    state.saas_tenants = std::sync::Arc::new(vec!["t1".into(), "t2".into()]);
    ClientStore::put(
        state.clients.as_ref(),
        "t1",
        ClientRecord {
            client_id: client_id.into(),
            redirect_uris: vec![REDIRECT.into()],
            application_type: Some("web".into()),
            token_endpoint_auth_method: "none".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let router = build_router(state.clone()).0;

    let verifier = "0123456789012345678901234567890123456789tenant";
    let challenge = s256_challenge(verifier);
    let authorization = format!(
        "/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(authorization)
                .header("host", "t1.aws.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let code = query_param(response.headers()["location"].to_str().unwrap(), "code").unwrap();
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}&client_id={client_id}"
    );

    let foreign = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", "t2.aws.example.com")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::BAD_REQUEST);
    let foreign_body = axum::body::to_bytes(foreign.into_body(), usize::MAX)
        .await
        .unwrap();
    let foreign_error: serde_json::Value = serde_json::from_slice(&foreign_body).unwrap();
    assert_eq!(foreign_error["error"], "invalid_grant");

    let owner = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", "t1.aws.example.com")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        owner.status(),
        StatusCode::OK,
        "the foreign attempt must not consume the owning tenant's code"
    );

    assert!(ClientStore::get(state.clients.as_ref(), "t1", client_id)
        .await
        .unwrap()
        .is_some());
    assert!(ClientStore::get(state.clients.as_ref(), "t2", client_id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        GrantStore::list_by_user(state.grants.as_ref(), "t1", "alice")
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        GrantStore::list_by_user(state.grants.as_ref(), "t2", "alice")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        RefreshStore::has_active_family_by_client(state.refresh.as_ref(), "t1", client_id)
            .await
            .unwrap()
    );
    assert!(
        !RefreshStore::has_active_family_by_client(state.refresh.as_ref(), "t2", client_id)
            .await
            .unwrap()
    );
}

// C2.11 / §2.8:同一 user 对不同 sector(OIDC vs MCP RS)得到不同 sub;MCP access token 的 sub != id_token.sub。
#[tokio::test]
async fn pairwise_mcp_sub_differs_from_oidc_sub() {
    let mut state = AppState::dev(HOST);
    state.subject_type = agent_auth_http::SubjectType::Pairwise;
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let (router, _) = build_router(state);

    // 流 A:openid 无 resource → id_token(OIDC sector sub)。
    let a = pairwise_flow(&router, "openid", None).await;
    let oidc_sub = id_token_sub(a["id_token"].as_str().unwrap());

    // 流 B:openid + resource=某 MCP RS → access token aud=RS,sub 按 RS sector 派生。
    let rs = "https://mcp.rs.example.com";
    let b = pairwise_flow(&router, "openid", Some(rs)).await;
    let mcp_access = b["access_token"].as_str().unwrap();
    let mcp_sub = {
        let payload = mcp_access.split('.').nth(1).unwrap();
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        // access token 的 aud 是数组(RFC 9068);断言含该 RS。
        assert_eq!(
            claims["aud"],
            serde_json::json!([rs]),
            "access token aud 应绑定 MCP RS"
        );
        claims["sub"].as_str().unwrap().to_string()
    };
    // 流 B 的 id_token 仍用 OIDC sector(与流 A 同)——跨 RS 关联被 sub 隔断,但 id_token 稳定。
    let b_id_sub = id_token_sub(b["id_token"].as_str().unwrap());

    assert_ne!(
        mcp_sub, "alice",
        "pairwise 下 MCP access sub 不得是明文 user_id"
    );
    assert_ne!(
        mcp_sub, oidc_sub,
        "§2.8:MCP RS sector 的 sub 必异于 OIDC sector 的 sub"
    );
    assert_eq!(
        b_id_sub, oidc_sub,
        "同 client 的 OIDC sector sub 稳定(与 resource 无关)"
    );
}

// access token payload 的 sub。
fn access_token_sub(access: &str) -> String {
    let payload = access.split('.').nth(1).unwrap();
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    claims["sub"].as_str().unwrap().to_string()
}

// C2.11 / §2.8:pairwise 下 refresh grant 换发的 access token,其 sub 必与原 access token 一致
// (refresh 也走同口径 pairwise 派生;否则 refresh 后 sub 漂移、泄露明文 user_id)。
#[tokio::test]
async fn pairwise_refresh_preserves_sub() {
    let mut state = AppState::dev(HOST);
    state.subject_type = agent_auth_http::SubjectType::Pairwise;
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let (router, _) = build_router(state);

    // 原 code flow:openid 无 resource → aud=/userinfo,pairwise OIDC sector sub。
    let tok = pairwise_flow(&router, "openid", None).await;
    let orig_access = tok["access_token"].as_str().unwrap();
    let orig_sub = access_token_sub(orig_access);
    assert_ne!(
        orig_sub, "alice",
        "pairwise 下 access sub 不得是明文 user_id"
    );
    let refresh = tok["refresh_token"].as_str().expect("应返回 refresh_token");

    // refresh 换发。
    let (st, r) = refresh_exchange(&router, refresh).await;
    assert_eq!(st, StatusCode::OK, "refresh 应成功");
    let new_sub = access_token_sub(r["access_token"].as_str().unwrap());
    assert_eq!(
        new_sub, orig_sub,
        "C2.11/§2.8:refresh 后 access sub 必与原 access sub 一致(不漂移、不泄露 user_id)"
    );
}

// POST /register,返回 (status, json)。
async fn register(
    router: &axum::Router,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    register_with_headers(router, body, None, None).await
}

async fn register_with_headers(
    router: &axum::Router,
    body: serde_json::Value,
    bearer: Option<&str>,
    forwarded_for: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    register_with_headers_at_host(router, HOST, body, bearer, forwarded_for).await
}

async fn register_with_headers_at_host(
    router: &axum::Router,
    host: &str,
    body: serde_json::Value,
    bearer: Option<&str>,
    forwarded_for: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let (status, _, body) =
        register_response_at_host(router, host, body, bearer, forwarded_for).await;
    (status, body)
}

async fn register_response_at_host(
    router: &axum::Router,
    host: &str,
    body: serde_json::Value,
    bearer: Option<&str>,
    forwarded_for: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri("/register")
        .header("host", host)
        .header("content-type", "application/json");
    if let Some(token) = bearer {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    if let Some(client_ip) = forwarded_for {
        request = request.header("x-forwarded-for", client_ip);
    }
    let resp = router
        .clone()
        .oneshot(
            request
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        headers,
        serde_json::from_slice(&b).unwrap_or(serde_json::json!({})),
    )
}

async fn register_with_host(
    router: &axum::Router,
    host: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("host", host)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&body).unwrap_or(serde_json::json!({})),
    )
}

#[tokio::test]
async fn dcr_application_type_defaults_persists_and_enforces_redirect_policy() {
    use agent_auth_http::ports::ClientStore;

    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());

    let (status, web) = register(
        &router,
        serde_json::json!({
            "redirect_uris": ["https://web.example.com/callback"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(web["application_type"], "web");
    let web_id = web["client_id"].as_str().unwrap();
    let stored = ClientStore::get(&*state.clients, "", web_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.application_type.as_deref(), Some("web"));

    for redirect_uri in [
        "http://127.0.0.1:49152/callback",
        "http://[::1]:49152/callback",
        "com.example.app:/oauth2/callback",
    ] {
        let (status, native) = register(
            &router,
            serde_json::json!({
                "redirect_uris": [redirect_uri],
                "application_type": "native"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{redirect_uri}");
        assert_eq!(native["application_type"], "native");
    }

    for body in [
        serde_json::json!({
            "redirect_uris": ["http://127.0.0.1/callback"]
        }),
        serde_json::json!({
            "redirect_uris": ["https://localhost./callback"]
        }),
        serde_json::json!({
            "redirect_uris": ["https://app.localhost./callback"]
        }),
        serde_json::json!({
            "redirect_uris": ["http://remote.example.com/callback"],
            "application_type": "native"
        }),
        serde_json::json!({
            "redirect_uris": ["http://localhost/callback"],
            "application_type": "native"
        }),
        serde_json::json!({
            "redirect_uris": ["https://web.example.com/callback"],
            "application_type": "desktop"
        }),
    ] {
        let (status, error) = register(&router, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            matches!(
                error["error"].as_str(),
                Some("invalid_redirect_uri" | "invalid_client_metadata")
            ),
            "{error}"
        );
    }
}

#[tokio::test]
async fn authorize_enforces_web_policy_for_legacy_and_unknown_client_records() {
    use agent_auth_http::ports::{ClientRecord, ClientStore};

    let state = AppState::dev(HOST);
    for (client_id, application_type) in [
        ("legacy-web-client", None),
        (
            "unknown-application-type-client",
            Some("desktop".to_string()),
        ),
    ] {
        ClientStore::put(
            state.clients.as_ref(),
            "",
            ClientRecord {
                client_id: client_id.into(),
                redirect_uris: vec!["https://localhost./callback".into()],
                application_type,
                token_endpoint_auth_method: "none".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
    let (router, _) = build_router(state);
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    for client_id in ["legacy-web-client", "unknown-application-type-client"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/authorize?response_type=code&client_id={client_id}\
                         &redirect_uri=https%3A%2F%2Flocalhost.%2Fcallback\
                         &code_challenge={challenge}&code_challenge_method=S256&scope=openid\
                         &login_user=alice"
                    ))
                    .header("host", HOST)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{client_id} must use the stricter web redirect policy"
        );
    }
}

// spec 005 §3.2 / C10.8:open 档匿名 POST /register 的 per-IP 注册洪水粗兜底。显式 source A
// 突发注册超桶容量(10)→ 429 temporarily_unavailable，而独立 source B 仍可注册。
// (桶补充 0.2/s 极慢,同秒内 11 次快速注册必触发;dev 内存 store 无 IO,同秒完成。)
#[tokio::test]
async fn register_per_ip_flood_throttled() {
    let state = AppState::dev(HOST); // dcr_mode = Open
    let (router, _) = build_router(state);
    let source_a = "198.51.100.10";
    let source_b = "198.51.100.11";
    let mut saw_429 = false;
    for i in 0..14 {
        let (st, headers, j) = register_response_at_host(
            &router,
            HOST,
            serde_json::json!({ "redirect_uris": [format!("https://app{i}.example.com/cb")] }),
            None,
            Some(source_a),
        )
        .await;
        if st == StatusCode::TOO_MANY_REQUESTS {
            saw_429 = true;
            assert_eq!(
                j["error"], "temporarily_unavailable",
                "注册洪水限流应 temporarily_unavailable"
            );
            assert!(
                headers
                    .get(axum::http::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
                    .is_some_and(|seconds| seconds >= 1),
                "per-IP throttling must advertise a positive Retry-After"
            );
            break;
        } else {
            assert_eq!(st, StatusCode::CREATED, "限流前的注册应 201");
        }
    }
    assert!(
        saw_429,
        "同 IP 突发注册超容量(10)应触发 per-IP 洪水限流 429(C10.8)"
    );
    let (other_status, _) = register_with_headers(
        &router,
        serde_json::json!({ "redirect_uris": ["https://other-ip.example.com/cb"] }),
        None,
        Some(source_b),
    )
    .await;
    assert_eq!(
        other_status,
        StatusCode::CREATED,
        "exhausting one source IP must not consume another source IP bucket"
    );
    let (same_status, _) = register_with_headers(
        &router,
        serde_json::json!({ "redirect_uris": ["https://same-ip-retry.example.com/cb"] }),
        None,
        Some(source_a),
    )
    .await;
    assert_eq!(
        same_status,
        StatusCode::TOO_MANY_REQUESTS,
        "the exhausted source IP must remain throttled while another source is admitted"
    );
}

#[tokio::test]
async fn register_global_quota_throttles_across_source_ips_without_creating_a_client() {
    use agent_auth_http::ports::{ClientStore, RateLimitStore};

    let state = AppState::dev(HOST);
    let rate_limit = state.rate_limit.as_ref().unwrap();
    let global_key = agent_auth_http::ratelimit_gate::register_global_quota_key("");
    assert!(
        rate_limit
            .try_consume(&global_key, i64::MAX / 4, 100.0, 2.0, 100.0)
            .await
            .unwrap()
            .allowed,
        "test setup must exhaust the tenant-global anonymous registration bucket"
    );
    let before = ClientStore::list(state.clients.as_ref(), "")
        .await
        .unwrap()
        .len();
    let (router, _) = build_router(state.clone());

    for (source, redirect) in [
        ("198.51.100.77", "https://global-quota-a.example.com/cb"),
        ("198.51.100.78", "https://global-quota-b.example.com/cb"),
    ] {
        let (status, headers, body) = register_response_at_host(
            &router,
            HOST,
            serde_json::json!({ "redirect_uris": [redirect] }),
            None,
            Some(source),
        )
        .await;

        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "the tenant-global quota must reject every source IP once exhausted"
        );
        assert_eq!(body["error"], "temporarily_unavailable");
        assert!(
            headers
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|seconds| seconds >= 1),
            "global quota rejection must advertise a positive Retry-After"
        );
    }
    assert_eq!(
        ClientStore::list(state.clients.as_ref(), "")
            .await
            .unwrap()
            .len(),
        before,
        "a globally throttled anonymous request must not create a client"
    );
}

#[tokio::test]
async fn register_global_quota_dependency_failure_is_fail_closed() {
    use agent_auth_http::ports::ClientStore;

    let mut state = AppState::dev(HOST);
    state.rate_limit = None;
    let before = ClientStore::list(state.clients.as_ref(), "")
        .await
        .unwrap()
        .len();
    let (router, _) = build_router(state.clone());

    let (status, headers, body) = register_response_at_host(
        &router,
        HOST,
        serde_json::json!({
            "redirect_uris": ["https://global-quota-unavailable.example.com/cb"]
        }),
        None,
        Some("198.51.100.78"),
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "temporarily_unavailable");
    assert_eq!(
        headers
            .get(axum::http::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("1"),
        "a missing mandatory global quota dependency must request a bounded retry"
    );
    assert_eq!(
        ClientStore::list(state.clients.as_ref(), "")
            .await
            .unwrap()
            .len(),
        before,
        "a request without the mandatory global quota dependency must not create a client"
    );
}

#[tokio::test]
async fn dcr_open_accepts_valid_iat_without_weakening_anonymous_flood_gate() {
    use agent_auth_discovery::Form;
    use agent_auth_http::ports::RateLimitStore;

    let mut state = AppState::dev("t1.aws.example.com"); // dcr_mode = Open
    state.form = Form::Saas {
        zone: "aws.example.com".into(),
        control_host: "c.aws.example.com".into(),
    };
    state.tenant_partitioning = true;
    state.saas_tenants = std::sync::Arc::new(vec!["t1".into(), "t2".into()]);
    let t1_token = seed_initial_access_token_for_tenant(&state, "t1", "t1-test", false, 1).await;
    let t2_token = seed_initial_access_token_for_tenant(&state, "t2", "t2-test", false, 1).await;
    let rate_limit = state.rate_limit.as_ref().unwrap();
    let global_key = agent_auth_http::ratelimit_gate::register_global_quota_key("t1");
    assert!(
        rate_limit
            .try_consume(&global_key, i64::MAX / 4, 100.0, 2.0, 100.0)
            .await
            .unwrap()
            .allowed,
        "test setup must exhaust the anonymous global bucket"
    );
    let (router, _) = build_router(state);

    let mut anonymous_throttled = false;
    for index in 0..14 {
        let (status, _) = register_with_headers_at_host(
            &router,
            "t1.aws.example.com",
            serde_json::json!({
                "redirect_uris": [format!("https://anonymous-{index}.example.com/cb")]
            }),
            None,
            Some("198.51.100.20"),
        )
        .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            anonymous_throttled = true;
            break;
        }
        assert_eq!(status, StatusCode::CREATED);
    }
    assert!(
        anonymous_throttled,
        "anonymous open DCR must retain its anonymous quota gates"
    );

    let (invalid_status, invalid_body) = register_with_headers_at_host(
        &router,
        "t1.aws.example.com",
        serde_json::json!({
            "redirect_uris": ["https://invalid-iat.example.com/cb"]
        }),
        Some("not-an-iat"),
        None,
    )
    .await;
    assert_eq!(
        invalid_status,
        StatusCode::UNAUTHORIZED,
        "an explicitly invalid IAT must not fall back to anonymous open DCR"
    );
    assert_eq!(invalid_body["error"], "invalid_token");

    let (valid_status, _) = register_with_headers_at_host(
        &router,
        "t1.aws.example.com",
        serde_json::json!({
            "redirect_uris": ["https://controlled-iat.example.com/cb"]
        }),
        Some(&t1_token),
        None,
    )
    .await;
    assert_eq!(
        valid_status,
        StatusCode::CREATED,
        "a valid tenant-scoped IAT must use its own quota instead of the anonymous IP bucket"
    );
    let (limited_status, limited_body) = register_with_headers_at_host(
        &router,
        "t1.aws.example.com",
        serde_json::json!({
            "redirect_uris": ["https://controlled-iat-second.example.com/cb"]
        }),
        Some(&t1_token),
        None,
    )
    .await;
    assert_eq!(
        limited_status,
        StatusCode::TOO_MANY_REQUESTS,
        "a valid IAT must consume its own configured quota"
    );
    assert_eq!(limited_body["error"], "temporarily_unavailable");

    let (cross_tenant_status, cross_tenant_body) = register_with_headers_at_host(
        &router,
        "t2.aws.example.com",
        serde_json::json!({
            "redirect_uris": ["https://cross-tenant-iat.example.com/cb"]
        }),
        Some(&t1_token),
        None,
    )
    .await;
    assert_eq!(
        cross_tenant_status,
        StatusCode::UNAUTHORIZED,
        "an IAT issued for t1 must not authorize registration in t2"
    );
    assert_eq!(cross_tenant_body["error"], "invalid_token");

    let (t2_status, _) = register_with_headers_at_host(
        &router,
        "t2.aws.example.com",
        serde_json::json!({
            "redirect_uris": ["https://t2-controlled-iat.example.com/cb"]
        }),
        Some(&t2_token),
        None,
    )
    .await;
    assert_eq!(
        t2_status,
        StatusCode::CREATED,
        "t1 quota exhaustion must not consume the independent t2 IAT quota"
    );
}

// F1/§2.8:pairwise 部署下,多 host redirect(无 sector_identifier_uri)的 DCR 注册 MUST 在注册时即拒。
#[tokio::test]
async fn pairwise_register_rejects_multi_host() {
    let mut state = AppState::dev(HOST);
    state.subject_type = agent_auth_http::SubjectType::Pairwise;
    state.dcr_mode = agent_auth_http::state::DcrMode::Open;
    let (router, _) = build_router(state);

    // 单 host → 放行(201)。
    let (st_ok, _) = register(
        &router,
        serde_json::json!({ "redirect_uris": ["https://app.example.com/cb", "https://app.example.com/cb2"] }),
    )
    .await;
    assert_eq!(st_ok, StatusCode::CREATED, "pairwise 单 host 应放行");

    // 多 host → 400 invalid_client_metadata(注册时即拒,不留签不出 id_token 的 client)。
    let (st_bad, body) = register(
        &router,
        serde_json::json!({ "redirect_uris": ["https://a.example.com/cb", "https://b.example.com/cb"] }),
    )
    .await;
    assert_eq!(
        st_bad,
        StatusCode::BAD_REQUEST,
        "pairwise 多 host 应在注册时拒(F1)"
    );
    assert_eq!(body["error"], "invalid_client_metadata");

    // public 部署:多 host 不受限(sub=user_id,无 sector 概念)。
    let pub_state = AppState::dev(HOST); // subject_type 默认 Public,dcr_mode 默认 Open
    let (pub_router, _) = build_router(pub_state);
    let (st_pub, _) = register(
        &pub_router,
        serde_json::json!({ "redirect_uris": ["https://a.example.com/cb", "https://b.example.com/cb"] }),
    )
    .await;
    assert_eq!(
        st_pub,
        StatusCode::CREATED,
        "public 部署多 host 不受 sector 限制"
    );
}

#[tokio::test]
async fn saas_dcr_uses_the_request_tenant_subject_profile() {
    use agent_auth_discovery::Form;
    use agent_auth_http::SubjectType;
    use std::collections::BTreeMap;

    let mut state = AppState::dev("t1.aws.example.com");
    state.form = Form::Saas {
        zone: "aws.example.com".into(),
        control_host: "c.aws.example.com".into(),
    };
    state.tenant_partitioning = true;
    state.saas_tenants = std::sync::Arc::new(vec!["t1".into(), "t3".into()]);
    state.tenant_subject_types =
        std::sync::Arc::new(BTreeMap::from([("t3".into(), SubjectType::Public)]));
    let (router, _) = build_router(state);
    let multi_host = serde_json::json!({
        "redirect_uris": [
            "https://a.example.com/cb",
            "https://b.example.com/cb"
        ]
    });

    let (pairwise_status, pairwise_body) =
        register_with_host(&router, "t1.aws.example.com", multi_host.clone()).await;
    assert_eq!(pairwise_status, StatusCode::BAD_REQUEST);
    assert_eq!(pairwise_body["error"], "invalid_client_metadata");

    let (public_status, _) = register_with_host(&router, "t3.aws.example.com", multi_host).await;
    assert_eq!(
        public_status,
        StatusCode::CREATED,
        "the explicit t3 public profile must not inherit t1 pairwise sector restrictions"
    );
}

#[tokio::test]
async fn dcr_prefix_redirect_is_default_off_without_an_explicit_host_allowlist() {
    let mut state = AppState::dev(HOST);
    state.dcr_mode = agent_auth_http::state::DcrMode::Open;
    let (router, _) = build_router(state.clone());

    let (status, body) = register(
        &router,
        serde_json::json!({
            "redirect_uris": ["https://callbacks.example.com/oauth/*"],
            "application_type": "web",
            "token_endpoint_auth_method": "client_secret_basic",
            "redirect_mode": "prefix"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_client_metadata");
    assert!(
        agent_auth_http::ports::ClientStore::list(&*state.clients, "")
            .await
            .unwrap()
            .is_empty(),
        "a rejected prefix registration must not persist a client"
    );
}

#[tokio::test]
async fn dcr_prefix_redirect_requires_confidential_client_and_tenant_host_allowlist() {
    use agent_auth_discovery::Form;

    let mut state = AppState::dev("t1.aws.example.com");
    state.dcr_mode = agent_auth_http::state::DcrMode::Open;
    state.form = Form::Saas {
        zone: "aws.example.com".into(),
        control_host: "c.aws.example.com".into(),
    };
    state.tenant_partitioning = true;
    state.saas_tenants = std::sync::Arc::new(vec!["t1".into(), "t3".into()]);
    state.redirect_prefix_allowed_hosts = std::sync::Arc::new(std::collections::BTreeMap::from([
        (
            "t1".to_string(),
            std::collections::BTreeSet::from(["callbacks.example.com".to_string()]),
        ),
        (
            "t3".to_string(),
            std::collections::BTreeSet::from(["t3-callbacks.example.com".to_string()]),
        ),
    ]));
    let (router, _) = build_router(state);

    let (allowed, body) = register_with_host(
        &router,
        "t1.aws.example.com",
        serde_json::json!({
            "redirect_uris": ["https://callbacks.example.com/oauth/*"],
            "application_type": "web",
            "token_endpoint_auth_method": "client_secret_basic",
            "redirect_mode": "prefix"
        }),
    )
    .await;
    assert_eq!(allowed, StatusCode::CREATED);
    assert_eq!(body["redirect_mode"], "prefix");

    let (public, _) = register_with_host(
        &router,
        "t1.aws.example.com",
        serde_json::json!({
            "redirect_uris": ["https://callbacks.example.com/public/*"],
            "application_type": "web",
            "token_endpoint_auth_method": "none",
            "redirect_mode": "prefix"
        }),
    )
    .await;
    assert_eq!(public, StatusCode::BAD_REQUEST);

    let (unknown_host, _) = register_with_host(
        &router,
        "t1.aws.example.com",
        serde_json::json!({
            "redirect_uris": ["https://other.example.com/oauth/*"],
            "application_type": "web",
            "token_endpoint_auth_method": "client_secret_basic",
            "redirect_mode": "prefix"
        }),
    )
    .await;
    assert_eq!(unknown_host, StatusCode::BAD_REQUEST);

    let (other_tenant, _) = register_with_host(
        &router,
        "t3.aws.example.com",
        serde_json::json!({
            "redirect_uris": ["https://callbacks.example.com/oauth/*"],
            "application_type": "web",
            "token_endpoint_auth_method": "client_secret_basic",
            "redirect_mode": "prefix"
        }),
    )
    .await;
    assert_eq!(
        other_tenant,
        StatusCode::BAD_REQUEST,
        "t1 must not lend its redirect-prefix host allowlist to t3"
    );

    let (t3_allowed, body) = register_with_host(
        &router,
        "t3.aws.example.com",
        serde_json::json!({
            "redirect_uris": ["https://t3-callbacks.example.com/oauth/*"],
            "application_type": "web",
            "token_endpoint_auth_method": "client_secret_basic",
            "redirect_mode": "prefix"
        }),
    )
    .await;
    assert_eq!(t3_allowed, StatusCode::CREATED);
    assert_eq!(body["redirect_mode"], "prefix");

    let (t3_host_at_t1, _) = register_with_host(
        &router,
        "t1.aws.example.com",
        serde_json::json!({
            "redirect_uris": ["https://t3-callbacks.example.com/oauth/*"],
            "application_type": "web",
            "token_endpoint_auth_method": "client_secret_basic",
            "redirect_mode": "prefix"
        }),
    )
    .await;
    assert_eq!(
        t3_host_at_t1,
        StatusCode::BAD_REQUEST,
        "t3 must not lend its redirect-prefix host allowlist to t1"
    );

    for invalid in [
        serde_json::json!({
            "redirect_uris": ["http://callbacks.example.com/oauth/*"],
            "application_type": "web",
            "token_endpoint_auth_method": "client_secret_basic",
            "redirect_mode": "prefix"
        }),
        serde_json::json!({
            "redirect_uris": ["https://callbacks.example.com/oauth/*?source=test"],
            "application_type": "web",
            "token_endpoint_auth_method": "client_secret_basic",
            "redirect_mode": "prefix"
        }),
        serde_json::json!({
            "redirect_uris": ["https://callbacks.example.com/oauth/*#fragment"],
            "application_type": "web",
            "token_endpoint_auth_method": "client_secret_basic",
            "redirect_mode": "prefix"
        }),
        serde_json::json!({
            "redirect_uris": ["https://callbacks.example.com/oauth/callback"],
            "application_type": "web",
            "token_endpoint_auth_method": "client_secret_basic",
            "redirect_mode": "prefix"
        }),
        serde_json::json!({
            "redirect_uris": ["https://callbacks.example.com/oauth/*"],
            "application_type": "native",
            "token_endpoint_auth_method": "client_secret_basic",
            "redirect_mode": "prefix"
        }),
    ] {
        let (status, _) = register_with_host(&router, "t1.aws.example.com", invalid).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

// spec 011 增量 A(C7.8/C7.8a):access token 与 id_token 各带**唯一 jti**(token-exchange subject 解析前置)。
#[tokio::test]
async fn access_and_id_token_carry_distinct_jti() {
    let router = app().await;
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
    );
    let loc = get_redirect(&router, &authz).await;
    let code = query_param(&loc, "code").unwrap();
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let tok: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let claim = |jwt: &str, key: &str| -> Option<String> {
        let payload = jwt.split('.').nth(1)?;
        let c: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
        c.get(key)?.as_str().map(str::to_string)
    };
    let at_jti =
        claim(tok["access_token"].as_str().unwrap(), "jti").expect("access token 应带 jti");
    let id_jti = claim(tok["id_token"].as_str().unwrap(), "jti").expect("id_token 应带 jti(C7.8a)");
    assert!(!at_jti.is_empty() && !id_jti.is_empty(), "jti 非空");
    assert_ne!(
        at_jti, id_jti,
        "access token 与 id_token 的 jti 互不相同(各自唯一)"
    );
}

// spec 005 §9.3(C10.5):tombstone client 的签发/建授权路径 fail-closed。
// authorize 建 code 前拒;已 tombstone 后 code flow /token 拒 invalid_client。
#[tokio::test]
async fn tombstoned_client_rejected_at_authorize_and_token() {
    use agent_auth_http::AppState;
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let router = {
        let (r, _) = build_router(state.clone());
        r
    };
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&state=xyz&login_user=alice"
    );

    // 未 tombstone:authorize 正常 302,拿到一个**真实有效 code**(先取,后 tombstone,验 /token 闸)。
    let loc = get_redirect(&router, &authz).await;
    assert!(
        loc.starts_with(REDIRECT),
        "未回收 client authorize 应 302 回跳"
    );
    let real_code = query_param(&loc, "code").expect("应得有效 code");

    // 转 tombstone(模拟回收任务:snapshot=None 允许,client 从未 touch)。
    use agent_auth_http::ports::ClientStore;
    assert!(
        state
            .clients
            .convert_to_tombstone("", CLIENT, 12345, None, 0)
            .await
            .unwrap(),
        "首次 tombstone 应成功"
    );

    // tombstone 后:authorize 拒 400(不建 code/session)。
    let denied = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&authz)
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        denied.status(),
        StatusCode::BAD_REQUEST,
        "tombstone client authorize 应 400 拒(不建新 code/session)"
    );

    // tombstone 后:用**真实有效 code** 换 token → client authentication 拒 401 invalid_client,不签。
    let form = format!(
        "grant_type=authorization_code&code={real_code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    let tok = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        tok.status(),
        StatusCode::UNAUTHORIZED,
        "tombstone client /token 应拒(invalid_client,不签)"
    );
    let body = axum::body::to_bytes(tok.into_body(), usize::MAX)
        .await
        .unwrap();
    let j: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(j["error"], "invalid_client", "错误码应 invalid_client");
}

// spec 005 §9.2(C10.5):成功签发后 client last_used_day 被记(天级追踪)。
#[tokio::test]
async fn successful_token_touches_client_last_used() {
    use agent_auth_http::ports::ClientStore;
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    // 签发前:未使用。
    assert_eq!(
        state
            .clients
            .get("", CLIENT)
            .await
            .unwrap()
            .unwrap()
            .last_used_day,
        None,
        "签发前 last_used_day=None"
    );
    let router = {
        let (r, _) = build_router(state.clone());
        r
    };
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&state=x&login_user=alice"
    );
    let loc = get_redirect(&router, &authz).await;
    let code = query_param(&loc, "code").expect("code");

    let failed = exchange_response(&router, "not-an-issued-code", verifier).await;
    assert_eq!(failed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        state
            .clients
            .get("", CLIENT)
            .await
            .unwrap()
            .unwrap()
            .last_used_day,
        None,
        "authorization-code 签发失败不得推进 client 活动"
    );

    let _ = exchange_token(&router, &code, verifier).await;
    // 签发后:last_used_day 已记(天级桶,>0)。
    let day = state
        .clients
        .get("", CLIENT)
        .await
        .unwrap()
        .unwrap()
        .last_used_day;
    assert!(
        day.is_some_and(|d| d > 0),
        "签发后 last_used_day 应被记(天级),得 {day:?}"
    );
}

#[tokio::test]
async fn client_activity_observation_failure_does_not_break_token_issuance() {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let (router, _) = build_router(state.clone());
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let authorization = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
    );
    let location = get_redirect(&router, &authorization).await;
    let code = query_param(&location, "code").expect("authorization code");

    match state.clients.as_ref() {
        ClientStoreImpl::Memory(store) => store.fail_next_touch_last_used(),
        #[allow(unreachable_patterns)]
        _ => panic!("dev state must use the memory client store"),
    }

    let response = exchange_response(&router, &code, verifier).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "best-effort activity observation must not reverse successful token issuance"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let tokens: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        tokens["access_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty()),
        "successful issuance must still return an access token"
    );
}
