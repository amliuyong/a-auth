//! 进程内 e2e:PAR(RFC 9126,spec 006 §7.3,P3)。
//!
//! 全链:POST /par(存授权参数→request_uri)→ GET /authorize?request_uri=→ 签 code(与直连等价)。
//! + 双评审 fail-closed:phase<P3 → 404;篡改其余 query 被忽略;一次性重放拒;过期拒;
//!   confidential client_secret 不落库(存前剔除);public 无认证并强制 PKCE。

use agent_auth_client::s256_challenge;
use agent_auth_http::{build_router, AppState, Phase};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

const HOST: &str = "localhost";
const CLIENT: &str = "par-client";
const REDIRECT: &str = "https://par-app.example.com/cb";
const VERIFIER: &str = "0123456789012345678901234567890123456789abc";

async fn p3_app() -> (axum::Router, AppState) {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P3;
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let (r, _) = build_router(state.clone());
    (r, state)
}

fn query_param(location: &str, key: &str) -> Option<String> {
    let q = location.split('?').nth(1)?;
    q.split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")).map(|v| v.to_string()))
}

// POST /par(form body)→ (status, json)。
async fn post_par(router: &axum::Router, body: &str) -> (StatusCode, serde_json::Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/par")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.to_string()))
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
        serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null),
    )
}

// GET /authorize?<query> → 302 Location(或非 302 时返回状态串)。
async fn get_authorize(router: &axum::Router, query: &str) -> (StatusCode, Option<String>) {
    let resp = router
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
    let st = resp.status();
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    (st, loc)
}

fn par_body() -> String {
    let challenge = s256_challenge(VERIFIER);
    format!(
        "response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&state=xyz&login_user=alice"
    )
}

// 快乐路径:/par → request_uri → /authorize?request_uri → 签 code。
#[tokio::test]
async fn par_push_then_authorize_issues_code() {
    let (router, _s) = p3_app().await;
    let (st, j) = post_par(&router, &par_body()).await;
    assert_eq!(st, StatusCode::CREATED, "/par 应 201");
    let request_uri = j["request_uri"].as_str().expect("request_uri");
    assert!(
        request_uri.starts_with("urn:ietf:params:oauth:request_uri:"),
        "request_uri MUST 是 RFC 9126 URN,得 {request_uri}"
    );
    assert!(j["expires_in"].as_i64().unwrap() > 0);

    // request_uri percent-encode 进 authorize query。
    let enc = request_uri.replace(':', "%3A");
    let (ast, loc) = get_authorize(&router, &format!("request_uri={enc}")).await;
    assert_eq!(
        ast,
        StatusCode::SEE_OTHER,
        "authorize?request_uri 应 302 签 code"
    );
    let loc = loc.unwrap();
    assert!(loc.starts_with(REDIRECT));
    assert!(query_param(&loc, "code").is_some(), "回跳应带 code");
    assert_eq!(
        query_param(&loc, "state").as_deref(),
        Some("xyz"),
        "存储的 state echo"
    );
}

// 一次性:同 request_uri 二次 authorize → 拒。
#[tokio::test]
async fn par_request_uri_one_shot() {
    let (router, _s) = p3_app().await;
    let (_st, j) = post_par(&router, &par_body()).await;
    let request_uri = j["request_uri"].as_str().unwrap();
    let enc = request_uri.replace(':', "%3A");
    let (ast1, _) = get_authorize(&router, &format!("request_uri={enc}")).await;
    assert_eq!(ast1, StatusCode::SEE_OTHER, "首次 302");
    let (ast2, _) = get_authorize(&router, &format!("request_uri={enc}")).await;
    assert_eq!(
        ast2,
        StatusCode::BAD_REQUEST,
        "同 request_uri 二次 → 400(一次性 consume)"
    );
}

// 防篡改:authorize 忽略请求里其余 query(含 client_id/scope),只认存储参数。
#[tokio::test]
async fn par_authorize_ignores_extra_query() {
    let (router, _s) = p3_app().await;
    let (_st, j) = post_par(&router, &par_body()).await;
    let request_uri = j["request_uri"].as_str().unwrap();
    let enc = request_uri.replace(':', "%3A");
    // 附加 client_id/scope/redirect_uri/request —— 应全被忽略,仍用存储的 CLIENT/REDIRECT。
    let (ast, loc) = get_authorize(
        &router,
        &format!(
            "request_uri={enc}&client_id=evil&scope=evil\
             &redirect_uri=https%3A%2F%2Fevil.com%2Fcb&request=ignored"
        ),
    )
    .await;
    assert_eq!(ast, StatusCode::SEE_OTHER, "篡改参数不应阻断(被忽略)");
    let loc = loc.unwrap();
    assert!(
        loc.starts_with(REDIRECT),
        "回跳 MUST 是存储的 redirect_uri(非篡改的 evil.com),得 {loc}"
    );
}

// 阶段门控:phase<P3 → /par 404。
#[tokio::test]
async fn par_endpoint_404_below_p3() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2; // < P3
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let (router, _) = build_router(state);
    let (st, _) = post_par(&router, &par_body()).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "phase<P3 /par 应 404");
}

// Public client 的 PKCE 必带:/par 缺 code_challenge → 400。
#[tokio::test]
async fn par_requires_pkce() {
    let (router, _s) = p3_app().await;
    let body =
        format!("response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}&scope=openid");
    let (st, _) = post_par(&router, &body).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "缺 PKCE → 400");
}

// 造一个 client_secret_post 的 confidential client(seed 无 post 便利,直接 put)。
async fn seed_post_client(state: &AppState, id: &str, secret: &str) {
    use agent_auth_http::ports::{ClientRecord, ClientStore};
    state
        .clients
        .put(
            "",
            ClientRecord {
                client_id: id.to_string(),
                redirect_uris: vec!["https://x/cb".to_string()],
                token_endpoint_auth_method: "client_secret_post".to_string(),
                client_secret: Some(secret.to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

// H3:confidential client 走 /par(client_secret_post,secret 在 body),存储**不含** client_secret。
#[tokio::test]
async fn par_strips_client_secret_from_storage() {
    use agent_auth_http::ports::ParStore;
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P3;
    seed_post_client(&state, "conf-par", "sekret-xyz").await;
    let st_clone = state.clone();
    let (router, _) = build_router(state);
    let challenge = s256_challenge(VERIFIER);
    // client_secret_post:secret 在 body 里。
    let body = format!(
        "response_type=code&client_id=conf-par&redirect_uri=https%3A%2F%2Fx%2Fcb\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&client_secret=sekret-xyz"
    );
    let (st, j) = post_par(&router, &body).await;
    assert_eq!(
        st,
        StatusCode::CREATED,
        "confidential /par(正确 secret)应 201,得 {j:?}"
    );
    let request_uri = j["request_uri"].as_str().unwrap();
    // 直接 consume 存储记录,断言 raw_params 不含 client_secret(H3)。
    let now = agent_auth_http::current_unix_secs();
    let rec = st_clone
        .par
        .consume("", request_uri, now)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !rec.raw_params.contains("client_secret"),
        "存储的 raw_params MUST NOT 含 client_secret(H3 防明文落库),得 {}",
        rec.raw_params
    );
    assert_eq!(rec.client_id, "conf-par");
}

#[tokio::test]
async fn par_allows_authenticated_confidential_client_without_pkce() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P3;
    seed_post_client(&state, "conf-par-no-pkce", "sekret-no-pkce").await;
    let (router, _) = build_router(state);
    let body = "response_type=code&client_id=conf-par-no-pkce\
                &redirect_uri=https%3A%2F%2Fx%2Fcb&scope=openid\
                &client_secret=sekret-no-pkce";
    let (status, response) = post_par(&router, body).await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "authenticated confidential PAR without PKCE should succeed: {response}"
    );
    assert!(response["request_uri"]
        .as_str()
        .is_some_and(|value| value.starts_with("urn:ietf:params:oauth:request_uri:")));
}

#[tokio::test]
async fn par_confidential_pkce_exemption_requires_both_parameters_absent() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P3;
    seed_post_client(&state, "conf-par-malformed-pkce", "sekret-malformed").await;
    let (router, _) = build_router(state);

    for malformed in [
        "code_challenge_method=S256",
        "code_challenge=&code_challenge_method=S256",
    ] {
        let body = format!(
            "response_type=code&client_id=conf-par-malformed-pkce\
             &redirect_uri=https%3A%2F%2Fx%2Fcb&scope=openid\
             &client_secret=sekret-malformed&{malformed}"
        );
        let (status, _) = post_par(&router, &body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "malformed PKCE tuple must not receive the confidential PAR exemption: {malformed}"
        );
    }
}

#[tokio::test]
async fn par_rejects_workload_client_authorization_code() {
    use agent_auth_http::ports::{ClientRecord, ClientStore};

    let mut state = AppState::dev(HOST);
    state.phase = Phase::P3;
    state
        .clients
        .put(
            "",
            ClientRecord {
                client_id: "workload-par".into(),
                redirect_uris: vec!["https://x/cb".into()],
                token_endpoint_auth_method: "client_secret_post".into(),
                client_secret: Some("workload-par-secret".into()),
                client_type: Some("workload".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (router, _) = build_router(state);
    let challenge = s256_challenge(VERIFIER);
    let body = format!(
        "response_type=code&client_id=workload-par&redirect_uri=https%3A%2F%2Fx%2Fcb\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid\
         &client_secret=workload-par-secret"
    );
    let (status, _) = post_par(&router, &body).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "workload clients must not create authorization-code PAR records"
    );
}

// confidential client 错 secret → /par 401(client 认证)。
#[tokio::test]
async fn par_confidential_wrong_secret_rejected() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P3;
    seed_post_client(&state, "conf-par2", "right-secret").await;
    let (router, _) = build_router(state);
    let challenge = s256_challenge(VERIFIER);
    let body = format!(
        "response_type=code&client_id=conf-par2&redirect_uri=https%3A%2F%2Fx%2Fcb\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&client_secret=WRONG"
    );
    let (st, _) = post_par(&router, &body).await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "confidential 错 secret /par → 401"
    );
}
