//! 进程内 e2e:P1a RP-logout(C9.6)+ prompt/max_age(C9.5a)。内存适配器,无 AWS。
//!
//! - /end-session:清会话 cookie(Max-Age=0 + 属性)、id_token_hint 无效拒不清、
//!   post_logout_redirect_uri 精确匹配(未注册拒)、GET+POST。
//! - /authorize prompt/max_age:prompt=none 无会话→login_required、prompt=login 强制重认证、
//!   max_age 超时重认证、反向(prompt=none 有会话不误拒)。

use agent_auth_client::s256_challenge;
use agent_auth_http::ports::{ClientStore, SessionRecord, SessionStore, Signer};
use agent_auth_http::{build_router, AppState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::Value;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

const HOST: &str = "localhost";
const CLIENT: &str = "logout-client";
const REDIRECT: &str = "https://client.example/cb";
const PLR: &str = "https://client.example/after-logout";

fn set_cookie_val(resp: &axum::http::Response<Body>, name: &str) -> Option<String> {
    for hv in resp.headers().get_all(axum::http::header::SET_COOKIE) {
        let s = hv.to_str().ok()?;
        if let Some(rest) = s.strip_prefix(&format!("{name}=")) {
            return Some(rest.split(';').next().unwrap_or("").to_string());
        }
    }
    None
}

// 取某个 name 的完整 Set-Cookie 行(判属性)。
fn set_cookie_line(resp: &axum::http::Response<Body>, name: &str) -> Option<String> {
    for hv in resp.headers().get_all(axum::http::header::SET_COOKIE) {
        let s = hv.to_str().ok()?;
        if s.starts_with(&format!("{name}=")) {
            return Some(s.to_string());
        }
    }
    None
}

async fn login_with_authorize_query(
    router: &axum::Router,
    email: &str,
    authorize_query: &str,
) -> (String, String) {
    let body = serde_json::json!({ "email": email, "authorize_query": authorize_query });
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login/magic-link")
                .header("host", HOST)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let nonce = set_cookie_val(&resp, "__Host-agent_auth_login_nonce").unwrap();
    let rbody = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let dev_link = serde_json::from_slice::<serde_json::Value>(&rbody).unwrap()["dev_link"]
        .as_str()
        .unwrap()
        .to_string();
    let pq = dev_link
        .split_once("/login/callback")
        .unwrap()
        .1
        .to_string();
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/login/callback{pq}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_login_nonce={nonce}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let session = set_cookie_val(&resp, "__Host-agent_auth_session").unwrap();
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    (session, location)
}

async fn login(router: &axum::Router, email: &str) -> String {
    login_with_authorize_query(router, email, "").await.0
}

async fn sign_rs256_hint(state: &AppState, aud: &str, exp: i64) -> String {
    let issuer = agent_auth_discovery::derive_issuer(HOST, &state.form).unwrap();
    let kid = state.signer.active_rsa_kid().await.unwrap();
    let header = serde_json::json!({"alg": "RS256", "typ": "JWT", "kid": kid});
    let claims = serde_json::json!({
        "iss": issuer.as_str(),
        "sub": "pairwise-logout-subject",
        "aud": aud,
        "iat": exp - 900,
        "exp": exp,
        "auth_time": exp - 900,
        "jti": format!("logout-hint-{aud}-{exp}"),
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let (_, signature) = state
        .signer
        .sign_rs256(signing_input.as_bytes())
        .await
        .unwrap();
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

async fn assert_valid_logout_hint(alg: &str, email: &str) {
    let state = AppState::dev(HOST);
    state
        .seed_dev_client_with_logout(CLIENT, REDIRECT, &[PLR])
        .await;
    let mut client = state.clients.get("", CLIENT).await.unwrap().unwrap();
    client.id_token_signed_response_alg = Some(alg.to_string());
    state.clients.put("", client).await.unwrap();
    state.seed_dev_user(email).await;
    let (router, _) = build_router(state);
    let session = login(&router, email).await;
    let token_response = authorize_via_consent(&router, &session, "").await;
    let hint = token_response["id_token"].as_str().unwrap();
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(hint.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(header["alg"], alg);
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("id_token_hint", hint)
        .append_pair("post_logout_redirect_uri", PLR)
        .append_pair("state", alg)
        .finish();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/end-session?{query}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()["location"].to_str().unwrap();
    assert!(
        location.starts_with(PLR) && url_param(location, "state").as_deref() == Some(alg),
        "合法 {alg} hint 应选择 client 并安全回跳: {location}"
    );

    let after_logout = authorize(&router, "", Some(&session)).await;
    assert_eq!(after_logout.status(), StatusCode::SEE_OTHER);
    let location = after_logout.headers()["location"].to_str().unwrap();
    assert!(
        location.contains("/login?") && !location.contains("/consent?"),
        "合法 {alg} hint 登出后旧 cookie 不得继续授权: {location}"
    );
}

// ---- C9.6 RP-logout ----

#[tokio::test]
async fn end_session_clears_cookie_and_session() {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    state.seed_dev_user("alice@example.com").await;
    let (router, _) = build_router(state);
    let session = login(&router, "alice@example.com").await;

    // 登出前:会话有效(consent/context 200)。
    let aq = format!("client_id={CLIENT}&redirect_uri={REDIRECT}&scope=openid");
    let probe = |cookie: String| {
        let router = router.clone();
        let uri = format!("/consent/context?{aq}");
        async move {
            router
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(uri)
                        .header("host", HOST)
                        .header("cookie", cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(
        probe(format!("__Host-agent_auth_session={session}")).await,
        StatusCode::OK
    );

    // GET /end-session(带会话 cookie,无 id_token_hint)→ 清 cookie。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/end-session")
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success());
    // Set-Cookie 清除:Max-Age=0 + 同属性(Path/Secure/HttpOnly)。
    let line = set_cookie_line(&resp, "__Host-agent_auth_session").expect("清 cookie Set-Cookie");
    assert!(line.contains("Max-Age=0"), "清 cookie 须 Max-Age=0: {line}");
    assert!(
        line.contains("Path=/") && line.contains("Secure") && line.contains("HttpOnly"),
        "属性须一致: {line}"
    );

    // 登出后:该会话已删,再探针 401。
    assert_eq!(
        probe(format!("__Host-agent_auth_session={session}")).await,
        StatusCode::UNAUTHORIZED,
        "登出后会话应失效"
    );

    let authorize_after_logout = authorize(&router, "", Some(&session)).await;
    assert_eq!(authorize_after_logout.status(), StatusCode::SEE_OTHER);
    let location = authorize_after_logout
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        location.contains("/login?") && !location.contains("/consent?"),
        "登出后的旧 cookie 访问 /authorize 必须重新登录: {location}"
    );
}

#[tokio::test]
async fn end_session_post_works() {
    let state = AppState::dev(HOST);
    state.seed_dev_user("bob@example.com").await;
    let (router, _) = build_router(state);
    let session = login(&router, "bob@example.com").await;
    // POST /end-session(form body)。
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/end-session")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::from(""))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success(), "POST /end-session 应支持");
    assert!(set_cookie_line(&resp, "__Host-agent_auth_session")
        .unwrap()
        .contains("Max-Age=0"));
}

#[tokio::test]
async fn end_session_valid_rs256_and_es256_id_token_hints_select_client_and_logout() {
    assert_valid_logout_hint("RS256", "rs256-logout@example.com").await;
    assert_valid_logout_hint("ES256", "es256-logout@example.com").await;
}

#[tokio::test]
async fn end_session_invalid_id_token_hint_rejected_no_clear() {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    state
        .seed_dev_client("other-logout-client", REDIRECT, None)
        .await;
    state.seed_dev_user("carol@example.com").await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let expired = sign_rs256_hint(&state, CLIENT, now - 301).await;
    let wrong_audience = sign_rs256_hint(&state, "other-logout-client", now + 900).await;
    let (router, _) = build_router(state);
    let session = login(&router, "carol@example.com").await;
    let valid = authorize_via_consent(&router, &session, "").await;
    let tampered = tamper_signature(valid["id_token"].as_str().unwrap());

    for (label, hint, client_id) in [
        ("malformed", "forged.jwt.token", None),
        ("tampered", tampered.as_str(), None),
        ("expired", expired.as_str(), None),
        ("wrong-audience", wrong_audience.as_str(), Some(CLIENT)),
    ] {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        serializer.append_pair("id_token_hint", hint);
        if let Some(client_id) = client_id {
            serializer.append_pair("client_id", client_id);
        }
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/end-session?{}", serializer.finish()))
                    .header("host", HOST)
                    .header("cookie", format!("__Host-agent_auth_session={session}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "{label} id_token_hint 应拒"
        );
        assert!(
            set_cookie_line(&resp, "__Host-agent_auth_session").is_none(),
            "{label} hint 被拒时不得清 cookie"
        );
    }

    // 会话未被清:探针仍 200。
    let aq = format!("client_id={CLIENT}&redirect_uri={REDIRECT}&scope=openid");
    let st = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/consent/context?{aq}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status();
    assert_eq!(st, StatusCode::OK, "伪造 hint 被拒后会话 MUST NOT 被清");
}

#[tokio::test]
async fn post_logout_redirect_unregistered_rejected() {
    let state = AppState::dev(HOST);
    // client 注册了 PLR;另一个未注册值应拒。
    state
        .seed_dev_client_with_logout(CLIENT, REDIRECT, &[PLR])
        .await;
    state.seed_dev_user("dave@example.com").await;
    state.seed_dev_user("erin@example.com").await;
    let (router, _) = build_router(state);
    let session = login(&router, "dave@example.com").await;

    // 未注册、尾斜杠近似值和 query 近似值都必须逐字拒绝；prefix/规范化匹配均不可接受。
    for candidate in [
        "http://evil.example.com/x",
        "HTTPS://client.example/after-logout",
        "https://CLIENT.example/after-logout",
        "https://client.example:443/after-logout",
        "https://client.example/after-logout/",
        "https://client.example/after-logout?next=1",
        "https://client.example/after-logout#fragment",
        "https://client.example/%61fter-logout",
    ] {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", CLIENT)
            .append_pair("post_logout_redirect_uri", candidate)
            .finish();
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/end-session?{query}"))
                    .header("host", HOST)
                    .header("cookie", format!("__Host-agent_auth_session={session}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "未逐字注册的 post_logout_redirect_uri 应拒: {candidate}"
        );
        assert!(
            set_cookie_line(&resp, "__Host-agent_auth_session")
                .expect("本地登出仍应清 cookie")
                .contains("Max-Age=0"),
            "开放重定向被拒不应回滚本地登出"
        );
    }

    let aq = format!("client_id={CLIENT}&redirect_uri={REDIRECT}&scope=openid");
    let probe = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/consent/context?{aq}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        probe.status(),
        StatusCode::UNAUTHORIZED,
        "未注册回跳值虽拒绝重定向，本地会话仍必须终止"
    );

    // 已注册值 → 303 回跳(echo state)。
    let session = login(&router, "erin@example.com").await;
    let resp = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/end-session?client_id={CLIENT}&post_logout_redirect_uri={PLR}&state=xyz"
                ))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "已注册值应回跳");
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        loc.starts_with(PLR) && loc.contains("state=xyz"),
        "回跳 + echo state: {loc}"
    );
}

// ---- C9.5a prompt/max_age ----

async fn authorize(
    router: &axum::Router,
    extra: &str,
    cookie: Option<&str>,
) -> axum::http::Response<Body> {
    let ch = s256_challenge("0123456789012345678901234567890123456789abc");
    let uri = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={ch}&code_challenge_method=S256&scope=openid&state=st{extra}"
    );
    let mut b = Request::builder().uri(&uri).header("host", HOST);
    if let Some(c) = cookie {
        b = b.header("cookie", format!("__Host-agent_auth_session={c}"));
    }
    router
        .clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

fn url_param(location: &str, name: &str) -> Option<String> {
    url::Url::parse(location)
        .ok()?
        .query_pairs()
        .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
}

async fn approve_consent(router: &axum::Router, session: &str, consent_location: &str) -> String {
    let authorize_query = url::Url::parse(consent_location)
        .unwrap()
        .query()
        .unwrap()
        .to_string();
    let context = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/consent/context?{authorize_query}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(context.status(), StatusCode::OK);
    let context_body = axum::body::to_bytes(context.into_body(), usize::MAX)
        .await
        .unwrap();
    let csrf = serde_json::from_slice::<Value>(&context_body).unwrap()["csrf_token"]
        .as_str()
        .unwrap()
        .to_string();

    let decision = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/consent/decision")
                .header("host", HOST)
                .header("content-type", "application/json")
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "decision": "approve",
                        "csrf": csrf,
                        "authorize_query": authorize_query,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = decision.status();
    let decision_body = axum::body::to_bytes(decision.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "consent failed: {}",
        String::from_utf8_lossy(&decision_body)
    );
    serde_json::from_slice::<Value>(&decision_body).unwrap()["redirect"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn exchange_code(router: &axum::Router, code: &str) -> Value {
    let verifier = "0123456789012345678901234567890123456789abc";
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("client_id", CLIENT)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("code_verifier", verifier)
        .finish();
    let response = router
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
        .unwrap();
    let status = response.status();
    let response_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "token exchange failed: {}",
        String::from_utf8_lossy(&response_body)
    );
    serde_json::from_slice(&response_body).unwrap()
}

async fn authorize_via_consent(router: &axum::Router, session: &str, extra: &str) -> Value {
    let response = authorize(router, extra, Some(session)).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()["location"].to_str().unwrap();
    assert!(location.contains("/consent?"), "{location}");
    let redirect = approve_consent(router, session, location).await;
    let code = url_param(&redirect, "code").expect("authorization code");
    exchange_code(router, &code).await
}

fn jwt_claims(token: &str) -> Value {
    let payload = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

fn tamper_signature(token: &str) -> String {
    let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
    let mut signature = URL_SAFE_NO_PAD.decode(&parts[2]).unwrap();
    signature[0] ^= 0x80;
    parts[2] = URL_SAFE_NO_PAD.encode(signature);
    parts.join(".")
}

#[tokio::test]
async fn prompt_none_without_session_returns_login_required() {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let (router, _) = build_router(state);
    // 无会话 + prompt=none → 回跳 error=login_required(不去 /login)。
    let resp = authorize(&router, "&prompt=none", None).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        loc.starts_with(REDIRECT),
        "应回跳 client redirect_uri: {loc}"
    );
    assert!(
        loc.contains("error=login_required"),
        "prompt=none 无会话应 login_required: {loc}"
    );
    assert!(!loc.contains("/login"), "MUST NOT 静默重定向到登录页");
}

#[tokio::test]
async fn prompt_none_without_prior_consent_returns_consent_required() {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    state.seed_dev_user("eve@example.com").await;
    let (router, _) = build_router(state);
    let session = login(&router, "eve@example.com").await;
    // prompt=none cannot display consent; an active login alone is insufficient.
    let resp = authorize(&router, "&prompt=none", Some(&session)).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        loc.starts_with(REDIRECT) && loc.contains("error=consent_required"),
        "没有既有授权时必须静默返回 consent_required: {loc}"
    );
    assert!(
        !loc.contains("/consent?"),
        "prompt=none MUST NOT show consent"
    );
}

#[tokio::test]
async fn prompt_none_with_prior_consent_issues_code_without_interaction() {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    state.seed_dev_user("silent@example.com").await;
    let (router, _) = build_router(state);
    let session = login(&router, "silent@example.com").await;
    let _ = authorize_via_consent(&router, &session, "").await;

    let response = authorize(&router, "&prompt=none", Some(&session)).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()["location"].to_str().unwrap();
    assert!(
        location.starts_with(REDIRECT),
        "prior consent must allow an immediate client redirect: {location}"
    );
    assert!(url_param(location, "code").is_some(), "{location}");
}

#[tokio::test]
async fn prompt_none_does_not_reuse_explicit_resource_consent_for_implicit_target() {
    const RESOURCE: &str = "https://resource.example.com";

    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    state.seed_dev_user("resource-consent@example.com").await;
    let (router, _) = build_router(state);
    let session = login(&router, "resource-consent@example.com").await;
    let _ = authorize_via_consent(&router, &session, &format!("&resource={RESOURCE}")).await;

    let response = authorize(&router, "&prompt=none", Some(&session)).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()["location"].to_str().unwrap();
    assert_eq!(
        url_param(location, "error").as_deref(),
        Some("consent_required")
    );
    assert!(url_param(location, "code").is_none(), "{location}");
}

#[tokio::test]
async fn valid_id_token_hint_with_prompt_none_reuses_the_active_subject() {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    state.seed_dev_user("hint@example.com").await;
    let (router, _) = build_router(state);
    let session = login(&router, "hint@example.com").await;
    let first = authorize_via_consent(&router, &session, "").await;
    let first_id_token = first["id_token"].as_str().unwrap();
    let encoded_hint = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("id_token_hint", first_id_token)
        .finish();

    let response = authorize(
        &router,
        &format!("&prompt=none&{encoded_hint}"),
        Some(&session),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()["location"].to_str().unwrap();
    let code = url_param(location, "code").expect("silent authorization code");
    let second = exchange_code(&router, &code).await;
    let first_claims = jwt_claims(first_id_token);
    let second_claims = jwt_claims(second["id_token"].as_str().unwrap());
    assert_eq!(second_claims["sub"], first_claims["sub"]);
    assert_eq!(second_claims["auth_time"], first_claims["auth_time"]);
}

#[tokio::test]
async fn tampered_id_token_hint_is_rejected_as_invalid_request() {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    state.seed_dev_user("tampered@example.com").await;
    let (router, _) = build_router(state);
    let session = login(&router, "tampered@example.com").await;
    let first = authorize_via_consent(&router, &session, "").await;
    let hint = tamper_signature(first["id_token"].as_str().unwrap());
    let encoded_hint = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("id_token_hint", &hint)
        .finish();

    let response = authorize(
        &router,
        &format!("&prompt=none&{encoded_hint}"),
        Some(&session),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()["location"].to_str().unwrap();
    assert_eq!(
        url_param(location, "error").as_deref(),
        Some("invalid_request")
    );
    assert!(url_param(location, "code").is_none(), "{location}");
}

#[tokio::test]
async fn id_token_hint_for_another_active_subject_requires_login() {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    state.seed_dev_user("hint-owner@example.com").await;
    state.seed_dev_user("browser-user@example.com").await;
    let (router, _) = build_router(state);
    let owner_session = login(&router, "hint-owner@example.com").await;
    let first = authorize_via_consent(&router, &owner_session, "").await;
    let browser_session = login(&router, "browser-user@example.com").await;
    let encoded_hint = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("id_token_hint", first["id_token"].as_str().unwrap())
        .finish();

    let response = authorize(
        &router,
        &format!("&prompt=none&{encoded_hint}"),
        Some(&browser_session),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()["location"].to_str().unwrap();
    assert_eq!(
        url_param(location, "error").as_deref(),
        Some("login_required")
    );
    assert!(url_param(location, "code").is_none(), "{location}");
}

#[tokio::test]
async fn es256_id_token_hint_is_accepted_for_silent_authorization() {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let mut client = state.clients.get("", CLIENT).await.unwrap().unwrap();
    client.id_token_signed_response_alg = Some("ES256".to_string());
    state.clients.put("", client).await.unwrap();
    state.seed_dev_user("es256-hint@example.com").await;
    let (router, _) = build_router(state);
    let session = login(&router, "es256-hint@example.com").await;
    let first = authorize_via_consent(&router, &session, "").await;
    let hint = first["id_token"].as_str().unwrap();
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(hint.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(header["alg"], "ES256");
    let encoded_hint = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("id_token_hint", hint)
        .finish();

    let response = authorize(
        &router,
        &format!("&prompt=none&{encoded_hint}"),
        Some(&session),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()["location"].to_str().unwrap();
    assert!(url_param(location, "code").is_some(), "{location}");
}

#[tokio::test]
async fn prompt_login_forces_reauth() {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    state.seed_dev_user("frank@example.com").await;
    let (router, _) = build_router(state);
    let session = login(&router, "frank@example.com").await;
    // 有会话但 prompt=login → 强制重认证(去 /login,不去 consent)。
    let resp = authorize(&router, "&prompt=login", Some(&session)).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        loc.contains("/login?"),
        "prompt=login 应强制重认证去 /login: {loc}"
    );
}

#[tokio::test]
async fn prompt_none_combined_is_invalid() {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let (router, _) = build_router(state);
    // prompt="none login"(none 与他值组合)→ OIDC 非法 → invalid_request(评审 codex)。
    let resp = authorize(&router, "&prompt=none%20login", None).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        loc.contains("error=invalid_request"),
        "none+其它值应 invalid_request: {loc}"
    );
}

#[tokio::test]
async fn logout_with_plr_but_no_client_is_local_logout_200() {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    state.seed_dev_user("heidi@example.com").await;
    let (router, _) = build_router(state);
    let session = login(&router, "heidi@example.com").await;
    // 带 post_logout_redirect_uri 但无 id_token_hint、无 client_id → 无法定 client →
    // 本地登出完成(200,清 cookie),不重定向(评审 codex/Kiro:不是 400)。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/end-session?post_logout_redirect_uri=http://127.0.0.1/after")
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "无法定 client 时本地登出 200,不重定向"
    );
    assert!(set_cookie_line(&resp, "__Host-agent_auth_session")
        .unwrap()
        .contains("Max-Age=0"));

    let after_logout = authorize(&router, "", Some(&session)).await;
    assert_eq!(after_logout.status(), StatusCode::SEE_OTHER);
    let location = after_logout.headers()["location"].to_str().unwrap();
    assert!(
        location.contains("/login?") && !location.contains("/consent?"),
        "无 client identity 的本地登出也必须删除权威会话: {location}"
    );
}

#[tokio::test]
async fn max_age_zero_forces_reauth() {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    state.seed_dev_user("grace@example.com").await;
    let (router, _) = build_router(state);
    let session = login(&router, "grace@example.com").await;
    // max_age=0 → now - auth_time > 0 → 强制重认证。
    let resp = authorize(&router, "&max_age=0", Some(&session)).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(loc.contains("/login?"), "max_age=0 应强制重认证: {loc}");
}

#[tokio::test]
async fn max_age_is_evaluated_at_authorization_not_later_consent() {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    state.seed_dev_user("max-age@example.com").await;
    let (router, _) = build_router(state);
    let session = login(&router, "max-age@example.com").await;

    let response = authorize(&router, "&max_age=1", Some(&session)).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let consent_location = response.headers()["location"].to_str().unwrap().to_string();
    assert!(consent_location.contains("/consent?"));

    tokio::time::sleep(Duration::from_secs(2)).await;
    let redirect = approve_consent(&router, &session, &consent_location).await;
    assert!(url_param(&redirect, "code").is_some());
}

#[tokio::test]
async fn max_age_accepts_reauthentication_after_authorization_started() {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    state.seed_dev_user("reauth@example.com").await;
    let now = agent_auth_http::current_unix_secs();
    let stale_session = "stale-reauth-session";
    state
        .sessions
        .create(
            "",
            SessionRecord {
                session_id: stale_session.to_string(),
                user_id: "user:reauth@example.com".to_string(),
                credential_epoch: 0,
                auth_time: now - 10,
                created_at: now - 10,
                last_used_at: now - 10,
                device: "Test browser".to_string(),
                expires_at: now + 3_600,
                acr: None,
                amr: vec!["pwd".to_string()],
            },
        )
        .await
        .unwrap();
    let (router, _) = build_router(state);

    let response = authorize(&router, "&max_age=1", Some(stale_session)).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let login_location = response.headers()["location"].to_str().unwrap();
    assert!(login_location.contains("/login?"), "{login_location}");
    let authorize_query = url::Url::parse(login_location)
        .unwrap()
        .query()
        .unwrap()
        .to_string();

    tokio::time::sleep(Duration::from_secs(2)).await;
    let (reauthenticated_session, consent_location) =
        login_with_authorize_query(&router, "reauth@example.com", &authorize_query).await;
    assert!(consent_location.contains("/consent?"), "{consent_location}");

    let redirect = approve_consent(&router, &reauthenticated_session, &consent_location).await;
    assert!(url_param(&redirect, "code").is_some());
}
