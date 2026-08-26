//! 进程内 e2e:magic-link 登录 + consent → 签发 code(假用户,无 AWS,内存适配器)。
//!
//! 验证 P0.5 登录/consent 后端:请求 magic-link(dev 回显链接)→ callback 校 login-CSRF(nonce
//! cookie)建会话 → consent/context 取 anti-CSRF token → POST /consent approve → 拿回跳 code。

use agent_auth_http::ports::{
    AuthzSessionStore, CodeStore, PasswordCredential, PasswordStore, ScimCreateOutcome,
    ScimReplaceInput, ScimReplaceOutcome, ScimUserInput, UsersStore,
};
use agent_auth_http::{build_router, AppState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

const HOST: &str = "localhost";
const CLIENT: &str = "login-client";
const REDIRECT: &str = "http://127.0.0.1/cb";

async fn app() -> axum::Router {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    for email in [
        "alice@example.com",
        "amr-user@example.com",
        "bob@example.com",
        "carol@example.com",
        "dave@example.com",
        "erin@example.com",
        "eve@example.com",
        "frank@example.com",
        "rar-display@example.com",
        "multi-resource@example.com",
        "duplicate-query@example.com",
    ] {
        state.seed_dev_user(email).await;
    }
    let (r, _) = build_router(state);
    r
}

// 取响应所有 Set-Cookie 里某 cookie 的值。
fn set_cookie_val(resp: &axum::http::Response<Body>, name: &str) -> Option<String> {
    for hv in resp.headers().get_all(axum::http::header::SET_COOKIE) {
        let s = hv.to_str().ok()?;
        if let Some(rest) = s.strip_prefix(&format!("{name}=")) {
            let v = rest.split(';').next().unwrap_or("");
            return Some(v.to_string());
        }
    }
    None
}

fn query_param(url: &str, key: &str) -> Option<String> {
    url.split('?')
        .nth(1)?
        .split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")).map(|v| v.to_string()))
}

// 取某 cookie 的**完整** Set-Cookie 行(含属性,供断言 Path/Secure/Domain)。
fn set_cookie_line(resp: &axum::http::Response<Body>, name: &str) -> Option<String> {
    for hv in resp.headers().get_all(axum::http::header::SET_COOKIE) {
        let s = hv.to_str().ok()?;
        if s.starts_with(&format!("{name}=")) {
            return Some(s.to_string());
        }
    }
    None
}

#[tokio::test]
async fn full_login_then_consent_issues_code() {
    let router = app().await;
    let initial_query = format!(
        "response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}&scope=openid\
         &state=st1&code_challenge=abc&code_challenge_method=S256"
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/authorize?{initial_query}"))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let login_url = url::Url::parse(
        response
            .headers()
            .get("location")
            .expect("login redirect")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(login_url.path(), "/login");
    let authorize_query = login_url
        .query()
        .expect("login continuation query")
        .to_string();

    // 1. 请求 magic-link(dev 回显链接 + 设 nonce cookie)。
    let body =
        serde_json::json!({ "email": "alice@example.com", "authorize_query": authorize_query });
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
    assert_eq!(resp.status(), StatusCode::OK);
    let nonce_cookie =
        set_cookie_val(&resp, "__Host-agent_auth_login_nonce").expect("nonce cookie");
    let rbody = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let rj: serde_json::Value = serde_json::from_slice(&rbody).unwrap();
    let dev_link = rj["dev_link"]
        .as_str()
        .expect("dev 回显 magic-link")
        .to_string();
    // dev_link 形如 https://localhost/login/callback?link_id=..&tag=..
    let path_q = dev_link.split_once("/login/callback").unwrap().1; // "?link_id=..&tag=.."

    // 2. callback 带 nonce cookie(同浏览器)→ 建会话 + 回跳 /consent。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/login/callback{path_q}"))
                .header("host", HOST)
                .header(
                    "cookie",
                    format!("__Host-agent_auth_login_nonce={nonce_cookie}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "callback 应 303 回跳");
    let session_cookie =
        set_cookie_val(&resp, "__Host-agent_auth_session").expect("session cookie");
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    let consent_url = url::Url::parse(loc).unwrap();
    assert_eq!(consent_url.path(), "/consent", "应回跳 consent 续授权流");
    let consent_query = consent_url
        .query()
        .expect("consent continuation query")
        .to_string();

    // 3. consent/context(带 session cookie)→ 取 anti-CSRF token。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/consent/context?{consent_query}"))
                .header("host", HOST)
                .header(
                    "cookie",
                    format!("__Host-agent_auth_session={session_cookie}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cbody = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let cj: serde_json::Value = serde_json::from_slice(&cbody).unwrap();
    let csrf = cj["csrf_token"].as_str().expect("csrf_token").to_string();

    // 4. POST /consent approve(带 session cookie + csrf)→ 拿回跳 code。
    let body = serde_json::json!({ "decision": "approve", "csrf": csrf, "authorize_query": consent_query });
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/consent/decision")
                .header("host", HOST)
                .header("content-type", "application/json")
                .header(
                    "cookie",
                    format!("__Host-agent_auth_session={session_cookie}"),
                )
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "consent approve 应成功");
    let dbody = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let dj: serde_json::Value = serde_json::from_slice(&dbody).unwrap();
    let redirect = dj["redirect"].as_str().expect("redirect");
    assert!(redirect.starts_with(REDIRECT));
    assert!(query_param(redirect, "code").is_some(), "回跳应带 code");
    assert_eq!(
        query_param(redirect, "state").as_deref(),
        Some("st1"),
        "state echo"
    );
    assert!(redirect.contains("iss="), "回跳带 iss(C1.4)");
}

// C9.2:异浏览器打开 magic-link(无/错 nonce cookie)→ 拒(login-CSRF)。
#[tokio::test]
async fn callback_different_browser_rejected() {
    let router = app().await;
    let body = serde_json::json!({ "email": "bob@example.com", "authorize_query": "" });
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
    let nonce = set_cookie_val(&resp, "__Host-agent_auth_login_nonce").expect("nonce cookie");
    let rbody = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let dev_link = serde_json::from_slice::<serde_json::Value>(&rbody).unwrap()["dev_link"]
        .as_str()
        .unwrap()
        .to_string();
    let path_q = dev_link.split_once("/login/callback").unwrap().1;

    // 携带不同 nonce cookie(异浏览器)→ SessionMismatch → 400。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/login/callback{path_q}"))
                .header("host", HOST)
                .header(
                    "cookie",
                    "__Host-agent_auth_login_nonce=wrong-browser-nonce",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "异浏览器打开应拒(C9.2)"
    );
    assert!(
        set_cookie_val(&resp, "__Host-agent_auth_session").is_none(),
        "异浏览器打开不得建立登录 session"
    );

    // 浏览器 B 的失败尝试不得烧掉 link；原始浏览器 A 仍须能兑现同一链接。
    let resp = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/login/callback{path_q}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_login_nonce={nonce}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "原始浏览器应仍能兑现同一 magic-link"
    );
    assert!(
        set_cookie_val(&resp, "__Host-agent_auth_session").is_some(),
        "原始浏览器成功兑现后应建立登录 session"
    );
}

#[tokio::test]
async fn callback_tampered_tag_does_not_consume_link() {
    let router = app().await;
    let body = serde_json::json!({ "email": "bob@example.com", "authorize_query": "" });
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
    let nonce = set_cookie_val(&resp, "__Host-agent_auth_login_nonce").expect("nonce cookie");
    let rbody = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let dev_link = serde_json::from_slice::<serde_json::Value>(&rbody).unwrap()["dev_link"]
        .as_str()
        .unwrap()
        .to_string();
    let path_q = dev_link.split_once("/login/callback").unwrap().1;
    let (path_without_tag, _) = path_q.split_once("&tag=").expect("tag query");
    let tampered_path = format!("{path_without_tag}&tag=tampered");

    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/login/callback{tampered_path}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_login_nonce={nonce}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        set_cookie_val(&resp, "__Host-agent_auth_session").is_none(),
        "篡改 tag 不得建立登录 session"
    );

    let resp = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/login/callback{path_q}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_login_nonce={nonce}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "篡改 tag 的失败尝试不得消费合法 magic-link"
    );
    assert!(
        set_cookie_val(&resp, "__Host-agent_auth_session").is_some(),
        "原 tag 重试应建立登录 session"
    );
}

#[tokio::test]
async fn callback_revocation_pending_does_not_consume_link() {
    let state = AppState::dev(HOST);
    let email = "pending-magic-link@example.com";
    let user_id = format!("user:{email}");
    state.seed_dev_user(email).await;
    let (router, _) = build_router(state.clone());

    let body = serde_json::json!({ "email": email, "authorize_query": "" });
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
    let nonce = set_cookie_val(&resp, "__Host-agent_auth_login_nonce").expect("nonce cookie");
    let response_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let dev_link = serde_json::from_slice::<serde_json::Value>(&response_body).unwrap()["dev_link"]
        .as_str()
        .expect("dev link")
        .to_string();
    let path_q = dev_link.split_once("/login/callback").unwrap().1;

    assert!(state
        .passwords
        .create_if_absent(
            "",
            PasswordCredential {
                user_id: user_id.clone(),
                password_hash: agent_auth_authn::password::dummy_hash().clone(),
                must_change: false,
                revocation_pending: true,
                credential_change_id: None,
                version: 1,
                updated_at: 1,
            },
        )
        .await
        .unwrap());

    let callback = || {
        Request::builder()
            .method("GET")
            .uri(format!("/login/callback{path_q}"))
            .header("host", HOST)
            .header("cookie", format!("__Host-agent_auth_login_nonce={nonce}"))
            .body(Body::empty())
            .unwrap()
    };
    let resp = router.clone().oneshot(callback()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        set_cookie_val(&resp, "__Host-agent_auth_session").is_none(),
        "pending credential revocation must not establish a session"
    );

    state.passwords.delete("", &user_id).await.unwrap();
    let resp = router.oneshot(callback()).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "a revocation-pending denial must not consume the magic link"
    );
    assert!(
        set_cookie_val(&resp, "__Host-agent_auth_session").is_some(),
        "the same link must remain redeemable after the prerequisite recovers"
    );
}

// C9.1:同 email 冷却窗口内二次请求 → 429。
#[tokio::test]
async fn magic_link_cooldown() {
    use agent_auth_http::ports::{MagicLinkStore, MessageOutbox};

    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    state.seed_dev_user("carol@example.com").await;
    let (router, _) = build_router(state.clone());
    let body = serde_json::json!({ "email": "carol@example.com", "authorize_query": "" });
    let mk = || {
        Request::builder()
            .method("POST")
            .uri("/login/magic-link")
            .header("host", HOST)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    };
    let r1 = router.clone().oneshot(mk()).await.unwrap();
    assert_eq!(r1.status(), StatusCode::OK);
    let first_sent_at = state
        .magic_links
        .last_sent_at("", "carol@example.com")
        .await
        .unwrap()
        .expect("first request must establish the per-email cooldown");
    assert_eq!(
        state.messages.list_recent("", 10).await.unwrap().len(),
        1,
        "first request must send exactly one magic-link message"
    );

    let r2 = router.oneshot(mk()).await.unwrap();
    assert_eq!(
        r2.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "冷却窗口内二次请求应 429(C9.1)"
    );
    assert_eq!(
        state
            .magic_links
            .last_sent_at("", "carol@example.com")
            .await
            .unwrap(),
        Some(first_sent_at),
        "a cooldown rejection must not advance the email's send window"
    );
    assert_eq!(
        state.messages.list_recent("", 10).await.unwrap().len(),
        1,
        "a cooldown rejection must not enqueue another message"
    );
}

#[tokio::test]
async fn magic_link_global_quota_throttles_across_emails_without_sending() {
    use agent_auth_http::ports::{MagicLinkStore, MessageOutbox, RateLimitStore};

    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    for email in ["alice@example.com", "bob@example.com"] {
        state.seed_dev_user(email).await;
    }
    let rate_limit = state.rate_limit.as_ref().expect("dev rate-limit store");
    assert!(
        rate_limit
            .try_consume(
                agent_auth_http::ratelimit_gate::global_email_quota_key(),
                i64::MAX / 4,
                100.0,
                2.0,
                100.0,
            )
            .await
            .unwrap()
            .allowed,
        "test setup must exhaust the production global email quota bucket"
    );
    let (router, _) = build_router(state.clone());

    for email in ["alice@example.com", "bob@example.com"] {
        let body = serde_json::json!({ "email": email, "authorize_query": "" });
        let response = router
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
        assert_eq!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "the shared quota must throttle distinct recipient addresses"
        );
        assert_eq!(
            state.magic_links.last_sent_at("", email).await.unwrap(),
            None,
            "a globally throttled request must not establish a cooldown row"
        );
    }

    assert!(
        state.messages.list_recent("", 10).await.unwrap().is_empty(),
        "globally throttled requests must not enqueue magic-link messages"
    );
}

// C9.1 短命一次性:magic-link 成功消费后,同 link 再打开 MUST 拒(consume 一次性,不可重放)。
#[tokio::test]
async fn magic_link_one_time_use_replay_rejected() {
    let router = app().await;
    let body = serde_json::json!({ "email": "erin@example.com", "authorize_query": "" });
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
    let nonce = set_cookie_val(&resp, "__Host-agent_auth_login_nonce").expect("nonce cookie");
    let rbody = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let dev_link = serde_json::from_slice::<serde_json::Value>(&rbody).unwrap()["dev_link"]
        .as_str()
        .unwrap()
        .to_string();
    let path_q = dev_link
        .split_once("/login/callback")
        .unwrap()
        .1
        .to_string();
    let cb = |pq: String, nonce: String| {
        Request::builder()
            .method("GET")
            .uri(format!("/login/callback{pq}"))
            .header("host", HOST)
            .header("cookie", format!("__Host-agent_auth_login_nonce={nonce}"))
            .body(Body::empty())
            .unwrap()
    };
    // 第一次打开 → 成功建会话(303)。
    let r1 = router
        .clone()
        .oneshot(cb(path_q.clone(), nonce.clone()))
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::SEE_OTHER, "首次打开应成功");
    // 同 link 再打开 → 拒(已消费,一次性;consume DeleteItem 后 link 不存在)。
    let r2 = router.oneshot(cb(path_q, nonce)).await.unwrap();
    assert_eq!(
        r2.status(),
        StatusCode::BAD_REQUEST,
        "已用 magic-link 重放应拒(C9.1 一次性)"
    );
}

#[tokio::test]
async fn magic_link_cannot_follow_a_reassigned_email_alias() {
    let state = AppState::dev(HOST);
    let original_id = "user:scim:magic-link-original";
    let replacement_id = "user:scim:magic-link-replacement";
    let email = "magic-link-reassigned@example.com";
    assert!(matches!(
        state
            .users
            .create_scim(
                "",
                ScimUserInput {
                    user_id: original_id.to_string(),
                    external_id: "magic-link-original-external".to_string(),
                    user_name: email.to_string(),
                    display_name: None,
                    active: true,
                    now: 1,
                },
            )
            .await
            .unwrap(),
        ScimCreateOutcome::Created(record) if record.user_id == original_id
    ));
    let (router, _) = build_router(state.clone());

    let request_body = serde_json::json!({ "email": email, "authorize_query": "" });
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login/magic-link")
                .header("host", HOST)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let nonce = set_cookie_val(&response, "__Host-agent_auth_login_nonce").expect("nonce cookie");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let link = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["dev_link"]
        .as_str()
        .unwrap()
        .to_string();
    let callback_query = link.split_once("/login/callback").unwrap().1;

    assert!(matches!(
        state
            .users
            .replace_scim(
                "",
                original_id,
                ScimReplaceInput {
                    external_id: "magic-link-original-moved".to_string(),
                    user_name: "magic-link-original-moved@example.com".to_string(),
                    display_name: None,
                    active: true,
                    now: 2,
                },
            )
            .await
            .unwrap(),
        ScimReplaceOutcome::Updated(record) if record.user_id == original_id
    ));
    assert!(matches!(
        state
            .users
            .create_scim(
                "",
                ScimUserInput {
                    user_id: replacement_id.to_string(),
                    external_id: "magic-link-replacement-external".to_string(),
                    user_name: email.to_string(),
                    display_name: None,
                    active: true,
                    now: 3,
                },
            )
            .await
            .unwrap(),
        ScimCreateOutcome::Created(record) if record.user_id == replacement_id
    ));

    let callback = router
        .oneshot(
            Request::builder()
                .uri(format!("/login/callback{callback_query}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_login_nonce={nonce}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(callback.status(), StatusCode::FORBIDDEN);
    assert!(
        set_cookie_val(&callback, "__Host-agent_auth_session").is_none(),
        "a link issued to the original identity must not authenticate the replacement owner"
    );
}

// C10.9:consent 无有效 anti-CSRF token → 403。
#[tokio::test]
async fn consent_without_csrf_rejected() {
    let router = app().await;
    // 先登录建会话。
    let body = serde_json::json!({ "email": "dave@example.com", "authorize_query": "" });
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
    let path_q = dev_link.split_once("/login/callback").unwrap().1;
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/login/callback{path_q}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_login_nonce={nonce}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let session = set_cookie_val(&resp, "__Host-agent_auth_session").unwrap();

    // POST /consent 带错误 csrf → 403。
    let aq = format!("client_id={CLIENT}&redirect_uri={REDIRECT}&scope=openid");
    let body = serde_json::json!({ "decision": "approve", "csrf": "WRONG", "authorize_query": aq });
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/consent/decision")
                .header("host", HOST)
                .header("content-type", "application/json")
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "错误 anti-CSRF 应 403(C10.9)"
    );
}

// 登录建会话,返回 session cookie 值。
async fn login_session(router: &axum::Router, email: &str) -> String {
    let body = serde_json::json!({ "email": email, "authorize_query": "" });
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
    set_cookie_val(&resp, "__Host-agent_auth_session").unwrap()
}

async fn authorize_continuation_query(
    router: &axum::Router,
    session: &str,
    authorize_query: &str,
) -> String {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/authorize?{authorize_query}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .expect("authorize redirect")
        .to_str()
        .unwrap();
    let location = url::Url::parse(location).expect("absolute consent redirect");
    assert_eq!(location.path(), "/consent");
    location
        .query()
        .expect("authorize continuation query")
        .to_string()
}

#[tokio::test]
async fn consent_csrf_is_per_request_session_bound_required_and_accepted() {
    async fn authorize_to_consent_query(
        router: &axum::Router,
        session: &str,
        state: &str,
    ) -> String {
        let uri = format!(
            "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
             &scope=openid&state={state}&code_challenge=csrf-challenge\
             &code_challenge_method=S256"
        );
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("host", HOST)
                    .header("cookie", format!("__Host-agent_auth_session={session}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get("location")
            .expect("authorize redirect")
            .to_str()
            .unwrap();
        let location = url::Url::parse(location).expect("absolute consent redirect");
        assert_eq!(location.path(), "/consent");
        location
            .query()
            .expect("authorize continuation query")
            .to_string()
    }

    async fn context_csrf(router: &axum::Router, session: &str, query: &str) -> String {
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
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["csrf_token"]
            .as_str()
            .expect("consent context must issue csrf_token")
            .to_string()
    }

    async fn decide(
        router: &axum::Router,
        session: &str,
        query: &str,
        csrf: Option<&str>,
    ) -> axum::http::Response<Body> {
        let mut body = serde_json::json!({ "decision": "approve", "authorize_query": query });
        if let Some(csrf) = csrf {
            body["csrf"] = serde_json::Value::String(csrf.to_string());
        }
        router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/consent/decision")
                    .header("host", HOST)
                    .header("content-type", "application/json")
                    .header("cookie", format!("__Host-agent_auth_session={session}"))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    let router = app().await;
    let session_a = login_session(&router, "dave@example.com").await;
    let session_b = login_session(&router, "erin@example.com").await;
    let query_a = authorize_to_consent_query(&router, &session_a, "csrf-state").await;
    let query_other = authorize_to_consent_query(&router, &session_a, "other-state").await;
    let query_b = authorize_to_consent_query(&router, &session_b, "other-session-state").await;
    let csrf_a1 = context_csrf(&router, &session_a, &query_a).await;
    let csrf_a2 = context_csrf(&router, &session_a, &query_a).await;
    let csrf_other = context_csrf(&router, &session_a, &query_other).await;
    let csrf_b = context_csrf(&router, &session_b, &query_b).await;
    assert_ne!(
        csrf_a1, csrf_a2,
        "each consent context response must issue a distinct per-request token"
    );

    let invented_query = format!(
        "response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &scope=openid&state=invented-state&code_challenge=csrf-challenge\
         &code_challenge_method=S256"
    );
    let invented_csrf = context_csrf(&router, &session_a, &invented_query).await;
    let response = decide(&router, &session_a, &invented_query, Some(&invented_csrf)).await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "a browser-created consent query without an authorization session must not issue a code"
    );

    for (label, csrf) in [
        ("missing-field", None),
        ("empty", Some("")),
        ("tampered", Some("not-a-valid-csrf-token")),
        ("other-authorize-request", Some(csrf_other.as_str())),
        ("other-session", Some(csrf_b.as_str())),
    ] {
        let response = decide(&router, &session_a, &query_a, csrf).await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{label} consent CSRF material must be rejected"
        );
    }

    let response = decide(&router, &session_a, &query_a, Some(&csrf_a2)).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the token issued for this request and browser session must be accepted"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let redirect = response["redirect"].as_str().expect("consent redirect");
    assert_eq!(
        query_param(redirect, "state").as_deref(),
        Some("csrf-state")
    );
    assert!(
        query_param(redirect, "code").is_some(),
        "valid consent CSRF must permit authorization-code issuance"
    );
}

#[tokio::test]
async fn authorize_fails_closed_when_authorization_session_creation_fails() {
    use agent_auth_http::state::AuthzSessionStoreImpl;

    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    state.seed_dev_user("alice@example.com").await;
    let (router, _) = build_router(state.clone());
    let session = login_session(&router, "alice@example.com").await;
    match state.authz_sessions.as_ref() {
        AuthzSessionStoreImpl::Memory(store) => store.fail_next_create(),
        #[cfg(feature = "aws")]
        AuthzSessionStoreImpl::Dynamo(_) => unreachable!("dev state uses the memory store"),
    }

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
                     &scope=openid&state=create-failed&code_challenge=csrf-challenge\
                     &code_challenge_method=S256"
                ))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], b"authorization session unavailable");
}

#[tokio::test]
async fn consent_binding_failure_does_not_issue_authorization_code() {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    state.seed_dev_user("alice@example.com").await;
    state.seed_dev_user("mallory@example.com").await;
    let (router, _) = build_router(state.clone());
    let session = login_session(&router, "alice@example.com").await;
    let (authz_session_id, _) = agent_auth_http::authz_session::create_session(
        &state,
        "",
        CLIENT,
        agent_auth_authn::authz_session::AuthzState::PendingConsent,
        agent_auth_http::current_unix_secs(),
    )
    .await
    .unwrap();
    state
        .authz_sessions
        .bind_user(
            "",
            &authz_session_id,
            "user:mallory@example.com",
            agent_auth_http::current_unix_secs(),
        )
        .await
        .unwrap()
        .expect("authorization session should bind to its first user");

    let authorize_query = format!(
        "client_id={CLIENT}&redirect_uri={REDIRECT}&scope=openid&state=st-bind\
         &code_challenge=abc&code_challenge_method=S256&authz_session_id={authz_session_id}"
    );
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
    let csrf = serde_json::from_slice::<serde_json::Value>(&context_body).unwrap()["csrf_token"]
        .as_str()
        .unwrap()
        .to_string();

    let response = router
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
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        !state
            .codes
            .has_unexpired_by_client("", CLIENT, agent_auth_http::current_unix_secs() - 1)
            .await
            .unwrap(),
        "failed authorization-session binding must not leave an authorization code"
    );
}

// 评审 CRITICAL:authorize 有会话时 MUST 重定向到 /consent(不直接签 code,防跳过用户同意)。
#[tokio::test]
async fn authorize_with_session_redirects_to_consent_not_code() {
    let router = app().await;
    let session = login_session(&router, "eve@example.com").await;
    let uri = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge=abc&code_challenge_method=S256&scope=openid&state=st2"
    );
    let resp = router
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        loc.contains("/consent?"),
        "有会话应重定向 consent(用户同意),而非直接签 code"
    );
    assert!(
        !loc.contains("code="),
        "authorize 有会话 MUST NOT 直接回跳 code(评审 CRITICAL)"
    );
}

// C4.1:direct consent driving must not bypass the public-client PKCE requirement.
#[tokio::test]
async fn consent_public_client_without_pkce_rejected() {
    let router = app().await;
    let session = login_session(&router, "frank@example.com").await;
    let csrf = {
        let aq = format!("client_id={CLIENT}&redirect_uri={REDIRECT}&scope=openid");
        let resp = router
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
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice::<serde_json::Value>(&b).unwrap()["csrf_token"]
            .as_str()
            .unwrap()
            .to_string()
    };
    // Public authorize_query 无 code_challenge → consent 应拒(C4.1)。
    let aq = format!("client_id={CLIENT}&redirect_uri={REDIRECT}&scope=openid");
    let body = serde_json::json!({ "decision": "approve", "csrf": csrf, "authorize_query": aq });
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/consent/decision")
                .header("host", HOST)
                .header("content-type", "application/json")
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "consent 缺 PKCE challenge 应拒(评审 #4)"
    );
}

#[tokio::test]
async fn consent_allows_registered_confidential_client_without_pkce() {
    use agent_auth_http::ports::{ClientRecord, ClientStore};

    const CONFIDENTIAL_REDIRECT: &str = "https://confidential.example.com/callback";
    let state = AppState::dev(HOST);
    state
        .clients
        .put(
            "",
            ClientRecord {
                client_id: "confidential-consent".into(),
                redirect_uris: vec![CONFIDENTIAL_REDIRECT.into()],
                token_endpoint_auth_method: "client_secret_basic".into(),
                client_secret: Some("confidential-consent-secret".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    state.seed_dev_user("frank@example.com").await;
    let router = build_router(state).0;
    let session = login_session(&router, "frank@example.com").await;
    let authorize_query = authorize_continuation_query(
        &router,
        &session,
        &format!(
            "response_type=code&client_id=confidential-consent\
             &redirect_uri={CONFIDENTIAL_REDIRECT}&scope=openid"
        ),
    )
    .await;
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
    let csrf = serde_json::from_slice::<serde_json::Value>(&context_body).unwrap()["csrf_token"]
        .as_str()
        .unwrap()
        .to_string();
    let response = router
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

    assert_eq!(response.status(), StatusCode::OK);
    let response_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let redirect = serde_json::from_slice::<serde_json::Value>(&response_body).unwrap()["redirect"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        query_param(&redirect, "code").is_some(),
        "confidential consent without PKCE should issue a code"
    );
}

#[tokio::test]
async fn consent_confidential_pkce_exemption_requires_both_parameters_absent() {
    use agent_auth_http::ports::{ClientRecord, ClientStore};

    const CONFIDENTIAL_REDIRECT: &str = "https://confidential.example.com/callback";
    let state = AppState::dev(HOST);
    state
        .clients
        .put(
            "",
            ClientRecord {
                client_id: "confidential-consent-malformed".into(),
                redirect_uris: vec![CONFIDENTIAL_REDIRECT.into()],
                token_endpoint_auth_method: "client_secret_basic".into(),
                client_secret: Some("confidential-consent-secret".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    state.seed_dev_user("frank@example.com").await;
    let router = build_router(state).0;
    let session = login_session(&router, "frank@example.com").await;
    let base_query = format!(
        "response_type=code&client_id=confidential-consent-malformed\
         &redirect_uri={CONFIDENTIAL_REDIRECT}&scope=openid"
    );

    for malformed in [
        "code_challenge_method=S256",
        "code_challenge=&code_challenge_method=S256",
    ] {
        let authorize_query = authorize_continuation_query(&router, &session, &base_query).await;
        let malformed_query = format!("{authorize_query}&{malformed}");
        let context = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/consent/context?{malformed_query}"))
                    .header("host", HOST)
                    .header("cookie", format!("__Host-agent_auth_session={session}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let context_body = axum::body::to_bytes(context.into_body(), usize::MAX)
            .await
            .unwrap();
        let csrf = serde_json::from_slice::<serde_json::Value>(&context_body).unwrap()
            ["csrf_token"]
            .as_str()
            .unwrap()
            .to_string();
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
                        serde_json::to_vec(&serde_json::json!({
                            "decision": "approve",
                            "csrf": csrf,
                            "authorize_query": malformed_query,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "malformed PKCE tuple must not receive the confidential consent exemption: {malformed}"
        );
    }
}

#[tokio::test]
async fn consent_rejects_workload_client_authorization_code() {
    use agent_auth_http::ports::{ClientRecord, ClientStore};

    const WORKLOAD_REDIRECT: &str = "https://workload.example.com/callback";
    let state = AppState::dev(HOST);
    state
        .clients
        .put(
            "",
            ClientRecord {
                client_id: "workload-consent".into(),
                redirect_uris: vec![WORKLOAD_REDIRECT.into()],
                token_endpoint_auth_method: "client_secret_basic".into(),
                client_secret: Some("workload-consent-secret".into()),
                client_type: Some("workload".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    state.seed_dev_user("frank@example.com").await;
    let router = build_router(state).0;
    let session = login_session(&router, "frank@example.com").await;
    let authorize_query = format!(
        "client_id=workload-consent&redirect_uri={WORKLOAD_REDIRECT}&scope=openid\
         &code_challenge=challenge&code_challenge_method=S256"
    );
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
    let context_body = axum::body::to_bytes(context.into_body(), usize::MAX)
        .await
        .unwrap();
    let csrf = serde_json::from_slice::<serde_json::Value>(&context_body).unwrap()["csrf_token"]
        .as_str()
        .unwrap()
        .to_string();
    let response = router
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

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "workload clients must not obtain authorization codes through direct consent"
    );
}

// ---- spec 003 §"登录后 next 回跳"(P0.5):无 authorize 上下文时按 next 回原 AS 前端页 ----

/// 走完整 magic-link 请求(带 authorize_query + next)→ 同浏览器 callback,返回回跳 Location。
async fn login_with(authorize_query: &str, next: &str) -> String {
    let router = app().await;
    let body = serde_json::json!({
        "email": "alice@example.com",
        "authorize_query": authorize_query,
        "next": next,
    });
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
    let nonce = set_cookie_val(&resp, "__Host-agent_auth_login_nonce").expect("nonce cookie");
    let rbody = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let rj: serde_json::Value = serde_json::from_slice(&rbody).unwrap();
    let dev_link = rj["dev_link"].as_str().expect("dev link").to_string();
    let path_q = dev_link.split_once("/login/callback").unwrap().1;
    let resp = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/login/callback{path_q}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_login_nonce={nonce}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "callback 应 303 回跳");
    resp.headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn login_next_same_origin_relative_redirects_to_next() {
    // 无 authorize 上下文 + 合法同源相对 next(会话过期被拦在批准页)→ 回原页。
    let loc = login_with("", "/approve?auth_req_id=abc-123").await;
    assert!(
        loc.ends_with("/approve?auth_req_id=abc-123"),
        "合法 next 应回跳原页,实际 loc={loc}"
    );
}

#[tokio::test]
async fn standalone_login_redirects_to_account() {
    let loc = login_with("", "").await;
    assert!(
        loc.ends_with("/account"),
        "独立登录成功后应进入账户页,不能经根路径又回登录页,实际 loc={loc}"
    );
}

#[tokio::test]
async fn saas_magic_link_preserves_tenant_origin_end_to_end() {
    const ZONE: &str = "aws.example.com";
    const CONTROL: &str = "c.aws.example.com";

    let mut state = AppState::dev("unused.example.com");
    state.form = agent_auth_discovery::Form::Saas {
        zone: ZONE.to_string(),
        control_host: CONTROL.to_string(),
    };
    state.saas_tenants = std::sync::Arc::new(vec!["t1".to_string(), "t2".to_string()]);
    state.tenant_partitioning = true;
    state.seed_dev_user_in_tenant("t1", "t1@example.com").await;
    state.seed_dev_user_in_tenant("t2", "t2@example.com").await;
    // 故意保留 control host 全局值:租户浏览器 origin 必须从请求 Host 派生,不能使用它。
    state.web_base_url = format!("https://{CONTROL}");
    let (router, _) = build_router(state);

    for tenant in ["t1", "t2"] {
        let host = format!("{tenant}.{ZONE}");
        let body = serde_json::json!({
            "email": format!("{tenant}@example.com"),
            "authorize_query": "",
            "next": "",
        });
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login/magic-link")
                    .header("host", &host)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let nonce = set_cookie_val(&resp, "__Host-agent_auth_login_nonce").unwrap();
        let response_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let link = serde_json::from_slice::<serde_json::Value>(&response_body).unwrap()["dev_link"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            link.starts_with(&format!("https://{host}/login/callback?")),
            "{tenant} magic-link 必须保持租户 origin,实际 {link}"
        );
        let path_query = link.split_once("/login/callback").unwrap().1;

        if tenant == "t1" {
            let control_resp = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/login/callback{path_query}"))
                        .header("host", CONTROL)
                        .header("cookie", format!("__Host-agent_auth_login_nonce={nonce}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                control_resp.status(),
                StatusCode::BAD_REQUEST,
                "control host 不是租户,且不得消费 t1 链接"
            );
        }

        let callback = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/login/callback{path_query}"))
                    .header("host", &host)
                    .header("cookie", format!("__Host-agent_auth_login_nonce={nonce}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(callback.status(), StatusCode::SEE_OTHER);
        assert!(
            set_cookie_val(&callback, "__Host-agent_auth_session").is_some(),
            "{tenant} callback 应建立租户 session"
        );
        assert_eq!(
            callback.headers().get("location").unwrap(),
            &format!("https://{host}/account")
        );
    }
}

#[tokio::test]
async fn login_next_malicious_fails_closed_to_account() {
    // 恶意 next(绝对 URL / 协议相对 / 反斜杠 / 伪协议)→ fail-closed 回落账户页,绝不 open-redirect。
    for bad in [
        "https://evil.example/steal",
        "//evil.example",
        "/\\evil.example",
        "javascript:alert(1)",
        // 编码绕过(评审 Kiro H1):%2f%2f / %5c%5c 入口即拒,不依赖 Location 头下游解码行为。
        "/%2f%2fevil.example",
        "/%5c%5cevil.example",
        // Unicode 空白(评审 Kiro H2):非 ASCII 一律拒。
        "/\u{00a0}//evil.example",
    ] {
        let loc = login_with("", bad).await;
        assert!(
            !loc.contains("evil.example") && !loc.contains("javascript:"),
            "恶意 next={bad:?} 不得 open-redirect,实际 loc={loc}"
        );
        assert!(
            loc.ends_with("/account"),
            "恶意 next={bad:?} 应回落账户页,实际 loc={loc}"
        );
    }
}

#[tokio::test]
async fn login_authorize_context_takes_precedence_over_next() {
    // 同时有 authorize 上下文 + next → 协议流优先(/consent),不走 next。
    let aq = format!(
        "client_id={CLIENT}&redirect_uri={REDIRECT}&scope=openid&state=st1&code_challenge=abc&code_challenge_method=S256"
    );
    let loc = login_with(&aq, "/account").await;
    assert!(
        loc.contains("/consent?"),
        "有 authorize 上下文应优先续 /consent,实际 loc={loc}"
    );
}

// spec 020 §1 / C10.21:浏览器 cookie 属性与服务端 tenant-scoped session lookup 共同隔离租户。
#[tokio::test]
async fn saas_session_cookie_is_host_only_and_server_side_tenant_bound() {
    use agent_auth_discovery::{Form, Phase};
    use agent_auth_http::ports::{ClientRecord, ClientStore};

    const ZONE: &str = "aws.example.com";
    const T1_HOST: &str = "t1.aws.example.com";
    const T2_HOST: &str = "t2.aws.example.com";
    const TENANT_CLIENT: &str = "tenant-login-client";
    const TENANT_REDIRECT: &str = "https://client.example.com/callback";

    async fn authorize_location(
        router: &axum::Router,
        host: &str,
        session: &str,
        uri: &str,
    ) -> url::Url {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("host", host)
                    .header("cookie", format!("__Host-agent_auth_session={session}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{host}");
        url::Url::parse(
            response
                .headers()
                .get("location")
                .expect("authorize redirect")
                .to_str()
                .unwrap(),
        )
        .unwrap()
    }

    let mut state = AppState::dev(T1_HOST);
    state.form = Form::Saas {
        zone: ZONE.to_string(),
        control_host: format!("c.{ZONE}"),
    };
    state.phase = Phase::P1;
    state.tenant_partitioning = true;
    state.saas_tenants = std::sync::Arc::new(vec!["t1".to_string(), "t2".to_string()]);
    for tenant in ["t1", "t2"] {
        ClientStore::put(
            state.clients.as_ref(),
            tenant,
            ClientRecord {
                client_id: TENANT_CLIENT.to_string(),
                redirect_uris: vec![TENANT_REDIRECT.to_string()],
                application_type: Some("web".to_string()),
                token_endpoint_auth_method: "none".to_string(),
                oidc_sector_identifier: Some("client.example.com".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
    state.seed_dev_user_in_tenant("t1", "t1@example.com").await;
    let router = build_router(state).0;

    // t1 请求 magic-link：nonce cookie 必须满足完整 __Host- 契约。
    let body = serde_json::json!({ "email": "t1@example.com", "authorize_query": "", "next": "" });
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login/magic-link")
                .header("host", T1_HOST)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let nonce_line =
        set_cookie_line(&resp, "__Host-agent_auth_login_nonce").expect("nonce cookie 行");
    assert_host_cookie(&nonce_line, "nonce");
    let nonce = set_cookie_val(&resp, "__Host-agent_auth_login_nonce").unwrap();
    let rbody = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let rj: serde_json::Value = serde_json::from_slice(&rbody).unwrap();
    let dev_link = rj["dev_link"].as_str().unwrap().to_string();
    assert!(dev_link.starts_with(&format!("https://{T1_HOST}/login/callback?")));
    let path_q = dev_link.split_once("/login/callback").unwrap().1;

    // t1 callback 建立的 session cookie 同样必须严格 host-only。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/login/callback{path_q}"))
                .header("host", T1_HOST)
                .header("cookie", format!("__Host-agent_auth_login_nonce={nonce}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let session_line =
        set_cookie_line(&resp, "__Host-agent_auth_session").expect("session cookie 行");
    assert_host_cookie(&session_line, "session");
    let session = set_cookie_val(&resp, "__Host-agent_auth_session").unwrap();

    let authorize_uri = format!(
        "/authorize?response_type=code&client_id={TENANT_CLIENT}\
         &redirect_uri={TENANT_REDIRECT}&scope=openid&state=c10-21\
         &code_challenge=0123456789012345678901234567890123456789abc\
         &code_challenge_method=S256"
    );

    let t1 = authorize_location(&router, T1_HOST, &session, &authorize_uri).await;
    assert_eq!(t1.host_str(), Some(T1_HOST));
    assert_eq!(t1.path(), "/consent", "t1 必须识别自己的登录会话");

    // 即使绕过浏览器 host-only 行为、手工把 t1 cookie 发给 t2，服务端也必须按 t2 分区查无。
    let t2 = authorize_location(&router, T2_HOST, &session, &authorize_uri).await;
    assert_eq!(t2.host_str(), Some(T2_HOST));
    assert_eq!(
        t2.path(),
        "/login",
        "t2 MUST NOT 把 t1 session 当作已认证会话"
    );

    let t1_again = authorize_location(&router, T1_HOST, &session, &authorize_uri).await;
    assert_eq!(t1_again.host_str(), Some(T1_HOST));
    assert_eq!(
        t1_again.path(),
        "/consent",
        "t2 的跨租户尝试不得删除或改变 t1 权威会话"
    );
}

// 断言一条 Set-Cookie 行满足 `__Host-` 契约(C10.21):`__Host-` 前缀 + Secure + Path=/ + **无 Domain**。
fn assert_host_cookie(line: &str, label: &str) {
    assert!(
        line.starts_with("__Host-"),
        "{label} cookie MUST `__Host-` 前缀:{line}"
    );
    assert!(line.contains("Secure"), "{label} cookie MUST Secure:{line}");
    assert!(line.contains("Path=/"), "{label} cookie MUST Path=/:{line}");
    assert!(
        line.contains("HttpOnly"),
        "{label} cookie MUST HttpOnly:{line}"
    );
    assert!(
        line.contains("SameSite=Lax"),
        "{label} cookie MUST SameSite=Lax:{line}"
    );
    // C10.21 核心:**绝不设 Domain**(否则跨子域越界;__Host- 契约也要求无 Domain)。
    assert!(
        !line.to_ascii_lowercase().contains("domain="),
        "{label} cookie MUST NOT 设 Domain(host-only 严格绑定发行子域,C10.21):{line}"
    );
}

// spec 010 §4 / DESIGN §721:GET /consent/context 回带 authorization_details(RAR)供 consent 页
// **结构化展示**用户正在同意的细粒度约束。合规 RAR 回显;不合规(未知 type/越界 locations)→ 不展示(空)。
#[tokio::test]
async fn consent_context_returns_rar_for_display() {
    let router = app().await;
    let session = login_session(&router, "rar-display@example.com").await;
    let rs = "https://mcp.kb.example.com";
    // 合规内建词汇表 RAR(locations 命中授权 resource)。
    let rar = format!(r#"[{{"type":"agent_auth_rar_v1","locations":["{rs}"],"max_records":25}}]"#);
    let rar_enc: String = url_encode(&rar);
    let aq = format!(
        "client_id={CLIENT}&redirect_uri={REDIRECT}&scope=openid&resource={rs}&authorization_details={rar_enc}"
    );
    let resp = router
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
    assert_eq!(resp.status(), StatusCode::OK);
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let cj: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let ad = cj["authorization_details"]
        .as_array()
        .expect("consent/context 应回带 authorization_details 供展示");
    assert_eq!(ad.len(), 1, "回显合规 RAR");
    assert_eq!(ad[0]["max_records"], 25);
    let first_csrf = cj["csrf_token"].as_str().unwrap();

    let resp = router
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
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let second: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_ne!(
        second["csrf_token"].as_str().unwrap(),
        first_csrf,
        "每次 consent context 请求必须签发不同的 per-request CSRF token"
    );

    // 不合规(越界 locations)→ 不展示(空/省略)。
    let bad_rar =
        url_encode(r#"[{"type":"agent_auth_rar_v1","locations":["https://evil.example.com"]}]"#);
    let aq_bad = format!(
        "client_id={CLIENT}&redirect_uri={REDIRECT}&scope=openid&resource={rs}&authorization_details={bad_rar}"
    );
    let resp = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/consent/context?{aq_bad}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let cj: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert!(
        cj.get("authorization_details").is_none()
            || cj["authorization_details"]
                .as_array()
                .map(|a| a.is_empty())
                .unwrap_or(true),
        "越界/不合规 RAR MUST NOT 展示(不误导用户同意畸形约束)"
    );
}

// C4.8:动态注册元数据是不可信自声明。即使注册请求夹带仿冒品牌名和外链 logo,
// 公开注册响应与 consent context 都不得把它们变成可渲染内容。
#[tokio::test]
async fn dynamic_client_consent_context_never_exposes_logo_uri() {
    let router = app().await;
    let redirect_uri = "https://trusted-bank.example/callback";
    let registration = serde_json::json!({
        "redirect_uris": [redirect_uri],
        "token_endpoint_auth_method": "none",
        "client_name": "Trusted Bank",
        "logo_uri": "https://attacker.invalid/trusted-bank.png"
    });
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("host", HOST)
                .header("x-forwarded-for", "203.0.113.48")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&registration).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let registered: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let client_id = registered["client_id"].as_str().expect("client_id");
    assert!(
        registered.get("client_name").is_none() && registered.get("logo_uri").is_none(),
        "DCR response MUST NOT reflect attacker-controlled branding"
    );

    let session = login_session(&router, "alice@example.com").await;
    let authorize_query = format!(
        "client_id={client_id}&redirect_uri={}&scope=openid",
        url_encode(redirect_uri)
    );
    let response = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/consent/context?{authorize_query}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let context: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(context["client_source"], "registered");
    assert_eq!(context["client_name"], client_id);
    assert!(
        context.get("logo_uri").is_none(),
        "consent context MUST NOT expose an external logo URI"
    );
    assert!(
        !String::from_utf8_lossy(&body).contains("attacker.invalid"),
        "consent context MUST NOT carry attacker-controlled branding"
    );
}

// C2.5b:consent 动态 context 与 approve 都必须保留 authorize 的完整 resource 集合。
#[tokio::test]
async fn consent_context_and_approval_preserve_all_resources() {
    const RA: &str = "https://mcp.a.example.com";
    const RB: &str = "https://mcp.b.example.com";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    let router = app().await;
    let session = login_session(&router, "multi-resource@example.com").await;
    let authorize_query = authorize_continuation_query(
        &router,
        &session,
        &format!(
            "response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}&scope=openid\
             &code_challenge={CHALLENGE}&code_challenge_method=S256&resource={RA}&resource={RB}"
        ),
    )
    .await;

    let resp = router
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
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let context: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(context["resources"], serde_json::json!([RA, RB]));
    let csrf = context["csrf_token"].as_str().unwrap();

    let decision = serde_json::json!({
        "decision": "approve",
        "csrf": csrf,
        "authorize_query": authorize_query,
    });
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/consent/decision")
                .header("host", HOST)
                .header("content-type", "application/json")
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::from(serde_json::to_vec(&decision).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let decision: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let code = query_param(decision["redirect"].as_str().unwrap(), "code").unwrap();

    let token_form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={VERIFIER}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}&resource={RB}"
    );
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(token_form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "consent 后应可下采样到 authorize 集合中的第二个 resource"
    );
}

#[tokio::test]
async fn consent_rejects_duplicate_singleton_parameters() {
    let router = app().await;
    let session = login_session(&router, "duplicate-query@example.com").await;
    let cookie = format!("__Host-agent_auth_session={session}");
    let duplicate_client = format!(
        "client_id=displayed-client&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge=abc&code_challenge_method=S256"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/consent/context?{duplicate_client}"))
                .header("host", HOST)
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "context 必须拒绝重复 singleton，不能展示首值后签末值"
    );

    let key_only_duplicate = format!(
        "client_id&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge=abc&code_challenge_method=S256"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/consent/context?{key_only_duplicate}"))
                .header("host", HOST)
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "context 必须把无等号参数视为空值并拒绝重复 singleton"
    );

    let clean_query = authorize_continuation_query(
        &router,
        &session,
        &format!(
            "response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
             &code_challenge=abc&code_challenge_method=S256"
        ),
    )
    .await;
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/consent/context?{clean_query}"))
                .header("host", HOST)
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let context: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let csrf = context["csrf_token"].as_str().unwrap();
    let duplicate_scope = format!("{clean_query}&scope&scope=openid%20admin");
    let decision = serde_json::json!({
        "decision": "approve",
        "csrf": csrf,
        "authorize_query": duplicate_scope,
    });
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/consent/decision")
                .header("host", HOST)
                .header("content-type", "application/json")
                .header("cookie", cookie)
                .body(Body::from(serde_json::to_vec(&decision).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "decision 必须在解析被篡改的重复 singleton 前先拒绝 query-bound CSRF"
    );
}

// 极简 URL 编码(测试用;编码 query 值里的 JSON 特殊字符)。
fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// C9.5b:认证方法 amr 透传进签发的 id_token——magic-link 登录(amr=email)→ 会话 → consent → code
// → /token(scope=openid)→ id_token MUST 含 amr:["email"]。**证 session→code→token 的 acr/amr 链通**
//(此前该链断:SessionRecord/CodeRecord 无 acr/amr 字段,上游/本地认证方法从不进 token)。
#[tokio::test]
async fn id_token_carries_amr_from_login_method() {
    let router = app().await;
    let verifier = "verifier-0123456789012345678901234567890123456789";
    let challenge = agent_auth_client::s256_challenge(verifier);
    // 1. magic-link 登录建会话(amr=email)。
    let session = login_session(&router, "amr-user@example.com").await;
    // 2. 有会话访问 authorize(带 response_type=code)→ 回跳 consent。
    let aq = authorize_continuation_query(
        &router,
        &session,
        &format!(
            "response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}&scope=openid&state=st9\
             &code_challenge={challenge}&code_challenge_method=S256"
        ),
    )
    .await;
    // 3. consent/context → csrf。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/consent/context?{aq}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let cj: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let csrf = cj["csrf_token"].as_str().unwrap().to_string();
    // 4. approve → code。
    let body = serde_json::json!({ "decision": "approve", "csrf": csrf, "authorize_query": aq });
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/consent/decision")
                .header("host", HOST)
                .header("content-type", "application/json")
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let dj: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let code = query_param(dj["redirect"].as_str().unwrap(), "code").expect("code");
    // 5. /token 换 id_token。
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
    assert_eq!(resp.status(), StatusCode::OK, "code 换 token 应成功");
    let tj: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let id_token = tj["id_token"].as_str().expect("openid → id_token");
    // 解 id_token payload,断言 amr 含 email(C9.5b 链通)。
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let payload = id_token.split('.').nth(1).unwrap();
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    assert_eq!(
        claims["amr"],
        serde_json::json!(["email"]),
        "id_token MUST 含登录方法 amr(magic-link=email;证 session→code→token acr/amr 链通,C9.5b)"
    );
}
