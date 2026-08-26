//! 进程内 e2e:`POST /revoke`(RFC 7009,spec 011 C7.6a,P1)。
//!
//! 覆盖:
//! - 调用方认证(RFC 7009 §2.1):匿名 → 401 invalid_client;错 secret → 401(不留匿名可达吊销面)。
//! - 吊销本 client 的 refresh family → 该 family 续期即被拒;access token 无关(离线仍认到过期)。
//! - 归属校验:跨 client 吊销 → 200 no-op 且**不生效**(不泄露归属)。
//! - 幂等 + 不泄露(RFC 7009 §2.2):未知 / 格式非法 / 已吊销 / access_token 输入 → 一律 200。

use agent_auth_client::s256_challenge;
use agent_auth_http::{build_router, AppState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tower::ServiceExt;

const HOST: &str = "localhost";
const RS_A: &str = "https://mcp.kb.example.com";

// 公开 client(none):走 code flow 拿 refresh。
async fn code_flow_refresh(
    router: &axum::Router,
    client: &str,
    redirect: &str,
) -> (String, String) {
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id={client}&redirect_uri={redirect}\
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
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let code = loc
        .split('?')
        .nth(1)
        .unwrap()
        .split('&')
        .find_map(|kv| kv.strip_prefix("code="))
        .unwrap()
        .to_string();
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={redirect}&client_id={client}"
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
    (
        tok["access_token"].as_str().unwrap().to_string(),
        tok["refresh_token"].as_str().unwrap().to_string(),
    )
}

// 用 refresh 续期(判断 family 是否还活)。
async fn refresh_status(router: &axum::Router, client: &str, refresh: &str) -> StatusCode {
    let form = format!("grant_type=refresh_token&refresh_token={refresh}&client_id={client}");
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
        .status()
}

// 调 /revoke(form)。auth 可选:basic=(id,secret) 或 form client_id。
async fn revoke(
    router: &axum::Router,
    token: &str,
    form_client_id: Option<&str>,
    basic: Option<(&str, &str)>,
) -> StatusCode {
    let mut form = format!("token={token}");
    if let Some(cid) = form_client_id {
        form.push_str(&format!("&client_id={cid}"));
    }
    let mut req = Request::builder()
        .method("POST")
        .uri("/revoke")
        .header("host", HOST)
        .header("content-type", "application/x-www-form-urlencoded");
    if let Some((id, sec)) = basic {
        req = req.header(
            "authorization",
            format!("Basic {}", STANDARD.encode(format!("{id}:{sec}"))),
        );
    }
    router
        .clone()
        .oneshot(req.body(Body::from(form)).unwrap())
        .await
        .unwrap()
        .status()
}

async fn revoke_public_form(router: &axum::Router, form: impl Into<String>) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/revoke")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form.into()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

async fn introspect(
    router: &axum::Router,
    caller_id: &str,
    caller_secret: &str,
    token: &str,
) -> serde_json::Value {
    let form = format!("token={token}&client_id={caller_id}");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/introspect")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .header(
                    "authorization",
                    format!(
                        "Basic {}",
                        STANDARD.encode(format!("{caller_id}:{caller_secret}"))
                    ),
                )
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

async fn published_ec_jwks(router: &axum::Router) -> Vec<agent_auth_http::jwks::Jwk> {
    let response = router
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
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let jwks: serde_json::Value = serde_json::from_slice(&body).unwrap();
    jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|key| key["kty"] == "EC")
        .map(|key| agent_auth_http::jwks::Jwk {
            kty: key["kty"].as_str().unwrap().to_string(),
            kid: key["kid"].as_str().unwrap().to_string(),
            alg: key["alg"].as_str().unwrap().to_string(),
            r#use: key["use"].as_str().unwrap().to_string(),
            crv: key["crv"].as_str().map(ToString::to_string),
            x: key["x"].as_str().map(ToString::to_string),
            y: key["y"].as_str().map(ToString::to_string),
            n: None,
            e: None,
        })
        .collect()
}

// 匿名 revoke → 401(不留匿名可达吊销面)。
#[tokio::test]
async fn revoke_requires_caller_auth() {
    let state = AppState::dev(HOST);
    state
        .seed_dev_client("pub-a", "https://a.example.com/cb", None)
        .await;
    let (router, _) = build_router(state);
    let (_at, refresh) = code_flow_refresh(&router, "pub-a", "https://a.example.com/cb").await;

    // 完全匿名(无 client_id、无 Basic)→ 401。
    let st = revoke(&router, &refresh, None, None).await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "匿名 revoke 应 401(invalid_client)"
    );

    // family 仍活(匿名请求未吊销)。
    assert_eq!(
        refresh_status(&router, "pub-a", &refresh).await,
        StatusCode::OK,
        "匿名 revoke 不应吊销 family"
    );
}

// confidential client 错 secret → 401。
#[tokio::test]
async fn revoke_wrong_secret_rejected() {
    let state = AppState::dev(HOST);
    state
        .seed_rs_introspect_client("conf-a", "sekret", &[])
        .await; // client_secret_basic
    let (router, _) = build_router(state);
    // conf-a 没走 code flow(无 redirect),这里只测认证门:任意 token + 错 secret → 401。
    let st = revoke(
        &router,
        "whatever.0",
        Some("conf-a"),
        Some(("conf-a", "WRONG")),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "错 secret 应 401");
}

// public client 吊销自己的 family → 续期即被拒。
#[tokio::test]
async fn revoke_own_family_denies_refresh() {
    let state = AppState::dev(HOST);
    state
        .seed_dev_client("pub-a", "https://a.example.com/cb", None)
        .await;
    let (router, _) = build_router(state);
    let (_at, refresh) = code_flow_refresh(&router, "pub-a", "https://a.example.com/cb").await;

    // 吊销前:refresh 可续期。
    // (不实际消费,以免轮换掉;直接吊销后验证。)
    let st = revoke(&router, &refresh, Some("pub-a"), None).await;
    assert_eq!(st, StatusCode::OK, "public client 吊销自己的 family 应 200");

    // 吊销后:该 family 续期被拒。
    assert_eq!(
        refresh_status(&router, "pub-a", &refresh).await,
        StatusCode::BAD_REQUEST,
        "吊销后 refresh 续期应被拒(invalid_grant)"
    );
}

// C7.6a:family revocation is immediate for online AS checks, while an offline RS keeps accepting
// the already-issued access token through its signed exp plus the configured clock-skew tolerance.
#[tokio::test]
async fn revoke_family_invalidates_online_state_but_preserves_offline_access_through_expiry_skew() {
    let state = AppState::dev(HOST);
    state
        .seed_dev_client("pub-a", "https://a.example.com/cb", Some(RS_A))
        .await;
    state
        .seed_rs_introspect_client("rs-a-introspect", "sekret-a", &[RS_A])
        .await;
    let (router, _) = build_router(state);
    let (access, refresh) = code_flow_refresh(&router, "pub-a", "https://a.example.com/cb").await;
    let jwks = published_ec_jwks(&router).await;

    let before = agent_auth_http::verify::verify_access_token(
        &access,
        &jwks,
        agent_auth_http::current_unix_secs(),
    )
    .expect("revocation 前离线 verifier 应接受 access token");
    let exp = before.claims["exp"].as_i64().expect("access token exp");
    assert!(
        exp > agent_auth_http::current_unix_secs(),
        "测试 access token 应仍在其配置 TTL 内"
    );
    assert_eq!(
        introspect(&router, "rs-a-introspect", "sekret-a", &access).await["active"],
        true,
        "revocation 前在线 introspection 应 active"
    );

    assert_eq!(
        revoke(&router, &refresh, Some("pub-a"), None).await,
        StatusCode::OK
    );
    assert_eq!(
        refresh_status(&router, "pub-a", &refresh).await,
        StatusCode::BAD_REQUEST,
        "family revocation 后 refresh 必须立即拒绝"
    );
    assert_eq!(
        introspect(&router, "rs-a-introspect", "sekret-a", &access).await["active"],
        false,
        "family revocation 后在线 introspection 必须立即 inactive"
    );

    let skew = agent_auth_infra_core::lifecycle::DEFAULT_CLOCK_SKEW_SECS;
    let at_last_accepted_second =
        agent_auth_http::verify::verify_access_token(&access, &jwks, exp + skew - 1)
            .expect("离线 verifier 不查 revocation，access token 在 exp + skew 边界前仍有效");
    assert_eq!(
        at_last_accepted_second.claims["exp"], before.claims["exp"],
        "revocation 不得改写已签发 token 的 TTL 边界"
    );
    assert_eq!(
        agent_auth_http::verify::verify_access_token(&access, &jwks, exp + skew),
        Err(agent_auth_http::verify::VerifyError::Expired),
        "离线 verifier 必须在 exp + configured skew 边界拒绝 token"
    );
}

#[tokio::test]
async fn revoke_missing_token_is_rejected() {
    let state = AppState::dev(HOST);
    state
        .seed_dev_client("pub-a", "https://a.example.com/cb", None)
        .await;
    let router = build_router(state).0;

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/revoke")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("client_id=pub-a"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "RFC 7009 缺少必填 token 必须返回 OAuth 400 invalid_request"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["error"], "invalid_request");
}

#[tokio::test]
async fn revoke_token_type_hint_does_not_change_result() {
    let state = AppState::dev(HOST);
    state
        .seed_dev_client("pub-a", "https://a.example.com/cb", None)
        .await;
    let router = build_router(state).0;
    let (_access, refresh) = code_flow_refresh(&router, "pub-a", "https://a.example.com/cb").await;

    assert_eq!(
        revoke_public_form(
            &router,
            format!("token={refresh}&token_type_hint=access_token&client_id=pub-a"),
        )
        .await,
        StatusCode::OK,
        "错误但已知的 token_type_hint 只能优化查找，不能改变吊销结果"
    );
    assert_eq!(
        refresh_status(&router, "pub-a", &refresh).await,
        StatusCode::BAD_REQUEST,
        "错误 hint 仍必须吊销 presented refresh family"
    );
}

// 跨 client 吊销 → 200 no-op 且不生效(不泄露归属)。
#[tokio::test]
async fn revoke_cross_client_is_noop_200() {
    let state = AppState::dev(HOST);
    state
        .seed_dev_client("pub-a", "https://a.example.com/cb", None)
        .await;
    // 攻击者 client B(也 public,能认证到自己身份)。
    state
        .seed_dev_client("pub-b", "https://b.example.com/cb", None)
        .await;
    let (router, _) = build_router(state);
    let (_at, refresh_a) = code_flow_refresh(&router, "pub-a", "https://a.example.com/cb").await;

    // B 用自己的身份吊销 A 的 token → 200(与未知 token 不可区分),但不生效。
    let st = revoke(&router, &refresh_a, Some("pub-b"), None).await;
    assert_eq!(st, StatusCode::OK, "跨 client 吊销应返 200(不泄露归属)");

    // A 的 family 仍活(B 无权吊销)。
    assert_eq!(
        refresh_status(&router, "pub-a", &refresh_a).await,
        StatusCode::OK,
        "跨 client 吊销不应生效"
    );
}

// 未知 / 格式非法 / access_token 输入 → 一律 200(RFC 7009 §2.2 幂等,不泄露)。
#[tokio::test]
async fn revoke_unknown_and_access_token_idempotent_200() {
    let state = AppState::dev(HOST);
    state
        .seed_dev_client("pub-a", "https://a.example.com/cb", None)
        .await;
    let (router, _) = build_router(state);
    let (access, refresh) = code_flow_refresh(&router, "pub-a", "https://a.example.com/cb").await;

    // 格式非法(无 .version)→ 200。
    assert_eq!(
        revoke(&router, "not-a-refresh-token", Some("pub-a"), None).await,
        StatusCode::OK
    );
    // 未知 family → 200。
    assert_eq!(
        revoke(&router, "nonexistentfamily.0", Some("pub-a"), None).await,
        StatusCode::OK
    );
    // access_token(JWT)作输入 → no-op 200。
    assert_eq!(
        revoke(&router, &access, Some("pub-a"), None).await,
        StatusCode::OK
    );

    // 真吊销一次,再重复吊销 → 仍 200(幂等)。
    assert_eq!(
        revoke(&router, &refresh, Some("pub-a"), None).await,
        StatusCode::OK
    );
    assert_eq!(
        revoke(&router, &refresh, Some("pub-a"), None).await,
        StatusCode::OK,
        "重复吊销幂等 200"
    );
}

// spec 005 §9.3(C10.5):tombstone client 的 refresh 换发被拒(invalid_client),即便 family 仍活。
// 区别于 revoke(那是吊销 family);tombstone 是回收 client,应在 client 认证前拦下、不 rotate。
#[tokio::test]
async fn tombstoned_client_refresh_rejected() {
    use agent_auth_http::ports::ClientStore;
    let state = AppState::dev(HOST);
    state
        .seed_dev_client("pub-tomb", "https://t.example.com/cb", None)
        .await;
    let (router, _) = build_router(state.clone());
    let (_at, refresh) = code_flow_refresh(&router, "pub-tomb", "https://t.example.com/cb").await;

    // tombstone 前:refresh 可续期(200)。
    assert_eq!(
        refresh_status(&router, "pub-tomb", &refresh).await,
        StatusCode::OK,
        "未回收 client refresh 应 200"
    );

    // 转 tombstone(模拟回收任务)。此处需新 refresh(上一步已轮换),重新走 code flow 拿。
    let (_at2, refresh2) = code_flow_refresh(&router, "pub-tomb", "https://t.example.com/cb").await;
    // 签发已 touch last_used_day 并创建 authority,故并发守卫的 day/revision 必须来自同一当前快照。
    let snapshot = state.clients.get("", "pub-tomb").await.unwrap().unwrap();
    assert!(
        state
            .clients
            .convert_to_tombstone(
                "",
                "pub-tomb",
                999,
                snapshot.last_used_day,
                snapshot.authority_revision,
            )
            .await
            .unwrap(),
        "tombstone 应成功(snapshot=当前 last_used_day + authority_revision)"
    );

    // tombstone 后:refresh 换发被拒(invalid_client),不 rotate family。
    assert_eq!(
        refresh_status(&router, "pub-tomb", &refresh2).await,
        StatusCode::BAD_REQUEST,
        "tombstone client refresh 换发应拒(invalid_client,tombstone 闸在 client 认证前拦下)"
    );
}
