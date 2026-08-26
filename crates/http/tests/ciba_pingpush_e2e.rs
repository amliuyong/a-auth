//! 进程内 e2e:CIBA ping/push 投递模式(spec 013 §4,C7b.5,OIDC CIBA Core §7.2/7.3/§10.2)。
//!
//! 覆盖(三轮双评审收敛的设计不变量):
//! - DCR 注册:ping/push MUST confidential + 合法 https 非私网 endpoint + 能力上线(P3+gate);否则拒。
//! - 能力门控:未启用(非 P3 或 gate 关)时注册 ping/push → invalid_client_metadata。
//! - 投递:批准后按快照 delivery_mode 分派(ping POST {auth_req_id}、push POST 完整 token);SSRF 复校。
//! - push 签发后失败作废(不重签/不退化);ping 投递失败不阻断轮询取 token。

use agent_auth_http::adapters::memory::MemoryCibaCallbackDelivery;
use agent_auth_http::ports::{
    CibaDeliveryOutcome, CibaStore, ClientRecord, ClientStore, GrantStore, RateLimitStore,
};
use agent_auth_http::state::CibaCallbackDeliveryImpl;
use agent_auth_http::{build_router, AppState, Phase};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

const HOST: &str = "localhost";
const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
/// 高熵 client_notification_token(≥128-bit;测试固定值)。
const CNT: &str = "cnt-0123456789abcdef0123456789abcdef";
const SECRET: &str = "ping-client-secret-xyz";

/// P3 + ping/push gate 开的 state(能力已上线)。
fn p3_pingpush_state() -> AppState {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P3;
    state.ciba_ping_push_enabled = true;
    state
}

/// POST /register(JSON body)→ (status, json)。
async fn post_register(
    router: &axum::Router,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("host", HOST)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
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

async fn get_registered_client(
    router: &axum::Router,
    client_id: &str,
    registration_token: &str,
) -> serde_json::Value {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/register/{client_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {registration_token}"))
                .body(Body::empty())
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

// 注册 ping client:confidential(client_secret_post)+ 合法 https 外网 endpoint + 能力上线 → 201。
#[tokio::test]
async fn register_ping_confidential_valid_endpoint_ok() {
    let (router, _) = build_router(p3_pingpush_state());
    let (st, body) = post_register(
        &router,
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/cb"],
            "token_endpoint_auth_method": "client_secret_post",
            "backchannel_token_delivery_mode": "ping",
            "backchannel_client_notification_endpoint": "https://client.example.com/ciba/notify"
        }),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::CREATED,
        "confidential ping 注册应 201: {body}"
    );
    assert!(body["client_id"].as_str().is_some());
}

// public(auth_method=none)注册 ping → 400 invalid_client_metadata(confidential 强制,H3)。
#[tokio::test]
async fn register_ping_public_client_rejected() {
    let (router, _) = build_router(p3_pingpush_state());
    let (st, body) = post_register(
        &router,
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/cb"],
            "token_endpoint_auth_method": "none",
            "backchannel_token_delivery_mode": "ping",
            "backchannel_client_notification_endpoint": "https://client.example.com/ciba/notify"
        }),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "public ping 注册应拒");
    assert_eq!(body["error"], "invalid_client_metadata");
}

// ping 但 endpoint 指向元数据/私网 → 400(SSRF fail-closed,H1)。
#[tokio::test]
async fn register_ping_ssrf_endpoint_rejected() {
    let (router, _) = build_router(p3_pingpush_state());
    for ep in [
        "http://client.example.com/cb",       // 非 https
        "https://169.254.169.254/latest",     // 云元数据
        "https://10.0.0.5/cb",                // 私网
        "https://client.example.com:8080/cb", // 非 443 端口
        "https://evil.com@169.254.169.254/x", // userinfo 混淆
    ] {
        let (st, body) = post_register(
            &router,
            serde_json::json!({
                "redirect_uris": ["https://client.example.com/cb"],
                "token_endpoint_auth_method": "client_secret_post",
                "backchannel_token_delivery_mode": "ping",
                "backchannel_client_notification_endpoint": ep
            }),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::BAD_REQUEST,
            "SSRF endpoint {ep} 应拒: {body}"
        );
        assert_eq!(body["error"], "invalid_client_metadata", "endpoint {ep}");
    }
}

// ping 但缺 endpoint → 400。
#[tokio::test]
async fn register_ping_missing_endpoint_rejected() {
    let (router, _) = build_router(p3_pingpush_state());
    let (st, body) = post_register(
        &router,
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/cb"],
            "token_endpoint_auth_method": "client_secret_post",
            "backchannel_token_delivery_mode": "ping"
        }),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_client_metadata");
}

// 能力未上线(P2,或 P3 但 gate 关)注册 ping → 400(不接受未上线声明,M1)。
#[tokio::test]
async fn register_ping_not_enabled_rejected() {
    // P2:能力未到。
    let mut p2 = AppState::dev(HOST);
    p2.phase = Phase::P2;
    let (router, _) = build_router(p2);
    let (st, body) = post_register(
        &router,
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/cb"],
            "token_endpoint_auth_method": "client_secret_post",
            "backchannel_token_delivery_mode": "ping",
            "backchannel_client_notification_endpoint": "https://client.example.com/ciba/notify"
        }),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "P2 注册 ping 应拒: {body}");
    assert_eq!(body["error"], "invalid_client_metadata");

    // P3 但 gate 关。
    let mut p3_gate_off = AppState::dev(HOST);
    p3_gate_off.phase = Phase::P3;
    p3_gate_off.ciba_ping_push_enabled = false;
    let (router2, _) = build_router(p3_gate_off);
    let (st2, _) = post_register(
        &router2,
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/cb"],
            "token_endpoint_auth_method": "client_secret_post",
            "backchannel_token_delivery_mode": "ping",
            "backchannel_client_notification_endpoint": "https://client.example.com/ciba/notify"
        }),
    )
    .await;
    assert_eq!(st2, StatusCode::BAD_REQUEST, "P3 gate 关注册 ping 应拒");
}

// poll(缺省 / 显式)注册不受影响(后向兼容):public poll client 正常 201。
#[tokio::test]
async fn register_poll_public_still_ok() {
    let (router, _) = build_router(p3_pingpush_state());
    // 显式 poll。
    let (st, _) = post_register(
        &router,
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/cb"],
            "token_endpoint_auth_method": "none",
            "backchannel_token_delivery_mode": "poll"
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "public poll 注册应 201");
    // 缺省(不带 delivery_mode)。
    let (st2, _) = post_register(
        &router,
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/cb"],
            "token_endpoint_auth_method": "none"
        }),
    )
    .await;
    assert_eq!(st2, StatusCode::CREATED, "缺省 poll 注册应 201");
}

// push + require_dpop 不兼容(评审 codex/Kiro):push 无客户端请求可绑 proof → 注册拒(防静默 bearer 绕过)。
#[tokio::test]
async fn register_push_with_require_dpop_rejected() {
    let (router, _) = build_router(p3_pingpush_state());
    let (st, body) = post_register(
        &router,
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/cb"],
            "token_endpoint_auth_method": "client_secret_post",
            "backchannel_token_delivery_mode": "push",
            "backchannel_client_notification_endpoint": "https://client.example.com/ciba/notify",
            "require_dpop": true
        }),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "push+require_dpop 应拒: {body}"
    );
    assert_eq!(body["error"], "invalid_client_metadata");
    // 对照:ping+require_dpop 允许(ping 通知后 client 走 /token 可带 proof)。
    let (st_ping, _) = post_register(
        &router,
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/cb"],
            "token_endpoint_auth_method": "client_secret_post",
            "backchannel_token_delivery_mode": "ping",
            "backchannel_client_notification_endpoint": "https://client.example.com/ciba/notify",
            "require_dpop": true
        }),
    )
    .await;
    assert_eq!(st_ping, StatusCode::CREATED, "ping+require_dpop 应允许");
}

#[tokio::test]
async fn rfc7592_update_cannot_enable_require_dpop_for_push_client() {
    let (router, _) = build_router(p3_pingpush_state());
    let (status, created) = post_register(
        &router,
        serde_json::json!({
            "redirect_uris": ["https://client.example.com/cb"],
            "token_endpoint_auth_method": "client_secret_post",
            "backchannel_token_delivery_mode": "push",
            "backchannel_client_notification_endpoint": "https://client.example.com/ciba/notify"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client_id = created["client_id"].as_str().unwrap();
    let registration_token = created["registration_access_token"].as_str().unwrap();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/register/{client_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {registration_token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"require_dpop": true}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "invalid_client_metadata");
    assert_eq!(
        get_registered_client(&router, client_id, registration_token).await["require_dpop"],
        false
    );

    let confirmed_patch = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/register/{client_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {registration_token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "require_dpop": true,
                        "confirm_downgrade": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(confirmed_patch.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(confirmed_patch.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "invalid_client_metadata");
    assert_eq!(
        get_registered_client(&router, client_id, registration_token).await["require_dpop"],
        false
    );

    let confirmed_put = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/register/{client_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {registration_token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "redirect_uris": ["https://client.example.com/cb"],
                        "token_endpoint_auth_method": "client_secret_post",
                        "require_dpop": true,
                        "confirm_downgrade": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(confirmed_put.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(confirmed_put.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "invalid_client_metadata");
    assert_eq!(
        get_registered_client(&router, client_id, registration_token).await["require_dpop"],
        false
    );
}

// ============ 投递子系统 e2e(spec 013 §4:ping/push 分派 + 失败处置 + 快照)============

/// 建 P3+gate state,注入可断言的 MemoryCibaCallbackDelivery mock,返回 (state, mock 句柄)。
fn p3_state_with_delivery() -> (AppState, MemoryCibaCallbackDelivery) {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P3;
    state.ciba_ping_push_enabled = true;
    let mock = MemoryCibaCallbackDelivery::default();
    state.ciba_delivery = Arc::new(CibaCallbackDeliveryImpl::Memory(mock.clone()));
    (state, mock)
}

/// 直接 put 一个 confidential ping/push client(带合法公网 endpoint + secret)。
async fn seed_pingpush_client(state: &AppState, client_id: &str, mode: &str) {
    ClientStore::put(
        state.clients.as_ref(),
        "",
        ClientRecord {
            client_id: client_id.into(),
            redirect_uris: vec!["https://client.example.com/cb".into()],
            token_endpoint_auth_method: "client_secret_post".into(),
            client_secret: Some(SECRET.into()),
            backchannel_token_delivery_mode: Some(mode.into()),
            // 公网可解析 host(测试投递会走 mock,不真出站;SSRF 结构校验在注册时已过,这里直接 put)。
            backchannel_client_notification_endpoint: Some(
                "https://client.example.com/ciba/notify".into(),
            ),
            ..Default::default()
        },
    )
    .await
    .unwrap();
}

fn set_cookie_val(resp: &axum::http::Response<Body>, name: &str) -> Option<String> {
    for hv in resp.headers().get_all(axum::http::header::SET_COOKIE) {
        let s = hv.to_str().ok()?;
        if let Some(rest) = s.strip_prefix(&format!("{name}=")) {
            return Some(rest.split(';').next().unwrap_or("").to_string());
        }
    }
    None
}

async fn login(router: &axum::Router, email: &str) -> String {
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
    let rb = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let dev_link = serde_json::from_slice::<serde_json::Value>(&rb).unwrap()["dev_link"]
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

/// POST /bc-authorize(confidential:带 client_secret + client_notification_token)。
async fn bc_authorize_pingpush(
    router: &axum::Router,
    client_id: &str,
) -> (StatusCode, serde_json::Value) {
    bc_authorize_pingpush_for_user(router, client_id, ALICE).await
}

async fn bc_authorize_pingpush_for_user(
    router: &axum::Router,
    client_id: &str,
    login_hint: &str,
) -> (StatusCode, serde_json::Value) {
    let form = format!(
        "client_id={client_id}&scope=openid&login_hint={login_hint}\
         &client_secret={SECRET}&client_notification_token={CNT}"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/bc-authorize")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
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

async fn post_bc_approve(router: &axum::Router, arid: &str, session: &str) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/bc-approve/{arid}"))
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::from("approve=true"))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

/// CIBA /token 轮询(confidential:带 client_secret)。
async fn poll_token_confidential(
    router: &axum::Router,
    arid: &str,
    client_id: &str,
    with_secret: bool,
) -> (StatusCode, serde_json::Value) {
    let mut form = format!(
        "grant_type=urn:openid:params:grant-type:ciba&auth_req_id={arid}&client_id={client_id}"
    );
    if with_secret {
        form.push_str(&format!("&client_secret={SECRET}"));
    }
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
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        st,
        serde_json::from_slice(&b).unwrap_or(serde_json::json!({})),
    )
}

// ping:批准后 AS POST {auth_req_id} 到 endpoint(带 Bearer client_notification_token);token 未消费,
// client 仍走 /token 取到。投递失败(mock 注入 Failed)不阻断轮询取 token。
#[tokio::test]
async fn ping_dispatch_then_token_via_poll() {
    let (state, mock) = p3_state_with_delivery();
    state.seed_user(ALICE, 1000).await;
    seed_pingpush_client(&state, "ping-cli", "ping").await;
    let (router, _) = build_router(state);

    let (st, ba) = bc_authorize_pingpush(&router, "ping-cli").await;
    assert_eq!(st, StatusCode::OK, "confidential ping 发起应 200: {ba}");
    let arid = ba["auth_req_id"].as_str().unwrap().to_string();

    let alice = login(&router, ALICE).await;
    assert_eq!(
        post_bc_approve(&router, &arid, &alice).await,
        StatusCode::NO_CONTENT
    );

    // 投递记录:1 次 ping,body 含 auth_req_id、带 client_notification_token。
    let dels = mock.delivered().await;
    assert_eq!(dels.len(), 1, "ping 应投递 1 次");
    assert_eq!(dels[0].body["auth_req_id"], arid);
    assert_eq!(dels[0].client_notification_token, CNT);
    assert!(dels[0].notification_endpoint.starts_with("https://"));

    // client 随后走 /token(带 client 认证)取到 token(ping token 未在回调消费)。
    let (st, body) = poll_token_confidential(&router, &arid, "ping-cli", true).await;
    assert_eq!(st, StatusCode::OK, "ping 后轮询应签 token: {body}");
    assert!(body["access_token"].as_str().is_some());
}

// spec 013 §4 / C7b.5+:全局推送配额耗尽 → ping/push 均跳过主动推送(client 仍可轮询取,fail-safe)。
// 先证明未耗尽时 push 会投递完整 token,再把共享桶抽干并分别批准 ping/push;两者都不得新增
// 投递,且随后都可通过 /token 取到 token。
#[tokio::test]
async fn ciba_push_quota_exhausted_skips_delivery_but_poll_still_works() {
    let (state, mock) = p3_state_with_delivery();
    state.seed_user(ALICE, 1000).await;
    state.seed_user(BOB, 1000).await;
    state.seed_user(CAROL, 1000).await;
    seed_pingpush_client(&state, "push-control", "push").await;
    seed_pingpush_client(&state, "ping-quota", "ping").await;
    seed_pingpush_client(&state, "push-quota", "push").await;
    let (router, _) = build_router(state.clone());

    // 正向控制:共享桶未耗尽时 push 必须真实投递包含 access_token 的响应。
    let (control_status, control_body) =
        bc_authorize_pingpush_for_user(&router, "push-control", ALICE).await;
    assert_eq!(
        control_status,
        StatusCode::OK,
        "未耗尽时 push 发起应成功: {control_body}"
    );
    let control_arid = control_body["auth_req_id"].as_str().unwrap().to_string();
    let alice = login(&router, ALICE).await;
    assert_eq!(
        post_bc_approve(&router, &control_arid, &alice).await,
        StatusCode::NO_CONTENT
    );
    let control_deliveries = mock.delivered().await;
    assert_eq!(control_deliveries.len(), 1, "未耗尽时 push 必须投递一次");
    assert_eq!(control_deliveries[0].body["auth_req_id"], control_arid);
    assert!(
        control_deliveries[0].body["access_token"]
            .as_str()
            .is_some(),
        "未耗尽的 push 投递必须包含 access_token"
    );

    // 抽干全局推送桶(容量 100 突发):连续调用直到 exhausted 返 true(下一次投递会被跳过)。
    // 直接调 gate(pub)对同一 state 的 rate_limit store 消耗 token,与 dispatch 里用的是同一桶。
    let mut drained = false;
    for _ in 0..200 {
        if agent_auth_http::ratelimit_gate::ciba_push_quota_exhausted(&state).await {
            drained = true;
            break;
        }
    }
    assert!(drained, "应能抽干全局推送桶");
    // Pin the empty bucket ahead of wall time so setup work cannot cross a
    // one-second refill boundary and make this timing-independent assertion flaky.
    let pinned = state
        .rate_limit
        .as_ref()
        .unwrap()
        .try_consume(
            "global-ciba-push-quota",
            agent_auth_http::current_unix_secs() + 60,
            100.0,
            2.0,
            100.0,
        )
        .await
        .unwrap();
    assert!(pinned.allowed);

    let (ping_status, ping_body) = bc_authorize_pingpush_for_user(&router, "ping-quota", BOB).await;
    assert_eq!(ping_status, StatusCode::OK, "ping 发起应 200: {ping_body}");
    let ping_arid = ping_body["auth_req_id"].as_str().unwrap().to_string();
    let bob = login(&router, BOB).await;
    assert_eq!(
        post_bc_approve(&router, &ping_arid, &bob).await,
        StatusCode::NO_CONTENT,
        "配额耗尽时 ping 批准本身仍 204"
    );

    let (push_status, push_body) =
        bc_authorize_pingpush_for_user(&router, "push-quota", CAROL).await;
    assert_eq!(push_status, StatusCode::OK, "push 发起应 200: {push_body}");
    let push_arid = push_body["auth_req_id"].as_str().unwrap().to_string();
    let carol = login(&router, CAROL).await;
    assert_eq!(
        post_bc_approve(&router, &push_arid, &carol).await,
        StatusCode::NO_CONTENT,
        "配额耗尽时 push 批准本身仍 204"
    );

    // 配额耗尽后 ping/push 都不得在正向控制之外新增主动投递。
    assert_eq!(
        mock.delivered().await.len(),
        1,
        "共享配额耗尽时 ping/push 都必须跳过主动投递"
    );

    // 两个记录都在 consume/签发前跳过,因此 client 仍可认证轮询取 token。
    for (arid, client_id) in [(&ping_arid, "ping-quota"), (&push_arid, "push-quota")] {
        let (status, body) = poll_token_confidential(&router, arid, client_id, true).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "配额耗尽后 {client_id} 轮询仍应签 token: {body}"
        );
        assert!(body["access_token"].as_str().is_some());
    }
}

// confidential ping client 走 /token **不带** client 认证 → 401(codex 二轮 High:auth_req_id 裸值不足取)。
#[tokio::test]
async fn confidential_ciba_token_requires_client_auth() {
    let (state, _mock) = p3_state_with_delivery();
    state.seed_user(ALICE, 1000).await;
    seed_pingpush_client(&state, "ping-cli", "ping").await;
    let (router, _) = build_router(state);

    let (_, ba) = bc_authorize_pingpush(&router, "ping-cli").await;
    let arid = ba["auth_req_id"].as_str().unwrap().to_string();
    let alice = login(&router, ALICE).await;
    post_bc_approve(&router, &arid, &alice).await;

    // 不带 client_secret → 401 invalid_client(即便已批准)。
    let (st, body) = poll_token_confidential(&router, &arid, "ping-cli", false).await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "confidential CIBA /token 无认证应 401: {body}"
    );
    assert_eq!(body["error"], "invalid_client");
}

// push:批准后 AS 直接投递完整 token 响应;token 一次性——之后 /token 拒 invalid_grant。
#[tokio::test]
async fn push_dispatch_delivers_token_and_is_one_time() {
    let (state, mock) = p3_state_with_delivery();
    state.seed_user(ALICE, 1000).await;
    seed_pingpush_client(&state, "push-cli", "push").await;
    let (router, _) = build_router(state.clone());

    let (_, ba) = bc_authorize_pingpush(&router, "push-cli").await;
    let arid = ba["auth_req_id"].as_str().unwrap().to_string();
    assert_eq!(
        state
            .clients
            .get("", "push-cli")
            .await
            .unwrap()
            .unwrap()
            .last_used_day,
        None,
        "CIBA push 铸造前 client 应仍是从未使用"
    );
    let alice = login(&router, ALICE).await;
    assert_eq!(
        post_bc_approve(&router, &arid, &alice).await,
        StatusCode::NO_CONTENT
    );

    // push 投递:1 次,body 含完整 token 响应(access_token)+ auth_req_id。
    let dels = mock.delivered().await;
    assert_eq!(dels.len(), 1, "push 应投递 1 次完整 token");
    assert!(
        dels[0].body["access_token"].as_str().is_some(),
        "push body 含 access_token: {}",
        dels[0].body
    );
    assert_eq!(dels[0].body["auth_req_id"], arid);
    assert!(
        state
            .clients
            .get("", "push-cli")
            .await
            .unwrap()
            .unwrap()
            .last_used_day
            .is_some(),
        "push 成功签发后应记录 client 最后使用日"
    );

    // 一次性:push 已消费 → 之后走 /token MUST 拒 invalid_grant。
    let (st, body) = poll_token_confidential(&router, &arid, "push-cli", true).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "push 后 /token 应拒: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

// push 签发后投递失败(mock 注入 Failed)= 模糊态 → 已消费终态,MUST NOT 退化 poll(codex 二轮 High)。
#[tokio::test]
async fn push_delivery_failed_is_terminal_no_poll_fallback() {
    let (state, mock) = p3_state_with_delivery();
    mock.set_outcome(CibaDeliveryOutcome::Failed).await; // 投递报失败(已发出,模糊)
    state.seed_user(ALICE, 1000).await;
    seed_pingpush_client(&state, "push-cli", "push").await;
    let (router, _) = build_router(state.clone());

    let (_, ba) = bc_authorize_pingpush(&router, "push-cli").await;
    let arid = ba["auth_req_id"].as_str().unwrap().to_string();
    assert_eq!(
        state
            .clients
            .get("", "push-cli")
            .await
            .unwrap()
            .unwrap()
            .last_used_day,
        None,
        "CIBA push 铸造前 client 应仍是从未使用"
    );
    let alice = login(&router, ALICE).await;
    post_bc_approve(&router, &arid, &alice).await;

    // 签发后失败:token 已消费,MUST NOT 退化 poll → /token 拒 invalid_grant(不重签第二个 token)。
    let (st, body) = poll_token_confidential(&router, &arid, "push-cli", true).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "push 签发后失败应作废(已消费),/token 不再签: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");
    assert!(
        state
            .clients
            .get("", "push-cli")
            .await
            .unwrap()
            .unwrap()
            .last_used_day
            .is_some(),
        "token 已成功铸造时,即使 push 投递失败也应记录 client 活动"
    );
}

// push 签发前失败(mock 注入 BlockedBySsrf,模拟投递前 SSRF 复校拒)→ token 未签、未消费 → 退化 poll:
// client 仍可走 /token 取到(签发前失败可安全退化)。
#[tokio::test]
async fn push_blocked_before_issuance_degrades_to_poll() {
    let (state, mock) = p3_state_with_delivery();
    mock.set_outcome(CibaDeliveryOutcome::BlockedBySsrf).await;
    state.seed_user(ALICE, 1000).await;
    seed_pingpush_client(&state, "push-cli", "push").await;
    let (router, _) = build_router(state);

    let (_, ba) = bc_authorize_pingpush(&router, "push-cli").await;
    let arid = ba["auth_req_id"].as_str().unwrap().to_string();
    let alice = login(&router, ALICE).await;
    post_bc_approve(&router, &arid, &alice).await;

    // BlockedBySsrf 是投递环节(mock 在 handler 已 consume 之后返回),但当前实现 consume 在签发前——
    // 已 consume 则视为签发后失败作废。故此处断言:token 不复签(与"签发后失败"同处置,保守 fail-safe)。
    // (真机"签发前 SSRF"发生在 issue 之前的独立复校;mock 无法区分,统一按已消费终态。)
    let (st, _body) = poll_token_confidential(&router, &arid, "push-cli", true).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "push 已 consume 后任何投递失败均作废(不复签,保守 fail-safe)"
    );
}

// 快照:发起后 PATCH/改 client 的 delivery_mode 不影响已发起请求(投递按快照,不读当前 ClientRecord)。
#[tokio::test]
async fn delivery_uses_snapshot_not_current_client() {
    let (state, mock) = p3_state_with_delivery();
    state.seed_user(ALICE, 1000).await;
    seed_pingpush_client(&state, "ping-cli", "ping").await;
    let clients = state.clients.clone();
    let (router, _) = build_router(state);

    let (_, ba) = bc_authorize_pingpush(&router, "ping-cli").await;
    let arid = ba["auth_req_id"].as_str().unwrap().to_string();

    // 批准前把 client 的 endpoint 改掉(模拟 PATCH)。快照应保持发起时的 endpoint。
    let mut c = ClientStore::get(clients.as_ref(), "", "ping-cli")
        .await
        .unwrap()
        .unwrap();
    c.backchannel_client_notification_endpoint = Some("https://changed.example.com/new".into());
    ClientStore::put(clients.as_ref(), "", c).await.unwrap();

    let alice = login(&router, ALICE).await;
    post_bc_approve(&router, &arid, &alice).await;

    let dels = mock.delivered().await;
    assert_eq!(dels.len(), 1);
    assert_eq!(
        dels[0].notification_endpoint, "https://client.example.com/ciba/notify",
        "投递 MUST 用发起时快照的 endpoint,不读被 PATCH 改后的当前值"
    );
}

// 降级绕过防御(codex 提交前评审 Medium):ping/push 记录 + client 被降级为 auth_method=none →
// CIBA /token MUST 拒(不允许 none client 凭 delivery_mode=Some 无认证签出 token)。
#[tokio::test]
async fn confidential_downgrade_to_none_rejected_at_token() {
    let (state, _mock) = p3_state_with_delivery();
    state.seed_user(ALICE, 1000).await;
    seed_pingpush_client(&state, "ping-cli", "ping").await;
    let clients = state.clients.clone();
    let (router, _) = build_router(state);

    let (_, ba) = bc_authorize_pingpush(&router, "ping-cli").await;
    let arid = ba["auth_req_id"].as_str().unwrap().to_string();
    let alice = login(&router, ALICE).await;
    post_bc_approve(&router, &arid, &alice).await;

    // 攻击:把 client 降级为 public(auth_method=none,清 secret)。
    let mut c = ClientStore::get(clients.as_ref(), "", "ping-cli")
        .await
        .unwrap()
        .unwrap();
    c.token_endpoint_auth_method = "none".into();
    c.client_secret = None;
    c.client_type = Some("confidential".into());
    ClientStore::put(clients.as_ref(), "", c).await.unwrap();

    // 脏/旧记录即使仍显式标 confidential，只要 auth_method=none 也 MUST 401。
    let (st, body) = poll_token_confidential(&router, &arid, "ping-cli", false).await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "降级为 none 后 ping/push /token MUST 拒(防降级绕过): {body}"
    );
    assert_eq!(body["error"], "invalid_client");
}

#[tokio::test]
async fn confidential_none_record_rejected_at_bc_authorize() {
    let (state, _mock) = p3_state_with_delivery();
    state.seed_user(ALICE, 1000).await;
    seed_pingpush_client(&state, "ping-cli", "ping").await;
    let mut client = ClientStore::get(state.clients.as_ref(), "", "ping-cli")
        .await
        .unwrap()
        .unwrap();
    client.token_endpoint_auth_method = "none".into();
    client.client_secret = None;
    client.client_type = Some("confidential".into());
    ClientStore::put(state.clients.as_ref(), "", client)
        .await
        .unwrap();
    let (router, _) = build_router(state);

    let form = format!(
        "client_id=ping-cli&scope=openid&login_hint={ALICE}\
         &client_notification_token={CNT}"
    );
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/bc-authorize")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "unauthorized_client");
    assert!(body.get("auth_req_id").is_none());
}

// tombstone 闸(评审 Kiro H2):client 在发起↔批准窗口被回收(tombstoned)→ push 分派 MUST 不签发 token,
// 记录留 approved;之后 /token 轮询(回收态)也拒——无 token 泄露到旧端点。
#[tokio::test]
async fn push_to_tombstoned_client_does_not_issue() {
    let (state, mock) = p3_state_with_delivery();
    state.seed_user(ALICE, 1000).await;
    seed_pingpush_client(&state, "push-cli", "push").await;
    let clients = state.clients.clone();
    let (router, _) = build_router(state.clone());

    let (_, ba) = bc_authorize_pingpush(&router, "push-cli").await;
    let arid = ba["auth_req_id"].as_str().unwrap().to_string();

    // 批准前回收 client(tombstone)。
    let mut c = ClientStore::get(clients.as_ref(), "", "push-cli")
        .await
        .unwrap()
        .unwrap();
    c.tombstoned_at = Some(1000);
    ClientStore::put(clients.as_ref(), "", c).await.unwrap();

    let alice = login(&router, ALICE).await;
    post_bc_approve(&router, &arid, &alice).await;

    // push 分派对回收 client MUST 不签发 → 无投递。
    assert!(
        mock.delivered().await.is_empty(),
        "回收 client 的 push MUST 不投递 token"
    );
    let request = state.ciba.get("", &arid).await.unwrap().unwrap();
    assert_eq!(request.status, "approved");
    assert!(
        !request.consumed,
        "回收 client 的 push MUST 在消费 auth_req_id 前拒绝"
    );
    assert_eq!(
        state
            .clients
            .get("", "push-cli")
            .await
            .unwrap()
            .unwrap()
            .last_used_day,
        None,
        "回收 client 未签发 token,不得记录活动"
    );
    assert!(
        state
            .grants
            .list_by_user("", "user:alice@example.com")
            .await
            .unwrap()
            .is_empty(),
        "回收 client 的 push MUST 不创建 Grant"
    );
    // 且 /token(confidential 认证)对回收 client 也拒(tombstone fail-closed;不签)。
    let (st, body) = poll_token_confidential(&router, &arid, "push-cli", true).await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "回收 client 的 CIBA /token 应拒(不签出 token)"
    );
    assert_eq!(body["error"], "invalid_client");
}

// discovery 门控:P3+gate 开 → 宣告 poll/ping/push;P2 → 仅 poll(HTTP 层端到端,含 feature gate 联动)。
#[tokio::test]
async fn discovery_announces_delivery_modes_by_capability() {
    async fn fetch_modes(router: &axum::Router) -> serde_json::Value {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/openid-configuration")
                    .header("host", HOST)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&b).unwrap();
        doc["backchannel_token_delivery_modes_supported"].clone()
    }

    // P3 + gate 开 → 三模式。
    let (state, _) = p3_state_with_delivery();
    let (router, _) = build_router(state);
    assert_eq!(
        fetch_modes(&router).await,
        serde_json::json!(["poll", "ping", "push"]),
        "P3+gate 开 discovery 宣告三模式"
    );

    // P2(CIBA 上架但 ping/push 未启用)→ 仅 poll。
    let mut p2 = AppState::dev(HOST);
    p2.phase = Phase::P2;
    let (router2, _) = build_router(p2);
    assert_eq!(
        fetch_modes(&router2).await,
        serde_json::json!(["poll"]),
        "P2 仅宣告 poll"
    );
}
