//! 进程内 e2e:Device Authorization Grant(RFC 8628,spec 013 C7b.4)。
//!
//! 覆盖:/device_authorization 铸 device_code+user_code;device_code 轮询 authorization_pending →
//! (批准)→ IssueToken;slow_down;过期;P1 阶段端点不可达 + grant 不受理。

use agent_auth_http::ports::{
    ClientStore, DeviceAuthGrant, DeviceStore, PasswordCredential, PasswordStore, RateLimitStore,
};
use agent_auth_http::security_event::{SecurityEventOutcome, SecurityEventStore};
use agent_auth_http::{build_router, AppState, Phase};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use tower::ServiceExt;

const HOST: &str = "localhost";
const CLIENT: &str = "device-client";
const TOKEN_HTU: &str = "https://localhost/token";

fn p2_state() -> AppState {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    state
}

async fn device_authorization(
    router: &axum::Router,
    client: &str,
) -> (StatusCode, serde_json::Value) {
    let form = format!("client_id={client}&scope=openid kb:read");
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/device_authorization")
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

async fn poll_token_response(router: &axum::Router, device_code: &str) -> axum::response::Response {
    let form = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={device_code}&client_id={CLIENT}"
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

async fn poll_token(router: &axum::Router, device_code: &str) -> (StatusCode, serde_json::Value) {
    let resp = poll_token_response(router, device_code).await;
    let st = resp.status();
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        st,
        serde_json::from_slice(&b).unwrap_or(serde_json::json!({})),
    )
}

async fn exhaust_client_rate_limit(state: &AppState, client_id: &str) {
    let rate_limit = state.rate_limit.as_ref().expect("dev rate-limit store");
    rate_limit.delete(client_id).await.unwrap();
    assert!(
        rate_limit
            .try_consume(client_id, i64::MAX / 4, 1.0, 0.0, 1.0)
            .await
            .unwrap()
            .allowed
    );
}

async fn poll_token_with_dpop(
    router: &axum::Router,
    device_code: &str,
    proof: &str,
) -> (StatusCode, serde_json::Value) {
    let form = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={device_code}&client_id={CLIENT}"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .header("dpop", proof)
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

fn device_dpop_keypair(seed: u8) -> (SigningKey, serde_json::Value) {
    let signing_key = SigningKey::from_bytes(&[seed; 32].into()).unwrap();
    let point = signing_key.verifying_key().to_encoded_point(false);
    (
        signing_key,
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": B64.encode(point.x().unwrap()),
            "y": B64.encode(point.y().unwrap()),
        }),
    )
}

fn device_dpop_proof(signing_key: &SigningKey, jwk: &serde_json::Value, jti: &str) -> String {
    let header = serde_json::json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": jwk });
    let claims = serde_json::json!({
        "htu": TOKEN_HTU,
        "htm": "POST",
        "iat": agent_auth_http::current_unix_secs(),
        "jti": jti,
    });
    let encoded_header = B64.encode(serde_json::to_vec(&header).unwrap());
    let encoded_claims = B64.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", B64.encode(signature.to_bytes()))
}

fn device_token_cnf(access_token: &str) -> Option<serde_json::Value> {
    let payload = access_token.split('.').nth(1)?;
    let claims: serde_json::Value = serde_json::from_slice(&B64.decode(payload).ok()?).ok()?;
    claims.get("cnf").cloned()
}

fn assert_access_token_es256(access_token: &str) {
    let header: serde_json::Value =
        serde_json::from_slice(&B64.decode(access_token.split('.').next().unwrap()).unwrap())
            .unwrap();
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "at+jwt");
}

fn device_jkt(jwk: &serde_json::Value) -> String {
    B64.encode(agent_auth_infra_core::jwks::ec_thumbprint(
        "P-256",
        jwk["x"].as_str().unwrap(),
        jwk["y"].as_str().unwrap(),
    ))
}

// C7b.4:device_authorization 参数与公开 /token 的 pending/slow_down/expired 轮询矩阵。
#[tokio::test]
async fn device_authorization_then_pending() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    let (router, _) = build_router(state.clone());

    let issued_not_before = agent_auth_http::token::current_unix_secs_pub();
    let (st, da) = device_authorization(&router, CLIENT).await;
    let issued_not_after = agent_auth_http::token::current_unix_secs_pub();
    assert_eq!(st, StatusCode::OK, "device_authorization 应 200: {da}");
    let device_code = da["device_code"].as_str().expect("device_code");
    assert!(
        da["user_code"]
            .as_str()
            .map(|u| u.len() == 8)
            .unwrap_or(false),
        "user_code 8 位"
    );
    // verification_uri 指向前端批准页 /approve(用户打开的页面),非 API 的 POST /device(页面提交动作)。
    assert!(da["verification_uri"]
        .as_str()
        .unwrap()
        .ends_with("/approve"));
    assert_eq!(da["interval"], 5);
    let advertised_ttl = da["expires_in"].as_i64().expect("expires_in");
    assert!(
        (1..=15 * 60).contains(&advertised_ttl),
        "device_code TTL must not exceed 15 minutes: {da}"
    );
    let grant = state
        .device
        .get("", device_code)
        .await
        .unwrap()
        .expect("device grant");
    assert!(
        grant.expires_at >= issued_not_before + advertised_ttl
            && grant.expires_at <= issued_not_after + advertised_ttl,
        "authoritative expiry must match the advertised TTL: grant={grant:?}, response={da}"
    );

    // 未批准轮询 → authorization_pending(400)。
    let (st, body) = poll_token(&router, device_code).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "authorization_pending");

    // 第一次公开轮询已记录 last_poll_at。保留下发 interval,只固定轮询时刻前置以消除调度抖动。
    let mut grant = state
        .device
        .get("", device_code)
        .await
        .unwrap()
        .expect("device grant");
    assert!(
        grant.last_poll_at.is_some(),
        "pending poll records last_poll_at"
    );
    assert_eq!(grant.interval, da["interval"].as_i64().unwrap());
    grant.last_poll_at = Some(agent_auth_http::token::current_unix_secs_pub() + 60);
    state.device.update("", grant).await.unwrap();

    // 权威 last_poll_at 仍在下发 interval 内 → slow_down。
    let (st, body) = poll_token(&router, device_code).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "slow_down");

    // 权威 last_poll_at 已越过下发 interval → 恢复 authorization_pending。
    let mut grant = state
        .device
        .get("", device_code)
        .await
        .unwrap()
        .expect("device grant");
    grant.last_poll_at = Some(agent_auth_http::token::current_unix_secs_pub() - grant.interval);
    state.device.update("", grant).await.unwrap();
    let (st, body) = poll_token(&router, device_code).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "authorization_pending");

    // 过期优先于频率判断,公开 /token 返回 expired_token。
    let mut grant = state
        .device
        .get("", device_code)
        .await
        .unwrap()
        .expect("device grant");
    grant.expires_at = 1;
    state.device.update("", grant).await.unwrap();
    let (st, body) = poll_token(&router, device_code).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "expired_token");
}

#[tokio::test]
async fn device_token_poll_rate_limit_uses_bound_client_without_claiming_poll() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    let (router, _) = build_router(state.clone());
    let (status, authorization) = device_authorization(&router, CLIENT).await;
    assert_eq!(status, StatusCode::OK);
    let device_code = authorization["device_code"].as_str().unwrap();

    exhaust_client_rate_limit(&state, CLIENT).await;
    let form = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={device_code}&client_id={CLIENT}"
    );
    let limited = router
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
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(limited
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|value| value > 0));
    let limited_body = axum::body::to_bytes(limited.into_body(), usize::MAX)
        .await
        .unwrap();
    let limited_body: serde_json::Value = serde_json::from_slice(&limited_body).unwrap();
    assert_eq!(limited_body["error"], "temporarily_unavailable");
    assert_eq!(
        state
            .device
            .get("", device_code)
            .await
            .unwrap()
            .unwrap()
            .last_poll_at,
        None,
        "aggregate client throttling must not claim the artifact poll slot"
    );

    state
        .rate_limit
        .as_ref()
        .unwrap()
        .delete(CLIENT)
        .await
        .unwrap();
    let (status, body) = poll_token(&router, device_code).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "authorization_pending");
}

#[tokio::test]
async fn device_concurrent_pending_polls_enforce_the_advertised_interval() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    let (router, _) = build_router(state);
    let (_, response) = device_authorization(&router, CLIENT).await;
    let device_code = response["device_code"].as_str().unwrap().to_string();

    let (first, second) = tokio::join!(
        poll_token(&router, &device_code),
        poll_token(&router, &device_code),
    );
    let mut errors = [
        first.1["error"].as_str().unwrap(),
        second.1["error"].as_str().unwrap(),
    ];
    errors.sort_unstable();
    assert_eq!(first.0, StatusCode::BAD_REQUEST);
    assert_eq!(second.0, StatusCode::BAD_REQUEST);
    assert_eq!(errors, ["authorization_pending", "slow_down"]);
}

// C7b.4:批准后轮询 → 签出 3LO access token(sub=用户、含 jti);一次性(再轮询 invalid_grant)。
#[tokio::test]
async fn device_approved_issues_token() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    let (router, _) = build_router(state.clone());
    assert_eq!(
        state
            .clients
            .get("", CLIENT)
            .await
            .unwrap()
            .unwrap()
            .last_used_day,
        None
    );
    let (unknown_status, _) = poll_token(&router, "unknown-device-code").await;
    assert_eq!(unknown_status, StatusCode::BAD_REQUEST);
    assert_eq!(
        state
            .clients
            .get("", CLIENT)
            .await
            .unwrap()
            .unwrap()
            .last_used_day,
        None,
        "device poll 签发失败不得推进 client 活动"
    );

    let (_, da) = device_authorization(&router, CLIENT).await;
    let device_code = da["device_code"].as_str().unwrap().to_string();
    let user_code = da["user_code"].as_str().unwrap().to_string();

    // 用户在批准页批准(approve_by_user_code)。
    agent_auth_http::device_flow::approve_by_user_code(&state, "", &user_code, "alice", true)
        .await
        .expect("批准应成功");

    // 首次轮询会因 slow_down 被拦?——首次轮询 last_poll_at=None,不算过快。但 pending→approved 后
    // last_poll_at 已被 pending 轮询设过?本测试未先轮询,故首次轮询直接 IssueToken。
    let (st, body) = poll_token(&router, &device_code).await;
    assert_eq!(st, StatusCode::OK, "批准后轮询应签出 token: {body}");
    let at = body["access_token"].as_str().expect("access_token");
    let payload = at.split('.').nth(1).unwrap();
    let c: serde_json::Value = serde_json::from_slice(&B64.decode(payload).unwrap()).unwrap();
    assert_eq!(c["sub"], "alice", "device 3LO sub=用户(public 形态)");
    assert!(c["jti"].as_str().is_some(), "含 jti");
    assert!(
        body.get("refresh_token").is_none(),
        "device flow P2 先不发 refresh"
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
        "成功 device poll 签发必须推进 client 活动"
    );

    // 一次性:再轮询同 device_code → invalid_grant(consumed)。
    let (st2, body2) = poll_token(&router, &device_code).await;
    assert_eq!(st2, StatusCode::BAD_REQUEST);
    assert_eq!(body2["error"], "invalid_grant", "已消费 device_code 重放拒");

    // spec 011 §5.1 / 013:device 3LO token **建 Grant**(auth_grant=grant_id)→ 可经 /grants 管理/吊销、
    // introspect 反映吊销(此前 device 不建 Grant,其 token 无法吊销/introspect 不反映——评审缺口)。
    let gid = c["https://a-auth.com/c"]["auth_grant"]
        .as_str()
        .expect("device token 命名空间应含 auth_grant");
    let g = agent_auth_http::ports::GrantStore::get(state.grants.as_ref(), "", gid)
        .await
        .unwrap()
        .expect("device 3LO 应建 Grant");
    assert_eq!(g.user_id, "alice", "Grant 属批准用户");
    assert_eq!(g.client_id, CLIENT);
    assert_eq!(
        g.status,
        agent_auth_grant::GrantStatus::Active,
        "device Grant 初始 Active"
    );
    assert!(
        g.constraints.actor_allowlist.is_empty(),
        "device 纯 3LO 不授委托(actor_allowlist 空)"
    );
}

#[tokio::test]
async fn device_kms_transient_returns_retry_after_and_releases_consumption() {
    use agent_auth_http::state::SignerImpl;

    let mut state = p2_state();
    let isolated_signer = std::sync::Arc::new(SignerImpl::Memory(
        agent_auth_http::adapters::memory::MemorySigner::from_seed([83; 32]),
    ));
    state.signer = isolated_signer.clone();
    state.tenant_keys = std::sync::Arc::new(
        agent_auth_http::tenant_keys::TenantKeyService::shared(isolated_signer),
    );
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    let router = build_router(state.clone()).0;
    let (_, authorization) = device_authorization(&router, CLIENT).await;
    let device_code = authorization["device_code"].as_str().unwrap().to_string();
    let user_code = authorization["user_code"].as_str().unwrap().to_string();
    agent_auth_http::device_flow::approve_by_user_code(&state, "", &user_code, "alice", true)
        .await
        .unwrap();
    let SignerImpl::Memory(signer) = state.signer.as_ref() else {
        panic!("dev state must use MemorySigner");
    };
    signer.fail_next_es256(true);

    let response = poll_token_response(&router, &device_code).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["retry-after"], "1");
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["error"], "temporarily_unavailable");
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());

    let mut grant = state.device.get("", &device_code).await.unwrap().unwrap();
    assert!(
        !grant.consumed,
        "transient signing failure must release device consumption"
    );
    grant.last_poll_at =
        Some(agent_auth_http::token::current_unix_secs_pub() - grant.interval.max(1));
    state.device.update("", grant).await.unwrap();
    assert_eq!(
        poll_token(&router, &device_code).await.0,
        StatusCode::OK,
        "the approved device code must remain retryable after backoff"
    );
}

// C8.7b:device-code grant 的 /token 轮询支持 DPoP opt-in，proof-free 路径保持 bearer。
#[tokio::test]
async fn device_token_dpop_and_bearer_binding() {
    let mut state = p2_state();
    state.phase = Phase::P3;
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    let (router, _) = build_router(state.clone());

    let (_, dpop_authorization) = device_authorization(&router, CLIENT).await;
    let dpop_device_code = dpop_authorization["device_code"].as_str().unwrap();
    let dpop_user_code = dpop_authorization["user_code"].as_str().unwrap();
    agent_auth_http::device_flow::approve_by_user_code(&state, "", dpop_user_code, "alice", true)
        .await
        .unwrap();
    let (signing_key, jwk) = device_dpop_keypair(42);
    let proof = device_dpop_proof(&signing_key, &jwk, "device-dpop");
    let (dpop_status, dpop_body) = poll_token_with_dpop(&router, dpop_device_code, &proof).await;
    assert_eq!(
        dpop_status,
        StatusCode::OK,
        "device DPoP issuance should succeed: {dpop_body}"
    );
    assert_eq!(dpop_body["token_type"], "DPoP");
    assert_access_token_es256(dpop_body["access_token"].as_str().unwrap());
    assert_eq!(
        device_token_cnf(dpop_body["access_token"].as_str().unwrap()).unwrap()["jkt"],
        device_jkt(&jwk)
    );

    let (_, bearer_authorization) = device_authorization(&router, CLIENT).await;
    let bearer_device_code = bearer_authorization["device_code"].as_str().unwrap();
    let bearer_user_code = bearer_authorization["user_code"].as_str().unwrap();
    agent_auth_http::device_flow::approve_by_user_code(&state, "", bearer_user_code, "alice", true)
        .await
        .unwrap();
    let (bearer_status, bearer_body) = poll_token(&router, bearer_device_code).await;
    assert_eq!(
        bearer_status,
        StatusCode::OK,
        "device bearer issuance should remain available: {bearer_body}"
    );
    assert_eq!(bearer_body["token_type"], "Bearer");
    assert_access_token_es256(bearer_body["access_token"].as_str().unwrap());
    assert!(
        device_token_cnf(bearer_body["access_token"].as_str().unwrap()).is_none(),
        "a proof-free device token must not receive an invented cnf"
    );
}

#[tokio::test]
async fn device_approval_rejects_a_request_from_a_previous_regional_activation() {
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

    let mut state = p2_state();
    state.region = region.clone();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    let (router, _) = build_router(state.clone());
    let (_, response) = device_authorization(&router, CLIENT).await;
    let device_code = response["device_code"].as_str().unwrap().to_string();
    let user_code = response["user_code"].as_str().unwrap().to_string();

    control
        .set(Some(RegionControlRecord {
            active: true,
            activation_not_before: 0,
            revision: 2,
        }))
        .await;
    assert_eq!(
        region
            .admit(agent_auth_http::current_unix_secs())
            .await
            .unwrap(),
        RegionAdmission::Active
    );

    assert_eq!(
        agent_auth_http::device_flow::approve_by_user_code(&state, "", &user_code, "alice", true,)
            .await,
        Err("wrong Region activation")
    );
    assert_eq!(
        state
            .device
            .get("", &device_code)
            .await
            .unwrap()
            .unwrap()
            .status,
        "pending"
    );
}

#[tokio::test]
async fn legacy_local_user_approval_without_password_version_fails_closed() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    let user_id = "user:legacy-device@example.com";
    state
        .passwords
        .create_if_absent(
            "",
            PasswordCredential {
                user_id: user_id.to_string(),
                password_hash: agent_auth_authn::password::dummy_hash().clone(),
                must_change: false,
                revocation_pending: false,
                credential_change_id: None,
                version: 2,
                updated_at: 1,
            },
        )
        .await
        .unwrap();
    state
        .device
        .put(
            "",
            DeviceAuthGrant {
                device_code: "legacy-device-code".to_string(),
                user_code: "LEGACY01".to_string(),
                client_id: CLIENT.to_string(),
                user_id: Some(user_id.to_string()),
                authz_session_id: None,
                scope: vec!["openid".to_string()],
                resources: vec![],
                interval: 5,
                last_poll_at: None,
                expires_at: i64::MAX,
                status: "approved".to_string(),
                consumed: false,
                password_credential_version: None,
            },
        )
        .await
        .unwrap();
    let (router, _) = build_router(state.clone());

    let (status, body) = poll_token(&router, "legacy-device-code").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(
        !state
            .device
            .get("", "legacy-device-code")
            .await
            .unwrap()
            .unwrap()
            .consumed
    );
}

// 评审 F1(HIGH,原子一次性):两个并发轮询同一批准的 device_code,恰好**一个**签出 token,
// 另一个 invalid_grant(consume CAS 保证)。防 TOCTOU 双发。
#[tokio::test]
async fn device_concurrent_poll_issues_exactly_one() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    let (router, _) = build_router(state.clone());
    let (_, da) = device_authorization(&router, CLIENT).await;
    let device_code = da["device_code"].as_str().unwrap().to_string();
    let user_code = da["user_code"].as_str().unwrap().to_string();
    agent_auth_http::device_flow::approve_by_user_code(&state, "", &user_code, "alice", true)
        .await
        .unwrap();

    // 并发两次轮询。核心安全不变式:**最多/恰好一个 200**(consume CAS 保证)。落败方的错误码不固定
    // (可能 invalid_grant,也可能因 claim_poll 抢先而 slow_down,评审 codex LOW):故只断言"恰一个
    // 200 + 另一个非 200",不锁死落败错误码。
    let (r1, r2) = tokio::join!(
        poll_token(&router, &device_code),
        poll_token(&router, &device_code),
    );
    let oks = [&r1, &r2]
        .iter()
        .filter(|(st, _)| *st == StatusCode::OK)
        .count();
    assert_eq!(
        oks, 1,
        "恰好一个并发轮询签出 token(一次性原子): r1={r1:?} r2={r2:?}"
    );
    // 落败方 MUST 非 200(未签第二个 token)。
    let non_ok = [&r1, &r2]
        .iter()
        .filter(|(st, _)| *st != StatusCode::OK)
        .count();
    assert_eq!(non_ok, 1, "另一个并发轮询未签出 token");
    // 后续再轮询(串行)MUST 是 invalid_grant(已消费,重放拒)。
    let (st3, body3) = poll_token(&router, &device_code).await;
    assert_eq!(st3, StatusCode::BAD_REQUEST);
    assert_eq!(
        body3["error"], "invalid_grant",
        "已消费 device_code 串行重放拒"
    );
}

// 评审 F3/HIGH-2:device flow 仅限 public client;confidential(client_secret_basic)拒 invalid_client。
#[tokio::test]
async fn device_authorization_rejects_confidential_client() {
    let state = p2_state();
    state
        .seed_rs_introspect_client("conf-client", "s3cret", &["https://rs.example/api"])
        .await;
    let (router, _) = build_router(state);
    let (st, body) = device_authorization(&router, "conf-client").await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "confidential 应拒: {body}");
    assert_eq!(body["error"], "unauthorized_client");
}

// 评审 codex F3 二轮:workload client(即便 token_endpoint_auth_method=none)MUST 拒——机器身份不走
// 用户 3LO,否则绕过 /authorize 的 workload 拒绝。用 client_type()==Public 规范判定(非仅 auth_method)。
#[tokio::test]
async fn device_authorization_rejects_workload_client_with_none_auth() {
    let state = p2_state();
    // seed_workload_client:client_type=workload 但 auth_method=none。
    state.seed_workload_client("wl-client").await;
    let (router, _) = build_router(state);
    let (st, body) = device_authorization(&router, "wl-client").await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "workload 应拒: {body}");
    assert_eq!(body["error"], "unauthorized_client");
}

// 评审 codex F1 二轮:并发批准不得用旧快照整对象写回重开已消费的 device_code。
// 场景:批准 → 轮询签出 token(consumed=true)→ 再次批准同 user_code(decide CAS 应因 status!=pending
// 落败,不重开)→ 轮询 MUST 仍 invalid_grant(未签第二个 token)。
#[tokio::test]
async fn device_reapprove_after_consume_does_not_reopen() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    let (router, _) = build_router(state.clone());
    let (_, da) = device_authorization(&router, CLIENT).await;
    let device_code = da["device_code"].as_str().unwrap().to_string();
    let user_code = da["user_code"].as_str().unwrap().to_string();

    // 批准 → 轮询签出 token(consumed=true)。
    agent_auth_http::device_flow::approve_by_user_code(&state, "", &user_code, "alice", true)
        .await
        .unwrap();
    let (st, _) = poll_token(&router, &device_code).await;
    assert_eq!(st, StatusCode::OK, "首次批准后应签出 token");

    // 已消费后再批准同 user_code:decide CAS 因 status=approved(非 pending)落败 → already decided。
    let re =
        agent_auth_http::device_flow::approve_by_user_code(&state, "", &user_code, "mallory", true)
            .await;
    assert_eq!(
        re,
        Err("already decided"),
        "已决定的码不可再批准(不重开 consumed)"
    );

    // 再轮询 MUST 仍 invalid_grant(未被重开,未签第二个 token)。
    let (st2, body2) = poll_token(&router, &device_code).await;
    assert_eq!(st2, StatusCode::BAD_REQUEST);
    assert_eq!(body2["error"], "invalid_grant", "consumed 未被重开");
}

// C7b.4:deny → access_denied。
#[tokio::test]
async fn device_denied() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    let (router, _) = build_router(state.clone());
    let (_, da) = device_authorization(&router, CLIENT).await;
    let device_code = da["device_code"].as_str().unwrap().to_string();
    let user_code = da["user_code"].as_str().unwrap().to_string();
    agent_auth_http::device_flow::approve_by_user_code(&state, "", &user_code, "alice", false)
        .await
        .unwrap();
    let (st, body) = poll_token(&router, &device_code).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "access_denied");
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    let denied = events
        .iter()
        .find(|stored| {
            stored.event.action == "grant.deny"
                && stored.event.outcome == SecurityEventOutcome::Denied
        })
        .expect("device denial must remain auditable");
    assert_eq!(denied.event.correlation.client_id.as_deref(), Some(CLIENT));
    assert_ne!(
        denied.event.correlation.operation_id.as_deref(),
        Some(device_code.as_str()),
        "live device_code must not enter the event envelope"
    );
}

// C7b.4:未知 device_code → invalid_grant。
#[tokio::test]
async fn device_unknown_code_rejected() {
    let state = p2_state();
    let (router, _) = build_router(state);
    let (st, body) = poll_token(&router, "nonexistent").await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
}

// C1.2:P1 阶段 /device_authorization 不可达(404)+ device_code grant 不受理。
#[tokio::test]
async fn device_flow_gated_at_p1() {
    let state = AppState::dev(HOST); // phase=P1
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    let (router, _) = build_router(state);
    let (st, _) = device_authorization(&router, CLIENT).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "P1 /device_authorization 应 404");
    // device_code grant P1 不受理(grant_accepted 门控 → unsupported_grant_type 400)。
    let (st2, _) = poll_token(&router, "x").await;
    assert_eq!(st2, StatusCode::BAD_REQUEST);
}

// C6.4 / spec 004 §3:device/CIBA 等价态映射(`ciba_state_str`)的每个目标字符串 MUST 是 004
// `AuthzState` 的**合法值**(不发明新态)。跨 crate 漂移守卫——ciba crate 不依赖 authn,若 004 改了
// 枚举字符串而 ciba 映射没跟上,这里在 http(同时依赖两者)编译期+运行期兜住。
#[tokio::test]
async fn ciba_device_state_mapping_targets_are_valid_authz_states() {
    use agent_auth_authn::authz_session::AuthzState;
    use agent_auth_ciba::{ciba_state_str, CibaState};
    for (state, expected) in [
        (CibaState::AuthorizationPending, "pending_consent"),
        (CibaState::AwaitingUserCode, "pending_user_authentication"),
        (
            CibaState::ApprovedAwaitingPoll,
            "code_issued_awaiting_exchange",
        ),
        (CibaState::Complete, "complete"),
        (CibaState::Denied, "denied"),
        (CibaState::Expired, "expired"),
    ] {
        let mapped = ciba_state_str(state);
        assert_eq!(
            mapped, expected,
            "CIBA/device 态 {state:?} MUST 映射到规范定义的等价 AuthzState"
        );
        assert!(
            AuthzState::parse(mapped).is_some(),
            "CIBA/device 态 {state:?} 映射到的 {mapped:?} 不是合法 004 AuthzState(映射漂移)"
        );
    }
    // 终态一致性:CIBA 终态映射到的 004 态也 MUST 是终态(语义对齐,不把终态映成可迁出态)。
    for s in [CibaState::Complete, CibaState::Denied, CibaState::Expired] {
        let mapped = AuthzState::parse(ciba_state_str(s)).unwrap();
        assert!(
            mapped.is_terminal(),
            "CIBA 终态 {s:?}→{mapped:?} 应是 004 终态"
        );
    }
}

// ---- spec 013 §2b:device 批准 HTTP 端点(POST /device,登录会话鉴权)----

fn set_cookie_val(resp: &axum::http::Response<Body>, name: &str) -> Option<String> {
    for hv in resp.headers().get_all(axum::http::header::SET_COOKIE) {
        let s = hv.to_str().ok()?;
        if let Some(rest) = s.strip_prefix(&format!("{name}=")) {
            return Some(rest.split(';').next().unwrap_or("").to_string());
        }
    }
    None
}

/// magic-link 登录 → session cookie(user_id = user:{email})。
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

async fn post_device_approve(
    router: &axum::Router,
    user_code: &str,
    approve: bool,
    session: Option<&str>,
) -> StatusCode {
    let mut b = Request::builder()
        .method("POST")
        .uri("/device")
        .header("host", HOST)
        .header("content-type", "application/x-www-form-urlencoded");
    if let Some(s) = session {
        b = b.header("cookie", format!("__Host-agent_auth_session={s}"));
    }
    router
        .clone()
        .oneshot(
            b.body(Body::from(format!(
                "user_code={user_code}&approve={approve}"
            )))
            .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

// §2b:已登录用户 POST /device 批准 → 轮询签出 token(sub=登录 user);未登录 401。
#[tokio::test]
async fn device_http_approve_by_logged_in_user() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    state.seed_dev_user("bob@example.com").await;
    let (router, _) = build_router(state);
    let (_, da) = device_authorization(&router, CLIENT).await;
    let device_code = da["device_code"].as_str().unwrap().to_string();
    let user_code = da["user_code"].as_str().unwrap().to_string();

    // 未登录批准 → 401。
    assert_eq!(
        post_device_approve(&router, &user_code, true, None).await,
        StatusCode::UNAUTHORIZED,
        "未登录批准应 401"
    );

    // 登录后批准 → 204。
    let session = login(&router, "bob@example.com").await;
    assert_eq!(
        post_device_approve(&router, &user_code, true, Some(&session)).await,
        StatusCode::NO_CONTENT
    );

    // 轮询签出 token,sub = 批准者(user:bob@example.com)。
    let (st, body) = poll_token(&router, &device_code).await;
    assert_eq!(st, StatusCode::OK, "批准后轮询应签 token: {body}");
    let at = body["access_token"].as_str().unwrap();
    let c: serde_json::Value =
        serde_json::from_slice(&B64.decode(at.split('.').nth(1).unwrap()).unwrap()).unwrap();
    assert_eq!(c["sub"], "user:bob@example.com", "sub = 批准者(登录 user)");
}

// §2b:未知 user_code 批准 → 404(不泄露)。
#[tokio::test]
async fn device_http_approve_unknown_user_code() {
    let state = p2_state();
    state.seed_dev_user("bob@example.com").await;
    let (router, _) = build_router(state);
    let session = login(&router, "bob@example.com").await;
    assert_eq!(
        post_device_approve(&router, "BOGUSXYZ", true, Some(&session)).await,
        StatusCode::NOT_FOUND
    );
}

// spec 013 Task 2b.3:device user_code 尝试限流(防爆破枚举)。同一登录批准者突发提交 user_code 超桶容量
// (5)→ 429。user_code 8 位短码,须限枚举频率(device_code 128-bit 是主防线,提交面加此闸)。
// 桶补充 0.1/s 极慢 → 限流触发确定性(不受 wall-clock 影响)。
#[tokio::test]
async fn device_user_code_attempt_throttled() {
    let state = p2_state();
    state.seed_dev_user("carol@example.com").await;
    state.seed_dev_user("dave@example.com").await;
    let (router, _) = build_router(state);
    let session = login(&router, "carol@example.com").await;
    let mut saw_429 = false;
    // 突发 8 次错 user_code 提交:前 5 次 404(桶内)、超容量后 429。
    for _ in 0..8 {
        let st = post_device_approve(&router, "BOGUSXYZ", true, Some(&session)).await;
        if st == StatusCode::TOO_MANY_REQUESTS {
            saw_429 = true;
            break;
        }
        assert_eq!(st, StatusCode::NOT_FOUND, "限流前错 user_code 应 404");
    }
    assert!(
        saw_429,
        "同批准者突发提交超容量(5)应触发 user_code 尝试限流 429(2b.3 防爆破)"
    );

    // 不同批准者独立桶:另一 user 首次提交不受限(429 是 per-user)。
    let session2 = login(&router, "dave@example.com").await;
    let st = post_device_approve(&router, "BOGUSXYZ", true, Some(&session2)).await;
    assert_eq!(
        st,
        StatusCode::NOT_FOUND,
        "不同批准者(新桶)首次提交不应被限流(404 而非 429)"
    );
}
