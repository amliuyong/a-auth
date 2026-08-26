//! 进程内 e2e:CIBA 异步授权(OpenID CIBA,spec 013 C7b.1–C7b.3)。
//!
//! 覆盖:/bc-authorize 强制用户标识三选一 + 铸 auth_req_id;auth_req_id 轮询 authorization_pending →
//! (批准)→ IssueToken(3LO,不经 /sessions);deny;一次性重放;并发恰一个;public-only 门控;P1 阶段门控。

use agent_auth_client::s256_challenge;
use agent_auth_http::ports::{
    CibaAuthRequest, CibaStore, ClientStore, PasswordCredential, PasswordStore, RateLimitStore,
    ScimCreateOutcome, ScimReplaceInput, ScimReplaceOutcome, ScimUserInput, Signer, UsersStore,
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
const CLIENT: &str = "ciba-client";
const TOKEN_HTU: &str = "https://localhost/token";
/// 默认被代表用户(login_hint = email;spec 013 §2b.5 契约 = email → users 表解析 user_id)。
const ALICE: &str = "alice@example.com";

fn p2_state() -> AppState {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    state
}

/// 预置默认注册用户 alice(CIBA login_hint 存在性校验前置:发起时用户须已注册)。
async fn seed_alice(state: &AppState) {
    state.seed_user(ALICE, 1000).await;
}

/// POST /bc-authorize(用 form body 直传,便于测异常参数)。
async fn bc_authorize_raw(router: &axum::Router, form: &str) -> (StatusCode, serde_json::Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/bc-authorize")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form.to_string()))
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

async fn bc_authorize(router: &axum::Router, client: &str) -> (StatusCode, serde_json::Value) {
    bc_authorize_raw(
        router,
        &format!("client_id={client}&scope=openid kb:read&login_hint={ALICE}"),
    )
    .await
}

async fn poll_token(router: &axum::Router, auth_req_id: &str) -> (StatusCode, serde_json::Value) {
    poll_token_for_client(router, auth_req_id, CLIENT).await
}

async fn poll_token_for_client(
    router: &axum::Router,
    auth_req_id: &str,
    client_id: &str,
) -> (StatusCode, serde_json::Value) {
    let resp = poll_token_response_for_client(router, auth_req_id, client_id).await;
    let st = resp.status();
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        st,
        serde_json::from_slice(&b).unwrap_or(serde_json::json!({})),
    )
}

async fn poll_token_response_for_client(
    router: &axum::Router,
    auth_req_id: &str,
    client_id: &str,
) -> axum::response::Response {
    let form = format!(
        "grant_type=urn:openid:params:grant-type:ciba&auth_req_id={auth_req_id}&client_id={client_id}"
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
    auth_req_id: &str,
    proof: &str,
) -> (StatusCode, serde_json::Value) {
    let form = format!(
        "grant_type=urn:openid:params:grant-type:ciba&auth_req_id={auth_req_id}&client_id={CLIENT}"
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

fn ciba_dpop_keypair(seed: u8) -> (SigningKey, serde_json::Value) {
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

fn ciba_dpop_proof(signing_key: &SigningKey, jwk: &serde_json::Value, jti: &str) -> String {
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

fn ciba_token_cnf(access_token: &str) -> Option<serde_json::Value> {
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

fn ciba_jkt(jwk: &serde_json::Value) -> String {
    B64.encode(agent_auth_infra_core::jwks::ec_thumbprint(
        "P-256",
        jwk["x"].as_str().unwrap(),
        jwk["y"].as_str().unwrap(),
    ))
}

// C7b.1/C7b.2:bc-authorize 返回轮询参数;公开 /token 保持标准 pending/slow_down/expired 矩阵。
#[tokio::test]
async fn ciba_authorize_then_pending() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    seed_alice(&state).await;
    let (router, _) = build_router(state.clone());

    let (st, ba) = bc_authorize(&router, CLIENT).await;
    assert_eq!(st, StatusCode::OK, "bc-authorize 应 200: {ba}");
    let auth_req_id = ba["auth_req_id"].as_str().expect("auth_req_id");
    assert!(!auth_req_id.is_empty());
    assert_eq!(ba["interval"], 5);
    assert_eq!(ba["expires_in"], 600);

    // 未批准轮询 → authorization_pending(400)。
    let (st, body) = poll_token(&router, auth_req_id).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "authorization_pending");

    // 第一次公开轮询已记录 last_poll_at。保留下发 interval,只固定轮询时刻前置以消除调度抖动。
    let mut record = state
        .ciba
        .get("", auth_req_id)
        .await
        .unwrap()
        .expect("CIBA request");
    assert!(
        record.last_poll_at.is_some(),
        "pending poll records last_poll_at"
    );
    assert_eq!(record.interval, ba["interval"].as_i64().unwrap());
    record.last_poll_at = Some(agent_auth_http::token::current_unix_secs_pub() + 60);
    state.ciba.update("", record).await.unwrap();

    // 权威 last_poll_at 仍在下发 interval 内 → slow_down。
    let (st, body) = poll_token(&router, auth_req_id).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "slow_down");

    // 权威 last_poll_at 已越过下发 interval → 恢复 authorization_pending。
    let mut record = state
        .ciba
        .get("", auth_req_id)
        .await
        .unwrap()
        .expect("CIBA request");
    record.last_poll_at = Some(agent_auth_http::token::current_unix_secs_pub() - record.interval);
    state.ciba.update("", record).await.unwrap();
    let (st, body) = poll_token(&router, auth_req_id).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "authorization_pending");

    // 过期优先于频率判断,公开 /token 返回 expired_token。
    let mut record = state
        .ciba
        .get("", auth_req_id)
        .await
        .unwrap()
        .expect("CIBA request");
    record.expires_at = 1;
    state.ciba.update("", record).await.unwrap();
    let (st, body) = poll_token(&router, auth_req_id).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "expired_token");
}

#[tokio::test]
async fn ciba_token_poll_rate_limit_uses_bound_client_without_claiming_poll() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    seed_alice(&state).await;
    let (router, _) = build_router(state.clone());
    let (status, authorization) = bc_authorize(&router, CLIENT).await;
    assert_eq!(status, StatusCode::OK);
    let auth_req_id = authorization["auth_req_id"].as_str().unwrap();

    exhaust_client_rate_limit(&state, CLIENT).await;
    let form = format!(
        "grant_type=urn:openid:params:grant-type:ciba&auth_req_id={auth_req_id}&client_id={CLIENT}"
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
            .ciba
            .get("", auth_req_id)
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
    let (status, body) = poll_token(&router, auth_req_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "authorization_pending");
}

#[tokio::test]
async fn ciba_concurrent_pending_polls_enforce_the_advertised_interval() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    seed_alice(&state).await;
    let (router, _) = build_router(state);
    let (_, response) = bc_authorize(&router, CLIENT).await;
    let auth_req_id = response["auth_req_id"].as_str().unwrap().to_string();

    let (first, second) = tokio::join!(
        poll_token(&router, &auth_req_id),
        poll_token(&router, &auth_req_id),
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

#[tokio::test]
async fn ciba_approval_rejects_a_request_from_a_previous_regional_activation() {
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
    seed_alice(&state).await;
    let (router, _) = build_router(state.clone());
    let (_, response) = bc_authorize(&router, CLIENT).await;
    let auth_req_id = response["auth_req_id"].as_str().unwrap().to_string();

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
        agent_auth_http::ciba_flow::approve_by_auth_req_id(
            &state,
            "",
            &auth_req_id,
            "user:alice@example.com",
            true,
        )
        .await,
        Err("wrong Region activation")
    );
    assert_eq!(
        state
            .ciba
            .get("", &auth_req_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        "pending"
    );
}

#[tokio::test]
async fn ciba_login_hint_follows_a_moved_scim_alias_to_its_canonical_id() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    let user_id = "user:scim:ciba-canonical-id";
    let old_email = "ciba-scim-old@example.com";
    let new_email = "ciba-scim-new@example.com";
    assert!(matches!(
        state
            .users
            .create_scim(
                "",
                ScimUserInput {
                    user_id: user_id.to_string(),
                    external_id: "ciba-scim-external-old".to_string(),
                    user_name: old_email.to_string(),
                    display_name: None,
                    active: true,
                    now: 1,
                },
            )
            .await
            .unwrap(),
        ScimCreateOutcome::Created(record) if record.user_id == user_id
    ));
    assert!(matches!(
        state
            .users
            .replace_scim(
                "",
                user_id,
                ScimReplaceInput {
                    external_id: "ciba-scim-external-new".to_string(),
                    user_name: new_email.to_string(),
                    display_name: None,
                    active: true,
                    now: 2,
                },
            )
            .await
            .unwrap(),
        ScimReplaceOutcome::Updated(record) if record.user_id == user_id
    ));
    let (router, _) = build_router(state.clone());

    let (old_status, old_body) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=openid&login_hint={old_email}"),
    )
    .await;
    assert_eq!(old_status, StatusCode::BAD_REQUEST, "{old_body}");
    assert_eq!(old_body["error"], "invalid_request");

    let (status, body) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=openid&login_hint={new_email}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let auth_req_id = body["auth_req_id"].as_str().unwrap();
    assert_eq!(
        state
            .ciba
            .get("", auth_req_id)
            .await
            .unwrap()
            .unwrap()
            .user_id,
        user_id
    );

    agent_auth_http::ciba_flow::approve_by_auth_req_id(&state, "", auth_req_id, user_id, true)
        .await
        .unwrap();
    let (token_status, token_body) = poll_token(&router, auth_req_id).await;
    assert_eq!(token_status, StatusCode::OK, "{token_body}");
    assert_eq!(
        jwt_claim(token_body["access_token"].as_str().unwrap(), "sub"),
        user_id
    );
}

#[tokio::test]
async fn legacy_local_user_approval_without_password_version_fails_closed() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    let user_id = "user:legacy-ciba@example.com";
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
        .ciba
        .put(
            "",
            CibaAuthRequest {
                auth_req_id: "legacy-ciba-request".to_string(),
                tenant: String::new(),
                client_id: CLIENT.to_string(),
                user_id: user_id.to_string(),
                authz_session_id: None,
                scope: vec!["openid".to_string()],
                resources: vec![],
                binding_message: None,
                interval: 5,
                last_poll_at: None,
                expires_at: i64::MAX,
                status: "approved".to_string(),
                consumed: false,
                delivery_mode: None,
                notification_endpoint: None,
                client_notification_token: None,
                password_credential_version: None,
            },
        )
        .await
        .unwrap();
    let (router, _) = build_router(state.clone());

    let (status, body) = poll_token(&router, "legacy-ciba-request").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(
        !state
            .ciba
            .get("", "legacy-ciba-request")
            .await
            .unwrap()
            .unwrap()
            .consumed
    );
}

// C7b.1:用户标识三选一——0 个或多个都拒(invalid_request)。
#[tokio::test]
async fn ciba_requires_exactly_one_user_hint() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    let (router, _) = build_router(state);

    // 0 个用户标识 → 拒。
    let (st, body) = bc_authorize_raw(&router, &format!("client_id={CLIENT}&scope=openid")).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "缺用户标识应拒: {body}");
    assert_eq!(body["error"], "invalid_request");

    // 任意两种或三种用户标识同时出现 → 拒。
    for hints in [
        "login_hint=alice&login_hint_token=opaque",
        "login_hint=alice&id_token_hint=jwt",
        "login_hint_token=opaque&id_token_hint=jwt",
        "login_hint=alice&login_hint_token=opaque&id_token_hint=jwt",
    ] {
        let (status, body) =
            bc_authorize_raw(&router, &format!("client_id={CLIENT}&scope=openid&{hints}")).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "多用户标识应拒({hints}): {body}"
        );
        assert_eq!(body["error"], "invalid_request");
    }
}

// C7b.1:login_hint_token 验签本切片仍未实现 → fail-closed 拒(不静默降级)。
// (id_token_hint 已实现,见下方 ciba_id_token_hint_* 测试。)
#[tokio::test]
async fn ciba_login_hint_token_fail_closed() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    let (router, _) = build_router(state);
    let (st, body) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=openid&login_hint_token=sometoken"),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "login_hint_token 未实现应拒: {body}"
    );
    assert_eq!(body["error"], "invalid_request");
}

/// 跑一遍 code flow(占位登录 `login_user`)拿一个**真实 RS256 id_token**(顺带写 jti→user_id 映射)。
/// 用作 id_token_hint 素材。`client` 决定 id_token 的 aud;`login_user` 决定 jti 映射的 user_id。
async fn mint_id_token(router: &axum::Router, client: &str, login_user: &str) -> String {
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id={client}&redirect_uri=http://127.0.0.1/cb\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&state=s\
         &login_user={login_user}&nonce=n0"
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
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "authorize 应回跳发码");
    let loc = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let code = loc
        .split(['?', '&'])
        .find_map(|kv| kv.strip_prefix("code="))
        .expect("code");
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri=http://127.0.0.1/cb&client_id={client}"
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
    assert_eq!(resp.status(), StatusCode::OK, "token 兑换应成功");
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let tok: serde_json::Value = serde_json::from_slice(&b).unwrap();
    tok["id_token"].as_str().expect("id_token").to_string()
}

async fn expire_id_token(state: &AppState, id_token: &str) -> String {
    let parts: Vec<&str> = id_token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let mut claims: serde_json::Value =
        serde_json::from_slice(&B64.decode(parts[1]).unwrap()).unwrap();
    claims["iat"] = serde_json::json!(1);
    claims["exp"] = serde_json::json!(1);
    let signing_input = format!(
        "{}.{}",
        parts[0],
        B64.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signer = state.tenant_keys.resolve("").await.unwrap();
    let (_, signature) = signer.sign_rs256(signing_input.as_bytes()).await.unwrap();
    format!("{signing_input}.{}", B64.encode(signature))
}

// spec 013 §2b.5 / C7b.1(评审 codex High + Kiro H1):有效 id_token_hint 验签 + jti→user_id,
// 归一到与 login_hint 同一 user_id(共享 per-user 冷却,不能换标识绕过)。
#[tokio::test]
async fn ciba_id_token_hint_resolves_and_shares_cooldown_with_login_hint() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    seed_alice(&state).await;
    state.seed_user("bob@example.com", 1000).await;
    let (router, _) = build_router(state);

    // 先造 Alice/Bob 的真实 id_token；后续同一 CIBA 冷却窗中 Alice 必须被节流、Bob 必须放行。
    let alice_id_token = mint_id_token(&router, CLIENT, "user:alice@example.com").await;
    let bob_id_token = mint_id_token(&router, CLIENT, "user:bob@example.com").await;

    // 先用 login_hint(email)发一次 → 占 alice 冷却窗。
    let (st1, _) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=openid&login_hint={ALICE}"),
    )
    .await;
    assert_eq!(st1, StatusCode::OK, "login_hint 首发应成功");

    // 用 id_token_hint 再发 → **同一 user 冷却窗内**,MUST 429(证明归一到同一 user_id,不能换标识绕过)。
    let (st2, body2) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=openid&id_token_hint={alice_id_token}"),
    )
    .await;
    assert_eq!(
        st2,
        StatusCode::TOO_MANY_REQUESTS,
        "id_token_hint 归一到同一 user_id,共享冷却应 429: {body2}"
    );
    assert_eq!(body2["error"], "temporarily_unavailable");

    // 不同用户的有效 id_token_hint 在同一时刻仍应放行，防止实现对所有 id_token_hint 固定返回 429。
    let (st3, body3) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=openid&id_token_hint={bob_id_token}"),
    )
    .await;
    assert_eq!(
        st3,
        StatusCode::OK,
        "不同用户的 id_token_hint 不应继承 Alice 的冷却: {body3}"
    );
}

#[tokio::test]
async fn ciba_expired_id_token_hint_reports_previous_regional_activation() {
    use agent_auth_http::region::{
        MemoryRegionControlStore, RegionControlRecord, RegionControlStoreImpl, RegionRuntime,
    };

    let control = MemoryRegionControlStore::with_record(RegionControlRecord {
        active: true,
        activation_not_before: 0,
        revision: 1,
    });
    let mut state = p2_state();
    state.region =
        RegionRuntime::controlled("us-east-1", RegionControlStoreImpl::Memory(control.clone()))
            .unwrap();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    seed_alice(&state).await;
    let (router, _) = build_router(state.clone());
    let id_token = mint_id_token(&router, CLIENT, "user:alice@example.com").await;
    let id_token = expire_id_token(&state, &id_token).await;

    control
        .set(Some(RegionControlRecord {
            active: true,
            activation_not_before: 0,
            revision: 2,
        }))
        .await;
    let (status, body) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=openid&id_token_hint={id_token}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(
        body["error_description"],
        "id_token_hint belongs to a previous regional activation"
    );
}

// id_token_hint 验签失败(篡改签名)→ invalid_request(不静默放行、不解析出用户)。
#[tokio::test]
async fn ciba_id_token_hint_tampered_rejected() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    seed_alice(&state).await;
    let (router, _) = build_router(state);

    let id_token = mint_id_token(&router, CLIENT, "user:alice@example.com").await;
    // 篡改签名段(翻转末字符;末字符若已是 'A' 则用 'B',确保**确定性改变**——防末字符恰为 'A' 时
    // bad_sig==sig 无篡改导致偶发验签通过 flaky)。
    let mut parts: Vec<&str> = id_token.split('.').collect();
    let sig = parts.pop().unwrap();
    let last = sig.chars().last().unwrap();
    let repl = if last == 'A' { 'B' } else { 'A' };
    let bad_sig = format!("{}{repl}", &sig[..sig.len() - 1]);
    let tampered = format!("{}.{}.{}", parts[0], parts[1], bad_sig);

    let (st, body) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=openid&id_token_hint={tampered}"),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "篡改 id_token_hint 应拒: {body}"
    );
    assert_eq!(body["error"], "invalid_request");
}

// id_token_hint 的 aud != 本次 client_id(他 client 的 id_token 重放)→ 拒(codex High:CIBA 无源 Grant,
// 必须绑 aud==client_id,否则跨 client 重放)。
#[tokio::test]
async fn ciba_id_token_hint_wrong_aud_rejected() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    // 第二个 client:给它签一个 alice 的 id_token(aud=other-client)。
    let other = "ciba-other-client";
    state
        .seed_dev_client(other, "http://127.0.0.1/cb", None)
        .await;
    seed_alice(&state).await;
    let (router, _) = build_router(state);

    let id_token_for_other = mint_id_token(&router, other, "user:alice@example.com").await;
    // 拿 other 的 id_token 当 CLIENT 的 hint → aud 不符,拒。
    let (st, body) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=openid&id_token_hint={id_token_for_other}"),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "aud!=client_id 的 id_token_hint 应拒(防跨 client 重放): {body}"
    );
    assert_eq!(body["error"], "invalid_request");
}

/// 从 JWT payload 取一个 claim(测试辅助)。
fn jwt_claim(jwt: &str, key: &str) -> String {
    let payload = jwt.split('.').nth(1).unwrap();
    let c: serde_json::Value = serde_json::from_slice(&B64.decode(payload).unwrap()).unwrap();
    c[key].as_str().unwrap().to_string()
}

// id_token_hint 的 jti 映射**已过期** → 拒(codex Med:过期映射不得解析出用户/占冷却窗)。
// 造真实 id_token 后,把其 jti 映射用过期 expires_at 覆盖写(tenant="default" = SelfHosted 空 tenant 口径)。
#[tokio::test]
async fn ciba_id_token_hint_expired_jti_mapping_rejected() {
    use agent_auth_http::ports::{JtiRecord, JtiStore};
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    seed_alice(&state).await;
    let (router, _) = build_router(state.clone());

    let id_token = mint_id_token(&router, CLIENT, "user:alice@example.com").await;
    let jti = jwt_claim(&id_token, "jti");
    // 覆盖写同 jti 的映射为**已过期**(expires_at=1,1970)。SelfHosted 空 tenant → jti tenant="default"。
    state
        .jti_store
        .as_ref()
        .unwrap()
        .put(JtiRecord {
            jti: jti.clone(),
            tenant_id: "default".into(),
            user_id: "user:alice@example.com".into(),
            family_id: None,
            grant_id: None,
            expires_at: 1,
        })
        .await
        .unwrap();

    let (st, body) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=openid&id_token_hint={id_token}"),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "jti 映射已过期的 id_token_hint 应拒: {body}"
    );
    assert_eq!(body["error"], "invalid_request");
}

// C7b.2/C7b.3:批准后轮询 → 签出 3LO access token(sub=用户、含 jti);轮询链不经 /sessions;一次性。
#[tokio::test]
async fn ciba_approved_issues_token() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    seed_alice(&state).await;
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
    let (unknown_status, _) = poll_token(&router, "unknown-auth-req-id").await;
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
        "CIBA poll 签发失败不得推进 client 活动"
    );

    let (_, ba) = bc_authorize(&router, CLIENT).await;
    let auth_req_id = ba["auth_req_id"].as_str().unwrap().to_string();

    // 用户批准(approve_by_auth_req_id;批准者=被代表用户,login_hint=email 解析后的 user:{email})。
    // tenant="":flag 关(AppState::dev),与 handler 派生一致(现网单租户透传)。
    agent_auth_http::ciba_flow::approve_by_auth_req_id(
        &state,
        "",
        &auth_req_id,
        "user:alice@example.com",
        true,
    )
    .await
    .expect("批准应成功");

    let (st, body) = poll_token(&router, &auth_req_id).await;
    assert_eq!(st, StatusCode::OK, "批准后轮询应签出 token: {body}");
    let at = body["access_token"].as_str().expect("access_token");
    let payload = at.split('.').nth(1).unwrap();
    let c: serde_json::Value = serde_json::from_slice(&B64.decode(payload).unwrap()).unwrap();
    assert_eq!(
        c["sub"], "user:alice@example.com",
        "CIBA 3LO sub=用户(public 形态;login_hint=email 解析后的内部 user_id)"
    );
    assert!(c["jti"].as_str().is_some(), "含 jti");
    assert!(
        body.get("refresh_token").is_none(),
        "CIBA P2 先不发 refresh"
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
        "成功 CIBA poll 签发必须推进 client 活动"
    );

    // 一次性:再轮询 → invalid_grant(consumed)。
    let (st2, body2) = poll_token(&router, &auth_req_id).await;
    assert_eq!(st2, StatusCode::BAD_REQUEST);
    assert_eq!(body2["error"], "invalid_grant", "已消费 auth_req_id 重放拒");
}

#[tokio::test]
async fn ciba_kms_transient_returns_retry_after_and_releases_consumption() {
    use agent_auth_http::state::SignerImpl;

    let mut state = p2_state();
    let isolated_signer = std::sync::Arc::new(SignerImpl::Memory(
        agent_auth_http::adapters::memory::MemorySigner::from_seed([84; 32]),
    ));
    state.signer = isolated_signer.clone();
    state.tenant_keys = std::sync::Arc::new(
        agent_auth_http::tenant_keys::TenantKeyService::shared(isolated_signer),
    );
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    seed_alice(&state).await;
    let router = build_router(state.clone()).0;
    let (_, authorization) = bc_authorize(&router, CLIENT).await;
    let auth_req_id = authorization["auth_req_id"].as_str().unwrap().to_string();
    agent_auth_http::ciba_flow::approve_by_auth_req_id(
        &state,
        "",
        &auth_req_id,
        "user:alice@example.com",
        true,
    )
    .await
    .unwrap();
    let SignerImpl::Memory(signer) = state.signer.as_ref() else {
        panic!("dev state must use MemorySigner");
    };
    signer.fail_next_es256(true);

    let response = poll_token_response_for_client(&router, &auth_req_id, CLIENT).await;
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

    let mut record = state.ciba.get("", &auth_req_id).await.unwrap().unwrap();
    assert!(
        !record.consumed,
        "transient signing failure must release CIBA consumption"
    );
    record.last_poll_at =
        Some(agent_auth_http::token::current_unix_secs_pub() - record.interval.max(1));
    state.ciba.update("", record).await.unwrap();
    assert_eq!(
        poll_token(&router, &auth_req_id).await.0,
        StatusCode::OK,
        "the approved CIBA request must remain retryable after backoff"
    );
}

// C8.7b:CIBA poll grant 的 /token 路径支持 DPoP opt-in，proof-free 路径保持 bearer。
#[tokio::test]
async fn ciba_token_dpop_and_bearer_binding() {
    let mut state = p2_state();
    state.phase = Phase::P3;
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    seed_alice(&state).await;
    state.seed_user("bob@example.com", 1000).await;
    let (router, _) = build_router(state.clone());

    let (_, dpop_authorization) = bc_authorize(&router, CLIENT).await;
    let dpop_auth_req_id = dpop_authorization["auth_req_id"].as_str().unwrap();
    agent_auth_http::ciba_flow::approve_by_auth_req_id(
        &state,
        "",
        dpop_auth_req_id,
        "user:alice@example.com",
        true,
    )
    .await
    .unwrap();
    let (signing_key, jwk) = ciba_dpop_keypair(43);
    let proof = ciba_dpop_proof(&signing_key, &jwk, "ciba-dpop");
    let (dpop_status, dpop_body) = poll_token_with_dpop(&router, dpop_auth_req_id, &proof).await;
    assert_eq!(
        dpop_status,
        StatusCode::OK,
        "CIBA DPoP issuance should succeed: {dpop_body}"
    );
    assert_eq!(dpop_body["token_type"], "DPoP");
    assert_access_token_es256(dpop_body["access_token"].as_str().unwrap());
    assert_eq!(
        ciba_token_cnf(dpop_body["access_token"].as_str().unwrap()).unwrap()["jkt"],
        ciba_jkt(&jwk)
    );

    let (_, bearer_authorization) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=openid kb:read&login_hint=bob@example.com"),
    )
    .await;
    let bearer_auth_req_id = bearer_authorization["auth_req_id"].as_str().unwrap();
    agent_auth_http::ciba_flow::approve_by_auth_req_id(
        &state,
        "",
        bearer_auth_req_id,
        "user:bob@example.com",
        true,
    )
    .await
    .unwrap();
    let (bearer_status, bearer_body) = poll_token(&router, bearer_auth_req_id).await;
    assert_eq!(
        bearer_status,
        StatusCode::OK,
        "CIBA bearer issuance should remain available: {bearer_body}"
    );
    assert_eq!(bearer_body["token_type"], "Bearer");
    assert_access_token_es256(bearer_body["access_token"].as_str().unwrap());
    assert!(
        ciba_token_cnf(bearer_body["access_token"].as_str().unwrap()).is_none(),
        "a proof-free CIBA token must not receive an invented cnf"
    );
}

// C7b.2:deny → access_denied。
#[tokio::test]
async fn ciba_denied() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    seed_alice(&state).await;
    let (router, _) = build_router(state.clone());
    let (_, ba) = bc_authorize(&router, CLIENT).await;
    let auth_req_id = ba["auth_req_id"].as_str().unwrap().to_string();
    agent_auth_http::ciba_flow::approve_by_auth_req_id(
        &state,
        "",
        &auth_req_id,
        "user:alice@example.com",
        false,
    )
    .await
    .unwrap();
    let (st, body) = poll_token(&router, &auth_req_id).await;
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
        .expect("CIBA denial must remain auditable");
    assert_eq!(denied.event.correlation.client_id.as_deref(), Some(CLIENT));
    assert_ne!(
        denied.event.correlation.operation_id.as_deref(),
        Some(auth_req_id.as_str()),
        "live auth_req_id must not enter the event envelope"
    );
}

// 评审 Kiro MED-1(批准者身份绑定):批准者 != 被代表用户(login_hint) → user_mismatch,不推进状态,
// 不签 token(防恶意 client 用 login_hint=<victim> 让别人误批出 sub=victim 的 token)。
#[tokio::test]
async fn ciba_approve_by_wrong_user_rejected() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    seed_alice(&state).await;
    let (router, _) = build_router(state.clone());
    let (_, ba) = bc_authorize(&router, CLIENT).await; // login_hint=alice@example.com → user:alice@example.com
    let auth_req_id = ba["auth_req_id"].as_str().unwrap().to_string();

    // mallory 试图批准 alice 的请求 → 拒。
    let re = agent_auth_http::ciba_flow::approve_by_auth_req_id(
        &state,
        "",
        &auth_req_id,
        "mallory",
        true,
    )
    .await;
    assert_eq!(re, Err("user_mismatch"), "批准者与被代表用户不符应拒");

    // 状态仍 pending → 轮询仍 authorization_pending(未被误推进)。
    let (st, body) = poll_token(&router, &auth_req_id).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "authorization_pending", "误批准不得推进状态");
}

// 评审 Kiro LOW-2(CIBA 是 OIDC 流):缺 openid scope → invalid_scope。
#[tokio::test]
async fn ciba_requires_openid_scope() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    let (router, _) = build_router(state);
    let (st, body) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=kb:read&login_hint=alice"),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "缺 openid 应拒: {body}");
    assert_eq!(body["error"], "invalid_scope");
}

// 一次性原子(同 device F1):并发两次轮询,恰一个签出 token。
#[tokio::test]
async fn ciba_concurrent_poll_issues_exactly_one() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    seed_alice(&state).await;
    let (router, _) = build_router(state.clone());
    let (_, ba) = bc_authorize(&router, CLIENT).await;
    let auth_req_id = ba["auth_req_id"].as_str().unwrap().to_string();
    agent_auth_http::ciba_flow::approve_by_auth_req_id(
        &state,
        "",
        &auth_req_id,
        "user:alice@example.com",
        true,
    )
    .await
    .unwrap();

    let (r1, r2) = tokio::join!(
        poll_token(&router, &auth_req_id),
        poll_token(&router, &auth_req_id),
    );
    let oks = [&r1, &r2]
        .iter()
        .filter(|(st, _)| *st == StatusCode::OK)
        .count();
    assert_eq!(oks, 1, "恰好一个并发轮询签出 token: r1={r1:?} r2={r2:?}");
    // 后续串行轮询 MUST invalid_grant(已消费)。
    let (st3, body3) = poll_token(&router, &auth_req_id).await;
    assert_eq!(st3, StatusCode::BAD_REQUEST);
    assert_eq!(body3["error"], "invalid_grant");
}

// C7b.1(binding_message):超长 binding_message 拒。
#[tokio::test]
async fn ciba_rejects_overlong_binding_message() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    let (router, _) = build_router(state);
    let long = "x".repeat(201);
    let (st, body) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&login_hint=alice&binding_message={long}"),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "超长 binding_message 应拒: {body}"
    );
    assert_eq!(body["error"], "invalid_binding_message");
}

// F3 同源:CIBA 仅限 public client;workload(auth_method=none)拒 unauthorized_client。
#[tokio::test]
async fn ciba_rejects_workload_client() {
    let state = p2_state();
    state.seed_workload_client("wl-client").await;
    let (router, _) = build_router(state);
    let (st, body) = bc_authorize_raw(&router, "client_id=wl-client&login_hint=alice").await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "workload 应拒: {body}");
    assert_eq!(body["error"], "unauthorized_client");
}

// C1.2:P1 阶段 /bc-authorize 不可达(404)+ CIBA grant 不受理。
#[tokio::test]
async fn ciba_gated_at_p1() {
    let state = AppState::dev(HOST); // phase=P1
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    let (router, _) = build_router(state);
    let (st, _) = bc_authorize(&router, CLIENT).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "P1 /bc-authorize 应 404");
    // CIBA grant P1 不受理(grant_accepted 门控 → unsupported_grant_type 400)。
    let (st2, _) = poll_token(&router, "x").await;
    assert_eq!(st2, StatusCode::BAD_REQUEST);
}

// ---- spec 013 §2b:CIBA 批准 HTTP 端点(/bc-approve/{auth_req_id},登录会话鉴权)----

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

async fn post_bc_approve(
    router: &axum::Router,
    auth_req_id: &str,
    approve: bool,
    session: Option<&str>,
) -> StatusCode {
    let mut b = Request::builder()
        .method("POST")
        .uri(format!("/bc-approve/{auth_req_id}"))
        .header("host", HOST)
        .header("content-type", "application/x-www-form-urlencoded");
    if let Some(s) = session {
        b = b.header("cookie", format!("__Host-agent_auth_session={s}"));
    }
    router
        .clone()
        .oneshot(b.body(Body::from(format!("approve={approve}"))).unwrap())
        .await
        .unwrap()
        .status()
}

async fn get_bc_approve(
    router: &axum::Router,
    auth_req_id: &str,
    session: &str,
) -> (StatusCode, serde_json::Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/bc-approve/{auth_req_id}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
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

async fn logout_and_assert_session_revoked(router: &axum::Router, session: &str) {
    let logout = router
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
    assert_eq!(logout.status(), StatusCode::OK);

    let stale_session = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/account/sessions")
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        stale_session.status(),
        StatusCode::UNAUTHORIZED,
        "logout must remove the server-side browser session"
    );
}

// §2b:被代表用户登录 POST /bc-approve → 批准 → 轮询签 token;跨用户 bob 批准 → 404;未登录 401。
#[tokio::test]
async fn ciba_http_flow_polls_without_session_material() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    // 被代表用户须**预先注册**(CIBA 发起时用户已存在;spec 013 §2b.5 契约:login_hint=email)。
    seed_alice(&state).await;
    state.seed_dev_user("bob@example.com").await;
    let (router, _) = build_router(state);
    // login_hint = email → users 表解析为内部 user_id(user:alice@example.com),使批准者==被代表用户。
    // **这是本契约的核心修复**:login_hint 走真解析后,与真实 magic-link 登录会话 user_id 对齐,
    // 真实用户 alice 能真正批准(不再恒 user_mismatch)。
    let (st, ba) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=openid&login_hint={ALICE}"),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "bc-authorize: {ba}");
    let arid = ba["auth_req_id"].as_str().unwrap().to_string();

    // 未登录 → 401。
    assert_eq!(
        post_bc_approve(&router, &arid, true, None).await,
        StatusCode::UNAUTHORIZED
    );
    // 跨用户 bob 登录批准 → 404(user_mismatch,不泄露)。
    let bob = login(&router, "bob@example.com").await;
    assert_eq!(
        post_bc_approve(&router, &arid, true, Some(&bob)).await,
        StatusCode::NOT_FOUND,
        "跨用户批准应拒(404)"
    );
    logout_and_assert_session_revoked(&router, &bob).await;

    // 被代表用户 alice 登录批准 → 204。
    let alice = login(&router, "alice@example.com").await;
    assert_eq!(
        post_bc_approve(&router, &arid, true, Some(&alice)).await,
        StatusCode::NO_CONTENT
    );
    // 批准完成后删除本流程最后一个服务端 browser session。
    logout_and_assert_session_revoked(&router, &alice).await;
    // 标准 CIBA client 只携带 grant_type/auth_req_id/client_id 轮询 `/token`。
    // 这里故意不带 browser cookie、Authorization、session token，也不调用 `/sessions`。
    let poll_form = format!(
        "grant_type=urn:openid:params:grant-type:ciba&auth_req_id={arid}&client_id={CLIENT}"
    );
    let poll = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(poll_form))
                .unwrap(),
        )
        .await
        .unwrap();
    let st = poll.status();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(poll.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(st, StatusCode::OK, "批准后应签 token: {body}");
    let at = body["access_token"].as_str().unwrap();
    let c: serde_json::Value =
        serde_json::from_slice(&B64.decode(at.split('.').nth(1).unwrap()).unwrap()).unwrap();
    assert_eq!(c["sub"], "user:alice@example.com");
}

// C7b.6: approval details always identify the requester, preserve an optional binding message,
// and do not approve the request until the user submits an explicit decision.
#[tokio::test]
async fn ciba_approval_view_shows_requester_and_optional_binding_without_approving() {
    const NO_BINDING_CLIENT: &str = "ciba-client-no-binding";

    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    state
        .seed_dev_client(NO_BINDING_CLIENT, "http://127.0.0.1/no-binding", None)
        .await;
    seed_alice(&state).await;
    state.seed_user("bob@example.com", 1000).await;
    let (router, _) = build_router(state);

    let expected_binding = "  Invoice\t#4242  | Ω  ";
    let (status, authorization) = bc_authorize_raw(
        &router,
        &format!(
            "client_id={CLIENT}&scope=openid&login_hint={ALICE}\
             &binding_message=%20%20Invoice%09%234242%20%20%7C%20%CE%A9%20%20"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "bc-authorize: {authorization}");
    let auth_req_id = authorization["auth_req_id"].as_str().unwrap();
    let alice = login(&router, ALICE).await;

    let (status, approval) = get_bc_approve(&router, auth_req_id, &alice).await;
    assert_eq!(status, StatusCode::OK, "approval details: {approval}");
    assert_eq!(approval["client_id"], CLIENT);
    assert_eq!(approval["binding_message"], expected_binding);
    assert_eq!(approval["status"], "pending");

    let (status, pending) = poll_token(&router, auth_req_id).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "poll before decision: {pending}"
    );
    assert_eq!(
        pending["error"], "authorization_pending",
        "viewing approval details must not implicitly approve the request"
    );

    let (status, authorization) = bc_authorize_raw(
        &router,
        &format!("client_id={NO_BINDING_CLIENT}&scope=openid&login_hint=bob@example.com"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "bc-authorize: {authorization}");
    let auth_req_id = authorization["auth_req_id"].as_str().unwrap();
    let bob = login(&router, "bob@example.com").await;
    let (status, approval) = get_bc_approve(&router, auth_req_id, &bob).await;
    assert_eq!(status, StatusCode::OK, "approval details: {approval}");
    assert_eq!(approval["client_id"], NO_BINDING_CLIENT);
    assert!(
        approval["binding_message"].is_null(),
        "an absent binding message must not be invented"
    );
    assert_eq!(approval["status"], "pending");

    let (status, pending) = poll_token_for_client(&router, auth_req_id, NO_BINDING_CLIENT).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "poll before decision: {pending}"
    );
    assert_eq!(
        pending["error"], "authorization_pending",
        "viewing approval details without a binding message must not approve the request"
    );
}

// ---- spec 013 Task 3.1/3.4:/bc-authorize 防批准疲劳节流(per-login_hint 冷却,C7b.6)----

#[tokio::test]
async fn bc_authorize_throttles_same_login_hint() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    // login_hint=email 契约:被节流/测试的用户须已注册(否则未注册先被 invalid_request 拒,测不到节流)。
    state.seed_user("victim@example.com", 1000).await;
    state.seed_user("other@example.com", 1000).await;
    let (router, _) = build_router(state);

    // 同一 login_hint 首发 → 200 铸 auth_req_id。
    let (st1, b1) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=openid&login_hint=victim@example.com"),
    )
    .await;
    assert_eq!(st1, StatusCode::OK, "首发应 200: {b1}");

    // 同一 login_hint 立即再发(冷却窗内)→ 429 temporarily_unavailable(防批准疲劳轰炸)。
    let (st2, b2) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=openid&login_hint=victim@example.com"),
    )
    .await;
    assert_eq!(
        st2,
        StatusCode::TOO_MANY_REQUESTS,
        "同 login_hint 冷却窗内应 429: {b2}"
    );
    assert_eq!(
        b2["error"], "temporarily_unavailable",
        "429 应带 temporarily_unavailable(评审 L2:非 slow_down)"
    );

    // 大小写变体不应绕过节流(归一 lowercase → 同一注册用户 + 同一冷却键,VICTIM@Example.com==victim@example.com)。
    let (st_case, b_case) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=openid&login_hint=VICTIM@Example.com"),
    )
    .await;
    assert_eq!(
        st_case,
        StatusCode::TOO_MANY_REQUESTS,
        "大小写变体应与 victim@example.com 同一冷却键、被节流: {b_case}"
    );
    assert_eq!(
        b_case["error"], "temporarily_unavailable",
        "大小写变体命中同一冷却键时也应返回 temporarily_unavailable"
    );

    // 不同 login_hint 不受影响(节流是 per-login_hint,非全局)。
    let (st3, b3) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=openid&login_hint=other@example.com"),
    )
    .await;
    assert_eq!(st3, StatusCode::OK, "不同 login_hint 应不受节流: {b3}");
}

#[tokio::test]
async fn bc_authorize_invalid_request_does_not_arm_throttle() {
    // 非法请求(缺 openid scope)不应推进节流状态——否则攻击者用非法请求"占用"受害者冷却窗。
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    state.seed_user("carol@example.com", 1000).await;
    let (router, _) = build_router(state);

    // 先发一个非法请求(缺 openid)→ 400,不应记录节流。
    let (st_bad, _) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=kb:read&login_hint=carol@example.com"),
    )
    .await;
    assert_eq!(st_bad, StatusCode::BAD_REQUEST, "缺 openid 应 400");

    // 紧接合法请求(同 login_hint)→ 应 200(非法请求没占用冷却窗)。
    let (st_ok, b) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=openid&login_hint=carol@example.com"),
    )
    .await;
    assert_eq!(st_ok, StatusCode::OK, "非法请求不应占用冷却窗: {b}");
}

// spec 013 §2b.5:CIBA login_hint 格式校验(超长/控制字符拒)+ **存在性校验**
// (login_hint=email → 未注册拒 invalid_request;已注册放行。用户拍板 2026-07-12:未注册直接拒)。
#[tokio::test]
async fn bc_authorize_rejects_malformed_login_hint() {
    let state = p2_state();
    state
        .seed_dev_client(CLIENT, "http://127.0.0.1/cb", None)
        .await;
    seed_alice(&state).await; // 仅 alice@example.com 已注册
    let (router, _) = build_router(state);

    // 超长 login_hint(>256)→ 400 invalid_request(格式闸,先于查库)。
    let long = "a".repeat(300);
    let (st, b) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=openid&login_hint={long}"),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "超长 login_hint 应拒: {b}");
    assert_eq!(b["error"], "invalid_request");

    // 含控制字符(%09 tab)→ 400(格式闸)。
    let (st, b) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=openid&login_hint=ab%09cd"),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "含控制字符 login_hint 应拒: {b}"
    );

    // **未注册 email → 400 invalid_request**(存在性校验;不静默照发 auth_req_id、不造僵尸记录)。
    let (st, b) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=openid&login_hint=nobody@example.com"),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "未注册 login_hint 应拒 invalid_request: {b}"
    );
    assert_eq!(b["error"], "invalid_request");

    // 已注册 email → 200(存在性校验放行;格式闸不误伤合法值)。
    let (st, b) = bc_authorize_raw(
        &router,
        &format!("client_id={CLIENT}&scope=openid&login_hint={ALICE}"),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "已注册 login_hint 应放行: {b}");
}
