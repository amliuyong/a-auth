//! 进程内 e2e:账户恢复(C9.3,P0.5 硬 gate)—— 一次性恢复码。
//!
//! 覆盖决策(见 recover.rs / DESIGN §7 / CONFORMANCE C9.3):
//! - 已登录用户 `POST /recovery/generate` → show-once 返回明文码。
//! - `POST /recovery/verify` 用一个码 → 验码消费 → 建新会话(登入)→ 引导绑新因子。
//! - 一次性:同一码只能短时重放同一已提交会话,不能建立第二个会话。
//! - 恢复吊销旧会话:恢复后旧 session cookie 失效(delete_by_user)。
//! - 限流:连续错码达阈值 → 锁定 429(按 user_lookup,无效码也能定位)。

use agent_auth_authn::passkey::PasskeyCredential;
use agent_auth_authn::password::hash_password;
use agent_auth_authn::recovery::{code_hash, format_code, SECRET_BYTES};
use agent_auth_http::ports::{
    CredentialChangeStart, GraceCacheEntry, GraceCachedResponse, GraceStore, MessageOutbox,
    PasskeyStore, PasswordCredential, PasswordStore, RecoveryCodeEntry, RecoveryRecord,
    RecoveryStore, RefreshFamilyRecord, RefreshStore, SessionRecord, SessionStore, UsersStore,
};
use agent_auth_http::security_event::{SecurityEventOutcome, SecurityEventStore};
use agent_auth_http::{build_router, state::UsersStoreImpl, AppState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const HOST: &str = "localhost";
const SESSION_PROBE_CLIENT: &str = "recovery-session-probe";
const SESSION_PROBE_REDIRECT: &str = "http://127.0.0.1/recovery-session-probe";

async fn app_with_state() -> (axum::Router, AppState) {
    let state = AppState::dev(HOST);
    state
        .seed_dev_client(SESSION_PROBE_CLIENT, SESSION_PROBE_REDIRECT, None)
        .await;
    for email in [
        "alice@example.com",
        "bob@example.com",
        "carol@example.com",
        "dave@example.com",
        "status@example.com",
        "alice-iso@example.com",
        "bob-iso@example.com",
        "flood-gen@example.com",
        "other-gen@example.com",
        "recovery-only@example.com",
        "contact-query@example.com",
    ] {
        state.seed_dev_user(email).await;
    }
    let (router, _) = build_router(state.clone());
    (router, state)
}

async fn app() -> axum::Router {
    app_with_state().await.0
}

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

// 登录建会话(magic-link → callback),返回 session cookie 值。
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

// Bypass the login ceremony when a test needs a new authoritative session
// after a credential mutation has advanced the session generation.
async fn fresh_session(state: &AppState, id: &str, email: &str) -> String {
    let now = agent_auth_http::current_unix_secs();
    let user_id = format!("user:{email}");
    let credential_epoch = state
        .users
        .get_by_id("", &user_id)
        .await
        .unwrap()
        .unwrap()
        .credential_epoch;
    state
        .sessions
        .create(
            "",
            SessionRecord {
                session_id: id.to_string(),
                user_id,
                credential_epoch,
                auth_time: now,
                created_at: now,
                last_used_at: now,
                device: "Test browser".to_string(),
                expires_at: now + 3_600,
                acr: None,
                amr: vec!["email".to_string()],
            },
        )
        .await
        .unwrap();
    id.to_string()
}

// 原始生成请求(返回响应,供断言状态码——如限流 429)。
async fn generate_raw(router: &axum::Router, session: &str) -> axum::http::Response<Body> {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/recovery/generate")
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

// 已登录用户生成一组恢复码,返回明文码列表。
async fn generate_codes(router: &axum::Router, session: &str) -> Vec<String> {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/recovery/generate")
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "已登录应能生成恢复码");
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let j: serde_json::Value = serde_json::from_slice(&b).unwrap();
    j["recovery_codes"]
        .as_array()
        .expect("recovery_codes 数组")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

async fn post_recover(router: &axum::Router, code: &str) -> axum::http::Response<Body> {
    post_recover_with_operation(router, code, &operation_for_code(code)).await
}

fn operation_for_code(code: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(code.as_bytes()))
}

async fn post_recover_with_operation(
    router: &axum::Router,
    code: &str,
    operation_id: &str,
) -> axum::http::Response<Body> {
    let body = serde_json::json!({ "code": code, "operation_id": operation_id });
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/recovery/verify")
                .header("host", HOST)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

// 未登录访问 /recovery/generate → 401(生成是敏感操作,必须已登录)。
#[tokio::test]
async fn generate_requires_login() {
    let router = app().await;
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/recovery/generate")
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "未登录不能生成恢复码"
    );
}

#[tokio::test]
async fn generation_is_show_once_hmac_stored_and_regeneration_supersedes_old_codes() {
    let (router, state) = app_with_state().await;
    let email = "alice@example.com";
    let session = login_session(&router, email).await;
    let first_codes = generate_codes(&router, &session).await;
    assert_eq!(first_codes.len(), 10);

    let lookup = first_codes[0].split('.').nth(1).unwrap().to_string();
    let first_record = state.recovery.get("", &lookup).await.unwrap().unwrap();
    assert_eq!(first_record.code_hashes.len(), first_codes.len());
    for (code, entry) in first_codes.iter().zip(&first_record.code_hashes) {
        assert_eq!(
            entry.hash_b64,
            URL_SAFE_NO_PAD.encode(code_hash(state.server_secret.as_ref(), code))
        );
        assert_ne!(
            entry.hash_b64, *code,
            "plaintext recovery codes must not persist"
        );
        assert!(!entry.consumed);
    }

    let status_session = fresh_session(&state, "show-once-status", email).await;
    let status = get_status(&router, Some(&status_session)).await;
    let status_json: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(status.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        status_json,
        serde_json::json!({ "configured": true, "remaining": 10 }),
        "subsequent public reads expose only status, never recovery plaintext"
    );

    let rotation_session = fresh_session(&state, "show-once-rotation", email).await;
    let second_codes = generate_codes(&router, &rotation_session).await;
    assert!(
        first_codes.iter().all(|code| !second_codes.contains(code)),
        "regeneration must return a wholly new show-once set"
    );
    let second_record = state.recovery.get("", &lookup).await.unwrap().unwrap();
    for (code, entry) in second_codes.iter().zip(&second_record.code_hashes) {
        assert_eq!(
            entry.hash_b64,
            URL_SAFE_NO_PAD.encode(code_hash(state.server_secret.as_ref(), code))
        );
    }
    assert_eq!(
        post_recover(&router, &first_codes[0]).await.status(),
        StatusCode::BAD_REQUEST,
        "regeneration must invalidate every old recovery code"
    );
    assert_eq!(
        post_recover(&router, &second_codes[0]).await.status(),
        StatusCode::OK,
        "the replacement set remains usable"
    );
}

// 主流程:生成 → 用一个码恢复 → 建会话(登入)+ 引导绑新因子。
#[tokio::test]
async fn generate_then_recover_logs_in() {
    let (router, state) = app_with_state().await;
    let session = login_session(&router, "alice@example.com").await;
    let codes = generate_codes(&router, &session).await;
    assert_eq!(codes.len(), 10, "默认生成 10 个恢复码");
    assert!(codes[0].starts_with("v1."), "码带版本前缀 v1.");
    let user_before_recovery = state
        .users
        .get_by_id("", "user:alice@example.com")
        .await
        .unwrap()
        .unwrap();
    let last_login_before_recovery = user_before_recovery
        .last_login_at
        .expect("生成恢复码前的 magic-link 登录应已有时间");

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let resp = post_recover(&router, &codes[0]).await;
    assert_eq!(resp.status(), StatusCode::OK, "有效码应恢复成功");
    let new_session =
        set_cookie_val(&resp, "__Host-agent_auth_session").expect("恢复应建新会话 cookie");
    assert!(!new_session.is_empty());
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let j: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(j["recovered"], true);
    assert_eq!(j["next"], "bind_new_factor", "恢复后引导绑新因子");
    let user_after_recovery = state
        .users
        .get_by_id("", "user:alice@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        user_after_recovery.credential_epoch,
        user_before_recovery.credential_epoch + 1,
        "successful recovery must fence every pre-recovery authentication artifact"
    );
    assert_eq!(
        state
            .sessions
            .get("", &new_session)
            .await
            .unwrap()
            .unwrap()
            .credential_epoch,
        user_after_recovery.credential_epoch
    );
    assert!(
        user_after_recovery
            .last_login_at
            .is_some_and(|timestamp| timestamp > last_login_before_recovery),
        "恢复码成功建立会话后应推进最后登录时间"
    );
    assert!(state
        .credential_audit
        .snapshot()
        .join("\n")
        .contains("action=consume tenant= actor=user:alice@example.com kind=recovery target=self result=success"));
    let recovery_message = state
        .messages
        .list_recent("", 50)
        .await
        .unwrap()
        .into_iter()
        .find(|message| message.kind == "recovery")
        .expect("successful recovery must notify the existing contact channel");
    assert_eq!(
        recovery_message.recipient, "alice@example.com",
        "a canonical user id is not a deliverable email recipient"
    );
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 500)
        .await
        .unwrap();
    assert!(events.iter().any(|stored| {
        stored.event.action == "authentication.recovery"
            && stored.event.outcome == SecurityEventOutcome::Success
    }));
}

#[tokio::test]
async fn recovery_without_a_deliverable_contact_email_does_not_consume_or_misaddress() {
    for (case, user_id, contact_email) in [
        ("missing", "user:fed:no-contact", None),
        (
            "invalid",
            "user:invalid-contact",
            Some("user:internal-identifier@example.com"),
        ),
    ] {
        let state = AppState::dev(HOST);
        let now = agent_auth_http::current_unix_secs();
        if let Some(email) = contact_email {
            state
                .users
                .create_or_get_by_email("", email, user_id, now)
                .await
                .unwrap();
        } else {
            state
                .users
                .create_or_get_by_id("", user_id, now)
                .await
                .unwrap();
        }
        let session_id = format!("{case}-contact-session");
        state
            .sessions
            .create(
                "",
                SessionRecord {
                    session_id: session_id.clone(),
                    user_id: user_id.to_string(),
                    credential_epoch: 0,
                    auth_time: now,
                    created_at: now,
                    last_used_at: now,
                    device: "Test browser".to_string(),
                    expires_at: now + 3_600,
                    acr: None,
                    amr: vec!["federated".to_string()],
                },
            )
            .await
            .unwrap();
        let (router, _) = build_router(state.clone());
        let response = generate_raw(&router, &session_id).await;
        assert_eq!(
            response.status(),
            StatusCode::CONFLICT,
            "recovery material must not be issued for {case} contact email"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"],
            "contact_channel_unavailable"
        );

        let lookup = format!("{case}-contact-lookup");
        let secret = [if case == "missing" { 1 } else { 2 }; SECRET_BYTES];
        let code = format_code(&lookup, &secret);
        state
            .recovery
            .put(
                "",
                RecoveryRecord {
                    user_lookup: lookup,
                    user_id: user_id.to_string(),
                    activation_id: "recovery".to_string(),
                    code_hashes: vec![RecoveryCodeEntry {
                        hash_b64: URL_SAFE_NO_PAD
                            .encode(code_hash(state.server_secret.as_ref(), &code)),
                        consumed: false,
                    }],
                    attempt_count: 0,
                    locked_until: 0,
                },
            )
            .await
            .unwrap();

        for _ in 0..2 {
            let response = post_recover(&router, &code).await;
            assert_eq!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "recovery must fail before consuming the code for {case} contact email"
            );
        }
        assert!(
            state
                .messages
                .list_recent("", 50)
                .await
                .unwrap()
                .iter()
                .all(|message| message.kind != "recovery"),
            "an internal identifier must never be recorded as a recipient"
        );
    }

    let (router, state) = app_with_state().await;
    let email = "contact-query@example.com";
    let session = login_session(&router, email).await;
    let user_before = state
        .users
        .get_by_id("", &format!("user:{email}"))
        .await
        .unwrap()
        .unwrap();
    match state.users.as_ref() {
        UsersStoreImpl::Memory(users) => users.fail_get_by_id_after(1),
        #[allow(unreachable_patterns)]
        _ => panic!("dev state must use the memory users store"),
    }
    assert_eq!(
        generate_raw(&router, &session).await.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "contact lookup failure must reject before issuing recovery material"
    );
    assert_eq!(
        state
            .users
            .get_by_id("", &format!("user:{email}"))
            .await
            .unwrap()
            .unwrap()
            .credential_epoch,
        user_before.credential_epoch
    );
    assert!(state.sessions.get("", &session).await.unwrap().is_some());

    let codes = generate_codes(&router, &session).await;
    let lookup = codes[0].split('.').nth(1).unwrap();
    let record_before = state.recovery.get("", lookup).await.unwrap().unwrap();
    match state.users.as_ref() {
        UsersStoreImpl::Memory(users) => users.fail_get_by_id_after(1),
        #[allow(unreachable_patterns)]
        _ => panic!("dev state must use the memory users store"),
    }
    assert_eq!(
        post_recover(&router, &codes[0]).await.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "canonical-user lookup failure must reject before consuming recovery material"
    );
    assert_eq!(
        state.recovery.get("", lookup).await.unwrap().unwrap(),
        record_before
    );
}

#[tokio::test]
async fn recovery_cannot_create_session_while_admin_reset_is_pending() {
    let state = AppState::dev(HOST);
    let email = "recover-reset@example.com";
    let user_id = format!("user:{email}");
    state.seed_dev_user(email).await;
    let (router, _) = build_router(state.clone());
    let session = login_session(&router, email).await;
    let codes = generate_codes(&router, &session).await;
    let last_login_before_recovery = state
        .users
        .get_by_id("", &user_id)
        .await
        .unwrap()
        .unwrap()
        .last_login_at;

    assert_eq!(
        state
            .passwords
            .reset_temporary(
                "",
                &user_id,
                agent_auth_authn::password::hash_password("Temporary reset password 123!").unwrap(),
                None,
                1,
            )
            .await
            .unwrap(),
        Some(1)
    );

    let response = post_recover(&router, &codes[0]).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(set_cookie_val(&response, "__Host-agent_auth_session").is_none());
    assert_eq!(
        state
            .users
            .get_by_id("", &user_id)
            .await
            .unwrap()
            .unwrap()
            .last_login_at,
        last_login_before_recovery,
        "authority 回滚的 recovery 会话不得推进最后登录时间"
    );
    assert_eq!(
        state
            .sessions
            .count_by_user(
                "",
                &user_id,
                agent_auth_http::token::current_unix_secs_pub()
            )
            .await
            .unwrap(),
        0
    );
    state.passwords.delete("", &user_id).await.unwrap();
    assert_eq!(
        post_recover(&router, &codes[0]).await.status(),
        StatusCode::OK,
        "a blocked recovery attempt must not consume its code"
    );
}

#[tokio::test]
async fn unknown_user_cannot_jit_through_recovery() {
    let state = AppState::dev(HOST);
    let user_id = "user:unknown-recovery@example.com";
    let lookup = "unknown-recovery";
    let secret = [7; SECRET_BYTES];
    let code = format_code(lookup, &secret);
    state
        .recovery
        .put(
            "",
            RecoveryRecord {
                user_lookup: lookup.to_string(),
                user_id: user_id.to_string(),
                activation_id: state.region.issue_id("recovery-no-jit"),
                code_hashes: vec![RecoveryCodeEntry {
                    hash_b64: URL_SAFE_NO_PAD
                        .encode(code_hash(state.server_secret.as_ref(), &code)),
                    consumed: false,
                }],
                attempt_count: 0,
                locked_until: 0,
            },
        )
        .await
        .unwrap();
    let record_before = state.recovery.get("", lookup).await.unwrap().unwrap();
    let (router, _) = build_router(state.clone());

    let response = post_recover(&router, &code).await;
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "recovery material for a missing canonical user must fail closed"
    );
    assert!(
        set_cookie_val(&response, "__Host-agent_auth_session").is_none(),
        "recovery for an unknown user must not establish a session"
    );
    assert!(
        state.users.get_by_id("", user_id).await.unwrap().is_none(),
        "recovery must not JIT-create the canonical user"
    );
    assert_eq!(
        state
            .sessions
            .count_by_user("", user_id, agent_auth_http::current_unix_secs())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        state.recovery.get("", lookup).await.unwrap().unwrap(),
        record_before,
        "a rejected unknown-user recovery must not consume or mutate the material"
    );
}

// 响应丢失重试:同一码只短时重放同一已提交会话;会话不可用后仍按一次性码拒绝。
#[tokio::test]
async fn recovery_code_retry_replays_only_the_committed_session() {
    let (router, state) = app_with_state().await;
    let session = login_session(&router, "bob@example.com").await;
    let codes = generate_codes(&router, &session).await;

    let r1 = post_recover(&router, &codes[0]).await;
    assert_eq!(r1.status(), StatusCode::OK, "首次消费成功");
    let first_session =
        set_cookie_val(&r1, "__Host-agent_auth_session").expect("首次恢复返回 session");
    let epoch = state
        .users
        .get_by_id("", "user:bob@example.com")
        .await
        .unwrap()
        .unwrap()
        .credential_epoch;

    let r2 = post_recover(&router, &codes[0]).await;
    assert_eq!(r2.status(), StatusCode::OK, "响应丢失后的短时重试应成功");
    assert_eq!(
        set_cookie_val(&r2, "__Host-agent_auth_session").as_deref(),
        Some(first_session.as_str()),
        "重试只能重放同一已提交 session"
    );
    assert_eq!(
        state
            .users
            .get_by_id("", "user:bob@example.com")
            .await
            .unwrap()
            .unwrap()
            .credential_epoch,
        epoch,
        "重试不得再次推进 credential epoch"
    );

    state.sessions.delete("", &first_session).await.unwrap();
    let r3 = post_recover(&router, &codes[0]).await;
    assert_eq!(
        r3.status(),
        StatusCode::BAD_REQUEST,
        "原会话不存在后同码仍应按一次性语义拒绝"
    );

    // 另一个未用码仍有效。
    let r4 = post_recover(&router, &codes[1]).await;
    assert_eq!(r4.status(), StatusCode::OK, "未消费的其他码仍有效");
}

#[tokio::test]
async fn recovery_result_is_bound_to_the_original_operation_and_code() {
    let (router, state) = app_with_state().await;
    let session = login_session(&router, "bob@example.com").await;
    let codes = generate_codes(&router, &session).await;
    let original_operation = URL_SAFE_NO_PAD.encode([11_u8; 32]);
    let other_operation = URL_SAFE_NO_PAD.encode([12_u8; 32]);
    let epoch_before = state
        .users
        .get_by_id("", "user:bob@example.com")
        .await
        .unwrap()
        .unwrap()
        .credential_epoch;

    let first = post_recover_with_operation(&router, &codes[0], &original_operation).await;
    assert_eq!(first.status(), StatusCode::OK);
    let first_session =
        set_cookie_val(&first, "__Host-agent_auth_session").expect("first recovery session");
    let last_login_after_first = state
        .users
        .get_by_id("", "user:bob@example.com")
        .await
        .unwrap()
        .unwrap()
        .last_login_at;

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let replay = post_recover_with_operation(&router, &codes[0], &original_operation).await;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(
        set_cookie_val(&replay, "__Host-agent_auth_session").as_deref(),
        Some(first_session.as_str())
    );
    assert_eq!(
        state
            .messages
            .list_recent("", 50)
            .await
            .unwrap()
            .iter()
            .filter(|message| message.kind == "recovery")
            .count(),
        1,
        "one recovery operation must emit at most one notification"
    );
    assert_eq!(
        state
            .users
            .get_by_id("", "user:bob@example.com")
            .await
            .unwrap()
            .unwrap()
            .last_login_at,
        last_login_after_first,
        "replaying an existing session must not advance last_login_at"
    );

    let different_operation =
        post_recover_with_operation(&router, &codes[0], &other_operation).await;
    assert_eq!(
        different_operation.status(),
        StatusCode::BAD_REQUEST,
        "a consumed code must not be replayable under a different operation"
    );
    let different_code = post_recover_with_operation(&router, &codes[1], &original_operation).await;
    assert_eq!(
        different_code.status(),
        StatusCode::BAD_REQUEST,
        "an operation result must remain bound to its presented code"
    );

    assert_eq!(
        state
            .users
            .get_by_id("", "user:bob@example.com")
            .await
            .unwrap()
            .unwrap()
            .credential_epoch,
        epoch_before + 1,
        "replay attempts must not advance authority again"
    );
}

#[tokio::test]
async fn recovery_result_replay_rechecks_password_authority() {
    let (router, state) = app_with_state().await;
    let user_id = "user:bob@example.com";
    let session = login_session(&router, "bob@example.com").await;
    let codes = generate_codes(&router, &session).await;
    let operation = URL_SAFE_NO_PAD.encode([14_u8; 32]);
    let recovered = post_recover_with_operation(&router, &codes[0], &operation).await;
    assert_eq!(recovered.status(), StatusCode::OK);

    assert_eq!(
        state
            .passwords
            .reset_temporary(
                "",
                user_id,
                hash_password("Pending replay reset 123!").unwrap(),
                None,
                agent_auth_http::current_unix_secs(),
            )
            .await
            .unwrap(),
        Some(1)
    );
    let replay = post_recover_with_operation(&router, &codes[0], &operation).await;
    assert_eq!(replay.status(), StatusCode::FORBIDDEN);
    assert!(set_cookie_val(&replay, "__Host-agent_auth_session").is_none());
}

#[tokio::test]
async fn recovery_result_is_rejected_after_user_authority_changes() {
    let (router, state) = app_with_state().await;
    let user_id = "user:bob@example.com";
    let session = login_session(&router, "bob@example.com").await;
    let codes = generate_codes(&router, &session).await;
    let operation = URL_SAFE_NO_PAD.encode([13_u8; 32]);
    let recovered = post_recover_with_operation(&router, &codes[0], &operation).await;
    assert_eq!(recovered.status(), StatusCode::OK);

    let epoch = state
        .users
        .get_by_id("", user_id)
        .await
        .unwrap()
        .unwrap()
        .credential_epoch;
    assert_eq!(
        state
            .users
            .begin_credential_change(
                "",
                user_id,
                epoch,
                "post-recovery-authority-change",
                agent_auth_http::current_unix_secs(),
            )
            .await
            .unwrap(),
        CredentialChangeStart::Started { epoch: epoch + 1 }
    );
    assert!(state
        .users
        .complete_credential_change(
            "",
            user_id,
            agent_auth_http::ports::CredentialChangeOwner {
                epoch: epoch + 1,
                operation_id: "post-recovery-authority-change",
            },
            agent_auth_http::current_unix_secs(),
        )
        .await
        .unwrap());

    let replay = post_recover_with_operation(&router, &codes[0], &operation).await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert!(set_cookie_val(&replay, "__Host-agent_auth_session").is_none());
}

#[tokio::test]
async fn pending_credential_fence_does_not_consume_recovery_code() {
    let (router, state) = app_with_state().await;
    let email = "alice@example.com";
    let user_id = format!("user:{email}");
    let session = login_session(&router, email).await;
    let codes = generate_codes(&router, &session).await;
    let user = state.users.get_by_id("", &user_id).await.unwrap().unwrap();
    assert_eq!(
        state
            .users
            .begin_credential_change(
                "",
                &user_id,
                user.credential_epoch,
                "recovery-block-owner",
                agent_auth_http::current_unix_secs(),
            )
            .await
            .unwrap(),
        CredentialChangeStart::Started {
            epoch: user.credential_epoch + 1
        }
    );

    let blocked = post_recover(&router, &codes[0]).await;
    assert_eq!(blocked.status(), StatusCode::SERVICE_UNAVAILABLE);
    let lookup = codes[0].split('.').nth(1).unwrap();
    assert!(
        !state
            .recovery
            .get("", lookup)
            .await
            .unwrap()
            .unwrap()
            .code_hashes[0]
            .consumed,
        "a pending user fence must reject before recovery-code consumption"
    );

    assert!(state
        .users
        .complete_credential_change(
            "",
            &user_id,
            agent_auth_http::ports::CredentialChangeOwner {
                epoch: user.credential_epoch + 1,
                operation_id: "recovery-block-owner",
            },
            agent_auth_http::current_unix_secs(),
        )
        .await
        .unwrap());
    assert_eq!(
        post_recover(&router, &codes[0]).await.status(),
        StatusCode::OK,
        "the same unconsumed code remains usable after the fence completes"
    );
}

#[tokio::test]
async fn recovery_only_session_cannot_rotate_away_its_last_recovery_material() {
    let (router, state) = app_with_state().await;
    let email = "recovery-only@example.com";
    let user_id = format!("user:{email}");
    let session = login_session(&router, email).await;
    let codes = generate_codes(&router, &session).await;
    let recovered = post_recover(&router, &codes[0]).await;
    assert_eq!(recovered.status(), StatusCode::OK);
    let recovered_session =
        set_cookie_val(&recovered, "__Host-agent_auth_session").expect("recovery session");
    let lookup = codes[0].split('.').nth(1).unwrap();
    let record_before = state.recovery.get("", lookup).await.unwrap().unwrap();

    let blocked = generate_raw(&router, &recovered_session).await;
    assert_eq!(blocked.status(), StatusCode::CONFLICT);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(blocked.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["error"], "last_viable_factor");
    assert!(
        state
            .sessions
            .get("", &recovered_session)
            .await
            .unwrap()
            .is_some(),
        "lockout prevention must preserve the authoritative recovery session"
    );
    assert_eq!(
        state.recovery.get("", lookup).await.unwrap().unwrap(),
        record_before,
        "lockout prevention must not replace or consume the existing recovery record"
    );
    assert!(state
        .credential_audit
        .snapshot()
        .join("\n")
        .contains("kind=recovery target=self result=lockout_prevented"));

    assert!(state
        .passwords
        .create_if_absent(
            "",
            PasswordCredential {
                user_id,
                password_hash: hash_password("Active recovery backup 123!").unwrap(),
                must_change: false,
                revocation_pending: false,
                credential_change_id: None,
                version: 1,
                updated_at: agent_auth_http::current_unix_secs(),
            },
        )
        .await
        .unwrap());
    assert_eq!(
        generate_raw(&router, &recovered_session).await.status(),
        StatusCode::OK,
        "an active password makes recovery rotation safe"
    );
}

#[tokio::test]
async fn current_rp_passkey_allows_recovery_only_session_to_rotate() {
    let mut state = AppState::dev(HOST);
    state.passkey_enabled = true;
    let email = "recovery-passkey@example.com";
    let user_id = format!("user:{email}");
    state.seed_dev_user(email).await;
    let (router, _) = build_router(state.clone());
    let session = login_session(&router, email).await;
    let codes = generate_codes(&router, &session).await;
    let recovered = post_recover(&router, &codes[0]).await;
    assert_eq!(recovered.status(), StatusCode::OK);
    let recovered_session =
        set_cookie_val(&recovered, "__Host-agent_auth_session").expect("recovery session");

    state
        .passkeys
        .put_new(
            "",
            PasskeyCredential {
                credential_id: "current-rp-backup".to_string(),
                user_id,
                rp_id: HOST.to_string(),
                public_key_sec1: vec![4; 65],
                sign_count: 0,
                name: "Current RP".to_string(),
                created_at: agent_auth_http::current_unix_secs(),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        generate_raw(&router, &recovered_session).await.status(),
        StatusCode::OK
    );
}

// 格式非法的码 → 400(码格式解析失败)。
#[tokio::test]
async fn malformed_code_rejected() {
    let router = app().await;
    let resp = post_recover(&router, "not-a-valid-code").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "非法格式应拒");
}

#[tokio::test]
async fn recovery_requires_a_canonical_32_byte_operation_id() {
    let router = app().await;
    for operation_id in [
        String::new(),
        URL_SAFE_NO_PAD.encode([1_u8; 31]),
        format!("{}=", URL_SAFE_NO_PAD.encode([2_u8; 32])),
    ] {
        let response =
            post_recover_with_operation(&router, "not-a-valid-code", &operation_id).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    let body = serde_json::json!({ "code": "not-a-valid-code" });
    let missing = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/recovery/verify")
                .header("host", HOST)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// 限流:连续错码(格式对但 hash 不命中)达阈值 → 锁定 429。
// 用真实码派生出格式合法但秘密错误的兄弟码(共享同一 user_lookup 前缀),触发 per-user 计数。
#[tokio::test]
async fn repeated_wrong_codes_locks_out() {
    let (router, state) = app_with_state().await;
    let session = login_session(&router, "carol@example.com").await;
    let codes = generate_codes(&router, &session).await;
    // 取真实码的 lookup 前缀,拼一个秘密段错误的同 user 码:v1.{lookup}.{wrong}
    let parts: Vec<&str> = codes[0].splitn(3, '.').collect();
    assert_eq!(parts.len(), 3);
    let wrong = format!(
        "{}.{}.{}",
        parts[0], parts[1], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );

    // MAX_ATTEMPTS = 5:前 5 次错 → Invalid(400),第 5 次起置锁。
    let mut saw_locked = false;
    for _ in 0..7 {
        let resp = post_recover(&router, &wrong).await;
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            saw_locked = true;
            break;
        }
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
    assert!(saw_locked, "连续错码应最终锁定(429)");
    let audit = state.credential_audit.snapshot().join("\n");
    assert!(audit.contains(
        "action=consume tenant= actor=user:carol@example.com kind=recovery target=self result=locked"
    ));

    // 锁定期内即便拿正确码也被拒(429),防绕过限流。
    let resp = post_recover(&router, &codes[0]).await;
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "锁定期内正确码也应 429"
    );
    assert!(state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 500)
        .await
        .unwrap()
        .iter()
        .any(|stored| {
            stored.event.action == "authentication.recovery"
                && stored.event.outcome == SecurityEventOutcome::Denied
        }));
}

// 恢复吊销既存 refresh family:恢复后该 user 的 refresh token 全被吊销(防攻击者旧 refresh 续用)。
#[tokio::test]
async fn recovery_revokes_refresh_families() {
    let state = AppState::dev(HOST);
    // 播一条属于登录用户(magic-link:user_id = "user:{email}")的 refresh family。
    let email = "grace@example.com";
    let user_id = format!("user:{email}");
    state
        .refresh
        .create(
            "",
            RefreshFamilyRecord {
                family_id: "fam-grace".into(),
                current_version: 0,
                revoked: false,
                client_id: "c".into(),
                cimd_snapshot: None,
                user_id: user_id.clone(),
                credential_epoch: 0,
                resources: vec![],
                scope: vec!["openid".into()],
                actor_allowlist: vec![],
                max_act_chain: 1,
                dpop_jkt: None,
                pkce_code_challenge: None,
                auth_time: None,
                acr: None,
                password_credential_version: Some(0),
            },
        )
        .await
        .unwrap();
    state
        .refresh
        .create(
            "",
            RefreshFamilyRecord {
                family_id: "fam-already-revoked".into(),
                current_version: 1,
                revoked: true,
                client_id: "c".into(),
                cimd_snapshot: None,
                user_id: user_id.clone(),
                credential_epoch: 0,
                resources: vec![],
                scope: vec!["openid".into()],
                actor_allowlist: vec![],
                max_act_chain: 1,
                dpop_jkt: None,
                pkce_code_challenge: None,
                auth_time: None,
                acr: None,
                password_credential_version: Some(0),
            },
        )
        .await
        .unwrap();
    let grace = state.grace.as_ref().unwrap();
    grace
        .put(GraceCacheEntry {
            family_id: "fam-already-revoked".into(),
            version: 0,
            fingerprint: [7; 32],
            client_id: "c".into(),
            dpop_jkt: None,
            response: GraceCachedResponse {
                access_token: "stale-access".into(),
                refresh_token: "stale-refresh".into(),
                id_token: None,
                scope: Some("openid".into()),
                expires_in: 300,
            },
            expires_at: i64::MAX,
        })
        .await
        .unwrap();
    state.seed_dev_user(email).await;
    let (router, _) = build_router(state.clone());

    // The family is live before recovery-material rotation begins.
    assert!(
        !state
            .refresh
            .get("", "fam-grace")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    let session = login_session(&router, email).await;
    let codes = generate_codes(&router, &session).await;
    // Rotating recovery material is itself a credential mutation and revokes
    // sessions, refresh families, and grace entries immediately.
    assert!(
        state
            .refresh
            .get("", "fam-grace")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    assert!(
        grace.get("fam-already-revoked", 0).await.unwrap().is_none(),
        "recovery rotation must clear grace for families that were already revoked"
    );

    let resp = post_recover(&router, &codes[0]).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Recovery remains idempotently revoked and cannot revive a family.
    assert!(
        state
            .refresh
            .get("", "fam-grace")
            .await
            .unwrap()
            .unwrap()
            .revoked,
        "恢复应吊销既存 refresh family(评审 codex#1)"
    );
}

// 恢复吊销旧会话:恢复后原 session cookie 对应会话失效(delete_by_user)。
// 用 /consent/context 探针(需有效会话才 200)验证旧会话已被吊销。
#[tokio::test]
async fn recovery_revokes_old_sessions() {
    let (router, state) = app_with_state().await;
    let session = login_session(&router, "dave@example.com").await;

    let aq = format!(
        "client_id={SESSION_PROBE_CLIENT}&redirect_uri={SESSION_PROBE_REDIRECT}&scope=openid"
    );
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
    let before = probe(format!("__Host-agent_auth_session={session}")).await;
    assert_eq!(before, StatusCode::OK, "轮换恢复码前旧会话应有效");

    let codes = generate_codes(&router, &session).await;
    let after_rotation = probe(format!("__Host-agent_auth_session={session}")).await;
    assert_eq!(
        after_rotation,
        StatusCode::UNAUTHORIZED,
        "轮换恢复码后旧会话应立即失效"
    );

    // A session established after rotation is still revoked by recovery.
    let post_rotation = fresh_session(&state, "dave-after-rotation", "dave@example.com").await;
    assert_eq!(
        probe(format!("__Host-agent_auth_session={post_rotation}")).await,
        StatusCode::OK
    );

    let resp = post_recover(&router, &codes[0]).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let after = probe(format!("__Host-agent_auth_session={post_rotation}")).await;
    assert_eq!(
        after,
        StatusCode::UNAUTHORIZED,
        "恢复后旧会话应被吊销(delete_by_user)"
    );
}

// GET /recovery/status(补 /account 恢复码设置区 UX 闭环):查当前登录用户自己是否已配置恢复码。
async fn get_status(router: &axum::Router, session: Option<&str>) -> axum::http::Response<Body> {
    let mut b = Request::builder()
        .method("GET")
        .uri("/recovery/status")
        .header("host", HOST);
    if let Some(s) = session {
        b = b.header("cookie", format!("__Host-agent_auth_session={s}"));
    }
    router
        .clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

// 未登录 → 401(与 /recovery/generate 同鉴权面,不留匿名可达面)。
#[tokio::test]
async fn status_requires_login() {
    let router = app().await;
    let resp = get_status(&router, None).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "未登录查 status 应 401"
    );
}

// 状态闭环:未配置 → configured=false/remaining=0;生成后 → configured=true/remaining=10;
// 消费一个码后 → remaining 递减为 9(前端据此提示"仅剩 N 个")。零跨用户(只查自己)。
#[tokio::test]
async fn status_reflects_configured_and_remaining() {
    let (router, state) = app_with_state().await;
    let session = login_session(&router, "status@example.com").await;

    // 尚未生成 → 未配置。
    let resp = get_status(&router, Some(&session)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let j: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(j["configured"], false, "未生成时 configured=false");
    assert_eq!(j["remaining"], 0);

    // 生成 10 码 → 已配置、剩 10。
    let codes = generate_codes(&router, &session).await;
    let status_session = fresh_session(&state, "status-after-rotation", "status@example.com").await;
    let resp = get_status(&router, Some(&status_session)).await;
    let j: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(j["configured"], true, "生成后 configured=true");
    assert_eq!(j["remaining"], 10, "剩余 10 未消费");

    // 消费一个码(恢复)→ 剩 9。恢复会吊销旧会话,故用新会话查 status。
    let resp = post_recover(&router, &codes[0]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let new_session = set_cookie_val(&resp, "__Host-agent_auth_session").unwrap();
    let resp = get_status(&router, Some(&new_session)).await;
    let j: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(j["configured"], true, "消费一个后仍有剩余 → 仍 configured");
    assert_eq!(j["remaining"], 9, "消费一个码后剩 9");
}

// 跨用户隔离(评审 codex 建议):user A 配置恢复码后,user B 用自己的会话查 status
// MUST 只见到自己的状态(未配置)——绝不泄露 A 是否配置。status 仅按调用方 session 派生
// user_lookup 定位,不接受任何用户输入 → 结构上无法查他人。
#[tokio::test]
async fn status_is_per_user_isolated() {
    let (router, state) = app_with_state().await;
    // user A 登录并生成 10 码。
    let sa = login_session(&router, "alice-iso@example.com").await;
    let _ = generate_codes(&router, &sa).await;
    let sa_after = fresh_session(&state, "alice-iso-after-rotation", "alice-iso@example.com").await;
    let ra = get_status(&router, Some(&sa_after)).await;
    let ja: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(ra.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(ja["configured"], true, "A 已配置");

    // user B(不同 email → 不同 user_id → 不同 user_lookup)用自己的会话查 → 只见自己(未配置)。
    let sb = login_session(&router, "bob-iso@example.com").await;
    let rb = get_status(&router, Some(&sb)).await;
    let jb: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(rb.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        jb["configured"], false,
        "B 未配置——MUST NOT 见到 A 的配置状态(跨用户隔离)"
    );
    assert_eq!(jb["remaining"], 0, "B 自己的 remaining=0");
}

// per-user 生成限流(C9.1 防滥刷 + 缓解 CSRF 使旧码失效):RECOVERY_GEN_CAPACITY=5,连续生成
// 超过 5 次(补充极慢 0.02/s)→ 最终 429。键 = 认证后 user_id(不同用户各自桶,互不影响)。
#[tokio::test]
async fn generate_is_rate_limited_per_user() {
    let (router, state) = app_with_state().await;
    // 桶容量 5:前 5 次应放行(200),之后触顶 429。
    let mut saw_429 = false;
    for i in 0..8 {
        let session = fresh_session(
            &state,
            &format!("flood-generation-{i}"),
            "flood-gen@example.com",
        )
        .await;
        let resp = generate_raw(&router, &session).await;
        match resp.status() {
            StatusCode::OK => {}
            StatusCode::TOO_MANY_REQUESTS => {
                saw_429 = true;
                break;
            }
            other => panic!("第 {i} 次生成非 200/429:{other}"),
        }
    }
    assert!(
        saw_429,
        "连续滥刷生成应最终 429(per-user 限流,防覆盖旧码滥用)"
    );
    let audit = state.credential_audit.snapshot().join("\n");
    assert!(audit.contains(
        "USER_CREDENTIAL_OPERATION action=rotate tenant= actor=user:flood-gen@example.com \
         kind=recovery target=self result=denied"
    ));
    assert!(!audit.contains("v1."), "审计不得包含明文恢复码");

    // 另一用户不受影响(独立桶,key=user_id 隔离)。
    let other = login_session(&router, "other-gen@example.com").await;
    let resp = generate_raw(&router, &other).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "限流按 user 隔离——他人不受某用户滥刷影响"
    );
}
