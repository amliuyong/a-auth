//! 进程内 e2e:用户自助 Grant 管理 API(spec 011 §5.1 / FAPI Grant Management,P2)。
//!
//! 覆盖:magic-link 登录建会话 → GET /grants(只见本人)→ GET/DELETE /grants/{id}(IDOR-safe:
//! 他人的 404)→ 吊销后 status=revoked。未登录 401;P1 阶段 404。

use agent_auth_grant::{Grant, GrantConstraints, GrantStatus, ResourceGrant};
use agent_auth_http::ports::{
    GraceCacheEntry, GraceCachedResponse, GraceStore, GrantStore, RefreshFamilyRecord, RefreshStore,
};
use agent_auth_http::{
    build_router,
    security_event::{SecurityEventOutcome, SecurityEventStore},
    state::{GraceStoreImpl, RefreshStoreImpl},
    AppState, Phase,
};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _; // grant-ref JWT header/claims 解码(mint 测试)
use tower::ServiceExt;

const HOST: &str = "localhost";

fn set_cookie_val(resp: &axum::http::Response<Body>, name: &str) -> Option<String> {
    for hv in resp.headers().get_all(axum::http::header::SET_COOKIE) {
        let s = hv.to_str().ok()?;
        if let Some(rest) = s.strip_prefix(&format!("{name}=")) {
            return Some(rest.split(';').next().unwrap_or("").to_string());
        }
    }
    None
}

/// magic-link 登录 → 返回 session cookie 值(user_id = user:{email})。
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

fn mk_grant(grant_id: &str, user_id: &str) -> Grant {
    Grant {
        grant_id: grant_id.into(),
        user_id: user_id.into(),
        client_id: "app-3lo".into(),
        per_resource: vec![ResourceGrant {
            resource: "https://mcp.kb.example.com".into(),
            scopes: vec!["kb:read".into()],
            authorization_details: vec![],
        }],
        effective_per_resource: vec![],
        effective_pv: 0,
        allowed_ip_cidrs: vec![],
        allowed_vpce: vec![],
        credential_epoch: 0,
        revision: 0,
        constraints: GrantConstraints {
            max_act_chain: 1,
            actor_allowlist: vec![],
            expires_at: 4_000_000_000,
        },
        status: GrantStatus::Active,
    }
}

async fn get_json(
    router: &axum::Router,
    uri: &str,
    session: &str,
) -> (StatusCode, serde_json::Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
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
        serde_json::from_slice(&b).unwrap_or(serde_json::json!(null)),
    )
}

async fn delete(router: &axum::Router, uri: &str, session: &str) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(uri)
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

// P2:登录用户列自己的 Grant;GET 单个;DELETE 吊销 → status=revoked。
#[tokio::test]
async fn grants_list_get_revoke_own() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    // alice 的两个 Grant(user_id = login 派生的 user:alice@example.com)。
    let alice = "user:alice@example.com";
    state.grants.put("", mk_grant("g1", alice)).await.unwrap();
    state.grants.put("", mk_grant("g2", alice)).await.unwrap();
    state.seed_dev_user("alice@example.com").await;
    let (router, _) = build_router(state.clone());
    let session = login(&router, "alice@example.com").await;

    // GET /grants → 见 g1,g2。
    let (st, body) = get_json(&router, "/grants", &session).await;
    assert_eq!(st, StatusCode::OK, "列表应 200: {body}");
    let arr = body.as_array().expect("数组");
    assert_eq!(arr.len(), 2, "alice 有 2 个 grant");
    assert!(arr.iter().all(|g| g["status"] == "active"));

    // GET /grants/g1 → 详情。
    let (st, g1) = get_json(&router, "/grants/g1", &session).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(g1["grant_id"], "g1");
    assert_eq!(g1["resources"][0]["resource"], "https://mcp.kb.example.com");

    // DELETE /grants/g1 → 204。
    assert_eq!(
        delete(&router, "/grants/g1", &session).await,
        StatusCode::NO_CONTENT
    );
    assert!(state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 500)
        .await
        .unwrap()
        .iter()
        .any(|stored| {
            stored.event.action == "grant.revoke"
                && stored.event.outcome == SecurityEventOutcome::Success
                && stored.event.correlation.grant_id.as_deref() == Some("g1")
        }));
    // 再 GET g1 → 仍在但 status=revoked(吊销不删记录)。
    let (st, g1) = get_json(&router, "/grants/g1", &session).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(g1["status"], "revoked", "吊销后 status=revoked");
    // DELETE 幂等:再吊 204。
    assert_eq!(
        delete(&router, "/grants/g1", &session).await,
        StatusCode::NO_CONTENT
    );
}

// IDOR-safe:mallory 登录看不到 / 动不了 alice 的 grant(404,不泄露存在性)。
#[tokio::test]
async fn grants_idor_safe_across_users() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    state
        .grants
        .put("", mk_grant("g-alice", "user:alice@example.com"))
        .await
        .unwrap();
    state.seed_dev_user("mallory@evil.example").await;
    state.seed_dev_user("alice@example.com").await;
    let (router, _) = build_router(state.clone());
    let mallory = login(&router, "mallory@evil.example").await;

    // mallory 列表为空(只列本人)。
    let (st, body) = get_json(&router, "/grants", &mallory).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 0, "mallory 无 grant");

    // GET alice 的 grant → 404(不泄露存在性)。
    let (st, _) = get_json(&router, "/grants/g-alice", &mallory).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "他人 grant 应 404");

    // DELETE alice 的 grant → 404(不吊销)。
    assert_eq!(
        delete(&router, "/grants/g-alice", &mallory).await,
        StatusCode::NOT_FOUND
    );
    // 确认 alice 的 grant 未被 mallory 吊销:alice 登录看仍 active。
    let alice = login(&router, "alice@example.com").await;
    let (_st, g) = get_json(&router, "/grants/g-alice", &alice).await;
    assert_eq!(
        g["status"], "active",
        "mallory 的 DELETE 未影响 alice 的 grant"
    );
    assert!(state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 500)
        .await
        .unwrap()
        .iter()
        .any(|stored| {
            stored.event.action == "grant.deny"
                && stored.event.outcome == SecurityEventOutcome::Denied
                && stored.event.correlation.grant_id.as_deref() == Some("g-alice")
        }));
}

// 未登录 → 401。
#[tokio::test]
async fn grants_requires_login() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    let (router, _) = build_router(state);
    let (st, _) = get_json(&router, "/grants", "bogus-session").await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "无有效会话应 401");
}

// C7.6b / 评审 codex HIGH:DELETE /grants **级联吊销 refresh family** —— 吊销后旧 refresh token
// MUST 不能再 rotate 换 access(否则"一键吊销授权"失效)。Grant.grant_id==family_id。
#[tokio::test]
async fn revoke_grant_cascades_to_refresh_family() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    let alice = "user:alice@example.com";
    // seed 一个 public client(refresh grant 需 client 认证)+ family(id=fam1)+ 同 id Grant。
    state
        .seed_dev_client("app-3lo", "http://127.0.0.1/cb", None)
        .await;
    state
        .refresh
        .create(
            "",
            RefreshFamilyRecord {
                family_id: "fam1".into(),
                current_version: 0,
                revoked: false,
                client_id: "app-3lo".into(),
                cimd_snapshot: None,
                user_id: alice.into(),
                credential_epoch: 0,
                resources: vec!["https://mcp.kb.example.com".into()],
                scope: vec!["kb:read".into()],
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
    state.grants.put("", mk_grant("fam1", alice)).await.unwrap();
    state.seed_dev_user("alice@example.com").await;
    let grants = state.grants.clone();
    let refresh = state.refresh.clone();
    let grace = state.grace.as_ref().expect("dev enables grace").clone();
    let (router, _) = build_router(state);
    let session = login(&router, "alice@example.com").await;

    // 吊销前:旧 refresh token(fam1.0)可 rotate。
    let refresh_ok = |router: axum::Router, tok: String| async move {
        let form = format!("grant_type=refresh_token&refresh_token={tok}&client_id=app-3lo");
        router
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
    };
    assert_eq!(
        refresh_ok(router.clone(), "fam1.0".into()).await,
        StatusCode::OK,
        "吊销前 refresh 应能 rotate"
    );
    assert!(
        grace.get("fam1", 0).await.unwrap().is_some(),
        "rotation must create the old-version grace response used by this cleanup assertion"
    );
    grace
        .put(GraceCacheEntry {
            family_id: "fam1".into(),
            version: 99,
            fingerprint: [9; 32],
            client_id: "app-3lo".into(),
            dpop_jkt: None,
            response: GraceCachedResponse {
                access_token: "cached-access-v99".into(),
                refresh_token: "fam1.100".into(),
                id_token: None,
                scope: Some("kb:read".into()),
                expires_in: 300,
            },
            expires_at: 4_000_000_000,
        })
        .await
        .unwrap();
    assert!(
        grace.get("fam1", 99).await.unwrap().is_some(),
        "the cleanup assertion must cover more than one cached family version"
    );

    // DELETE /grants/fam1 → 级联吊销 family。
    assert_eq!(
        delete(&router, "/grants/fam1", &session).await,
        StatusCode::NO_CONTENT
    );
    let grant = grants
        .get("", "fam1")
        .await
        .unwrap()
        .expect("Grant remains as a revoked authority record");
    assert_eq!(grant.status, GrantStatus::Revoked);
    assert!(
        refresh
            .get("", "fam1")
            .await
            .unwrap()
            .expect("family remains as a revoked record")
            .revoked,
        "Grant DELETE must revoke the associated refresh family"
    );
    assert!(
        grace.get("fam1", 0).await.unwrap().is_none(),
        "Grant DELETE must clear the rotation-created grace response"
    );
    assert!(
        grace.get("fam1", 99).await.unwrap().is_none(),
        "Grant DELETE must clear every cached response in the family"
    );

    // 吊销后:refresh(无论旧 fam1.0 还是 rotate 出的 fam1.1)MUST 拒(family 已 revoked)。
    assert_eq!(
        refresh_ok(router.clone(), "fam1.0".into()).await,
        StatusCode::BAD_REQUEST,
        "Grant 吊销后 refresh MUST 拒(级联吊销 family)"
    );
    assert_eq!(
        refresh_ok(router.clone(), "fam1.1".into()).await,
        StatusCode::BAD_REQUEST,
        "rotate 出的新 refresh 也失效"
    );
}

// C7.6b:Grant 已写 Revoked 后，refresh-family/grace cleanup 任一失败都不得伪报 204。
// DELETE 必须可幂等重试，并且一次尝试里 refresh 与 grace cleanup 相互独立，避免前者失败
// 阻止后者执行。
#[tokio::test]
async fn revoke_grant_cleanup_failure_is_retriable_and_retry_clears_family_and_grace() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    let alice = "user:alice@example.com";
    state
        .seed_dev_client("app-3lo", "http://127.0.0.1/cb", None)
        .await;
    state
        .refresh
        .create(
            "",
            RefreshFamilyRecord {
                family_id: "fam-cleanup".into(),
                current_version: 1,
                revoked: false,
                client_id: "app-3lo".into(),
                cimd_snapshot: None,
                user_id: alice.into(),
                credential_epoch: 0,
                resources: vec!["https://mcp.kb.example.com".into()],
                scope: vec!["kb:read".into()],
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
        .grants
        .put("", mk_grant("fam-cleanup", alice))
        .await
        .unwrap();
    let grace = state.grace.as_ref().expect("dev enables grace").clone();
    grace
        .put(GraceCacheEntry {
            family_id: "fam-cleanup".into(),
            version: 0,
            fingerprint: [7; 32],
            client_id: "app-3lo".into(),
            dpop_jkt: None,
            response: GraceCachedResponse {
                access_token: "cached-access".into(),
                refresh_token: "fam-cleanup.1".into(),
                id_token: None,
                scope: Some("kb:read".into()),
                expires_in: 300,
            },
            expires_at: 4_000_000_000,
        })
        .await
        .unwrap();
    state.seed_dev_user("alice@example.com").await;

    #[allow(unreachable_patterns)]
    match state.refresh.as_ref() {
        RefreshStoreImpl::Memory(store) => store.fail_next_revoke(false),
        _ => panic!("test requires memory refresh store"),
    }
    #[allow(unreachable_patterns)]
    match grace.as_ref() {
        GraceStoreImpl::Memory(store) => store.fail_next_delete_family(true),
        _ => panic!("test requires memory grace store"),
    }

    let refresh = state.refresh.clone();
    let grants = state.grants.clone();
    let (router, _) = build_router(state);
    let session = login(&router, "alice@example.com").await;

    assert_eq!(
        delete(&router, "/grants/fam-cleanup", &session).await,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a permanent cleanup failure must not be masked by a simultaneous transient failure"
    );
    assert_eq!(
        grants
            .get("", "fam-cleanup")
            .await
            .unwrap()
            .expect("Grant remains as the revocation authority")
            .status,
        GrantStatus::Revoked,
        "cleanup retry must occur after the Grant is already revoked"
    );

    #[allow(unreachable_patterns)]
    match refresh.as_ref() {
        RefreshStoreImpl::Memory(store) => store.fail_next_revoke(true),
        _ => panic!("test requires memory refresh store"),
    }
    #[allow(unreachable_patterns)]
    match grace.as_ref() {
        GraceStoreImpl::Memory(store) => store.fail_next_delete_family(true),
        _ => panic!("test requires memory grace store"),
    }
    assert_eq!(
        delete(&router, "/grants/fam-cleanup", &session).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "cleanup failure must be retriable instead of reporting a false 204"
    );
    assert_eq!(
        delete(&router, "/grants/fam-cleanup", &session).await,
        StatusCode::NO_CONTENT,
        "an idempotent retry must finish cleanup after the Grant is already revoked"
    );
    assert!(
        refresh
            .get("", "fam-cleanup")
            .await
            .unwrap()
            .expect("family remains as a revoked record")
            .revoked,
        "retry must mark the refresh family revoked"
    );
    assert!(
        grace.get("fam-cleanup", 0).await.unwrap().is_none(),
        "retry must remove every cached grace response for the Grant family"
    );
}

// spec 020 §5.3 / C11.2:refresh 校验**联查 Grant 最新 status**——即便本地 refresh 表 family.revoked=false,
// Grant 被吊销(status=Revoked)时 refresh MUST 拒(双源 AND;堵"级联吊销 best-effort 失败"/"Grant 有效期"
// /"多区域 family 标记未复制但 Grant 已复制"的窗)。对照:无 Grant 的老 family 仍能 refresh(后向兼容)。
#[tokio::test]
async fn refresh_rejected_when_grant_revoked_but_family_active() {
    use agent_auth_grant::GrantStatus;
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    let alice = "user:alice@example.com";
    state
        .seed_dev_client("app-3lo", "http://127.0.0.1/cb", None)
        .await;
    // family fam-revoked-grant:**family.revoked=false**(本地表 active),但其同 id Grant 被吊销。
    state
        .refresh
        .create(
            "",
            RefreshFamilyRecord {
                family_id: "fam-rg".into(),
                current_version: 0,
                revoked: false, // ← 本地 refresh 表标记仍 active(模拟级联失败/多区域未复制窗)
                client_id: "app-3lo".into(),
                cimd_snapshot: None,
                user_id: alice.into(),
                credential_epoch: 0,
                resources: vec!["https://mcp.kb.example.com".into()],
                scope: vec!["kb:read".into()],
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
    // 同 id Grant 但 status=Revoked(身份表权威源已吊销)。
    let mut revoked_grant = mk_grant("fam-rg", alice);
    revoked_grant.status = GrantStatus::Revoked;
    state.grants.put("", revoked_grant).await.unwrap();

    // 对照 family fam-nogrant:**无 Grant**(老 family / pre-migration),family.revoked=false。
    state
        .refresh
        .create(
            "",
            RefreshFamilyRecord {
                family_id: "fam-ng".into(),
                current_version: 0,
                revoked: false,
                client_id: "app-3lo".into(),
                cimd_snapshot: None,
                user_id: alice.into(),
                credential_epoch: 0,
                resources: vec!["https://mcp.kb.example.com".into()],
                scope: vec!["kb:read".into()],
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
    // fam-ng 不 put Grant(无 Grant)。
    let refresh = state.refresh.clone();
    let (router, _) = build_router(state);

    let refresh_status = |router: axum::Router, tok: String| async move {
        let form = format!("grant_type=refresh_token&refresh_token={tok}&client_id=app-3lo");
        router
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
    };

    // Grant 吊销(family 本地仍 active)→ 联查 Grant.status 拒(§5.3 核心)。
    assert_eq!(
        refresh_status(router.clone(), "fam-rg.0".into()).await,
        StatusCode::BAD_REQUEST,
        "Grant 吊销后 refresh MUST 拒(联查 Grant status,即便 family.revoked=false)"
    );
    let rejected_family = refresh
        .get("", "fam-rg")
        .await
        .unwrap()
        .expect("rejected family remains present");
    assert_eq!(
        rejected_family.current_version, 0,
        "Grant status gate MUST reject before consuming the regional refresh version"
    );
    assert!(
        !rejected_family.revoked,
        "the test fixture keeps the regional family active to isolate the Grant authority gate"
    );
    // 对照:无 Grant 的老 family(family.revoked=false)→ refresh 成功(后向兼容,不因无 Grant 拒)。
    assert_eq!(
        refresh_status(router.clone(), "fam-ng.0".into()).await,
        StatusCode::OK,
        "无 Grant 的老 family MUST 仍能 refresh(后向兼容,回退只看 family.revoked)"
    );
}

// C1.2:P1 阶段 /grants 不可达(404)。
#[tokio::test]
async fn grants_gated_at_p1() {
    let state = AppState::dev(HOST); // phase=P1
    state.seed_dev_user("alice@example.com").await;
    let (router, _) = build_router(state);
    // 即便带会话,阶段未到也 404(门控优先)。
    let session = login(&router, "alice@example.com").await;
    let (st, _) = get_json(&router, "/grants", &session).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "P1 /grants 应 404");
}

// ============ grant-ref 铸造端点 POST /grants/{id}/refs(spec 011 §4,模型 A)============

// POST(session-auth)带 JSON body → (status, json)。
async fn post_json(
    router: &axum::Router,
    uri: &str,
    session: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("host", HOST)
                .header("content-type", "application/json")
                .header("cookie", format!("__Host-agent_auth_session={session}"))
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
        serde_json::from_slice(&b).unwrap_or(serde_json::json!(null)),
    )
}

// Grant(带 actor_allowlist,供铸 grant-ref)。
fn mk_grant_with_actor(grant_id: &str, user_id: &str, actor: &str) -> Grant {
    let mut g = mk_grant(grant_id, user_id);
    g.constraints.actor_allowlist = vec![actor.into()];
    g
}

// 铸造:登录用户对自己的 Grant + bound_agent ∈ actor_allowlist → 201 + grant-ref(typ=grant-ref+jwt)。
#[tokio::test]
async fn mint_grant_ref_happy_path() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    let alice = "user:alice@example.com";
    state
        .grants
        .put("", mk_grant_with_actor("g1", alice, "wl-agent"))
        .await
        .unwrap();
    state.seed_dev_user("alice@example.com").await;
    let (router, _) = build_router(state);
    let session = login(&router, "alice@example.com").await;

    let (st, body) = post_json(
        &router,
        "/grants/g1/refs",
        &session,
        serde_json::json!({ "bound_agent": "wl-agent" }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "铸 grant-ref 应 201: {body}");
    let gref = body["grant_ref"].as_str().expect("含 grant_ref");
    assert_eq!(
        body["token_type"], "urn:agent-auth:params:token-type:grant-ref",
        "grant-ref 必须使用独立 token_type,不得伪装 bearer"
    );
    assert_eq!(body["expires_in"], 300, "grant-ref 固定短时 300 秒");
    // header 固定 ES256 + grant-ref+jwt,与 access token 隔离。
    let hdr: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(gref.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(hdr["alg"], "ES256");
    assert_eq!(hdr["typ"], "grant-ref+jwt", "grant-ref header typ 隔离");
    // claims 绑 grant_id + bound_agent + 本 AS,且 exp-iat 精确等于短时契约。
    let c: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(gref.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(c["grant_id"], "g1");
    assert_eq!(c["bound_agent"], "wl-agent");
    assert_eq!(c["iss"], format!("https://{HOST}"));
    assert_eq!(
        c["exp"].as_i64().unwrap() - c["iat"].as_i64().unwrap(),
        300,
        "grant-ref JWT 本身也必须固定 300 秒寿命"
    );
    for bearer_claim in [
        "sub",
        "aud",
        "client_id",
        "scope",
        "https://a-auth.com/c",
        "act",
    ] {
        assert!(
            c.get(bearer_claim).is_none(),
            "grant-ref must not mint access-token claim {bearer_claim}"
        );
    }
}

// bound_agent ∉ actor_allowlist → 400(不铸受理侧双闸必拒的死 ref)。
#[tokio::test]
async fn mint_grant_ref_bound_agent_not_in_allowlist_rejected() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    let alice = "user:alice@example.com";
    state
        .grants
        .put("", mk_grant_with_actor("g1", alice, "wl-agent"))
        .await
        .unwrap();
    state.seed_dev_user("alice@example.com").await;
    let (router, _) = build_router(state);
    let session = login(&router, "alice@example.com").await;
    let (st, _body) = post_json(
        &router,
        "/grants/g1/refs",
        &session,
        serde_json::json!({ "bound_agent": "other-agent" }), // 不在 allowlist
    )
    .await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "bound_agent 不在 allowlist 应 400"
    );
}

// IDOR:mallory 铸 alice 的 Grant → 404(不泄露)。
#[tokio::test]
async fn mint_grant_ref_idor_rejected() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    state
        .grants
        .put(
            "",
            mk_grant_with_actor("g-alice", "user:alice@example.com", "wl-agent"),
        )
        .await
        .unwrap();
    state.seed_dev_user("mallory@example.com").await;
    let (router, _) = build_router(state);
    let mallory = login(&router, "mallory@example.com").await;
    let (st, _body) = post_json(
        &router,
        "/grants/g-alice/refs",
        &mallory,
        serde_json::json!({ "bound_agent": "wl-agent" }),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::NOT_FOUND,
        "他人 Grant 铸 ref → 404(IDOR-safe)"
    );
}

// 未登录铸造 → 401。
#[tokio::test]
async fn mint_grant_ref_requires_login() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    state
        .grants
        .put(
            "",
            mk_grant_with_actor("g1", "user:alice@example.com", "wl-agent"),
        )
        .await
        .unwrap();
    let (router, _) = build_router(state);
    let (st, _) = post_json(
        &router,
        "/grants/g1/refs",
        "bogus-session",
        serde_json::json!({ "bound_agent": "wl-agent" }),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "未登录铸造 → 401");
}
