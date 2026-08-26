//! 进程内 e2e:Admin 控制台(spec 025)——双鉴权域 + 仪表盘 + client 管理。
//!
//! 覆盖:
//! - admin 认证:无 Bearer / 错 token → 401;对 token → 放行。**不读用户会话**(独立域)。
//! - `GET /admin/overview`:phase/issuer/endpoints(与 discovery 同源)/client_count。
//! - `GET /admin/clients`:列表**不回 client_secret / reg_token_hash**(H5)。
//! - `DELETE /admin/clients/{id}`:级联吊销 refresh family;重复删 → 404。
//! - `PATCH /admin/clients/{id}`:白名单更新;auth_method 弱化(降级)未确认 → 400。
//! - RFC 7592 `/register/{id}`:reg_token 校验 + ownership(A 的 token 管不了 B);
//!   两域互不代替(admin_token 不进 /register/{id};reg_token 不进 /admin/*)。

use agent_auth_grant::{Grant, GrantConstraints, GrantStatus, ResourceGrant};
use agent_auth_http::ports::{
    ClientRecord, ClientStore, GrantStore, RefreshFamilyRecord, RefreshStore,
};
use agent_auth_http::{
    build_router,
    security_event::{
        SecurityEventCategory, SecurityEventOutcome, SecurityEventStore, SecuritySubject,
    },
    AppState,
};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

const HOST: &str = "localhost";
const ADMIN: &str = "dev-admin-token-not-for-prod"; // AppState::dev 固定 admin token

fn admin_auth() -> String {
    format!("Bearer {ADMIN}")
}

fn client_grant(grant_id: &str, user_id: &str, client_id: &str) -> Grant {
    Grant {
        grant_id: grant_id.into(),
        user_id: user_id.into(),
        client_id: client_id.into(),
        per_resource: vec![ResourceGrant {
            resource: "https://resource.example.com".into(),
            scopes: vec!["read".into()],
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
            expires_at: i64::MAX,
        },
        status: GrantStatus::Active,
    }
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

// admin 认证:无 token → 401;错 token → 401;对 token → 200。且**不接受用户会话 cookie**。
#[tokio::test]
async fn admin_auth_gate_independent_of_user_session() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());

    // 无 Authorization → 401。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/overview")
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "无 admin token 应 401"
    );

    // 错 token → 401。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/overview")
                .header("host", HOST)
                .header("authorization", "Bearer WRONG")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "错 admin token 应 401"
    );
    let denied = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap()
        .into_iter()
        .find(|stored| stored.event.action == "authentication.admin")
        .expect("an explicit invalid Admin bearer must be auditable");
    assert_eq!(denied.event.category, SecurityEventCategory::Authentication);
    assert_eq!(denied.event.outcome, SecurityEventOutcome::Denied);
    assert!(!serde_json::to_string(&denied).unwrap().contains("WRONG"));

    // 携带用户会话 cookie(伪造)但无 admin token → 仍 401(不读 current_session)。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/overview")
                .header("host", HOST)
                .header("cookie", "as_session=whatever")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "用户会话不代替 admin token"
    );

    // 对 token → 200。
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/admin/overview")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "对 admin token 应放行");
}

// 缺失 admin credential Secret identity → admin 面 fail-closed 全关。
#[tokio::test]
async fn admin_disabled_when_token_absent() {
    let mut state = AppState::dev(HOST);
    state.admin_credentials = std::sync::Arc::new(
        agent_auth_http::admin_credentials::AdminCredentialResolver::disabled(),
    );
    let (router, _) = build_router(state);

    let resp = router
        .oneshot(
            Request::builder()
                .uri("/admin/overview")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "缺失 credential Secret identity 应全关(fail-closed)"
    );
}

// 消息 outbox(SES 模拟):notifier 发出的 magic-link / recovery 落 outbox,GET /admin/messages 可见。
#[tokio::test]
async fn admin_messages_lists_outbox() {
    use agent_auth_http::ports::Notifier;
    let state = AppState::dev(HOST);
    // 模拟发一封 magic-link + 一次 recovery 通知(经 dev outbox notifier)。
    state
        .notifier
        .send_magic_link("", "alice@example.com", "https://x/login/callback?link=abc")
        .await
        .unwrap();
    state
        .notifier
        .notify_recovery(
            "",
            "recovery-notification-id",
            "bob@example.com",
            1_700_000_000,
            Some("203.0.113.9"),
        )
        .await
        .unwrap();
    let (router, _) = build_router(state);

    // 无 token → 401。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/messages")
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "无 token 应 401");

    // 对 token → 列出两条(倒序;含 kind/recipient/body/ttl)。
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/admin/messages")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(j["total"], 2, "应有 2 条消息");
    let msgs = j["messages"].as_array().unwrap();
    let kinds: Vec<&str> = msgs.iter().map(|m| m["kind"].as_str().unwrap()).collect();
    assert!(kinds.contains(&"magic_link"), "含 magic_link");
    assert!(kinds.contains(&"recovery"), "含 recovery");
    // TTL = created_at + 1 天(86400)。
    for m in msgs {
        let created = m["created_at"].as_i64().unwrap();
        let ttl = m["ttl"].as_i64().unwrap();
        assert_eq!(ttl - created, 86_400, "TTL 应为 created_at + 1 天");
    }
    // magic_link 消息 body 含链接;recovery 消息 recipient 是可投递邮箱。
    let ml = msgs.iter().find(|m| m["kind"] == "magic_link").unwrap();
    assert_eq!(ml["recipient"], "alice@example.com");
    assert!(
        ml["body"].as_str().unwrap().contains("/login/callback"),
        "magic_link body 含链接"
    );
    let rc = msgs.iter().find(|m| m["kind"] == "recovery").unwrap();
    assert_eq!(rc["recipient"], "bob@example.com");
}

// 评审 M4:overview.active_sessions 反映真实活跃数(非终态 + 未过期),不含终态/过期。
#[tokio::test]
async fn overview_active_sessions_counts_only_live() {
    use agent_auth_http::ports::{AuthzSessionRecord, AuthzSessionStore};
    let state = AppState::dev(HOST);
    let mk = |id: &str, st: &str, exp: i64| AuthzSessionRecord {
        session_id: id.into(),
        client_id: "c1".into(),
        user_id: None,
        state: st.into(),
        session_token_hash: "h".into(),
        sequence: 1,
        last_error: None,
        expires_at: exp,
    };
    // 活跃(非终态 + 未过期)。
    AuthzSessionStore::create(
        &*state.authz_sessions,
        "",
        mk("live", "code_issued_awaiting_exchange", 99999999999),
    )
    .await
    .unwrap();
    // 终态(complete)→ 不计。
    AuthzSessionStore::create(
        &*state.authz_sessions,
        "",
        mk("done", "complete", 99999999999),
    )
    .await
    .unwrap();
    // 未过期但终态(denied)→ 不计。
    AuthzSessionStore::create(
        &*state.authz_sessions,
        "",
        mk("deny", "denied", 99999999999),
    )
    .await
    .unwrap();
    // 非终态但已过期 → 不计。
    AuthzSessionStore::create(&*state.authz_sessions, "", mk("old", "pending_consent", 1))
        .await
        .unwrap();
    let (router, _) = build_router(state);

    let resp = router
        .oneshot(
            Request::builder()
                .uri("/admin/overview")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let j = body_json(resp).await;
    assert_eq!(j["active_sessions"], 1, "仅 1 个活跃会话(非终态+未过期)");
}

// overview:phase/issuer/endpoints(与 discovery 同源,含 authorization_endpoint 等)/client_count。
#[tokio::test]
async fn overview_reports_authoritative_snapshot() {
    let state = AppState::dev(HOST);
    state
        .seed_dev_client("app-a", "https://app.example.com/cb", None)
        .await;
    let (router, _) = build_router(state);

    let resp = router
        .oneshot(
            Request::builder()
                .uri("/admin/overview")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(j["phase"], "P1"); // spec 011:/revoke 落地后部署 phase 升 P1
    assert_eq!(j["issuer"], format!("https://{HOST}"));
    assert_eq!(j["client_count"], 1);
    // endpoints 来自 discovery(不硬编码);至少含 authorization/token endpoint + P1 的 revocation。
    let eps: Vec<String> = j["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(
        eps.contains(&"authorization_endpoint".to_string()),
        "endpoints 应含 authorization_endpoint"
    );
    assert!(
        eps.contains(&"token_endpoint".to_string()),
        "endpoints 应含 token_endpoint"
    );
    assert!(
        eps.contains(&"jwks_uri".to_string()),
        "endpoints 应含 jwks_uri"
    );
    assert!(
        eps.contains(&"revocation_endpoint".to_string()),
        "P1 应含 revocation_endpoint"
    );
}

// list_clients / get_client:MUST NOT 回 client_secret / reg_token_hash(H5)。
#[tokio::test]
async fn client_views_never_leak_secret() {
    let state = AppState::dev(HOST);
    // 带 secret + reg_token_hash 的 client。
    let _ = ClientStore::put(
        &*state.clients,
        "",
        ClientRecord {
            client_id: "conf-a".into(),
            redirect_uris: vec!["https://a.example.com/cb".into()],
            application_type: None,
            token_endpoint_auth_method: "client_secret_basic".into(),
            client_secret: Some("SUPER-SECRET".into()),
            client_secret_credentials: Default::default(),
            jwks: None,
            jwks_uri: None,
            token_endpoint_auth_signing_alg: None,
            default_resource: None,
            introspect_enabled: false,
            resource_ids: vec![],
            post_logout_redirect_uris: vec![],
            reg_token_hash: Some("HASHVALUE".into()),
            registration_token_credentials: Default::default(),
            client_type: None,
            id_token_signed_response_alg: None,
            oidc_sector_identifier: None,
            allowed_resources: vec![],
            allowed_scopes: vec![],
            redirect_mode: None,
            created_at: 0,
            last_used_day: Some(20_000),
            authority_revision: 0,
            tombstoned_at: None,
            backchannel_token_delivery_mode: None,
            backchannel_client_notification_endpoint: None,
            require_dpop: false,
            prm_domains: vec![],
        },
    )
    .await;
    ClientStore::put(
        &*state.clients,
        "",
        ClientRecord {
            client_id: "never-used".into(),
            redirect_uris: vec!["https://never-used.example.com/cb".into()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (router, _) = build_router(state);

    // 列表。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/clients")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(j["total"], 2);
    let raw = serde_json::to_string(&j).unwrap();
    assert!(!raw.contains("SUPER-SECRET"), "列表不得泄露 client_secret");
    assert!(!raw.contains("HASHVALUE"), "列表不得泄露 reg_token_hash");
    // ClientView MUST NOT 含 client_secret / reg_token_hash 字段(检 JSON 键,非子串——
    // token_endpoint_auth_method 值 "client_secret_basic" 会误命中子串)。
    let c0 = j["clients"]
        .as_array()
        .unwrap()
        .iter()
        .find(|client| client["client_id"] == "conf-a")
        .expect("used client appears in Admin list GET");
    assert!(
        c0.get("client_secret").is_none(),
        "列表不得含 client_secret 键"
    );
    assert!(
        c0.get("reg_token_hash").is_none(),
        "列表不得含 reg_token_hash 键"
    );
    assert_eq!(
        c0["last_used_at"],
        20_000 * 86_400,
        "ClientView 应把天级桶换算成 UTC Unix 秒"
    );
    let never_used = j["clients"]
        .as_array()
        .unwrap()
        .iter()
        .find(|client| client["client_id"] == "never-used")
        .expect("never-used client appears in Admin list GET");
    assert_eq!(
        never_used["last_used_at"],
        serde_json::Value::Null,
        "Admin list GET 应把从未使用表示为 JSON null"
    );

    // 单个。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/clients/conf-a")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(j["client_id"], "conf-a");
    assert_eq!(j["last_used_at"], 20_000 * 86_400);
    let raw = serde_json::to_string(&j).unwrap();
    assert!(
        !raw.contains("SUPER-SECRET") && !raw.contains("HASHVALUE"),
        "单 client 不得泄露敏感字段"
    );

    let response = router
        .oneshot(
            Request::builder()
                .uri("/admin/clients/never-used")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_json(response).await["last_used_at"],
        serde_json::Value::Null,
        "Admin detail GET 应把从未使用表示为 JSON null"
    );
}

// get_client:不存在 → 404。
#[tokio::test]
async fn get_missing_client_404() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state);
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/admin/clients/nope")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// DELETE:级联吊销 refresh family + client 消失;重复删 → 404。
#[tokio::test]
async fn delete_cascades_refresh_and_is_idempotent_404() {
    let state = AppState::dev(HOST);
    state
        .seed_dev_client("app-del", "https://d.example.com/cb", None)
        .await;
    // 给该 client 建一个 refresh family。
    let _ = RefreshStore::create(
        &*state.refresh,
        "",
        RefreshFamilyRecord {
            family_id: "fam-1".into(),
            current_version: 0,
            revoked: false,
            client_id: "app-del".into(),
            cimd_snapshot: None,
            user_id: "u-1".into(),
            credential_epoch: 0,
            resources: vec![],
            scope: vec!["openid".into()],
            actor_allowlist: vec![],
            max_act_chain: 1,
            dpop_jkt: None,
            pkce_code_challenge: None,
            auth_time: None,
            acr: None,
            password_credential_version: None,
        },
    )
    .await;
    state
        .grants
        .put("", client_grant("grant-app-del", "u-1", "app-del"))
        .await
        .unwrap();
    let (router, _) = build_router(state.clone());

    let conflict = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/admin/clients/app-del")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("x-agent-auth-expected-authority-revision", "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert!(state
        .grants
        .get("", "grant-app-del")
        .await
        .unwrap()
        .is_some());

    // 删除 → 200。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/admin/clients/app-del")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("x-agent-auth-expected-authority-revision", "0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let delete_body = body_json(resp).await;
    assert_eq!(delete_body["deleted"], true);
    assert_eq!(delete_body["deleted_grants"], 1);
    assert_eq!(delete_body["refresh_families"], 1);

    // client 消失。
    assert!(
        ClientStore::get(&*state.clients, "", "app-del")
            .await
            .unwrap()
            .is_none(),
        "client 应已删除"
    );
    // refresh family 已吊销(级联)。
    let fam = RefreshStore::get(&*state.refresh, "", "fam-1")
        .await
        .unwrap()
        .unwrap();
    assert!(fam.revoked, "删除 client 应级联吊销其 refresh family");
    assert!(
        state
            .grants
            .get("", "grant-app-del")
            .await
            .unwrap()
            .is_none(),
        "删除 client 应物理级联删除其 Grant"
    );

    // 重复删 → 404(幂等)。
    let resp = router
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/admin/clients/app-del")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "重复删除应 404");
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 500)
        .await
        .unwrap();
    assert!(events.iter().any(|stored| {
        stored.event.action == "client.delete"
            && stored.event.outcome == SecurityEventOutcome::Success
            && stored.event.correlation.client_id.as_deref() == Some("app-del")
    }));
}

// PATCH:白名单字段更新;client_id/secret/introspect/resource_ids 不可改。
#[tokio::test]
async fn patch_whitelist_only() {
    let state = AppState::dev(HOST);
    let _ = ClientStore::put(
        &*state.clients,
        "",
        ClientRecord {
            client_id: "app-p".into(),
            redirect_uris: vec!["https://p.example.com/cb".into()],
            application_type: None,
            token_endpoint_auth_method: "none".into(),
            client_secret: None,
            client_secret_credentials: Default::default(),
            jwks: None,
            jwks_uri: Some("https://keys.example.com/client.jwks".into()),
            token_endpoint_auth_signing_alg: None,
            default_resource: None,
            introspect_enabled: false,
            resource_ids: vec!["should-stay".into()],
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
    let (router, _) = build_router(state.clone());

    // 尝试改 redirect_uris(白名单内;新增 uri 是放宽,带 confirm_downgrade)+ 偷改
    // introspect_enabled/resource_ids/client_id(白名单外,应被忽略)。
    let patch = serde_json::json!({
        "redirect_uris": ["https://p.example.com/cb", "https://p2.example.com/cb"],
        "confirm_downgrade": true,
        "introspect_enabled": true,
        "resource_ids": ["hacked"],
        "client_id": "evil"
    });
    let resp = router
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/admin/clients/app-p")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(patch.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let c = ClientStore::get(&*state.clients, "", "app-p")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(c.redirect_uris.len(), 2, "白名单字段 redirect_uris 应更新");
    assert!(
        !c.introspect_enabled,
        "introspect_enabled 不在白名单,不得被改"
    );
    assert_eq!(
        c.resource_ids,
        vec!["should-stay".to_string()],
        "resource_ids 不在白名单,不得被改"
    );
    assert_eq!(c.client_id, "app-p", "client_id 不可改");
}

// PATCH:auth_method 弱化(private_key_jwt→none)= 降级,未确认 → 400 downgrade_confirmation_required。
#[tokio::test]
async fn patch_downgrade_requires_confirmation() {
    let state = AppState::dev(HOST);
    let _ = ClientStore::put(
        &*state.clients,
        "",
        ClientRecord {
            client_id: "app-dg".into(),
            redirect_uris: vec!["https://dg.example.com/cb".into()],
            application_type: None,
            token_endpoint_auth_method: "private_key_jwt".into(),
            client_secret: None,
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
    let (router, _) = build_router(state.clone());

    // 未确认降级 → 400。
    let patch = serde_json::json!({ "token_endpoint_auth_method": "none" });
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/admin/clients/app-dg")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(patch.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let j = body_json(resp).await;
    assert_eq!(j["error"], "downgrade_confirmation_required");
    // 未确认时不得已落库。
    let c = ClientStore::get(&*state.clients, "", "app-dg")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        c.token_endpoint_auth_method, "private_key_jwt",
        "未确认降级不得落库"
    );

    // 带 confirm_downgrade=true → 200 + 落库。
    let patch =
        serde_json::json!({ "token_endpoint_auth_method": "none", "confirm_downgrade": true });
    let resp = router
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/admin/clients/app-dg")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(patch.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let c = ClientStore::get(&*state.clients, "", "app-dg")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(c.token_endpoint_auth_method, "none", "确认后降级应落库");
}

#[tokio::test]
async fn admin_dpop_downgrade_requires_confirmation() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state);

    let created = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("host", HOST)
                .header("content-type", "application/json")
                .header("x-forwarded-for", "203.0.113.47")
                .body(Body::from(
                    serde_json::json!({
                        "redirect_uris": ["https://dpop.example.com/callback"],
                        "token_endpoint_auth_method": "none",
                        "require_dpop": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = body_json(created).await;
    assert_eq!(created["require_dpop"], true);
    let client_id = created["client_id"].as_str().unwrap();

    let unconfirmed = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/clients/{client_id}"))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"require_dpop": false}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unconfirmed.status(), StatusCode::BAD_REQUEST);
    let unconfirmed = body_json(unconfirmed).await;
    assert_eq!(unconfirmed["error"], "downgrade_confirmation_required");
    assert_eq!(
        unconfirmed["downgraded_fields"],
        serde_json::json!(["require_dpop"])
    );

    let unchanged = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/admin/clients/{client_id}"))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unchanged.status(), StatusCode::OK);
    assert_eq!(body_json(unchanged).await["require_dpop"], true);

    let confirmed = router
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/clients/{client_id}"))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "require_dpop": false,
                        "confirm_downgrade": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(confirmed.status(), StatusCode::OK);
    assert_eq!(body_json(confirmed).await["require_dpop"], false);
}

#[tokio::test]
async fn rfc7592_dpop_patch_and_put_downgrades_require_confirmation() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state);

    let created = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("host", HOST)
                .header("content-type", "application/json")
                .header("x-forwarded-for", "203.0.113.48")
                .body(Body::from(
                    serde_json::json!({
                        "redirect_uris": ["https://rfc7592-dpop.example.com/callback"],
                        "token_endpoint_auth_method": "none",
                        "require_dpop": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = body_json(created).await;
    let client_id = created["client_id"].as_str().unwrap();
    let registration_token = created["registration_access_token"].as_str().unwrap();

    let unconfirmed_patch = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/register/{client_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {registration_token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"require_dpop": false}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unconfirmed_patch.status(), StatusCode::BAD_REQUEST);
    let unconfirmed_patch = body_json(unconfirmed_patch).await;
    assert_eq!(
        unconfirmed_patch["error"],
        "downgrade_confirmation_required"
    );
    assert_eq!(
        unconfirmed_patch["downgraded_fields"],
        serde_json::json!(["require_dpop"])
    );

    let unchanged_after_patch = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/register/{client_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {registration_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unchanged_after_patch.status(), StatusCode::OK);
    assert_eq!(body_json(unchanged_after_patch).await["require_dpop"], true);

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
                        "require_dpop": false,
                        "confirm_downgrade": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(confirmed_patch.status(), StatusCode::OK);
    assert_eq!(body_json(confirmed_patch).await["require_dpop"], false);

    let tightened_patch = router
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
    assert_eq!(tightened_patch.status(), StatusCode::OK);
    assert_eq!(body_json(tightened_patch).await["require_dpop"], true);

    let put_body = serde_json::json!({
        "redirect_uris": ["https://rfc7592-dpop.example.com/callback"],
        "token_endpoint_auth_method": "none"
    });
    let unconfirmed_put = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/register/{client_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {registration_token}"))
                .header("content-type", "application/json")
                .body(Body::from(put_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unconfirmed_put.status(), StatusCode::BAD_REQUEST);
    let unconfirmed_put = body_json(unconfirmed_put).await;
    assert_eq!(unconfirmed_put["error"], "downgrade_confirmation_required");
    assert_eq!(
        unconfirmed_put["downgraded_fields"],
        serde_json::json!(["require_dpop"])
    );

    let unchanged_after_put = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/register/{client_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {registration_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unchanged_after_put.status(), StatusCode::OK);
    assert_eq!(body_json(unchanged_after_put).await["require_dpop"], true);

    let confirmed_put = router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/register/{client_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {registration_token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "redirect_uris": ["https://rfc7592-dpop.example.com/callback"],
                        "token_endpoint_auth_method": "none",
                        "confirm_downgrade": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(confirmed_put.status(), StatusCode::OK);
    assert_eq!(body_json(confirmed_put).await["require_dpop"], false);
}

#[tokio::test]
async fn rfc7592_put_omitted_auth_method_requires_downgrade_confirmation() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state);

    let created = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("host", HOST)
                .header("content-type", "application/json")
                .header("x-forwarded-for", "203.0.113.49")
                .body(Body::from(
                    serde_json::json!({
                        "redirect_uris": ["https://rfc7592-auth.example.com/callback"],
                        "token_endpoint_auth_method": "client_secret_basic"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = body_json(created).await;
    let client_id = created["client_id"].as_str().unwrap();
    let registration_token = created["registration_access_token"].as_str().unwrap();

    let unconfirmed = router
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
                        "redirect_uris": ["https://rfc7592-auth.example.com/callback"]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unconfirmed.status(), StatusCode::BAD_REQUEST);
    let unconfirmed = body_json(unconfirmed).await;
    assert_eq!(unconfirmed["error"], "downgrade_confirmation_required");
    assert_eq!(
        unconfirmed["downgraded_fields"],
        serde_json::json!(["token_endpoint_auth_method"])
    );

    let unchanged = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/register/{client_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {registration_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unchanged.status(), StatusCode::OK);
    assert_eq!(
        body_json(unchanged).await["token_endpoint_auth_method"],
        "client_secret_basic"
    );

    let confirmed = router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/register/{client_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {registration_token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "redirect_uris": ["https://rfc7592-auth.example.com/callback"],
                        "confirm_downgrade": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(confirmed.status(), StatusCode::OK);
    assert_eq!(
        body_json(confirmed).await["token_endpoint_auth_method"],
        "none"
    );
}

// RFC 7592:注册取回 reg_token → 能管理自己;且**两域互不代替**。
#[tokio::test]
async fn rfc7592_self_service_and_domain_isolation() {
    let state = AppState::dev(HOST); // dcr_mode = Open
    let (router, _) = build_router(state.clone());

    // POST /register 注册 client A,拿 reg_token。
    let reg = serde_json::json!({ "redirect_uris": ["https://a.example.com/cb"] });
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("host", HOST)
                .header("content-type", "application/json")
                .body(Body::from(reg.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let a = body_json(resp).await;
    let a_id = a["client_id"].as_str().unwrap().to_string();
    let a_tok = a["registration_access_token"].as_str().unwrap().to_string();
    state
        .grants
        .put("", client_grant("grant-rfc7592", "alice", &a_id))
        .await
        .unwrap();

    // 注册 client B。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("host", HOST)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"redirect_uris":["https://b.example.com/cb"]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let b = body_json(resp).await;
    let b_id = b["client_id"].as_str().unwrap().to_string();
    let b_tok = b["registration_access_token"].as_str().unwrap().to_string();

    // A 用自己的 reg_token GET 自己 → 200。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/register/{a_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {a_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "A 用自己的 reg_token 应能读回自己"
    );

    for authorization in [None, Some("Bearer forged-registration-token")] {
        let mut request = Request::builder()
            .uri(format!("/register/{a_id}"))
            .header("host", HOST);
        if let Some(value) = authorization {
            request = request.header("authorization", value);
        }
        let resp = router
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "RFC 7592 management must reject missing and forged registration tokens"
        );
    }

    // ownership:A 的 reg_token 管 B → 401(哈希不匹配)。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/register/{b_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {a_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "A 的 reg_token 不得管理 B"
    );

    // 域隔离①:admin_token 不进 /register/{id}(reg_token 域)→ 401。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/register/{a_id}"))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "admin_token 不代替 reg_token"
    );

    // 域隔离②:reg_token 不进 /admin/*(admin 域)→ 401。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/clients")
                .header("host", HOST)
                .header("authorization", format!("Bearer {b_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "reg_token 不代替 admin_token"
    );

    // A 自助 PATCH 自己(白名单 redirect_uris;新增 uri 属放宽,带 confirm_downgrade)→ 200。
    let patch = serde_json::json!({
        "redirect_uris": ["https://a.example.com/cb", "https://a2.example.com/cb"],
        "confirm_downgrade": true
    });
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/register/{a_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {a_tok}"))
                .header("content-type", "application/json")
                .body(Body::from(patch.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "A 自助 PATCH 白名单字段应成功"
    );
    let patched = body_json(resp).await;
    assert!(
        patched.get("registration_access_token").is_none(),
        "PATCH MUST NOT return or rotate registration_access_token"
    );
    let c = ClientStore::get(&*state.clients, "", &a_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(c.redirect_uris.len(), 2);

    // C4.3 生命周期钉死:PATCH/PUT **不轮换** reg_token(spec 002 Task 2.2)——**原** reg_token
    // PATCH 后仍能 GET(否则客户端会因一次更新失去管理权)。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/register/{a_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {a_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PATCH 后原 reg_token MUST 仍有效(不轮换,C4.3 生命周期)"
    );

    // A 自助 DELETE 自己 → 204。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/register/{a_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {a_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "A 自助注销应 204");
    assert!(
        ClientStore::get(&*state.clients, "", &a_id)
            .await
            .unwrap()
            .is_none(),
        "注销后 client 消失"
    );
    assert!(
        state
            .grants
            .get("", "grant-rfc7592")
            .await
            .unwrap()
            .is_none(),
        "RFC 7592 注销应物理级联删除该 client 的 Grant"
    );

    // spec 025:用原 reg_token 再次 DELETE MUST 返 404(不存在,非 401)。
    let resp = router
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/register/{a_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {a_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "重复 DELETE 已注销 client 应 404(spec 025)"
    );
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 500)
        .await
        .unwrap();
    for action in ["client.create", "client.update", "client.delete"] {
        assert!(events.iter().any(|stored| {
            stored.event.action == action
                && stored.event.correlation.client_id.as_deref() == Some(a_id.as_str())
        }));
    }
    let registration_credential = events
        .iter()
        .find(|stored| {
            stored.event.action == "credential.registration_access_token.create"
                && stored.event.correlation.client_id.as_deref() == Some(a_id.as_str())
        })
        .expect("DCR registration token issuance must be audited");
    let serialized = serde_json::to_string(registration_credential).unwrap();
    assert!(!serialized.contains(&a_tok));
    assert!(!serialized.contains(&b_tok));
}

#[tokio::test]
async fn rfc7592_application_type_round_trips_through_get_patch_and_put() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());

    let created = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("host", HOST)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "application_type": "native",
                        "redirect_uris": ["com.example.app:/oauth2/callback"]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = body_json(created).await;
    assert_eq!(created["application_type"], "native");
    let client_id = created["client_id"].as_str().unwrap().to_string();
    let registration_token = created["registration_access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let get = router
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
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(body_json(get).await["application_type"], "native");

    let patched = router
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
                        "application_type": "web",
                        "redirect_uris": ["https://app.example.com/callback"],
                        "confirm_downgrade": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(patched.status(), StatusCode::OK);
    assert_eq!(body_json(patched).await["application_type"], "web");

    let get = router
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
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(body_json(get).await["application_type"], "web");

    let replaced = router
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
                        "application_type": "native",
                        "redirect_uris": ["com.example.app:/oauth2/replaced"],
                        "confirm_downgrade": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replaced.status(), StatusCode::OK);
    assert_eq!(body_json(replaced).await["application_type"], "native");

    let get = router
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
    assert_eq!(get.status(), StatusCode::OK);
    let get = body_json(get).await;
    assert_eq!(get["application_type"], "native");
    assert_eq!(
        get["redirect_uris"],
        serde_json::json!(["com.example.app:/oauth2/replaced"])
    );

    let defaulted = router
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
                        "redirect_uris": ["https://app.example.com/defaulted"],
                        "confirm_downgrade": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(defaulted.status(), StatusCode::OK);
    assert_eq!(body_json(defaulted).await["application_type"], "web");

    let get = router
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
    assert_eq!(get.status(), StatusCode::OK);
    let get = body_json(get).await;
    assert_eq!(get["application_type"], "web");
    assert_eq!(
        get["redirect_uris"],
        serde_json::json!(["https://app.example.com/defaulted"])
    );

    let stored = ClientStore::get(&*state.clients, "", &client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.application_type.as_deref(), Some("web"));
}

#[tokio::test]
async fn admin_legacy_and_unknown_application_type_view_and_update_as_web() {
    let state = AppState::dev(HOST);
    for (client_id, application_type) in [
        ("legacy-application-type-client", None),
        (
            "unknown-application-type-client",
            Some("desktop".to_string()),
        ),
    ] {
        ClientStore::put(
            state.clients.as_ref(),
            "",
            ClientRecord {
                client_id: client_id.to_string(),
                redirect_uris: vec!["https://app.example.com/original".to_string()],
                application_type,
                token_endpoint_auth_method: "none".to_string(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
    let (router, _) = build_router(state.clone());

    for client_id in [
        "legacy-application-type-client",
        "unknown-application-type-client",
    ] {
        let get = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/clients/{client_id}"))
                    .header("host", HOST)
                    .header("authorization", admin_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get.status(), StatusCode::OK);
        assert_eq!(body_json(get).await["application_type"], "web");

        let invalid = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/admin/clients/{client_id}"))
                    .header("host", HOST)
                    .header("authorization", admin_auth())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "redirect_uris": ["https://127.0.0.1/callback"]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            invalid.status(),
            StatusCode::BAD_REQUEST,
            "{client_id} must reject redirects forbidden by the web policy"
        );

        let updated = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/admin/clients/{client_id}"))
                    .header("host", HOST)
                    .header("authorization", admin_auth())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "redirect_uris": ["https://updated.example.com/callback"],
                            "confirm_downgrade": true
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(updated.status(), StatusCode::OK);
        let updated = body_json(updated).await;
        assert_eq!(updated["application_type"], "web");

        let stored = ClientStore::get(&*state.clients, "", client_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.application_type.as_deref(), Some("web"));
        assert_eq!(
            stored.redirect_uris,
            vec!["https://updated.example.com/callback".to_string()]
        );
    }
}

// POST /admin/clients:admin 超级权限注册(client_secret 仅此一次回显;可设 introspect_enabled)。
#[tokio::test]
async fn admin_create_client_echoes_secret_once() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());

    // client_secret_basic → 回 client_secret(仅此一次);设 introspect_enabled + resource_ids。
    let body = serde_json::json!({
        "redirect_uris": ["https://c.example.com/cb"],
        "token_endpoint_auth_method": "client_secret_basic",
        "require_dpop": true,
        "introspect_enabled": true,
        "resource_ids": ["https://mcp.example.com"]
    });
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/clients")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let j = body_json(resp).await;
    let cid = j["client_id"].as_str().unwrap().to_string();
    let secret = j["client_secret"].as_str().unwrap().to_string();
    assert!(!secret.is_empty(), "client_secret_basic 应回显 secret");
    assert_eq!(j["application_type"], "web");
    assert_eq!(j["require_dpop"], true);
    assert_eq!(j["introspect_enabled"], true, "admin 可授 introspect 权限");

    // 落库校验:只存不可逆 verifier、introspect_enabled=true;再 GET 不回 secret。
    let c = ClientStore::get(&*state.clients, "", &cid)
        .await
        .unwrap()
        .unwrap();
    assert!(c.client_secret.is_none(), "不得持久化明文 client_secret");
    assert!(c
        .client_secret_credentials
        .verify(
            &state.server_secret,
            agent_auth_http::credential::CredentialKind::ClientSecret,
            "",
            &secret,
            agent_auth_http::current_unix_secs(),
        )
        .is_some());
    assert!(c.introspect_enabled);
    assert!(c.require_dpop);
    assert_eq!(c.application_type.as_deref(), Some("web"));
    assert_eq!(c.resource_ids, vec!["https://mcp.example.com".to_string()]);
    let security_events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 500)
        .await
        .unwrap();
    assert!(security_events.iter().any(|stored| {
        stored.event.category == SecurityEventCategory::Administration
            && stored.event.action == "client.create"
            && stored.event.outcome == SecurityEventOutcome::Success
            && stored.event.correlation.client_id.as_deref() == Some(cid.as_str())
    }));
    let credential_event = security_events
        .iter()
        .find(|stored| stored.event.action == "admin.credential.create")
        .expect("client-secret issuance must emit a security event");
    assert_eq!(
        credential_event.event.category,
        SecurityEventCategory::KeySecret
    );
    assert_eq!(
        credential_event.event.outcome,
        SecurityEventOutcome::Success
    );
    assert_eq!(
        credential_event.event.correlation.client_id.as_deref(),
        Some(cid.as_str())
    );
    assert!(credential_event
        .event
        .correlation
        .credential_id
        .as_deref()
        .is_some_and(|id| id.starts_with("cred_")));
    assert!(
        !serde_json::to_string(credential_event)
            .unwrap()
            .contains(&secret),
        "security event must not contain the issued plaintext secret"
    );

    let resp = router
        .oneshot(
            Request::builder()
                .uri(format!("/admin/clients/{cid}"))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let j = body_json(resp).await;
    assert!(j.get("client_secret").is_none(), "GET 不得回 client_secret");

    // 匿名 POST → 401。
    let resp = router_no_state_check().await;
    assert_eq!(resp, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn saas_admin_client_create_uses_the_request_tenant_subject_profile() {
    use agent_auth_discovery::Form;
    use agent_auth_http::admin_credentials::{
        AdminCredentialOwner, AdminCredentialRecord, AdminCredentialResolver, AdminCredentialSet,
        MemoryAdminCredentialStore,
    };
    use agent_auth_http::SubjectType;
    use std::{
        collections::{BTreeMap, HashMap},
        sync::Arc,
        time::Duration,
    };

    const T1_TOKEN: &str = "t1-admin-secret-v1";
    const T3_TOKEN: &str = "t3-admin-secret-v1";

    let mut state = AppState::dev("t1.aws.example.com");
    state.form = Form::Saas {
        zone: "aws.example.com".into(),
        control_host: "c.aws.example.com".into(),
    };
    state.tenant_partitioning = true;
    state.saas_tenants = Arc::new(vec!["t1".into(), "t3".into()]);
    state.tenant_subject_types = Arc::new(BTreeMap::from([("t3".into(), SubjectType::Public)]));

    let now = agent_auth_http::current_unix_secs();
    let store = MemoryAdminCredentialStore::default();
    let platform_ref = "memory:platform";
    store.put_set(
        platform_ref,
        &AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            AdminCredentialRecord::explicit("platform-v1", ADMIN, now - 60, now - 60, now + 86_400),
        ),
        now,
    );
    let mut tenant_refs = HashMap::new();
    for (tenant, token) in [("t1", T1_TOKEN), ("t3", T3_TOKEN)] {
        let secret_ref = format!("memory:tenant:{tenant}");
        tenant_refs.insert(tenant.to_string(), secret_ref.clone());
        store.put_set(
            &secret_ref,
            &AdminCredentialSet::single(
                AdminCredentialOwner::tenant(tenant),
                AdminCredentialRecord::explicit(
                    format!("{tenant}-v1"),
                    token,
                    now - 60,
                    now - 60,
                    now + 86_400,
                ),
            ),
            now,
        );
    }
    state.admin_credentials = Arc::new(AdminCredentialResolver::memory(
        Some(platform_ref.to_string()),
        tenant_refs,
        store,
        Duration::ZERO,
    ));

    let (router, _) = build_router(state.clone());
    let payload = serde_json::json!({
        "redirect_uris": [
            "https://a.example.com/cb",
            "https://b.example.com/cb"
        ],
        "application_type": "web",
        "token_endpoint_auth_method": "none"
    });

    let pairwise = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/clients")
                .header("host", "t1.aws.example.com")
                .header("authorization", format!("Bearer {T1_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        pairwise.status(),
        StatusCode::BAD_REQUEST,
        "the pairwise tenant must reject ambiguous multi-host metadata"
    );
    assert_eq!(
        state.clients.list("t1").await.unwrap().len(),
        0,
        "a rejected pairwise client must not be persisted"
    );

    let public = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/clients")
                .header("host", "t3.aws.example.com")
                .header("authorization", format!("Bearer {T3_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        public.status(),
        StatusCode::CREATED,
        "the explicit public tenant must accept valid multi-host metadata"
    );
}

#[tokio::test]
async fn admin_application_type_update_revalidates_redirects() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());
    let body = serde_json::json!({
        "redirect_uris": ["com.example.app:/oauth2/callback"],
        "application_type": "native"
    });
    let created = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/clients")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = body_json(created).await;
    assert_eq!(created["application_type"], "native");
    let client_id = created["client_id"].as_str().unwrap();

    let invalid = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/clients/{client_id}"))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"application_type": "web"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

    let trailing_dot_localhost = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/clients/{client_id}"))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "application_type": "web",
                        "redirect_uris": ["https://app.localhost./callback"],
                        "confirm_downgrade": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(trailing_dot_localhost.status(), StatusCode::BAD_REQUEST);

    let unconfirmed = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/clients/{client_id}"))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "application_type": "web",
                        "redirect_uris": ["https://app.example.com/callback"]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unconfirmed.status(), StatusCode::BAD_REQUEST);
    let unconfirmed = body_json(unconfirmed).await;
    assert_eq!(unconfirmed["error"], "downgrade_confirmation_required");
    assert_eq!(
        unconfirmed["downgraded_fields"],
        serde_json::json!(["application_type", "redirect_uris"])
    );

    let valid = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/clients/{client_id}"))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "application_type": "web",
                        "redirect_uris": ["https://app.example.com/callback"],
                        "confirm_downgrade": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(valid.status(), StatusCode::OK);
    let valid = body_json(valid).await;
    assert_eq!(valid["application_type"], "web");
    let stored = ClientStore::get(&*state.clients, "", client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.application_type.as_deref(), Some("web"));
}

#[tokio::test]
async fn admin_and_rfc7592_share_redirect_prefix_policy_and_downgrade_guard() {
    let mut state = AppState::dev(HOST);
    state.redirect_prefix_allowed_hosts =
        std::sync::Arc::new(std::collections::BTreeMap::from([(
            "default".to_string(),
            std::collections::BTreeSet::from(["callbacks.example.com".to_string()]),
        )]));
    let (router, _) = build_router(state.clone());

    let admin_created = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/clients")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "redirect_uris": ["https://callbacks.example.com/admin/*"],
                        "application_type": "web",
                        "token_endpoint_auth_method": "client_secret_basic",
                        "redirect_mode": "prefix"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(admin_created.status(), StatusCode::CREATED);
    let admin_created = body_json(admin_created).await;
    assert_eq!(admin_created["redirect_mode"], "prefix");

    let rejected_host = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/clients")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "redirect_uris": ["https://other.example.com/admin/*"],
                        "application_type": "web",
                        "token_endpoint_auth_method": "client_secret_basic",
                        "redirect_mode": "prefix"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected_host.status(), StatusCode::BAD_REQUEST);

    let exact_admin = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/clients")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "redirect_uris": ["https://callbacks.example.com/admin/callback"],
                        "application_type": "web",
                        "token_endpoint_auth_method": "client_secret_basic"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(exact_admin.status(), StatusCode::CREATED);
    let exact_admin = body_json(exact_admin).await;
    let admin_client_id = exact_admin["client_id"].as_str().unwrap();

    let unconfirmed = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/clients/{admin_client_id}"))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "redirect_uris": ["https://callbacks.example.com/admin/*"],
                        "redirect_mode": "prefix"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unconfirmed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(unconfirmed).await["error"],
        "downgrade_confirmation_required"
    );

    let confirmed = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/clients/{admin_client_id}"))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "redirect_uris": ["https://callbacks.example.com/admin/*"],
                        "redirect_mode": "prefix",
                        "confirm_downgrade": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(confirmed.status(), StatusCode::OK);
    assert_eq!(body_json(confirmed).await["redirect_mode"], "prefix");

    let dcr_created = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("host", HOST)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "redirect_uris": ["https://callbacks.example.com/dcr/callback"],
                        "application_type": "web",
                        "token_endpoint_auth_method": "client_secret_basic"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dcr_created.status(), StatusCode::CREATED);
    let dcr_created = body_json(dcr_created).await;
    let dcr_client_id = dcr_created["client_id"].as_str().unwrap();
    let registration_token = dcr_created["registration_access_token"].as_str().unwrap();

    let rfc_unconfirmed = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/register/{dcr_client_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {registration_token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "redirect_uris": ["https://callbacks.example.com/dcr/*"],
                        "redirect_mode": "prefix"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rfc_unconfirmed.status(), StatusCode::BAD_REQUEST);

    let rfc_confirmed = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/register/{dcr_client_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {registration_token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "redirect_uris": ["https://callbacks.example.com/dcr/*"],
                        "redirect_mode": "prefix",
                        "confirm_downgrade": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rfc_confirmed.status(), StatusCode::OK);
    assert_eq!(body_json(rfc_confirmed).await["redirect_mode"], "prefix");

    let rfc_rejected_host = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/register/{dcr_client_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {registration_token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "redirect_uris": ["https://other.example.com/dcr/*"],
                        "redirect_mode": "prefix",
                        "confirm_downgrade": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rfc_rejected_host.status(), StatusCode::BAD_REQUEST);

    let put_rejected_host = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/register/{dcr_client_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {registration_token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "redirect_uris": ["https://other.example.com/dcr/*"],
                        "application_type": "web",
                        "token_endpoint_auth_method": "client_secret_basic",
                        "redirect_mode": "prefix",
                        "confirm_downgrade": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_rejected_host.status(), StatusCode::BAD_REQUEST);

    let put_allowed = router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/register/{dcr_client_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {registration_token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "redirect_uris": ["https://callbacks.example.com/dcr/*"],
                        "application_type": "web",
                        "token_endpoint_auth_method": "client_secret_basic",
                        "redirect_mode": "prefix",
                        "confirm_downgrade": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_allowed.status(), StatusCode::OK);
    assert_eq!(body_json(put_allowed).await["redirect_mode"], "prefix");
}

// 匿名 POST /admin/clients → 401(辅助)。
async fn router_no_state_check() -> StatusCode {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state);
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/clients")
                .header("host", HOST)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"redirect_uris":["https://x/cb"]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status()
}

// PUT /admin/clients/{id}:全量替换白名单;缺 redirect_uris → 400;降级需确认。
#[tokio::test]
async fn admin_put_client_full_replace() {
    let state = AppState::dev(HOST);
    let _ = ClientStore::put(
        &*state.clients,
        "",
        ClientRecord {
            client_id: "app-put".into(),
            redirect_uris: vec![
                "https://put.example.com/cb".into(),
                "https://old.example.com/cb".into(),
            ],
            application_type: None,
            token_endpoint_auth_method: "none".into(),
            client_secret: None,
            client_secret_credentials: Default::default(),
            jwks: None,
            jwks_uri: None,
            token_endpoint_auth_signing_alg: None,
            default_resource: Some("https://res.example.com".into()),
            introspect_enabled: false,
            resource_ids: vec![],
            post_logout_redirect_uris: vec!["https://put.example.com/after".into()],
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
    let (router, _) = build_router(state.clone());

    // 全替换为更窄的 redirect 集合(收窄不算降级)+ 清空 default_resource + post_logout。
    let put = serde_json::json!({
        "redirect_uris": ["https://put.example.com/cb"],
        "post_logout_redirect_uris": []
    });
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/admin/clients/app-put")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(put.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let c = ClientStore::get(&*state.clients, "", "app-put")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        c.redirect_uris,
        vec!["https://put.example.com/cb".to_string()],
        "全替换收窄 redirect"
    );
    assert_eq!(
        c.default_resource, None,
        "PUT 未带 default_resource → 清空(全替换语义)"
    );
    assert!(
        c.post_logout_redirect_uris.is_empty(),
        "PUT 空 post_logout → 清空"
    );
    assert!(
        c.jwks.is_none() && c.jwks_uri.is_none(),
        "PUT 未带 key metadata → 清空(全替换语义)"
    );
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 500)
        .await
        .unwrap();
    assert!(events.iter().any(|stored| {
        stored.event.action == "client.update"
            && stored.event.correlation.client_id.as_deref() == Some("app-put")
            && stored.event.outcome == SecurityEventOutcome::Success
    }));

    // 缺 redirect_uris(空)→ 400。
    let put = serde_json::json!({ "redirect_uris": [] });
    let resp = router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/admin/clients/app-put")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(put.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "PUT 空 redirect_uris 应 400"
    );
}

// 评审 M3:PATCH 把 auth_method 从 none 切到 client_secret_basic → 铸造并回显 secret 一次(防 brick)。
#[tokio::test]
async fn patch_auth_method_switch_mints_secret() {
    let state = AppState::dev(HOST);
    state
        .seed_dev_client("app-sw", "https://sw.example.com/cb", None)
        .await; // none, 无 secret
    let (router, _) = build_router(state.clone());

    // none → client_secret_basic(升级,不算降级)→ 应回显新 secret。
    let patch = serde_json::json!({ "token_endpoint_auth_method": "client_secret_basic" });
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/admin/clients/app-sw")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(patch.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    let secret = j["client_secret"]
        .as_str()
        .expect("切入 client_secret_* 应回显新 secret");
    assert!(!secret.is_empty());
    // 落库:只存 verifier + auth_method 更新。
    let c = ClientStore::get(&*state.clients, "", "app-sw")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(c.token_endpoint_auth_method, "client_secret_basic");
    assert!(c.client_secret.is_none());
    assert!(c
        .client_secret_credentials
        .verify(
            &state.server_secret,
            agent_auth_http::credential::CredentialKind::ClientSecret,
            "",
            secret,
            agent_auth_http::current_unix_secs(),
        )
        .is_some());

    // 反向:client_secret_basic → none(降级,需确认)→ 清空 secret,不回显。
    let patch =
        serde_json::json!({ "token_endpoint_auth_method": "none", "confirm_downgrade": true });
    let resp = router
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/admin/clients/app-sw")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(patch.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert!(j.get("client_secret").is_none(), "切到 none 不回显 secret");
    let c = ClientStore::get(&*state.clients, "", "app-sw")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(c.client_secret, None, "切到 none 应清空 secret");
    assert!(c.client_secret_credentials.current.is_none());
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    let secret_updates = events
        .iter()
        .filter(|stored| {
            stored.event.category == SecurityEventCategory::KeySecret
                && stored.event.action == "credential.client_secret.update"
                && stored.event.outcome == SecurityEventOutcome::Success
                && stored.event.correlation.client_id.as_deref() == Some("app-sw")
        })
        .count();
    assert_eq!(
        secret_updates, 2,
        "secret creation and clearing must both remain typed key/secret events"
    );
}

// 评审 M3:未知 token_endpoint_auth_method → 400(白名单校验)。
#[tokio::test]
async fn patch_unknown_auth_method_rejected() {
    let state = AppState::dev(HOST);
    state
        .seed_dev_client("app-uk", "https://uk.example.com/cb", None)
        .await;
    let (router, _) = build_router(state);
    let patch = serde_json::json!({ "token_endpoint_auth_method": "magic" });
    let resp = router
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/admin/clients/app-uk")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(patch.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "未知认证方式应 400");
}

// 评审 L4:PATCH 用空串清空 default_resource。
#[tokio::test]
async fn patch_clears_default_resource_with_empty_string() {
    let state = AppState::dev(HOST);
    state
        .seed_dev_client(
            "app-dr",
            "https://dr.example.com/cb",
            Some("https://res.example.com"),
        )
        .await;
    let (router, _) = build_router(state.clone());
    let patch = serde_json::json!({ "default_resource": "" });
    let resp = router
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/admin/clients/app-dr")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(patch.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let c = ClientStore::get(&*state.clients, "", "app-dr")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(c.default_resource, None, "空串 default_resource 应清空");
}

// 评审 L2:Authorization scheme 大小写不敏感(`bearer <token>` 应放行)。
#[tokio::test]
async fn admin_auth_scheme_case_insensitive() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state);
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/admin/overview")
                .header("host", HOST)
                .header("authorization", format!("bearer {ADMIN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "小写 bearer scheme 应放行(RFC 7235)"
    );
}

// 评审 M2:DELETE 时 revoke_by_client 失败 → 503 且 client 不删(fail-closed)。
// (内存 store 不会失败;此处以真机 AWS 适配器覆盖为主,这里断言正常路径级联已在
//  delete_cascades_refresh_and_is_idempotent_404 覆盖;M2 的失败分支靠代码审查 + AWS e2e。)

// RFC 7592:无 reg_token_hash 的内建 client(seed)不可被自助管理(fail-closed)。
#[tokio::test]
async fn rfc7592_builtin_client_not_self_manageable() {
    let state = AppState::dev(HOST);
    state
        .seed_dev_client("builtin", "https://x.example.com/cb", None)
        .await; // reg_token_hash = None
    let (router, _) = build_router(state);

    // 任意 Bearer(甚至 admin_token)→ 401,因该 client 无 reg_token_hash。
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/register/builtin")
                .header("host", HOST)
                .header("authorization", "Bearer anything")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "无 reg_token_hash 的 client 不可自助管理"
    );
}

// spec 003 §4 Task 4.7:联邦 IdP 注册管理面(admin 认证 + fail-closed 校验 + tenant 守卫 + 不回显 secret_ref)。
#[tokio::test]
async fn federation_idp_admin_register_list_delete() {
    let state = AppState::dev(HOST); // SelfHosted;dev platform credential = ADMIN
    let (router, _) = build_router(state.clone());

    let put = |body: serde_json::Value, auth: Option<&'static str>| {
        let router = router.clone();
        async move {
            let mut b = Request::builder()
                .method("PUT")
                .uri("/admin/federation")
                .header("host", HOST)
                .header("content-type", "application/json");
            if let Some(a) = auth {
                b = b.header("authorization", a);
            }
            router
                .oneshot(
                    b.body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap()
        }
    };

    let ok_body = serde_json::json!({
        "tenant_id": "default",
        "upstream_idp_id": "okta",
        "upstream_issuer": "https://okta.example.com",
        "client_id": "as-rp",
        "client_secret_ref": "secretsmanager:fed/okta",
        "authorization_endpoint": "https://okta.example.com/authorize",
        "token_endpoint": "https://okta.example.com/token",
        "jwks_uri": "https://okta.example.com/jwks",
        "scopes": ["openid", "profile"],
        "strong_acr_values": ["urn:okta:loa:2fa"]
    });

    // 无 admin token → 401(不留匿名可达面)。
    assert_eq!(
        put(ok_body.clone(), None).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // 合法 → 201。
    assert_eq!(
        put(
            ok_body.clone(),
            Some(Box::leak(admin_auth().into_boxed_str()))
        )
        .await
        .status(),
        StatusCode::CREATED
    );

    // SelfHosted tenant 守卫(F8):tenant != "default" → 403。
    let mut wrong_tenant = ok_body.clone();
    wrong_tenant["tenant_id"] = serde_json::json!("t-other");
    assert_eq!(
        put(wrong_tenant, Some(Box::leak(admin_auth().into_boxed_str())))
            .await
            .status(),
        StatusCode::FORBIDDEN,
        "SelfHosted 非 default tenant 应拒(防永不命中静默陷阱)"
    );

    // SSRF 防线:http 内网元数据 endpoint → 400(validate 拒非 https)。
    let mut ssrf = ok_body.clone();
    ssrf["token_endpoint"] = serde_json::json!("http://169.254.169.254/latest/meta-data");
    assert_eq!(
        put(ssrf, Some(Box::leak(admin_auth().into_boxed_str())))
            .await
            .status(),
        StatusCode::BAD_REQUEST,
        "非 https endpoint 应拒(SSRF 防线)"
    );

    // GET 列表 → 200 + 含刚登记的 okta,且**不回显 client_secret_ref**。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/federation/default")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(j["total"], 1);
    assert_eq!(j["idps"][0]["upstream_idp_id"], "okta");
    assert_eq!(j["idps"][0]["client_id"], "as-rp");
    assert_eq!(
        j["idps"][0]["strong_acr_values"],
        serde_json::json!(["urn:okta:loa:2fa"])
    );
    let raw = j.to_string();
    assert!(
        !raw.contains("secretsmanager:fed/okta") && !raw.contains("client_secret_ref"),
        "列表 MUST NOT 回显 secret 引用名:{raw}"
    );

    // DELETE 复合键 → 200;再列表 → 空。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/admin/federation/default/okta")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/admin/federation/default")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_json(resp).await["total"], 0, "删后列表空");
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    for action in [
        "secret.federation_idp.configure",
        "secret.federation_idp.delete",
    ] {
        let event = events
            .iter()
            .find(|stored| stored.event.action == action)
            .unwrap_or_else(|| panic!("missing {action} security event"));
        assert_eq!(event.event.category, SecurityEventCategory::KeySecret);
        assert_eq!(event.event.outcome, SecurityEventOutcome::Success);
        assert_eq!(event.event.subject, SecuritySubject::issuer("okta"));
        assert!(
            !serde_json::to_string(event)
                .unwrap()
                .contains("secretsmanager:fed/okta"),
            "secret reference names must not enter the event envelope"
        );
    }
}
