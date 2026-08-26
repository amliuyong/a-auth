//! 进程内 e2e:授权会话状态机(spec 004,C6)。内存适配器,无 AWS。
//!
//! 覆盖:code flow 建会话→code_issued→complete;confidential GET /sessions?client_id=me 发现 +
//! 按 id 查询;只凭 id 裸查拒(404);session_token(Bearer)鉴权;归属不符 404;exchange_failed 态。

use agent_auth_authn::authz_session::AuthzState;
use agent_auth_client::s256_challenge;
use agent_auth_http::ports::{
    AuthzSessionStore, ClientRecord, ClientStore, CodeStore, LeaseAcquire,
};
use agent_auth_http::state::CodeStoreImpl;
use agent_auth_http::{build_router, AppState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tower::ServiceExt;

const HOST: &str = "localhost";
const CLIENT: &str = "sess-client";
const REDIRECT: &str = "https://app.example.com/cb";
const VERIFIER: &str = "0123456789012345678901234567890123456789abc";

fn basic(id: &str, sec: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{id}:{sec}")))
}

async fn register_basic_client(state: &AppState) {
    ClientStore::put(
        &*state.clients,
        "",
        ClientRecord {
            client_id: CLIENT.into(),
            redirect_uris: vec![REDIRECT.into()],
            application_type: None,
            token_endpoint_auth_method: "client_secret_basic".into(),
            client_secret: Some("sekret".into()),
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

// magic-link 登录建 AS 会话,返回 __Host-agent_auth_session cookie 值。
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

// 走 authorize(占位)→ 拿 code(此路径已建授权会话并推进到 code_issued)。
async fn authorize_get_code(router: &axum::Router) -> String {
    let ch = s256_challenge(VERIFIER);
    let uri = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={ch}&code_challenge_method=S256&scope=openid&state=s&login_user=alice"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&uri)
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
    loc.split('?')
        .nth(1)
        .unwrap()
        .split('&')
        .find_map(|kv| kv.strip_prefix("code="))
        .unwrap()
        .to_string()
}

async fn get_status(
    router: &axum::Router,
    uri: &str,
    auth: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut b = Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", HOST);
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    let resp = router
        .clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let st = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        st,
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
    )
}

async fn get_raw_status(
    router: &axum::Router,
    uri: &str,
    auth: Option<&str>,
) -> (StatusCode, Vec<u8>) {
    let mut request = Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", HOST);
    if let Some(auth) = auth {
        request = request.header("authorization", auth);
    }
    let response = router
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, body)
}

// 完整 code flow → 会话推进 created→...→code_issued→complete;confidential 可发现+查询。
#[tokio::test]
async fn code_flow_drives_session_to_complete_and_confidential_can_query() {
    let state = AppState::dev(HOST);
    // confidential owner client(client_secret_basic)。
    ClientStore::put(
        &*state.clients,
        "",
        ClientRecord {
            client_id: CLIENT.into(),
            redirect_uris: vec![REDIRECT.into()],
            application_type: None,
            token_endpoint_auth_method: "client_secret_basic".into(),
            client_secret: Some("sekret".into()),
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
    .await
    .unwrap();
    let (router, _) = build_router(state.clone());

    let code = authorize_get_code(&router).await;

    // 发现:confidential 凭 client 认证列自己名下会话。
    let (st, list) = get_status(
        &router,
        "/sessions?client_id=me",
        Some(&basic(CLIENT, "sekret")),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let ids = list["sessions"].as_array().unwrap();
    assert_eq!(ids.len(), 1, "一次 authorize 建一个授权会话");
    let sid = ids[0].as_str().unwrap().to_string();

    // 按 id 查(confidential owner 认证)→ code_issued_awaiting_exchange。
    let (st, view) = get_status(
        &router,
        &format!("/sessions/{sid}"),
        Some(&basic(CLIENT, "sekret")),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(view["state"], "code_issued_awaiting_exchange");

    // 兑换 code → complete。
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={VERIFIER}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("authorization", basic(CLIENT, "sekret"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "token 兑换应成功");

    let (_, view) = get_status(
        &router,
        &format!("/sessions/{sid}"),
        Some(&basic(CLIENT, "sekret")),
    )
    .await;
    assert_eq!(view["state"], "complete", "兑换成功后会话 complete");
}

// MEDIUM-4:client_secret_post 的 confidential client 也能凭 query 凭证发现自己名下会话。
#[tokio::test]
async fn client_secret_post_can_list_sessions() {
    let state = AppState::dev(HOST);
    ClientStore::put(
        &*state.clients,
        "",
        ClientRecord {
            client_id: CLIENT.into(),
            redirect_uris: vec![REDIRECT.into()],
            application_type: None,
            token_endpoint_auth_method: "client_secret_post".into(),
            client_secret: Some("postsecret".into()),
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
    .await
    .unwrap();
    let (router, _) = build_router(state);
    authorize_get_code(&router).await;
    // client_secret_post:凭证走 query(auth_client_id + client_secret),无 Basic 头。
    let (st, list) = get_status(
        &router,
        &format!("/sessions?client_id=me&auth_client_id={CLIENT}&client_secret=postsecret"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "client_secret_post 应能列会话");
    assert_eq!(list["sessions"].as_array().unwrap().len(), 1);
}

// C6.1:只凭 session_id 裸查(无 token、无 client 认证)→ 404。
#[tokio::test]
async fn bare_id_query_rejected() {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let (router, _) = build_router(state.clone());
    authorize_get_code(&router).await;
    // 直接从 store 取一个真实存在的 sid(seed 的是 public client,无法用 client 认证发现)。
    let ids = state
        .authz_sessions
        .list_by_client("", CLIENT)
        .await
        .unwrap();
    let sid = ids.first().cloned().unwrap();
    // 裸查(无鉴权)→ 404(不泄露存在)。
    let (st, _) = get_status(&router, &format!("/sessions/{sid}"), None).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "只凭 id 裸查 MUST 拒(C6.1)");
    // 随机不存在 id → 同样 404(枚举无信息增益)。
    let (st2, _) = get_status(&router, "/sessions/nonexistent-random-id", None).await;
    assert_eq!(st2, StatusCode::NOT_FOUND);
}

// C6.1:session_token(Bearer)鉴权可查(public 客户端路径的 fixture 验证)。
#[tokio::test]
async fn session_token_bearer_grants_query() {
    // 直接用纯逻辑建一个会话 + 已知 token,注入 store,验 Bearer 鉴权分支。
    use agent_auth_authn::authz_session::{session_token_hash, AuthzState};
    use agent_auth_http::ports::AuthzSessionRecord;
    let state = AppState::dev(HOST);
    let token = "fixture-session-token-ascii-high-entropy-abc123"; // 真实 token 是 base64url(ASCII)
    let rec = AuthzSessionRecord {
        session_id: "sess-1".into(),
        client_id: "pub-client".into(),
        user_id: None,
        state: AuthzState::CodeIssuedAwaitingExchange.as_str().into(),
        session_token_hash: session_token_hash(&state.server_secret, token),
        sequence: 3,
        last_error: None,
        expires_at: 99999999999,
    };
    state.authz_sessions.create("", rec).await.unwrap();
    let (router, _) = build_router(state);

    // 正确 token → 200。
    let (st, view) = get_status(
        &router,
        "/sessions/sess-1",
        Some(&format!("Bearer {token}")),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(view["state"], "code_issued_awaiting_exchange");
    // 错 token → 404(不泄露存在)。
    let (st2, _) = get_status(&router, "/sessions/sess-1", Some("Bearer wrong-token")).await;
    assert_eq!(st2, StatusCode::NOT_FOUND, "错 session_token MUST 统一 404");
}

#[tokio::test]
async fn expired_session_token_projects_expired_without_ttl_gc() {
    use agent_auth_authn::authz_session::{session_token_hash, AuthzState};
    use agent_auth_http::ports::AuthzSessionRecord;

    let state = AppState::dev(HOST);
    let token = "expired-session-token-ascii-high-entropy-abc123";
    state
        .authz_sessions
        .create(
            "",
            AuthzSessionRecord {
                session_id: "expired-session-token-record".into(),
                client_id: "pub-client".into(),
                user_id: None,
                state: AuthzState::PendingConsent.as_str().into(),
                session_token_hash: session_token_hash(&state.server_secret, token),
                sequence: 1,
                last_error: None,
                expires_at: 1,
            },
        )
        .await
        .unwrap();
    let router = build_router(state).0;

    let (status, view) = get_status(
        &router,
        "/sessions/expired-session-token-record",
        Some(&format!("Bearer {token}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["state"], "expired");
}

#[tokio::test]
async fn c6_2_all_session_misses_share_the_same_404_body() {
    use agent_auth_authn::authz_session::session_token_hash;
    use agent_auth_http::ports::AuthzSessionRecord;

    let state = AppState::dev(HOST);
    for id in ["owner-client", "other-client"] {
        ClientStore::put(
            &*state.clients,
            "",
            ClientRecord {
                client_id: id.into(),
                redirect_uris: vec![REDIRECT.into()],
                application_type: None,
                token_endpoint_auth_method: "client_secret_basic".into(),
                client_secret: Some("sekret".into()),
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
        .await
        .unwrap();
    }
    let session_id = "session-c6-2";
    let session_token = "known-session-token";
    state
        .authz_sessions
        .create(
            "",
            AuthzSessionRecord {
                session_id: session_id.into(),
                client_id: "owner-client".into(),
                user_id: None,
                state: AuthzState::CodeIssuedAwaitingExchange.as_str().into(),
                session_token_hash: session_token_hash(&state.server_secret, session_token),
                sequence: 1,
                last_error: None,
                expires_at: 99_999_999_999,
            },
        )
        .await
        .unwrap();
    let (router, _) = build_router(state);

    let non_owner_auth = basic("other-client", "sekret");
    let cases = [
        ("unknown-id", "/sessions/nonexistent-c6-2", None),
        ("bare-existing-id", "/sessions/session-c6-2", None),
        (
            "wrong-bearer",
            "/sessions/session-c6-2",
            Some("Bearer wrong-session-token"),
        ),
        (
            "authenticated-non-owner",
            "/sessions/session-c6-2",
            Some(non_owner_auth.as_str()),
        ),
    ];
    let mut expected_body = None;
    for (label, uri, auth) in cases {
        let (status, body) = get_raw_status(&router, uri, auth).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{label} must return 404");
        if let Some(expected) = expected_body.as_ref() {
            assert_eq!(&body, expected, "{label} must use the unified 404 body");
        } else {
            assert_eq!(body, b"not found");
            expected_body = Some(body);
        }
    }
}

// C6.1:confidential 认证但非 owner → 404(不泄露归属)。
#[tokio::test]
async fn non_owner_confidential_gets_404() {
    let state = AppState::dev(HOST);
    // owner + 另一个 confidential client(都能认证,但只有 owner 该看)。
    for (id, owner) in [(CLIENT, true), ("other-client", false)] {
        ClientStore::put(
            &*state.clients,
            "",
            ClientRecord {
                client_id: id.into(),
                redirect_uris: vec![REDIRECT.into()],
                application_type: None,
                token_endpoint_auth_method: "client_secret_basic".into(),
                client_secret: Some("sekret".into()),
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
        .await
        .unwrap();
        let _ = owner;
    }
    let (router, _) = build_router(state.clone());
    authorize_get_code(&router).await; // owner=CLIENT 建会话
    let sid = state
        .authz_sessions
        .list_by_client("", CLIENT)
        .await
        .unwrap()[0]
        .clone();

    // other-client 认证通过但非 owner → 404。
    let (st, _) = get_status(
        &router,
        &format!("/sessions/{sid}"),
        Some(&basic("other-client", "sekret")),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::NOT_FOUND,
        "非 owner confidential MUST 404(不泄露归属)"
    );
}

// H2/C6:pending_consent 在真实登录流可观测(authorize 受理即建会话);expired 读投影。
#[tokio::test]
async fn pending_and_expired_observable() {
    use agent_auth_authn::authz_session::AuthzState;
    use agent_auth_http::ports::AuthzSessionRecord;
    let state = AppState::dev(HOST);
    ClientStore::put(
        &*state.clients,
        "",
        ClientRecord {
            client_id: CLIENT.into(),
            redirect_uris: vec![REDIRECT.into()],
            application_type: None,
            token_endpoint_auth_method: "client_secret_basic".into(),
            client_secret: Some("sekret".into()),
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
    .await
    .unwrap();
    let (router, _) = build_router(state.clone());

    // 未带 login_user 的 authorize(未登录)→ 重定向 /login,且**受理时已建会话**(pending_user_authentication)。
    let ch = s256_challenge(VERIFIER);
    let uri = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={ch}&code_challenge_method=S256&scope=openid&state=s"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(loc.contains("/login?"), "未登录应去 /login");
    assert!(
        loc.contains("authz_session_id="),
        "重定向链应透传 authz_session_id(H2)"
    );

    // 会话已存在且为 pending_user_authentication(真实流的可观测态,非死代码)。
    let ids = state
        .authz_sessions
        .list_by_client("", CLIENT)
        .await
        .unwrap();
    assert_eq!(ids.len(), 1);
    let (_, view) = get_status(
        &router,
        &format!("/sessions/{}", ids[0]),
        Some(&basic(CLIENT, "sekret")),
    )
    .await;
    assert_eq!(
        view["state"], "pending_user_authentication",
        "authorize 受理即建 pending 态"
    );

    // expired 读投影:注入一条已过期的非终态会话,读时呈 expired(fail-closed,C10.4)。
    state
        .authz_sessions
        .create(
            "",
            AuthzSessionRecord {
                session_id: "expired-1".into(),
                client_id: CLIENT.into(),
                user_id: None,
                state: AuthzState::PendingConsent.as_str().into(),
                session_token_hash: "x".into(),
                sequence: 1,
                last_error: None,
                expires_at: 1, // 1970,早过期
            },
        )
        .await
        .unwrap();
    let (_, ev) = get_status(
        &router,
        "/sessions/expired-1",
        Some(&basic(CLIENT, "sekret")),
    )
    .await;
    assert_eq!(ev["state"], "expired", "过期非终态读时投影为 expired");
}

// C6:consent deny → 会话终态 denied(端到端,经 login→consent)。
#[tokio::test]
async fn consent_deny_marks_session_denied() {
    let state = AppState::dev(HOST);
    ClientStore::put(
        &*state.clients,
        "",
        ClientRecord {
            client_id: CLIENT.into(),
            redirect_uris: vec![REDIRECT.into()],
            application_type: None,
            token_endpoint_auth_method: "client_secret_basic".into(),
            client_secret: Some("sekret".into()),
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
    .await
    .unwrap();
    state.seed_dev_user("u@example.com").await;
    let (router, _) = build_router(state.clone());

    // 登录建 AS 会话 + 拿到透传了 authz_session_id 的 authorize_query。
    let aq = format!(
        "client_id={CLIENT}&redirect_uri={REDIRECT}&scope=openid&code_challenge={}&code_challenge_method=S256",
        s256_challenge(VERIFIER)
    );
    // 直接建授权会话(模拟 authorize 受理)。
    let (sid, _) = agent_auth_http::authz_session::create_session(
        &state,
        "",
        CLIENT,
        agent_auth_authn::authz_session::AuthzState::PendingConsent,
        agent_auth_http::current_unix_secs(),
    )
    .await
    .unwrap();
    let aq_full = format!("{aq}&authz_session_id={sid}");

    // 登录建会话 cookie。
    let session_cookie = login_session(&router, "u@example.com").await;
    // consent/context 取 csrf。
    let (_, ctx) = {
        let uri = format!("/consent/context?{aq_full}");
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
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
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            StatusCode::OK,
            serde_json::from_slice::<serde_json::Value>(&b).unwrap(),
        )
    };
    let csrf = ctx["csrf_token"].as_str().unwrap();

    // POST /consent deny。
    let body = serde_json::json!({ "decision": "deny", "csrf": csrf, "authorize_query": aq_full });
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
    assert_eq!(resp.status(), StatusCode::OK);

    // 会话终态 denied。
    let (_, view) = get_status(
        &router,
        &format!("/sessions/{sid}"),
        Some(&basic(CLIENT, "sekret")),
    )
    .await;
    assert_eq!(view["state"], "denied", "consent deny → 会话 denied");
}

// C6.3b:token 语义失败(redirect_uri 不匹配)→ 会话终态 exchange_failed + last_error。
#[tokio::test]
async fn exchange_failure_marks_session_exchange_failed() {
    let state = AppState::dev(HOST);
    register_basic_client(&state).await;
    let (router, _) = build_router(state.clone());
    let code = authorize_get_code(&router).await;
    let sid = state
        .authz_sessions
        .list_by_client("", CLIENT)
        .await
        .unwrap()[0]
        .clone();
    let before_sequence = state
        .authz_sessions
        .get("", &sid)
        .await
        .unwrap()
        .expect("authorization session before exchange failure")
        .sequence;

    // 兑换时用错 redirect_uri → 语义失败(invalid_grant)。
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={VERIFIER}\
         &redirect_uri=https://evil.example.com/cb&client_id={CLIENT}"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("authorization", basic(CLIENT, "sekret"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 会话终态 exchange_failed + last_error。
    let (_, view) = get_status(
        &router,
        &format!("/sessions/{sid}"),
        Some(&basic(CLIENT, "sekret")),
    )
    .await;
    assert_eq!(view["state"], "exchange_failed");
    assert_eq!(view["sequence"], before_sequence + 1);
    assert!(
        view["last_error"]["error"].is_string(),
        "带结构化 last_error"
    );
    assert_eq!(view["last_error"]["at"], "token_endpoint");

    // C6.3a:同 code 重放 → 拒(code 已消费)。
    let form2 = format!(
        "grant_type=authorization_code&code={code}&code_verifier={VERIFIER}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    let resp2 = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("authorization", basic(CLIENT, "sekret"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form2))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::BAD_REQUEST,
        "同 code 重放 MUST 拒(C6.3a)"
    );
}

#[tokio::test]
async fn exchange_failure_conflict_leaves_code_and_session_unchanged() {
    let state = AppState::dev(HOST);
    register_basic_client(&state).await;
    let (router, _) = build_router(state.clone());
    let code = authorize_get_code(&router).await;
    let sid = state
        .authz_sessions
        .list_by_client("", CLIENT)
        .await
        .unwrap()[0]
        .clone();
    let before = state
        .authz_sessions
        .transition(
            "",
            &sid,
            AuthzState::Complete.as_str(),
            None,
            agent_auth_http::current_unix_secs(),
        )
        .await
        .unwrap()
        .expect("test conflict transition");

    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={VERIFIER}\
         &redirect_uri=https://evil.example.com/cb&client_id={CLIENT}"
    );
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("authorization", basic(CLIENT, "sekret"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["error"], "temporarily_unavailable");

    let after = state
        .authz_sessions
        .get("", &sid)
        .await
        .unwrap()
        .expect("authorization session");
    assert_eq!(after, before, "failed commit must not rewrite the session");
    let retry_now = agent_auth_http::current_unix_secs() + 31;
    assert!(
        matches!(
            state
                .codes
                .acquire_lease("", &code, "retry-owner", retry_now, retry_now + 60)
                .await
                .unwrap(),
            LeaseAcquire::Acquired(_)
        ),
        "failed commit must leave the authorization code unconsumed"
    );
}

#[tokio::test]
async fn injected_exchange_failure_leaves_code_issued_session_retriable() {
    let state = AppState::dev(HOST);
    register_basic_client(&state).await;
    let (router, _) = build_router(state.clone());
    let code = authorize_get_code(&router).await;
    let sid = state
        .authz_sessions
        .list_by_client("", CLIENT)
        .await
        .unwrap()[0]
        .clone();
    let before = state
        .authz_sessions
        .get("", &sid)
        .await
        .unwrap()
        .expect("authorization session");
    match state.codes.as_ref() {
        CodeStoreImpl::Memory(store) => store.fail_next_exchange_failure(),
        #[cfg(feature = "aws")]
        CodeStoreImpl::Dynamo(_) => panic!("test requires memory code store"),
    }

    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={VERIFIER}\
         &redirect_uri=https://evil.example.com/cb&client_id={CLIENT}"
    );
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("authorization", basic(CLIENT, "sekret"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["error"], "temporarily_unavailable");

    let after = state
        .authz_sessions
        .get("", &sid)
        .await
        .unwrap()
        .expect("authorization session");
    assert_eq!(after, before, "failed commit must not rewrite the session");
    assert_eq!(after.state, AuthzState::CodeIssuedAwaitingExchange.as_str());
    let retry_now = agent_auth_http::current_unix_secs() + 31;
    assert!(
        matches!(
            state
                .codes
                .acquire_lease("", &code, "retry-owner", retry_now, retry_now + 60)
                .await
                .unwrap(),
            LeaseAcquire::Acquired(_)
        ),
        "failed commit must leave the authorization code unconsumed"
    );
}

#[tokio::test]
async fn concurrent_exchange_failures_never_leave_a_split_state() {
    let state = AppState::dev(HOST);
    register_basic_client(&state).await;
    let (router, _) = build_router(state.clone());
    let code = authorize_get_code(&router).await;
    let sid = state
        .authz_sessions
        .list_by_client("", CLIENT)
        .await
        .unwrap()[0]
        .clone();
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={VERIFIER}\
         &redirect_uri=https://evil.example.com/cb&client_id={CLIENT}"
    );
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/token")
            .header("host", HOST)
            .header("authorization", basic(CLIENT, "sekret"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form.clone()))
            .unwrap()
    };

    let (first, second) = tokio::join!(
        router.clone().oneshot(request()),
        router.clone().oneshot(request())
    );
    let statuses = [first.unwrap().status(), second.unwrap().status()];
    assert!(statuses.contains(&StatusCode::BAD_REQUEST));
    assert!(statuses.iter().all(|status| matches!(
        *status,
        StatusCode::BAD_REQUEST | StatusCode::SERVICE_UNAVAILABLE
    )));

    let session = state
        .authz_sessions
        .get("", &sid)
        .await
        .unwrap()
        .expect("authorization session");
    assert_eq!(session.state, AuthzState::ExchangeFailed.as_str());
    let retry_now = agent_auth_http::current_unix_secs() + 31;
    assert!(matches!(
        state
            .codes
            .acquire_lease("", &code, "third-owner", retry_now, retry_now + 60)
            .await
            .unwrap(),
        LeaseAcquire::AlreadyConsumed { .. }
    ));
}
