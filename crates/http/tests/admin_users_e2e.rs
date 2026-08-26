//! 进程内 e2e:admin 本地 email 用户管理面(spec 003 §1.4,类 Cognito User Pool)。
//!
//! 覆盖(§1.4-au4):
//! - create 幂等(重复 201 复用同 user_id)+ tombstone 后同 email create → 409;
//! - list 分页(limit=1 逐页翻,合法 cursor 翻页)+ 非法 cursor → 400(非 500);
//! - get 聚合计数(不泄露敏感)+ 未认证 401;
//! - magic-link 登录复用同 user_id(create 预建 → 登录命中);
//! - **disable 即时挡 magic-link 登录**(require_active_user gate)+ 级联(会话吊销);
//! - enable 恢复登录;
//! - delete=tombstone → 同 email 再 magic-link 登录被拒(不复活);
//! - SaaS(Form::Saas)下 /admin/users* → 404。

use std::{collections::HashMap, sync::Arc, time::Duration};

use agent_auth_http::{
    admin_credentials::{
        AdminCredentialOwner, AdminCredentialRecord, AdminCredentialResolver, AdminCredentialSet,
        MemoryAdminCredentialStore,
    },
    build_router, current_unix_secs,
    ports::{MessageOutbox, PasswordStore, UsersStore},
    security_event::{SecurityEventOutcome, SecurityEventStore},
    state::UsersStoreImpl,
    AppState,
};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

const HOST: &str = "localhost";
const ADMIN: &str = "dev-admin-token-not-for-prod";
const INITIAL_PASSWORD: &str = "Initial password 123!";
const ACTIVE_PASSWORD: &str = "Active password 456!";

fn admin_auth() -> String {
    format!("Bearer {ADMIN}")
}

fn saas_admin_credentials(tokens: &[(&str, &str)]) -> Arc<AdminCredentialResolver> {
    let now = current_unix_secs();
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
    for (tenant, token) in tokens {
        let secret_ref = format!("memory:tenant:{tenant}");
        tenant_refs.insert((*tenant).to_string(), secret_ref.clone());
        store.put_set(
            secret_ref,
            &AdminCredentialSet::single(
                AdminCredentialOwner::tenant(*tenant),
                AdminCredentialRecord::explicit(
                    format!("{tenant}-v1"),
                    *token,
                    now - 60,
                    now - 60,
                    now + 86_400,
                ),
            ),
            now,
        );
    }
    Arc::new(AdminCredentialResolver::memory(
        Some(platform_ref.to_string()),
        tenant_refs,
        store,
        Duration::ZERO,
    ))
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
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

// POST /admin/users {email};返回 (status, json)。
async fn create_user(router: &axum::Router, email: &str) -> (StatusCode, Value) {
    let body = serde_json::json!({
        "email": email,
        "initial_password": INITIAL_PASSWORD,
    });
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let st = resp.status();
    (st, body_json(resp).await)
}

async fn activate_password(router: &axum::Router, email: &str) {
    let body = serde_json::json!({
        "email": email,
        "current_password": INITIAL_PASSWORD,
        "new_password": ACTIVE_PASSWORD,
    });
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login/password/change")
                .header("host", HOST)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "首次改密应成功");
}

struct MagicLinkObservation {
    status: StatusCode,
    content_type: String,
    body: Value,
    callback_url: url::Url,
    nonce: String,
}

async fn observe_link_request(router: &axum::Router, email: &str) -> MagicLinkObservation {
    let body = serde_json::json!({ "email": email });
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
    let status = resp.status();
    let content_type = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let nonce = set_cookie_val(&resp, "__Host-agent_auth_login_nonce").expect("nonce cookie");
    let body = body_json(resp).await;
    let dev_link = body["dev_link"].as_str().expect("dev_link");
    let callback_url = url::Url::parse(dev_link).expect("absolute dev_link");
    MagicLinkObservation {
        status,
        content_type,
        body,
        callback_url,
        nonce,
    }
}

fn callback_public_shape(callback_url: &url::Url) -> (&str, Vec<String>) {
    (
        callback_url.path(),
        callback_url
            .query_pairs()
            .map(|(key, _)| key.into_owned())
            .collect(),
    )
}

fn callback_query_suffix(callback_url: &url::Url) -> String {
    format!("?{}", callback_url.query().expect("callback query"))
}

fn assert_same_magic_link_public_shape(
    ineligible: &MagicLinkObservation,
    eligible: &MagicLinkObservation,
) {
    assert_eq!(eligible.status, StatusCode::OK);
    assert_eq!(ineligible.status, eligible.status);
    assert_eq!(ineligible.content_type, eligible.content_type);
    assert_eq!(eligible.body["sent"], true);
    assert_eq!(ineligible.body["sent"], eligible.body["sent"]);
    let mut ineligible_keys = ineligible
        .body
        .as_object()
        .unwrap()
        .keys()
        .collect::<Vec<_>>();
    let mut eligible_keys = eligible
        .body
        .as_object()
        .unwrap()
        .keys()
        .collect::<Vec<_>>();
    ineligible_keys.sort();
    eligible_keys.sort();
    assert_eq!(ineligible_keys, eligible_keys);
    let eligible_callback_shape = callback_public_shape(&eligible.callback_url);
    assert_eq!(
        eligible_callback_shape,
        (
            "/login/callback",
            vec!["link_id".to_string(), "tag".to_string()]
        )
    );
    assert_eq!(
        callback_public_shape(&ineligible.callback_url),
        eligible_callback_shape
    );
}

// 请求 magic-link(dev 回显 link),返回 (callback_path_q, nonce_cookie)。
// **per-email 冷却 60s**:同一 email 一个测试内只请求一次(否则 429);故分离 request/callback,
// 使"link 在 Active 时签发、状态变更后再兑现"的威胁模型可精确复现(gate 在 callback 侧)。
async fn request_link(router: &axum::Router, email: &str) -> (String, String) {
    let observation = observe_link_request(router, email).await;
    assert_eq!(observation.status, StatusCode::OK, "magic-link 请求应 200");
    (
        callback_query_suffix(&observation.callback_url),
        observation.nonce,
    )
}

// 打开 magic-link callback(同浏览器,带 nonce cookie)。返回 (status, Option<session_cookie>)。
async fn open_callback(
    router: &axum::Router,
    path_q: &str,
    nonce: &str,
) -> (StatusCode, Option<String>) {
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
    let st = resp.status();
    let session = set_cookie_val(&resp, "__Host-agent_auth_session");
    (st, session)
}

// 便利:请求 + 打开(仅用于每 email 首次登录,不触发冷却)。
async fn magic_login(router: &axum::Router, email: &str) -> (StatusCode, Option<String>) {
    let (pq, nonce) = request_link(router, email).await;
    open_callback(router, &pq, &nonce).await
}

// GET /admin/users/{id} 的 JSON(带 admin auth)。
async fn get_user_json(router: &axum::Router, uid: &str) -> Value {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/admin/users/{uid}"))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    body_json(resp).await
}

async fn list_users(router: &axum::Router, query: &str) -> (StatusCode, Value) {
    let uri = if query.is_empty() {
        "/admin/users".to_string()
    } else {
        format!("/admin/users?{query}")
    };
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

fn listed_user_ids(body: &Value) -> Vec<&str> {
    body["users"]
        .as_array()
        .expect("users array")
        .iter()
        .map(|user| user["user_id"].as_str().expect("user_id"))
        .collect()
}

fn app() -> axum::Router {
    app_with_state().0
}

fn app_with_state() -> (axum::Router, AppState) {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());
    (router, state)
}

// 带 seed client 的 app(code-flow refresh gate 测试用)。
const CF_CLIENT: &str = "cf-client";
const CF_REDIRECT: &str = "https://cf-client.example.com/cb";

async fn app_with_client() -> axum::Router {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CF_CLIENT, CF_REDIRECT, None).await;
    let (r, _) = build_router(state);
    r
}

fn s256_challenge(verifier: &str) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(d)
}

fn query_param(url: &str, key: &str) -> Option<String> {
    url.split('?')
        .nth(1)?
        .split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")).map(|v| v.to_string()))
}

// ---- create 幂等 + tombstone 409 ----

#[tokio::test]
async fn create_is_idempotent_and_derives_stable_user_id() {
    let router = app();
    let (st, j) = create_user(&router, "Alice@Example.com").await;
    assert_eq!(st, StatusCode::CREATED);
    // 归一 email(小写)+ 派生 user_id。
    assert_eq!(j["email"], "alice@example.com");
    assert_eq!(j["user_id"], "user:alice@example.com");
    assert_eq!(j["status"], "active");
    assert_eq!(j["last_login_at"], Value::Null, "新用户应显示从未登录");

    let detail = get_user_json(&router, "user:alice@example.com").await;
    assert_eq!(
        detail["last_login_at"],
        Value::Null,
        "Admin detail GET 应把从未登录表示为 JSON null"
    );
    let list_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/users?limit=10")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let list = body_json(list_response).await;
    let listed = list["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|user| user["user_id"] == "user:alice@example.com")
        .expect("created user appears in Admin list GET");
    assert_eq!(
        listed["last_login_at"],
        Value::Null,
        "Admin list GET 应把从未登录表示为 JSON null"
    );

    // 重复 create(不同大小写)→ 幂等复用同 user_id + created_at 不变。
    let created_at = j["created_at"].as_i64().unwrap();
    let (st2, j2) = create_user(&router, "alice@example.com").await;
    assert_eq!(st2, StatusCode::CREATED);
    assert_eq!(j2["user_id"], "user:alice@example.com");
    assert_eq!(
        j2["created_at"].as_i64().unwrap(),
        created_at,
        "复用不覆盖 created_at"
    );
}

#[tokio::test]
async fn create_rejects_invalid_email() {
    let router = app();
    for bad in ["", "noat", "@x.com", "a@", "a@@b"] {
        let (st, _) = create_user(&router, bad).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "非法 email {bad:?} 应 400");
    }
}

// ---- 认证门 ----

#[tokio::test]
async fn unauthenticated_admin_users_rejected() {
    let router = app();
    // 无 admin token → 401(create/list/get/disable/delete 各一)。
    for (method, uri) in [
        ("POST", "/admin/users"),
        ("GET", "/admin/users"),
        ("GET", "/admin/users?status=unknown"),
        ("GET", "/admin/users/user:x@y.com"),
        ("POST", "/admin/users/user:x@y.com/disable"),
        ("POST", "/admin/users/user:x@y.com/enable"),
        ("POST", "/admin/users/user:x@y.com/reset-password"),
        ("DELETE", "/admin/users/user:x@y.com"),
    ] {
        let body = if uri == "/admin/users" {
            "{\"email\":\"x@y.com\",\"initial_password\":\"Initial password 123!\"}"
        } else if uri.ends_with("/reset-password") {
            "{\"temporary_password\":\"Reset password 456!\"}"
        } else {
            "{}"
        };
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("host", HOST)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri} 无 admin token 应 401"
        );
    }
}

// ---- list 分页 + 非法 cursor 400 ----

#[tokio::test]
async fn admin_user_status_filter_defaults_to_non_deleted_and_supports_explicit_views() {
    let router = app();
    for email in [
        "active@example.com",
        "disabled@example.com",
        "deleted@example.com",
    ] {
        assert_eq!(create_user(&router, email).await.0, StatusCode::CREATED);
    }
    assert_eq!(
        disable(&router, "user:disabled@example.com").await,
        StatusCode::OK
    );
    assert_eq!(
        delete(&router, "user:deleted@example.com").await,
        StatusCode::OK
    );

    for query in ["", "status=non_deleted"] {
        let (status, body) = list_users(&router, query).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            listed_user_ids(&body),
            vec!["user:active@example.com", "user:disabled@example.com",],
            "missing status and explicit non_deleted both hide tombstones"
        );
    }

    for (filter, expected) in [
        ("active", vec!["user:active@example.com"]),
        ("disabled", vec!["user:disabled@example.com"]),
        ("tombstoned", vec!["user:deleted@example.com"]),
        (
            "all",
            vec![
                "user:active@example.com",
                "user:deleted@example.com",
                "user:disabled@example.com",
            ],
        ),
    ] {
        let (status, body) = list_users(&router, &format!("status={filter}")).await;
        assert_eq!(status, StatusCode::OK, "status={filter}");
        assert_eq!(listed_user_ids(&body), expected, "status={filter}");
    }

    let (status, _) = list_users(&router, "status=unknown").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_user_status_filter_composes_with_search_and_paginates_after_tombstones() {
    let router = app();
    for email in [
        "a-deleted@example.com",
        "b-active@example.com",
        "c-disabled@example.com",
    ] {
        assert_eq!(create_user(&router, email).await.0, StatusCode::CREATED);
    }
    assert_eq!(
        delete(&router, "user:a-deleted@example.com").await,
        StatusCode::OK
    );
    assert_eq!(
        disable(&router, "user:c-disabled@example.com").await,
        StatusCode::OK
    );

    let (status, first) = list_users(&router, "limit=1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        listed_user_ids(&first),
        vec!["user:b-active@example.com"],
        "the default page must skip the leading tombstone before filling limit=1"
    );
    let cursor = first["next_cursor"]
        .as_str()
        .expect("one non-deleted user remains")
        .to_string();

    let (status, second) = list_users(&router, &format!("limit=1&cursor={cursor}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        listed_user_ids(&second),
        vec!["user:c-disabled@example.com"]
    );
    assert!(second.get("next_cursor").is_none());

    let (status, searched) = list_users(&router, "status=disabled&q=ACTIVE%40EXAMPLE.COM").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        listed_user_ids(&searched).is_empty(),
        "search and lifecycle status must both match"
    );

    let (status, searched) = list_users(&router, "status=disabled&q=DISABLED%40EXAMPLE.COM").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        listed_user_ids(&searched),
        vec!["user:c-disabled@example.com"]
    );
}

#[tokio::test]
async fn c10_23_user_searches_complete_set_before_pagination_by_email_and_user_id() {
    let (router, state) = app_with_state();
    for e in ["a@x.com", "b@x.com", "c@x.com"] {
        let (st, _) = create_user(&router, e).await;
        assert_eq!(st, StatusCode::CREATED);
    }
    state
        .users
        .create_or_get_by_email(
            "",
            "zeta@example.net",
            "zz-scim-random-7f3",
            current_unix_secs(),
        )
        .await
        .unwrap();
    // limit=1 → 回 1 条 + next_cursor。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/users?limit=1")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(j["users"].as_array().unwrap().len(), 1, "limit=1 应回 1 条");
    assert_eq!(j["users"][0]["user_id"], "user:a@x.com");
    let cursor = j["next_cursor"]
        .as_str()
        .expect("有 next_cursor")
        .to_string();

    // 用 cursor 翻下一页。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/admin/users?limit=1&cursor={cursor}"))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "合法 cursor 应 200 翻页");

    // 非法/篡改 cursor → 400(非 500)。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/users?cursor=!!!not-base64!!!")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "非法 cursor 应 400(不当 500)"
    );

    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/users?limit=1&q=C%40X.COM")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let searched = body_json(resp).await;
    assert_eq!(searched["users"].as_array().unwrap().len(), 1);
    assert_eq!(
        searched["users"][0]["user_id"], "user:c@x.com",
        "搜索必须先覆盖完整用户集,再分页;目标用户不在未筛选第一页"
    );
    assert!(searched.get("next_cursor").is_none());

    for (query, field) in [
        ("ZETA%40EXAMPLE.NET", "email"),
        ("ZZ-SCIM-RANDOM-7F3", "user_id"),
    ] {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/users?limit=1&q={query}"))
                    .header("host", HOST)
                    .header("authorization", admin_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let searched = body_json(resp).await;
        assert_eq!(
            searched["users"].as_array().unwrap().len(),
            1,
            "{field} search must match before pagination"
        );
        assert_eq!(searched["users"][0]["user_id"], "zz-scim-random-7f3");
        assert!(
            searched.get("next_cursor").is_none(),
            "single {field} match must exhaust the filtered result set"
        );
    }

    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/users?q=bad%0Aquery")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ---- get 聚合(基本信息 + 计数,不泄露敏感)----

#[tokio::test]
async fn get_returns_aggregate_counts_without_secrets() {
    let router = app();
    create_user(&router, "get@x.com").await;
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/users/user:get@x.com")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(j["email"], "get@x.com");
    assert_eq!(j["status"], "active");
    // 新用户:计数全 0 / has_recovery=false。
    assert_eq!(j["active_grants"], 0);
    assert_eq!(j["passkeys"], 0);
    assert_eq!(j["sessions"], 0);
    assert_eq!(j["has_recovery"], false);
    // 不泄露敏感字段。
    let s = j.to_string();
    assert!(!s.contains("code_hash"), "不回恢复码哈希");
    assert!(!s.contains("session_id"), "不回 session id");

    // 不存在 → 404。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/users/user:nope@x.com")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---- 生命周期主链:预建 → 登录复用 → disable 挡登录 → enable 恢复 → delete 拒复活 ----

async fn disable(router: &axum::Router, uid: &str) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/users/{uid}/disable"))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

async fn enable(router: &axum::Router, uid: &str) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/users/{uid}/enable"))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

async fn delete(router: &axum::Router, uid: &str) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/users/{uid}"))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

// 主链之一:预建 → 登录复用同 user_id → disable(级联)→ enable 恢复。
// 每 email 只请求一次 magic-link(避冷却);disable/enable 的"挡登录/恢复"用**独立 email** 验证。
#[tokio::test]
async fn create_then_login_reuses_user_id_disable_enable() {
    let (router, state) = app_with_state();
    let email = "bob@example.com";
    let uid = "user:bob@example.com";

    // 预建。
    let (st, cj) = create_user(&router, email).await;
    assert_eq!(st, StatusCode::CREATED);
    assert_eq!(cj["user_id"], uid);
    activate_password(&router, email).await;
    let last_login_before_magic = get_user_json(&router, uid).await["last_login_at"]
        .as_i64()
        .expect("password activation establishes the baseline session");
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // Active 登录成功(复用预建 user_id)。
    let (login_st, session) = magic_login(&router, email).await;
    assert_eq!(login_st, StatusCode::SEE_OTHER, "Active 用户应登录成功");
    let session = session.expect("登录应下发 session cookie");
    assert!(
        get_user_json(&router, uid).await["last_login_at"]
            .as_i64()
            .is_some_and(|timestamp| timestamp > last_login_before_magic),
        "magic-link 成功建立新会话后应推进最后登录时间"
    );

    // disable → 200 + 级联(会话吊销:该 session cookie 应失效)。
    assert_eq!(disable(&router, uid).await, StatusCode::OK);
    assert_eq!(get_user_json(&router, uid).await["status"], "disabled");

    // 级联断言:disable 前建的会话应被 delete_by_user 吊销 → consent/context 会话鉴权 401。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/consent/context?client_id=x&redirect_uri=x&scope=openid&state=s")
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "disable 级联应吊销既存会话(会话端点 401)"
    );

    // enable → 200 恢复 Active。
    assert_eq!(enable(&router, uid).await, StatusCode::OK);
    assert_eq!(get_user_json(&router, uid).await["status"], "active");
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 500)
        .await
        .unwrap();
    for action in ["user.create", "user.disable", "user.enable"] {
        assert!(events.iter().any(|stored| {
            stored.event.action == action && stored.event.outcome == SecurityEventOutcome::Success
        }));
    }
}

#[tokio::test]
async fn last_login_observation_failure_does_not_break_magic_link_session() {
    let (router, state) = app_with_state();
    let email = "observation-failure@example.com";
    let uid = "user:observation-failure@example.com";

    let (status, _) = create_user(&router, email).await;
    assert_eq!(status, StatusCode::CREATED);
    activate_password(&router, email).await;
    let last_login_before_failure = get_user_json(&router, uid).await["last_login_at"].clone();
    assert!(
        last_login_before_failure.as_i64().is_some(),
        "password activation establishes the baseline session"
    );

    match state.users.as_ref() {
        UsersStoreImpl::Memory(store) => store.fail_next_touch_last_login(),
        #[allow(unreachable_patterns)]
        _ => panic!("dev state must use the memory users store"),
    }

    let (login_status, session) = magic_login(&router, email).await;
    assert_eq!(
        login_status,
        StatusCode::SEE_OTHER,
        "best-effort activity observation must not reverse successful authentication"
    );
    assert!(
        session.is_some(),
        "successful authentication must still issue a session cookie"
    );
    assert_eq!(
        get_user_json(&router, uid).await["last_login_at"],
        last_login_before_failure,
        "the injected observation write must leave the prior timestamp unchanged"
    );
}

// 评审 codex Blocker:tombstone 不可变——delete 后 disable/enable 不得复活。
#[tokio::test]
async fn tombstone_is_immutable_no_revival_via_disable_enable() {
    let (router, state) = app_with_state();
    let email = "erin@example.com";
    let uid = "user:erin@example.com";
    create_user(&router, email).await;

    // delete = tombstone。
    assert_eq!(delete(&router, uid).await, StatusCode::OK);
    assert_eq!(get_user_json(&router, uid).await["status"], "tombstoned");

    // disable 已 tombstone 的用户 → 409(不可把 Tombstoned 覆盖成 Disabled)。
    assert_eq!(
        disable(&router, uid).await,
        StatusCode::CONFLICT,
        "tombstone 后 disable 应 409(不可变)"
    );
    // status 仍是 tombstoned(未被覆盖)。
    assert_eq!(get_user_json(&router, uid).await["status"], "tombstoned");

    // enable 仍 → 409(墓碑不可 enable)。
    assert_eq!(enable(&router, uid).await, StatusCode::CONFLICT);
    // status 仍 tombstoned。
    assert_eq!(get_user_json(&router, uid).await["status"], "tombstoned");

    // 再 magic-link 请求返回等形假链接;callback 无真实记录 → 400,且不复活。
    let (pq, nonce) = request_link(&router, email).await;
    let (st, session) = open_callback(&router, &pq, &nonce).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "tombstone 后假链接不可兑现");
    assert!(session.is_none());
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 500)
        .await
        .unwrap();
    assert!(events.iter().any(|stored| {
        stored.event.action == "user.delete"
            && stored.event.outcome == SecurityEventOutcome::Success
    }));
    assert!(events.iter().any(|stored| {
        stored.event.action == "authentication.magic_link"
            && stored.event.outcome == SecurityEventOutcome::Denied
    }));
}

// disable 即时挡 magic-link 登录:link 在 Active 时签发,disable 后再兑现 callback → 403(gate)。
#[tokio::test]
async fn disable_blocks_pending_magic_link_at_callback() {
    let (router, state) = app_with_state();
    let email = "carol@example.com";
    let uid = "user:carol@example.com";
    create_user(&router, email).await;
    activate_password(&router, email).await;
    let last_login_before_denial = get_user_json(&router, uid).await["last_login_at"].clone();

    // Active 时请求 link(拿到未兑现的 callback)。
    let (pq, nonce) = request_link(&router, email).await;

    // 兑现前 disable。
    assert_eq!(disable(&router, uid).await, StatusCode::OK);

    // 现在打开 callback → require_active_user 查到 Disabled → 403,不建会话。
    let (st, session) = open_callback(&router, &pq, &nonce).await;
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "Disabled 用户兑现 pending magic-link 应被 gate 拒(403)"
    );
    assert!(session.is_none(), "被拒不应下发 session cookie");
    assert_eq!(
        get_user_json(&router, uid).await["last_login_at"],
        last_login_before_denial,
        "被禁用后的 magic-link callback 未建立会话,不得推进最后登录时间"
    );

    let disabled_email = "disabled-before-magic-link@example.com";
    let disabled_uid = "user:disabled-before-magic-link@example.com";
    create_user(&router, disabled_email).await;
    activate_password(&router, disabled_email).await;
    let activated_credential = state
        .passwords
        .get("", disabled_uid)
        .await
        .unwrap()
        .expect("password activation must persist the credential");
    assert!(
        !activated_credential.must_change && !activated_credential.revocation_pending,
        "the no-send assertion must start from a fully activated credential"
    );
    assert_eq!(disable(&router, disabled_uid).await, StatusCode::OK);

    let eligible_email = "eligible-disabled-comparator@example.com";
    create_user(&router, eligible_email).await;
    activate_password(&router, eligible_email).await;
    let messages_before = state.messages.list_recent("", 50).await.unwrap().len();
    let fake = observe_link_request(&router, disabled_email).await;
    assert_eq!(
        state.messages.list_recent("", 50).await.unwrap().len(),
        messages_before,
        "Disabled 用户的通用成功响应不得产生发信副作用"
    );
    let eligible = observe_link_request(&router, eligible_email).await;
    assert_eq!(
        state.messages.list_recent("", 50).await.unwrap().len(),
        messages_before + 1,
        "eligible Active 用户必须形成真实发信对照"
    );
    assert_same_magic_link_public_shape(&fake, &eligible);
    let (status, session) = open_callback(
        &router,
        &callback_query_suffix(&fake.callback_url),
        &fake.nonce,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(session.is_none());
}

// delete=tombstone:同 email 再登录被拒(不复活)+ create 409 + enable 409。
#[tokio::test]
async fn delete_tombstones_and_blocks_revival() {
    let (router, state) = app_with_state();
    let email = "dave@example.com";
    let uid = "user:dave@example.com";
    create_user(&router, email).await;
    activate_password(&router, email).await;

    // Active 时请求 link。
    let (pq, nonce) = request_link(&router, email).await;

    // delete = tombstone(幂等:再 delete 仍 200)。
    assert_eq!(delete(&router, uid).await, StatusCode::OK);
    assert_eq!(delete(&router, uid).await, StatusCode::OK, "delete 幂等");
    assert_eq!(get_user_json(&router, uid).await["status"], "tombstoned");

    // 兑现 pending link → 拒(不复活 Active)。
    let (st, session) = open_callback(&router, &pq, &nonce).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "Tombstoned 用户登录应拒(不复活)");
    assert!(session.is_none());

    // 同 email create → 409(须显式 restore)。
    let (st, _) = create_user(&router, email).await;
    assert_eq!(
        st,
        StatusCode::CONFLICT,
        "tombstone 后 create 同 email → 409"
    );

    // tombstone 不可 enable → 409。
    assert_eq!(enable(&router, uid).await, StatusCode::CONFLICT);

    let tombstoned_email = "tombstoned-before-magic-link@example.com";
    let tombstoned_uid = "user:tombstoned-before-magic-link@example.com";
    create_user(&router, tombstoned_email).await;
    activate_password(&router, tombstoned_email).await;
    assert_eq!(delete(&router, tombstoned_uid).await, StatusCode::OK);

    let eligible_email = "eligible-tombstone-comparator@example.com";
    create_user(&router, eligible_email).await;
    activate_password(&router, eligible_email).await;
    let messages_before = state.messages.list_recent("", 50).await.unwrap().len();
    let fake = observe_link_request(&router, tombstoned_email).await;
    assert_eq!(
        state.messages.list_recent("", 50).await.unwrap().len(),
        messages_before,
        "Tombstoned 用户的通用成功响应不得产生发信副作用"
    );
    let eligible = observe_link_request(&router, eligible_email).await;
    assert_eq!(
        state.messages.list_recent("", 50).await.unwrap().len(),
        messages_before + 1,
        "eligible Active 用户必须形成真实发信对照"
    );
    assert_same_magic_link_public_shape(&fake, &eligible);
    let (status, session) = open_callback(
        &router,
        &callback_query_suffix(&fake.callback_url),
        &fake.nonce,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(session.is_none());
    assert_eq!(
        get_user_json(&router, tombstoned_uid).await["status"],
        "tombstoned"
    );
}

// ---- SaaS gate 绑数据面分区(P0-D):分区**关**时 /admin/users* → 404 ----

#[tokio::test]
async fn saas_without_partitioning_disables_admin_users() {
    let mut state = AppState::dev(HOST);
    // SaaS 形态 + tenant_partitioning **关**(灰度过渡:子域已切、分区未开)。
    // 此时 tpk 透传 → 所有租户共享物理分区,放行 user 管理会跨租户越权 → gate 仍 404。
    state.form = agent_auth_discovery::Form::Saas {
        zone: "aws.example.com".to_string(),
        control_host: "c.aws.example.com".to_string(),
    };
    state.saas_tenants = std::sync::Arc::new(vec!["t1".to_string()]);
    state.tenant_partitioning = false;
    let (router, _) = build_router(state);

    for (method, uri) in [
        ("POST", "/admin/users"),
        ("GET", "/admin/users"),
        ("GET", "/admin/users?status=unknown"),
        ("GET", "/admin/users/user:x@y.com"),
        ("POST", "/admin/users/user:x@y.com/disable"),
        ("POST", "/admin/users/user:x@y.com/enable"),
        ("POST", "/admin/users/user:x@y.com/reset-password"),
        ("DELETE", "/admin/users/user:x@y.com"),
    ] {
        let body = if uri == "/admin/users" {
            "{\"email\":\"x@y.com\",\"initial_password\":\"Initial password 123!\"}"
        } else if uri.ends_with("/reset-password") {
            "{\"temporary_password\":\"Reset password 456!\"}"
        } else {
            "{}"
        };
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("host", "t1.aws.example.com")
                    .header("authorization", admin_auth())
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{method} {uri} SaaS+分区关 应 404"
        );
    }
}

// ---- P0-D:SaaS + tenant_partitioning **开** → user 管理放行 + 跨租户物理隔离 ----

fn saas_partitioned_app() -> axum::Router {
    let mut state = AppState::dev(HOST);
    state.form = agent_auth_discovery::Form::Saas {
        zone: "aws.example.com".to_string(),
        control_host: "c.aws.example.com".to_string(),
    };
    state.saas_tenants = std::sync::Arc::new(vec!["t1".to_string(), "t2".to_string()]);
    state.tenant_partitioning = true; // 数据面分区已就绪(020 §2.3 done)
    state.admin_credentials =
        saas_admin_credentials(&[("t1", "t1-admin-secret-v1"), ("t2", "t2-admin-secret-v1")]);
    let (r, _) = build_router(state);
    r
}

// 带 Host 的 admin 请求(SaaS 下 Host 决定 tenant)。
async fn admin_req(
    router: &axum::Router,
    method: &str,
    uri: &str,
    host: &str,
    body: Option<&str>,
) -> (StatusCode, Value) {
    let token = if host == "t1.aws.example.com" {
        "t1-admin-secret-v1"
    } else if host == "t2.aws.example.com" {
        "t2-admin-secret-v1"
    } else {
        "dev-admin-token-not-for-prod"
    };
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("host", host)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(
                    body.map(|b| Body::from(b.to_string()))
                        .unwrap_or(Body::empty()),
                )
                .unwrap(),
        )
        .await
        .unwrap();
    let st = resp.status();
    (st, body_json(resp).await)
}

// 带自定义 bearer + Host 的 admin 请求(逐租户 RBAC 测试用)→ http_code。
async fn admin_req_tok(router: &axum::Router, uri: &str, host: &str, token: &str) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("host", host)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

// H(SaaS 审计):逐租户 admin RBAC——per-tenant token 只能管自己租户,换 Host 到他租户即拒。
// 消除"单一全局 admin_token 换 Host 管任意租户"爆炸半径。
#[tokio::test]
async fn saas_per_tenant_admin_rbac() {
    let mut state = AppState::dev(HOST);
    state.form = agent_auth_discovery::Form::Saas {
        zone: "aws.example.com".to_string(),
        control_host: "c.aws.example.com".to_string(),
    };
    state.saas_tenants = std::sync::Arc::new(vec!["t1".to_string(), "t2".to_string()]);
    state.tenant_partitioning = true;
    state.admin_credentials =
        saas_admin_credentials(&[("t1", "t1-admin-secret-v1"), ("t2", "t2-admin-secret-v1")]);
    let (router, _) = build_router(state);
    let t1 = "t1.aws.example.com";
    let t2 = "t2.aws.example.com";

    // t1 admin token 在 t1 Host → 放行(200)。
    assert_eq!(
        admin_req_tok(&router, "/admin/users", t1, "t1-admin-secret-v1").await,
        StatusCode::OK,
        "t1 admin 在自己租户应放行"
    );
    // 🔴 t1 admin token 换到 t2 Host → 拒(401):tenant 派生为 t2,不匹配 t2 条目。
    assert_eq!(
        admin_req_tok(&router, "/admin/users", t2, "t1-admin-secret-v1").await,
        StatusCode::UNAUTHORIZED,
        "t1 admin token 换 Host 到 t2 MUST 拒(逐租户 RBAC 核心:消除跨租户爆炸半径)"
    );
    // t2 admin token 在 t2 Host → 放行。
    assert_eq!(
        admin_req_tok(&router, "/admin/users", t2, "t2-admin-secret-v1").await,
        StatusCode::OK,
        "t2 admin 在自己租户应放行"
    );
    // 平台超级 token(此配置下已关)在任意租户都拒。
    assert_eq!(
        admin_req_tok(&router, "/admin/users", t1, "dev-admin-token-not-for-prod").await,
        StatusCode::UNAUTHORIZED,
        "关掉平台超级 token 后旧超级 token MUST 拒"
    );
}

// 2026-07-20 增量:平台控制 token 不再兼任任一租户 admin。
#[tokio::test]
async fn saas_platform_token_rejected_by_tenant_admin_apis() {
    let mut state = AppState::dev(HOST);
    state.form = agent_auth_discovery::Form::Saas {
        zone: "aws.example.com".to_string(),
        control_host: "c.aws.example.com".to_string(),
    };
    state.saas_tenants = std::sync::Arc::new(vec!["t1".to_string(), "t2".to_string()]);
    state.tenant_partitioning = true;
    state.admin_credentials =
        saas_admin_credentials(&[("t1", "t1-admin-secret-v1"), ("t2", "t2-admin-secret-v1")]);
    let (router, _) = build_router(state);
    // 平台 token 在 t1/t2 租户 API 都拒,避免成为共享租户密码。
    for host in ["t1.aws.example.com", "t2.aws.example.com"] {
        assert_eq!(
            admin_req_tok(
                &router,
                "/admin/users",
                host,
                "dev-admin-token-not-for-prod"
            )
            .await,
            StatusCode::UNAUTHORIZED,
            "平台 token 不得访问租户 admin API ({host})"
        );
    }
    // t1 的逐租户 token 仍不能管 t2。
    assert_eq!(
        admin_req_tok(
            &router,
            "/admin/users",
            "t2.aws.example.com",
            "t1-admin-secret-v1"
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "逐租户 token 不越租户(即便平台超级 token 并存)"
    );
}

#[tokio::test]
async fn saas_partitioned_allows_user_mgmt_and_isolates_tenants() {
    let router = saas_partitioned_app();
    let t1 = "t1.aws.example.com";
    let t2 = "t2.aws.example.com";

    // t1 建用户 → 放行(200/201),不再 404。
    let (st, _) = admin_req(
        &router,
        "POST",
        "/admin/users",
        t1,
        Some("{\"email\":\"alice@example.com\",\"initial_password\":\"Initial password 123!\"}"),
    )
    .await;
    assert!(
        st == StatusCode::OK || st == StatusCode::CREATED,
        "SaaS+分区开:t1 建用户应放行,got {st}"
    );

    // t1 列表见到该用户;t2(**同一 admin token,不同 Host**)列表**看不到** t1 的用户(跨租户隔离)。
    let (st1, j1) = admin_req(&router, "GET", "/admin/users", t1, None).await;
    assert_eq!(st1, StatusCode::OK);
    assert_eq!(
        j1["users"].as_array().unwrap().len(),
        1,
        "t1 见到自己的用户"
    );
    let (st2, j2) = admin_req(&router, "GET", "/admin/users", t2, None).await;
    assert_eq!(st2, StatusCode::OK);
    assert_eq!(
        j2["users"].as_array().unwrap().len(),
        0,
        "t2 MUST NOT 见到 t1 的用户(同 admin token 跨 Host 隔离,C10.19)"
    );

    // t2 用同 email 建 → 独立记录(email 跨租户是不同用户)。
    let (st, _) = admin_req(
        &router,
        "POST",
        "/admin/users",
        t2,
        Some("{\"email\":\"alice@example.com\",\"initial_password\":\"Initial password 123!\"}"),
    )
    .await;
    assert!(st == StatusCode::OK || st == StatusCode::CREATED);
    let (_, j2b) = admin_req(&router, "GET", "/admin/users", t2, None).await;
    assert_eq!(
        j2b["users"].as_array().unwrap().len(),
        1,
        "t2 现有自己的 alice"
    );

    // t2 GET t1 独有用户 → 404(跨租户不可读)。用只有 t1 建过的 email 隔离验证。
    let (_, _) = admin_req(
        &router,
        "POST",
        "/admin/users",
        t1,
        Some("{\"email\":\"t1only@example.com\",\"initial_password\":\"Initial password 123!\"}"),
    )
    .await;
    let (st_cross, _) = admin_req(
        &router,
        "GET",
        "/admin/users/user:t1only@example.com",
        t2,
        None,
    )
    .await;
    assert_eq!(
        st_cross,
        StatusCode::NOT_FOUND,
        "t2 GET t1 独有用户应 404(跨租户隔离)"
    );
}

// M2(评审 Kiro-M2):disable/delete 跨租户隔离——t1 对同名 user 的 disable/delete 绝不误伤 t2 的同名 user。
#[tokio::test]
async fn saas_disable_delete_isolated_across_tenants() {
    let router = saas_partitioned_app();
    let t1 = "t1.aws.example.com";
    let t2 = "t2.aws.example.com";
    let uid = "user:carol@example.com";
    // 两租户各建同 email 用户(email 跨租户是不同用户)。
    for h in [t1, t2] {
        let (st, _) = admin_req(
            &router,
            "POST",
            "/admin/users",
            h,
            Some(
                "{\"email\":\"carol@example.com\",\"initial_password\":\"Initial password 123!\"}",
            ),
        )
        .await;
        assert!(st == StatusCode::OK || st == StatusCode::CREATED);
    }
    // t1 disable carol → 只影响 t1;t2 的 carol 仍 Active。
    let (st, _) = admin_req(
        &router,
        "POST",
        &format!("/admin/users/{uid}/disable"),
        t1,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (_, jt1) = admin_req(&router, "GET", &format!("/admin/users/{uid}"), t1, None).await;
    assert_eq!(jt1["status"], "disabled", "t1 carol 已禁用");
    let (_, jt2) = admin_req(&router, "GET", &format!("/admin/users/{uid}"), t2, None).await;
    assert_eq!(
        jt2["status"], "active",
        "t2 同名 carol MUST 不受 t1 disable 影响"
    );
    // t1 delete carol → t2 的 carol 仍在(未被跨租户级联删)。
    let (st, _) = admin_req(&router, "DELETE", &format!("/admin/users/{uid}"), t1, None).await;
    assert_eq!(st, StatusCode::OK);
    let (st_t2, jt2b) = admin_req(&router, "GET", &format!("/admin/users/{uid}"), t2, None).await;
    assert_eq!(
        st_t2,
        StatusCode::OK,
        "t2 carol 仍可读(未被 t1 delete 波及)"
    );
    assert_eq!(jt2b["status"], "active", "t2 carol 仍 active");
}

// M2:控制面 Host / 派生失败 Host 访问 /admin/users(flag 开)→ 400(tenant_or_400 fail-closed)。
#[tokio::test]
async fn saas_control_plane_host_rejected_for_admin_users() {
    let router = saas_partitioned_app();
    // 控制面 Host 不接受平台 token 进入租户管理 API → 401。
    let (st, _) = admin_req(&router, "GET", "/admin/users", "c.aws.example.com", None).await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "控制面 Host 访问租户 /admin/users 应 401"
    );
}

// H1(评审 codex#1 + Kiro-H1):SaaS 分区**关**(灰度态)时 /admin/messages 与 /admin/overview 恒 404
// ——否则 tenant="" 使所有租户消息落同一分区,list 会跨租户泄露 magic-link URL / PII。
#[tokio::test]
async fn saas_without_partitioning_disables_messages_and_overview() {
    let mut state = AppState::dev(HOST);
    state.form = agent_auth_discovery::Form::Saas {
        zone: "aws.example.com".to_string(),
        control_host: "c.aws.example.com".to_string(),
    };
    state.saas_tenants = std::sync::Arc::new(vec!["t1".to_string()]);
    state.tenant_partitioning = false; // 灰度:子域切了、分区没开
    let (router, _) = build_router(state);
    for uri in ["/admin/messages", "/admin/overview"] {
        let (st, _) = admin_req(&router, "GET", uri, "t1.aws.example.com", None).await;
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
            "{uri} SaaS+分区关 应 404(防跨租户泄露)"
        );
    }
}

// #5(评审 codex#5):属性 API 恒 SelfHosted-only——分区就绪的 SaaS 也 404(不随 user gate 放宽)。
#[tokio::test]
async fn saas_partitioned_still_disables_attributes_api() {
    let router = saas_partitioned_app();
    let (st, _) = admin_req(
        &router,
        "PUT",
        "/admin/users/user:x@y.com/attributes?namespace=https%3A%2F%2Frs.example.com%2F",
        "t1.aws.example.com",
        Some("{\"role\":\"admin\"}"),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::NOT_FOUND,
        "SaaS(分区开)属性 API 仍应 404(spec 007 C8.12 SelfHosted-only)"
    );
}

// ---- refresh_token 入口 gate(评审 codex High #2):disable 后续期被拒 ----
//
// 走 code flow 拿到 refresh_token(login_user=本地 email 用户,使 user_id=`user:{email}` 受 gate 管辖)→
// 首次 refresh 成功 → admin disable → 再 refresh **被 gate 拒**(独立于级联 family.revoked 的第二道闸)。
#[tokio::test]
async fn refresh_token_rejected_after_disable() {
    let router = app_with_client().await;
    let email = "frank@example.com";
    let uid = "user:frank@example.com";
    // 预建并完成首次改密。login_user 用完整 user_id 形态,令 authorize 占位路径产出受 gate 的
    // user_id；临时凭证本身必须被 password gate 拒绝 refresh。
    create_user(&router, email).await;
    activate_password(&router, email).await;

    // 1. code flow:authorize(login_user=user:frank@example.com,scope 含 offline_access 拿 refresh)。
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let login_user = "user:frank@example.com";
    let authz = format!(
        "/authorize?response_type=code&client_id={CF_CLIENT}&redirect_uri={CF_REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid%20offline_access&login_user={login_user}"
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
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "authorize 应回跳");
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    let code = query_param(loc, "code").expect("回跳带 code");

    // 2. token 兑换(code → access + refresh)。
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={CF_REDIRECT}&client_id={CF_CLIENT}"
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
    assert_eq!(resp.status(), StatusCode::OK, "token 兑换应 200");
    let tok = body_json(resp).await;
    let refresh = tok["refresh_token"]
        .as_str()
        .expect("应含 refresh_token(offline_access)")
        .to_string();

    // 3. 首次 refresh(Active)→ 成功。
    let do_refresh = |rt: String| {
        let router = router.clone();
        async move {
            router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/token")
                        .header("host", HOST)
                        .header("content-type", "application/x-www-form-urlencoded")
                        .body(Body::from(format!(
                            "grant_type=refresh_token&refresh_token={rt}&client_id={CF_CLIENT}"
                        )))
                        .unwrap(),
                )
                .await
                .unwrap()
        }
    };
    let resp = do_refresh(refresh.clone()).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "Active 用户首次 refresh 应成功"
    );
    let tok2 = body_json(resp).await;
    let refresh2 = tok2["refresh_token"]
        .as_str()
        .unwrap_or(&refresh)
        .to_string();

    // 4. admin disable。
    assert_eq!(disable(&router, uid).await, StatusCode::OK);

    // 5. 再 refresh → gate 拒(invalid_grant / 400)。既覆盖级联 family.revoked,也覆盖独立 gate。
    let resp = do_refresh(refresh2).await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "Disabled 用户 refresh 应被拒(gate + 级联双闸)"
    );
}
