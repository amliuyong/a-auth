//! CORS 按端点五分类的进程内验收(C10.10 / spec 005 §6)。
//!
//! 验 build_router 的 CORS 分组:
//! - ①公开 GET(discovery/JWKS/PRM)、②协议 POST(token/revoke/introspect/device_authorization/
//!   bc-authorize)、③open 档 `/register` → `Access-Control-Allow-Origin: *`(不带浏览器 cookie,`*` 安全);
//! - ④会话端点(consent/grants/sessions/end-session/device 批准/bc-approve/admin/register 管理)+
//!   ⑤浏览器导航(authorize)→ **不发 CORS 头**(统一入口同源 + 防跨域 CSRF);
//! - **任何端点都不设 `Access-Control-Allow-Credentials: true`**(与 `*` 组合被浏览器禁止)。
//! - preflight `OPTIONS` 对 CORS 组回 2xx + Allow-Methods(tower-http CorsLayer 自动)。

use agent_auth_client::s256_challenge;
use agent_auth_http::{build_router, AppState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt; // oneshot

const HOST: &str = "localhost";
const CLIENT: &str = "cors-client";
const REDIRECT: &str = "https://app.example.com/cb";
const VERIFIER: &str = "0123456789012345678901234567890123456789abc";

async fn app() -> axum::Router {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state);
    router
}

async fn app_with_client() -> axum::Router {
    let state = AppState::dev(HOST);
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    let (router, _) = build_router(state);
    router
}

// 发一个带 Origin 的简单请求,返回 (status, allow_origin, allow_credentials)。
async fn req_with_origin(
    router: &axum::Router,
    method: &str,
    uri: &str,
    origin: &str,
) -> (StatusCode, Option<String>, Option<String>) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("host", HOST)
                .header("origin", origin)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let ao = resp
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let ac = resp
        .headers()
        .get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    (resp.status(), ao, ac)
}

// preflight OPTIONS:带 Access-Control-Request-Method,返回 (status, allow_origin, allow_methods)。
async fn preflight(
    router: &axum::Router,
    uri: &str,
    origin: &str,
    req_method: &str,
) -> (StatusCode, Option<String>, Option<String>, Option<String>) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri(uri)
                .header("host", HOST)
                .header("origin", origin)
                .header("access-control-request-method", req_method)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let ao = resp
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let am = resp
        .headers()
        .get("access-control-allow-methods")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let ac = resp
        .headers()
        .get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    (resp.status(), ao, am, ac)
}

async fn successful_token_response(
    router: &axum::Router,
    origin: &str,
) -> axum::response::Response {
    let challenge = s256_challenge(VERIFIER);
    let authorize = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
                     &scope=openid&state=cors&code_challenge={challenge}\
                     &code_challenge_method=S256&login_user=alice"
                ))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorize.status(), StatusCode::SEE_OTHER);
    let location = authorize
        .headers()
        .get("location")
        .expect("authorize redirect")
        .to_str()
        .unwrap();
    let code = url::Url::parse(location)
        .unwrap()
        .query_pairs()
        .find_map(|(key, value)| (key == "code").then(|| value.into_owned()))
        .expect("authorization code");

    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("origin", origin)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&code_verifier={VERIFIER}\
                     &redirect_uri={REDIRECT}&client_id={CLIENT}"
                )))
                .unwrap(),
        )
        .await
        .unwrap()
}

// ① 公开 GET:discovery / JWKS / PRM → Allow-Origin: *,无 Allow-Credentials。
#[tokio::test]
async fn public_get_endpoints_allow_any_origin() {
    let router = app().await;
    for uri in [
        "/openapi.json",
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/jwks.json",
    ] {
        let (st, ao, ac) = req_with_origin(&router, "GET", uri, "https://evil.example.com").await;
        assert_eq!(st, StatusCode::OK, "{uri} 应 200");
        assert_eq!(
            ao.as_deref(),
            Some("*"),
            "{uri} 应 Allow-Origin: *(公开 GET,C10.10①)"
        );
        assert_eq!(
            ac, None,
            "{uri} MUST NOT 设 Allow-Credentials(与 * 组合浏览器禁止)"
        );
    }
}

// ② 协议 POST:/token 等 → Allow-Origin: *(不带浏览器 cookie,`*` 安全,C10.10②)。
// 用 OPTIONS preflight 验(不实际触发业务逻辑,只看 CORS 头)。
#[tokio::test]
async fn protocol_post_endpoints_allow_any_origin_preflight() {
    let router = app().await;
    for uri in [
        "/token",
        "/revoke",
        "/introspect",
        "/device_authorization",
        "/bc-authorize",
    ] {
        let (st, ao, am, _ac) = preflight(&router, uri, "https://app.example.com", "POST").await;
        assert!(
            st.is_success(),
            "{uri} preflight 应 2xx(tower-http CorsLayer 自动),got {st}"
        );
        assert_eq!(
            ao.as_deref(),
            Some("*"),
            "{uri} preflight 应 Allow-Origin: *(协议 POST 不带 cookie,C10.10②)"
        );
        assert!(
            am.map(|m| m.contains("POST")).unwrap_or(false),
            "{uri} preflight 应回 Allow-Methods 含 POST"
        );
    }
}

// ③ open 档 `POST /register` → Allow-Origin: *(dev state = DcrMode::Open)。
#[tokio::test]
async fn open_register_allows_any_origin() {
    let router = app().await;
    let (st, ao, _am, _ac) =
        preflight(&router, "/register", "https://app.example.com", "POST").await;
    assert!(st.is_success(), "register preflight 应 2xx,got {st}");
    assert_eq!(
        ao.as_deref(),
        Some("*"),
        "open 档 /register 应 Allow-Origin: *(C10.10③)"
    );
}

// ④ 会话端点:consent/grants/sessions/end-session/admin → **不发 CORS 头**(同源 + 防 CSRF,C10.10④)。
#[tokio::test]
async fn session_endpoints_emit_no_cors_headers() {
    let router = app().await;
    // 这些端点带浏览器 cookie 或属会话面;跨 origin 时 MUST 无 Allow-Origin 头(preflight 得不到 → 浏览器阻断)。
    for (method, uri) in [
        ("GET", "/grants"),
        ("GET", "/account/sessions"),
        ("DELETE", "/account/sessions"),
        ("GET", "/sessions"),
        ("POST", "/consent/decision"),
        ("GET", "/admin/overview"),
    ] {
        let (_st, ao, ac) = req_with_origin(&router, method, uri, "https://evil.example.com").await;
        assert_eq!(
            ao, None,
            "{method} {uri} 会话端点 MUST NOT 发 Allow-Origin(防跨域 credentialed CSRF,C10.10④)"
        );
        assert_eq!(ac, None, "{method} {uri} MUST NOT 发 Allow-Credentials");
    }
}

// ④ RFC 7592 管理端点 `GET /register/{id}` → 无 CORS 头(Bearer,非浏览器 fetch)。
#[tokio::test]
async fn register_manage_endpoint_emits_no_cors_headers() {
    let router = app().await;
    let (_st, ao, _ac) = req_with_origin(
        &router,
        "GET",
        "/register/some-id",
        "https://evil.example.com",
    )
    .await;
    assert_eq!(
        ao, None,
        "RFC 7592 管理端点 MUST NOT 发 Allow-Origin(不给浏览器内任意 origin 兑换 reg_token 能力,C10.10④)"
    );
}

// ⑤ 浏览器导航 `/authorize` → 无 CORS 头(顶层跳转、非 fetch,不适用 CORS)。
#[tokio::test]
async fn authorize_navigation_emits_no_cors_headers() {
    let router = app().await;
    // 缺参数会 400,但只看 CORS 头:导航端点不应发 Allow-Origin。
    let (_st, ao, _ac) = req_with_origin(
        &router,
        "GET",
        "/authorize?response_type=code&client_id=x&redirect_uri=y",
        "https://evil.example.com",
    )
    .await;
    assert_eq!(
        ao, None,
        "/authorize 浏览器导航 MUST NOT 发 Allow-Origin(非 fetch,C10.10⑤)"
    );
}

#[tokio::test]
async fn c10_10_all_endpoint_classes_are_partitioned_without_credentials() {
    let router = app_with_client().await;
    let evil = "https://evil.example.com";

    for uri in [
        "/openapi.json",
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
        "/jwks.json",
    ] {
        let (_status, allow_origin, allow_credentials) =
            req_with_origin(&router, "GET", uri, evil).await;
        assert_eq!(
            allow_origin.as_deref(),
            Some("*"),
            "public GET {uri} must allow any origin"
        );
        assert_eq!(
            allow_credentials, None,
            "public GET {uri} must not allow browser credentials"
        );
    }

    for uri in [
        "/token",
        "/revoke",
        "/introspect",
        "/device_authorization",
        "/bc-authorize",
    ] {
        let (status, allow_origin, allow_methods, allow_credentials) =
            preflight(&router, uri, evil, "POST").await;
        assert!(status.is_success(), "{uri} preflight must succeed");
        assert_eq!(
            allow_origin.as_deref(),
            Some("*"),
            "protocol POST {uri} must allow any origin"
        );
        assert!(
            allow_methods
                .as_deref()
                .is_some_and(|methods| methods.contains("POST")),
            "protocol POST {uri} must advertise POST"
        );
        assert_eq!(
            allow_credentials, None,
            "protocol POST {uri} must not allow browser credentials"
        );
    }

    let token_response = successful_token_response(&router, evil).await;
    assert_eq!(token_response.status(), StatusCode::OK);
    assert_eq!(
        token_response
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("*"),
        "a successful token response must retain wildcard no-cookie CORS"
    );
    assert!(
        token_response
            .headers()
            .get("access-control-allow-credentials")
            .is_none(),
        "a successful token response must not enable browser credentials"
    );

    let (status, allow_origin, allow_methods, allow_credentials) =
        preflight(&router, "/register", evil, "POST").await;
    assert!(status.is_success(), "open DCR preflight must succeed");
    assert_eq!(allow_origin.as_deref(), Some("*"));
    assert!(allow_methods
        .as_deref()
        .is_some_and(|methods| methods.contains("POST")));
    assert_eq!(
        allow_credentials, None,
        "open DCR must not allow browser credentials"
    );

    for (method, uri) in [
        ("POST", "/login/magic-link"),
        ("GET", "/consent/context"),
        ("POST", "/consent/decision"),
        ("GET", "/grants"),
        ("GET", "/sessions"),
        ("GET", "/end-session"),
        ("POST", "/device"),
        ("POST", "/bc-approve"),
        ("GET", "/admin/overview"),
        ("GET", "/register/some-id"),
        ("GET", "/account/credentials"),
        ("GET", "/account/sessions"),
        ("POST", "/recovery/begin"),
        ("POST", "/passkey/authenticate/begin"),
        ("POST", "/password/login"),
        ("POST", "/invitations/accept"),
        ("GET", "/federation/callback"),
        ("GET", "/scim/v2/Users"),
        ("GET", "/admin/sso/configs"),
        ("GET", "/ssf/configurations"),
        ("POST", "/privacy/export"),
    ] {
        let (_status, allow_origin, allow_credentials) =
            req_with_origin(&router, method, uri, evil).await;
        assert_eq!(
            allow_origin, None,
            "{method} {uri} must remain same-origin/no-CORS"
        );
        assert_eq!(
            allow_credentials, None,
            "{method} {uri} must not allow browser credentials"
        );
    }

    for uri in [
        "/authorize?response_type=code&client_id=x&redirect_uri=y",
        "/login/callback?link_id=x&tag=y",
    ] {
        let (_status, allow_origin, allow_credentials) =
            req_with_origin(&router, "GET", uri, evil).await;
        assert_eq!(
            allow_origin, None,
            "browser navigation {uri} must not emit CORS"
        );
        assert_eq!(
            allow_credentials, None,
            "browser navigation {uri} must not allow credentials"
        );
    }
}
