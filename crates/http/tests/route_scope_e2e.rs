use agent_auth_http::{build_router_for_scope, AppState, RouteScope};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use tower::ServiceExt;

async fn status(scope: RouteScope, method: Method, path: &str) -> StatusCode {
    let (router, _) = build_router_for_scope(AppState::dev("auth.example.com"), scope);
    router
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("host", "auth.example.com")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response")
        .status()
}

#[tokio::test]
async fn token_scope_exposes_only_the_token_endpoint() {
    assert_ne!(
        status(RouteScope::Token, Method::POST, "/token").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status(
            RouteScope::Token,
            Method::GET,
            "/.well-known/openid-configuration"
        )
        .await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status(RouteScope::Token, Method::GET, "/admin").await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn non_token_scope_excludes_token_and_preserves_discovery() {
    assert_eq!(
        status(RouteScope::NonToken, Method::POST, "/token").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status(
            RouteScope::NonToken,
            Method::GET,
            "/.well-known/openid-configuration"
        )
        .await,
        StatusCode::OK
    );
}
