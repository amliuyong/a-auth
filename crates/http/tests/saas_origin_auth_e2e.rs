use std::sync::Arc;

use agent_auth_http::origin_auth::{
    SaasOriginAuth, LEGACY_ORIGIN_AUTH_HEADER, PRIMARY_ORIGIN_AUTH_HEADER,
    SECONDARY_ORIGIN_AUTH_HEADER,
};
use agent_auth_http::{build_router, AppState};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use tower::ServiceExt;

const API_HOST: &str = "api-id.execute-api.us-east-1.amazonaws.com";
const ZONE: &str = "auth.example.com";
const CONTROL_HOST: &str = "c.auth.example.com";
const T1_HOST: &str = "t1.auth.example.com";
const T2_HOST: &str = "t2.auth.example.com";
const PRIMARY: &str = "primary-origin-secret-at-least-32-bytes";
const SECONDARY: &str = "secondary-origin-secret-at-least-32-bytes";

fn saas_router() -> axum::Router {
    let mut state = AppState::dev("unused.example.com");
    state.form = agent_auth_discovery::Form::Saas {
        zone: ZONE.to_string(),
        control_host: CONTROL_HOST.to_string(),
    };
    state.saas_tenants = Arc::new(vec!["t1".to_string()]);
    state.tenant_partitioning = true;
    state.saas_origin_auth =
        Arc::new(SaasOriginAuth::required(PRIMARY.to_string(), SECONDARY.to_string()).unwrap());
    build_router(state).0
}

async fn send(
    router: &axum::Router,
    method: Method,
    path: &str,
    forwarded_host: &str,
    origin_header: Option<(&'static str, &'static str)>,
) -> StatusCode {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", API_HOST)
        .header("x-forwarded-host", forwarded_host);
    if let Some((name, value)) = origin_header {
        request = request.header(name, value);
    }
    router
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn direct_origin_is_rejected_before_every_saas_route_family() {
    let router = saas_router();
    for (method, path) in [
        (Method::GET, "/.well-known/openid-configuration"),
        (Method::POST, "/token"),
        (Method::GET, "/admin/overview"),
        (Method::GET, "/scim/v2/ServiceProviderConfig"),
        (Method::GET, "/passkey/status"),
    ] {
        assert_eq!(
            send(&router, method, path, T1_HOST, None).await,
            StatusCode::FORBIDDEN,
            "{path} must reject an unauthenticated direct-origin request"
        );
    }
}

#[tokio::test]
async fn either_rotation_slot_and_the_rolling_legacy_header_reach_the_handler() {
    let router = saas_router();
    for header in [
        (PRIMARY_ORIGIN_AUTH_HEADER, PRIMARY),
        (SECONDARY_ORIGIN_AUTH_HEADER, SECONDARY),
        (LEGACY_ORIGIN_AUTH_HEADER, PRIMARY),
    ] {
        assert_eq!(
            send(
                &router,
                Method::GET,
                "/.well-known/openid-configuration",
                T1_HOST,
                Some(header),
            )
            .await,
            StatusCode::OK
        );
    }
}

#[tokio::test]
async fn wrong_missing_and_swapped_credentials_fail_before_tenant_admission() {
    let router = saas_router();
    for header in [
        None,
        Some((PRIMARY_ORIGIN_AUTH_HEADER, "wrong-primary")),
        Some((SECONDARY_ORIGIN_AUTH_HEADER, "wrong-secondary")),
        Some((PRIMARY_ORIGIN_AUTH_HEADER, SECONDARY)),
        Some((SECONDARY_ORIGIN_AUTH_HEADER, PRIMARY)),
    ] {
        assert_eq!(
            send(
                &router,
                Method::GET,
                "/.well-known/openid-configuration",
                T2_HOST,
                header,
            )
            .await,
            StatusCode::FORBIDDEN
        );
    }

    assert_eq!(
        send(
            &router,
            Method::GET,
            "/.well-known/openid-configuration",
            T2_HOST,
            Some((PRIMARY_ORIGIN_AUTH_HEADER, PRIMARY)),
        )
        .await,
        StatusCode::NOT_FOUND,
        "a trusted edge request proceeds to the registered-tenant gate"
    );
}

#[tokio::test]
async fn authenticated_parent_and_control_hosts_are_not_tenant_issuers() {
    let router = saas_router();
    for host in [ZONE, CONTROL_HOST] {
        assert_eq!(
            send(
                &router,
                Method::GET,
                "/.well-known/openid-configuration",
                host,
                Some((PRIMARY_ORIGIN_AUTH_HEADER, PRIMARY)),
            )
            .await,
            StatusCode::BAD_REQUEST,
            "{host} must not become a tenant issuer after edge authentication"
        );
    }
}

#[tokio::test]
async fn self_hosted_routes_do_not_require_the_saas_edge_credential() {
    let router = build_router(AppState::dev("self.example.com")).0;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .header("host", "self.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
