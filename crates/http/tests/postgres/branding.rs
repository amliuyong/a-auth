//! Development HTTP control with explicit PostgreSQL presentation authority.
//! This fixture does not establish production AppState composition.

use super::ssf_contracts::isolated_database;
use agent_auth_http::{
    adapters::postgres::PostgresStore, branding_store::BrandingStore, build_router, AppState,
};
use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Barrier;
use tower::ServiceExt;

fn router(store: PostgresStore) -> axum::Router {
    let mut state = AppState::dev("localhost");
    state.branding = Arc::new(BrandingStore::postgres(store));
    build_router(state).0
}

async fn request(
    router: &axum::Router,
    method: Method,
    path: &str,
    authenticated: bool,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json");
    if authenticated {
        request = request.header(header::AUTHORIZATION, "Bearer dev-admin-token-not-for-prod");
    }
    let response = router
        .clone()
        .oneshot(
            request
                .body(body.map_or_else(Body::empty, |value| {
                    Body::from(serde_json::to_vec(&value).unwrap())
                }))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn postgres_branding_http_restart_and_two_pool_editors_preserve_one_revision() {
    let (first, _pool, admin, name, url) = isolated_database().await;
    let second = PostgresStore::connect(&url, 8).await.unwrap();
    let routers = [router(first), router(second)];
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let router = routers[index % 2].clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            request(
                &router,
                Method::PUT,
                "/admin/branding",
                true,
                Some(json!({
                    "expected_revision": 0,
                    "settings": {
                        "name": format!("Editor {index}"),
                        "logo": "shield",
                        "primary": "teal"
                    }
                })),
            )
            .await
        }));
    }
    let mut winner = None;
    for task in tasks {
        let (status, value) = task.await.unwrap();
        match status {
            StatusCode::OK => assert!(winner.replace(value).is_none()),
            StatusCode::CONFLICT => {}
            other => panic!("unexpected branding admission {other}"),
        }
    }
    let winner = winner.unwrap();
    drop(routers);
    let restarted = router(PostgresStore::connect(&url, 8).await.unwrap());
    let (status, observed) = request(&restarted, Method::GET, "/ui/branding", false, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(observed["revision"], 1);
    assert_eq!(observed["settings"], winner["settings"]);
    let (status, reset) = request(
        &restarted,
        Method::POST,
        "/admin/branding/reset",
        true,
        Some(json!({"expected_revision": 1})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reset["revision"], 2);
    let (status, _) = request(
        &restarted,
        Method::PUT,
        "/admin/branding",
        true,
        Some(json!({"expected_revision": 1, "settings": winner["settings"]})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
}

#[tokio::test]
async fn postgres_branding_corrupted_physical_revision_is_not_replaced_by_an_editor() {
    let (store, pool, admin, name, _url) = isolated_database().await;
    let router = router(store);
    let input = json!({
        "expected_revision": 0,
        "settings": {"name": "Initial", "logo": "none", "primary": "blue"}
    });
    assert_eq!(
        request(
            &router,
            Method::PUT,
            "/admin/branding",
            false,
            Some(input.clone())
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(&router, Method::PUT, "/admin/branding", true, Some(input))
            .await
            .0,
        StatusCode::OK
    );
    sqlx::query("UPDATE a_auth.branding SET revision=2")
        .execute(&pool)
        .await
        .unwrap();
    let (status, _) = request(
        &router,
        Method::PUT,
        "/admin/branding",
        true,
        Some(json!({
            "expected_revision": 2,
            "settings": {"name": "Replacement", "logo": "key", "primary": "violet"}
        })),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let physical: String = sqlx::query_scalar("SELECT record FROM a_auth.branding")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(physical.contains("Initial"));
    assert!(!physical.contains("Replacement"));
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
}
