use std::{collections::HashMap, sync::Arc, time::Duration};

use agent_auth_http::{
    admin_credentials::{
        AdminCredentialOwner, AdminCredentialRecord, AdminCredentialResolver, AdminCredentialSet,
        MemoryAdminCredentialStore,
    },
    build_router, current_unix_secs,
    ssf::{SsfStore, RISC_ACCOUNT_DISABLED_EVENT},
    AppState,
};
use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use serde_json::{json, Value};
use tower::ServiceExt;

const ZONE: &str = "ssf.example.com";
const CONTROL: &str = "c.ssf.example.com";
const T1_HOST: &str = "t1.ssf.example.com";
const T2_HOST: &str = "t2.ssf.example.com";
const T1_TOKEN: &str = "t1-ssf-admin-secret";
const T2_TOKEN: &str = "t2-ssf-admin-secret";

fn credentials() -> Arc<AdminCredentialResolver> {
    let now = current_unix_secs();
    let store = MemoryAdminCredentialStore::default();
    let platform_ref = "memory:platform";
    store.put_set(
        platform_ref,
        &AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            AdminCredentialRecord::explicit(
                "platform-v1",
                "platform-only-token",
                now - 60,
                now - 60,
                now + 3_600,
            ),
        ),
        now,
    );
    let mut refs = HashMap::new();
    for (tenant, token) in [("t1", T1_TOKEN), ("t2", T2_TOKEN)] {
        assert!(
            token.len() >= agent_auth_http::admin_credentials::MIN_ADMIN_CREDENTIAL_SECRET_BYTES
        );
        let secret_ref = format!("memory:tenant:{tenant}");
        refs.insert(tenant.to_string(), secret_ref.clone());
        store.put_set(
            &secret_ref,
            &AdminCredentialSet::single(
                AdminCredentialOwner::tenant(tenant),
                AdminCredentialRecord::explicit(
                    format!("{tenant}-v1"),
                    token,
                    now - 60,
                    now - 60,
                    now + 3_600,
                ),
            ),
            now,
        );
    }
    Arc::new(AdminCredentialResolver::memory(
        Some(platform_ref.to_string()),
        refs,
        store,
        Duration::ZERO,
    ))
}

fn state() -> AppState {
    let mut state = AppState::dev("localhost");
    state.form = agent_auth_discovery::Form::Saas {
        zone: ZONE.to_string(),
        control_host: CONTROL.to_string(),
    };
    state.tenant_partitioning = true;
    state.admin_credentials = credentials();
    state.saas_tenants = Arc::new(vec!["t1".to_string(), "t2".to_string()]);
    state
}

async fn request(
    router: &axum::Router,
    method: Method,
    host: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", host);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    let response = router
        .clone()
        .oneshot(
            builder
                .body(body.map_or_else(Body::empty, |value| {
                    Body::from(serde_json::to_vec(&value).unwrap())
                }))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn tenant_admin_streams_are_physically_scoped_by_host_and_credential_owner() {
    let state = state();
    let inspection = state.clone();
    let (router, _) = build_router(state);

    for (host, token, receiver) in [
        (T1_HOST, T1_TOKEN, "receiver-t1.example.net"),
        (T2_HOST, T2_TOKEN, "receiver-t2.example.net"),
    ] {
        let (status, created) = request(
            &router,
            Method::POST,
            host,
            "/admin/ssf/streams",
            Some(token),
            Some(json!({
                "endpoint": format!("https://{receiver}/events"),
                "audience": format!("https://{receiver}"),
                "event_types": [RISC_ACCOUNT_DISABLED_EVENT]
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(created["tenant_id"], host.split('.').next().unwrap());
    }

    for (host, token, expected_tenant) in [(T1_HOST, T1_TOKEN, "t1"), (T2_HOST, T2_TOKEN, "t2")] {
        let (status, listed) = request(
            &router,
            Method::GET,
            host,
            "/admin/ssf/streams",
            Some(token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed["streams"].as_array().unwrap().len(), 1);
        assert_eq!(listed["streams"][0]["tenant_id"], expected_tenant);
    }

    assert_eq!(
        request(
            &router,
            Method::GET,
            T2_HOST,
            "/admin/ssf/streams",
            Some(T1_TOKEN),
            None,
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(inspection.ssf.list_streams("t1").await.unwrap().len(), 1);
    assert_eq!(inspection.ssf.list_streams("t2").await.unwrap().len(), 1);
    assert!(inspection.ssf.list_streams("t3").await.unwrap().is_empty());
}

#[tokio::test]
async fn ssf_metadata_is_tenant_specific_and_control_host_is_not_an_issuer() {
    let (router, _) = build_router(state());
    for (host, issuer) in [
        (T1_HOST, "https://t1.ssf.example.com"),
        (T2_HOST, "https://t2.ssf.example.com"),
    ] {
        let (status, metadata) = request(
            &router,
            Method::GET,
            host,
            "/.well-known/ssf-configuration",
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(metadata["spec_version"], "1_0");
        assert_eq!(metadata["issuer"], issuer);
        assert_eq!(metadata["jwks_uri"], format!("{issuer}/jwks.json"));
        assert_eq!(
            metadata["delivery_methods_supported"],
            json!(["urn:ietf:rfc:8935"])
        );
    }
    assert_eq!(
        request(
            &router,
            Method::GET,
            CONTROL,
            "/.well-known/ssf-configuration",
            None,
            None,
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}
