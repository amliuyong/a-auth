//! Public HTTP contract for bounded self-hosted deployment branding.

use agent_auth_http::{build_router, AppState};
use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use serde_json::{json, Value};
use tower::ServiceExt;

#[cfg(feature = "aws")]
#[tokio::test]
#[ignore = "requires A_AUTH_TEST_DYNAMODB_ENDPOINT pointing to local DynamoDB"]
async fn branding_dynamodb_survives_http_restart_and_fences_concurrent_editors() {
    use agent_auth_http::branding_store::BrandingStore;
    use aws_sdk_dynamodb::types::{
        AttributeDefinition, BillingMode, KeySchemaElement, KeyType, ScalarAttributeType,
    };

    let endpoint = std::env::var("A_AUTH_TEST_DYNAMODB_ENDPOINT").expect("local DynamoDB endpoint");
    let parsed = url::Url::parse(&endpoint).unwrap();
    assert_eq!(parsed.scheme(), "http");
    assert_eq!(
        parsed.host_str(),
        Some("127.0.0.1"),
        "this test only writes to a local DynamoDB emulator"
    );
    let new_db = || {
        aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                .endpoint_url(&endpoint)
                .build(),
        )
    };
    let db = new_db();
    let table = format!("a-auth-branding-test-{}", rand::random::<u64>());
    db.create_table()
        .table_name(&table)
        .billing_mode(BillingMode::PayPerRequest)
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("key")
                .attribute_type(ScalarAttributeType::S)
                .build()
                .unwrap(),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("key")
                .key_type(KeyType::Hash)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let new_state = || {
        let mut state = AppState::dev("localhost");
        state.branding = std::sync::Arc::new(BrandingStore::dynamo(new_db(), table.clone()));
        state
    };
    async fn start(state: AppState) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let (router, _) = build_router(state);
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (address, task)
    }
    async fn stop(task: tokio::task::JoinHandle<()>) {
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
    async fn http(
        address: &str,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = reqwest::Client::new()
            .request(method, format!("{address}{path}"))
            .header(header::HOST, "localhost")
            .bearer_auth("dev-admin-token-not-for-prod");
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        let status = response.status();
        (status, response.json().await.unwrap())
    }
    let settings = json!({"name": "Durable", "logo": "shield", "primary": "teal"});
    let (address, task) = start(new_state()).await;
    let (status, saved) = http(
        &address,
        Method::PUT,
        "/admin/branding",
        Some(json!({"expected_revision": 0, "settings": settings})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(saved["revision"], 1);
    stop(task).await;

    let (address, task) = start(new_state()).await;
    let (status, loaded) = http(&address, Method::GET, "/ui/branding", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(loaded["revision"], 1);
    assert_eq!(loaded["settings"], settings);
    let (other_address, other_task) = start(new_state()).await;
    let (first, second) = tokio::join!(
        http(
            &address,
            Method::PUT,
            "/admin/branding",
            Some(json!({
                "expected_revision": 1,
                "settings": {"name": "First", "logo": "key", "primary": "violet"}
            }))
        ),
        http(
            &other_address,
            Method::PUT,
            "/admin/branding",
            Some(json!({
                "expected_revision": 1,
                "settings": {"name": "Second", "logo": "none", "primary": "blue"}
            }))
        ),
    );
    assert!(
        first.0 == StatusCode::OK && second.0 == StatusCode::CONFLICT
            || first.0 == StatusCode::CONFLICT && second.0 == StatusCode::OK
    );
    let winner = if first.0 == StatusCode::OK {
        first.1
    } else {
        second.1
    };
    stop(task).await;
    stop(other_task).await;

    let (address, task) = start(new_state()).await;
    let (_, loaded) = http(&address, Method::GET, "/ui/branding", None).await;
    assert_eq!(loaded["revision"], 2);
    assert_eq!(loaded["settings"], winner["settings"]);
    let (status, reset) = http(
        &address,
        Method::POST,
        "/admin/branding/reset",
        Some(json!({"expected_revision": 2})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reset["revision"], 3);
    stop(task).await;

    let (address, task) = start(new_state()).await;
    let (status, loaded) = http(&address, Method::GET, "/ui/branding", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(loaded["revision"], 3);
    assert_eq!(
        loaded["settings"],
        json!({"name": null, "logo": "none", "primary": "blue"})
    );
    let (status, _) = http(
        &address,
        Method::PUT,
        "/admin/branding",
        Some(json!({"expected_revision": 2, "settings": settings})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    stop(task).await;
    db.delete_table().table_name(&table).send().await.unwrap();
}

async fn request(
    router: &axum::Router,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
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
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, value)
}

#[tokio::test]
async fn an_older_self_hosted_deployment_has_public_branding_defaults() {
    let (router, _) = build_router(AppState::dev("localhost"));
    let (status, headers, value) = request(&router, Method::GET, "/ui/branding", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        value,
        json!({
            "status": "ready",
            "version": 1,
            "revision": 0,
            "settings": {"name": null, "logo": "none", "primary": "blue"}
        })
    );
}

#[tokio::test]
async fn saving_branding_updates_public_rendering_and_rejects_a_stale_editor() {
    let (router, _) = build_router(AppState::dev("localhost"));
    let update = json!({
        "expected_revision": 0,
        "settings": {"name": "Demo", "logo": "shield", "primary": "teal"}
    });
    let (status, _, saved) = request(
        &router,
        Method::PUT,
        "/admin/branding",
        Some("dev-admin-token-not-for-prod"),
        Some(update.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(saved["revision"], 1);
    let (status, _, public) = request(&router, Method::GET, "/ui/branding", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        public["settings"],
        json!({"name": "Demo", "logo": "shield", "primary": "teal"})
    );
    let (status, _, _) = request(
        &router,
        Method::PUT,
        "/admin/branding",
        Some("dev-admin-token-not-for-prod"),
        Some(update),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn restoring_defaults_keeps_a_revision_and_blocks_the_pre_reset_editor() {
    let (router, _) = build_router(AppState::dev("localhost"));
    let update = json!({
        "expected_revision": 0,
        "settings": {"name": "Demo", "logo": "key", "primary": "violet"}
    });
    let (status, _, _) = request(
        &router,
        Method::PUT,
        "/admin/branding",
        Some("dev-admin-token-not-for-prod"),
        Some(update),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, reset) = request(
        &router,
        Method::POST,
        "/admin/branding/reset",
        Some("dev-admin-token-not-for-prod"),
        Some(json!({"expected_revision": 1})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reset["revision"], 2);
    assert_eq!(
        reset["settings"],
        json!({"name": null, "logo": "none", "primary": "blue"})
    );
    let (status, _, _) = request(
        &router,
        Method::PUT,
        "/admin/branding",
        Some("dev-admin-token-not-for-prod"),
        Some(json!({
            "expected_revision": 1,
            "settings": {"name": "Stale", "logo": "none", "primary": "blue"}
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (_, _, current) = request(&router, Method::GET, "/ui/branding", None, None).await;
    assert_eq!(current["revision"], 2);
    assert_eq!(current["settings"]["name"], Value::Null);
}

#[tokio::test]
async fn invalid_branding_never_changes_the_public_settings() {
    let (router, _) = build_router(AppState::dev("localhost"));
    let invalid = [
        json!({"name": "", "logo": "none", "primary": "blue"}),
        json!({"name": "x".repeat(65), "logo": "none", "primary": "blue"}),
        json!({"name": "line\nbreak", "logo": "none", "primary": "blue"}),
        json!({"name": "hidden\u{202e}facts", "logo": "none", "primary": "blue"}),
        json!({"name": "hidden\u{061c}facts", "logo": "none", "primary": "blue"}),
        json!({"name": "hidden\u{200e}facts", "logo": "none", "primary": "blue"}),
        json!({"name": "hidden\u{200f}facts", "logo": "none", "primary": "blue"}),
        json!({"name": "Demo", "logo": "https://images.example/logo.svg", "primary": "blue"}),
        json!({"name": "Demo", "logo": "data:image/svg+xml,ignored", "primary": "blue"}),
        json!({"name": "Demo", "logo": "none", "primary": "#ffffff"}),
        json!({"name": "Demo", "logo": "none", "primary": "blue", "workload_actor": "other"}),
    ];
    for settings in invalid {
        let (status, _, _) = request(
            &router,
            Method::PUT,
            "/admin/branding",
            Some("dev-admin-token-not-for-prod"),
            Some(json!({"expected_revision": 0, "settings": settings})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let (_, _, current) = request(&router, Method::GET, "/ui/branding", None, None).await;
    assert_eq!(current["revision"], 0);
    assert_eq!(
        current["settings"],
        json!({"name": null, "logo": "none", "primary": "blue"})
    );
}

#[tokio::test]
async fn simultaneous_editors_can_commit_only_one_revision() {
    let (router, _) = build_router(AppState::dev("localhost"));
    let first = json!({
        "expected_revision": 0,
        "settings": {"name": "First", "logo": "none", "primary": "blue"}
    });
    let second = json!({
        "expected_revision": 0,
        "settings": {"name": "Second", "logo": "none", "primary": "blue"}
    });
    let (first, second) = tokio::join!(
        request(
            &router,
            Method::PUT,
            "/admin/branding",
            Some("dev-admin-token-not-for-prod"),
            Some(first)
        ),
        request(
            &router,
            Method::PUT,
            "/admin/branding",
            Some("dev-admin-token-not-for-prod"),
            Some(second)
        ),
    );
    assert!(
        first.0 == StatusCode::OK && second.0 == StatusCode::CONFLICT
            || first.0 == StatusCode::CONFLICT && second.0 == StatusCode::OK
    );
    let (_, _, current) = request(&router, Method::GET, "/ui/branding", None, None).await;
    assert_eq!(current["revision"], 1);
    assert!(current["settings"]["name"] == "First" || current["settings"]["name"] == "Second");
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn saas_branding_never_reads_or_writes_the_durable_store() {
    use agent_auth_http::admin_credentials::{
        AdminCredentialOwner, AdminCredentialRecord, AdminCredentialResolver, AdminCredentialSet,
        MemoryAdminCredentialStore,
    };
    use agent_auth_http::branding_store::BrandingStore;
    use aws_smithy_http_client::test_util::capture_request;
    use std::{collections::HashMap, sync::Arc, time::Duration};

    let mut state = AppState::dev("t1.example.com");
    state.form = agent_auth_discovery::Form::Saas {
        zone: "example.com".into(),
        control_host: "c.example.com".into(),
    };
    state.tenant_partitioning = true;
    state.saas_tenants = Arc::new(vec!["t1".into()]);
    let now = agent_auth_http::current_unix_secs();
    let credentials = MemoryAdminCredentialStore::default();
    credentials.put_set(
        "memory:platform",
        &AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            AdminCredentialRecord::explicit(
                "synthetic-platform-v1",
                "synthetic-platform-admin",
                now - 60,
                now - 60,
                now + 86400,
            ),
        ),
        now,
    );
    credentials.put_set(
        "memory:t1",
        &AdminCredentialSet::single(
            AdminCredentialOwner::tenant("t1"),
            AdminCredentialRecord::explicit(
                "synthetic-v1",
                "synthetic-tenant-admin",
                now - 60,
                now - 60,
                now + 86400,
            ),
        ),
        now,
    );
    state.admin_credentials = Arc::new(AdminCredentialResolver::memory_scoped(
        Some("memory:platform".into()),
        HashMap::from([("t1".into(), "memory:t1".into())]),
        HashMap::new(),
        credentials,
        Duration::ZERO,
    ));
    let (http, captured) = capture_request(None);
    let db = aws_sdk_dynamodb::Client::from_conf(
        aws_sdk_dynamodb::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
            .http_client(http)
            .build(),
    );
    state.branding = Arc::new(BrandingStore::dynamo(db, "UnusedBrandingTable".into()));
    let (router, _) = build_router(state);
    for (method, path, body, expected) in [
        (Method::GET, "/ui/branding", Value::Null, StatusCode::OK),
        (Method::GET, "/admin/branding", Value::Null, StatusCode::OK),
        (
            Method::PUT,
            "/admin/branding",
            json!({"expected_revision": 0, "settings": {"name": null, "logo": "none", "primary": "blue"}}),
            StatusCode::NOT_IMPLEMENTED,
        ),
        (
            Method::POST,
            "/admin/branding/reset",
            json!({"expected_revision": 0}),
            StatusCode::NOT_IMPLEMENTED,
        ),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method.clone())
                    .uri(path)
                    .header(header::HOST, "t1.example.com")
                    .header(header::AUTHORIZATION, "Bearer synthetic-tenant-admin")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{method} {path}");
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
        if method == Method::GET {
            assert_eq!(body["status"], "unsupported_deployment");
            assert_eq!(body["revision"], 0);
            if path.starts_with("/admin") {
                assert_eq!(body["can_manage"], false);
            }
        }
    }
    captured.expect_no_request();
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn an_unknown_durable_version_is_read_only_even_for_an_owner() {
    use agent_auth_http::branding_store::BrandingStore;
    use aws_smithy_http_client::test_util::capture_request;
    use aws_smithy_types::body::SdkBody;
    use std::sync::Arc;

    let base = AppState::dev("localhost");
    for (method, path, body, expected) in [
        (Method::GET, "/admin/branding", None, StatusCode::OK),
        (
            Method::PUT,
            "/admin/branding",
            Some(json!({
                "expected_revision": 7,
                "settings": {"name": "Overwrite", "logo": "none", "primary": "blue"}
            })),
            StatusCode::CONFLICT,
        ),
        (
            Method::POST,
            "/admin/branding/reset",
            Some(json!({"expected_revision": 7})),
            StatusCode::CONFLICT,
        ),
    ] {
        let future = json!({
            "version": 2, "revision": 7,
            "settings": {"future_logo": "https://ignored.example/logo.svg"}
        });
        let response = axum::http::Response::builder()
            .status(200)
            .header(header::CONTENT_TYPE, "application/x-amz-json-1.0")
            .body(SdkBody::from(
                json!({"Item": {
                    "record_type": {"S": "branding"},
                    "schema_version": {"N": "2"},
                    "revision": {"N": "7"},
                    "record_json": {"S": future.to_string()}
                }})
                .to_string(),
            ))
            .unwrap();
        let (http, captured) = capture_request(Some(response));
        let db = aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                .endpoint_url("https://dynamodb.us-east-1.amazonaws.com")
                .http_client(http)
                .build(),
        );
        let mut state = base.clone();
        state.branding = Arc::new(BrandingStore::dynamo(db, "DurableAdminTable".into()));
        let (router, _) = build_router(state);
        let (status, _, value) = request(
            &router,
            method.clone(),
            path,
            Some("dev-admin-token-not-for-prod"),
            body,
        )
        .await;
        assert_eq!(status, expected, "{method} {path}");
        if method == Method::GET {
            assert_eq!(value["status"], "unsupported_version");
            assert_eq!(value["revision"], 7);
            assert_eq!(value["can_manage"], false);
            assert_eq!(
                value["settings"],
                json!({"name": null, "logo": "none", "primary": "blue"})
            );
        }
        let captured = captured.expect_request();
        let body: Value = serde_json::from_slice(captured.body().bytes().unwrap()).unwrap();
        assert_eq!(body["TableName"], "DurableAdminTable");
        assert_eq!(body["Key"]["key"]["S"], "branding#deployment#localhost");
        assert_eq!(body["ConsistentRead"], true);
        assert_eq!(
            captured.headers().get("x-amz-target"),
            Some("DynamoDB_20120810.GetItem")
        );
    }
}
