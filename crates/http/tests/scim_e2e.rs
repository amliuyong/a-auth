use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Duration,
};

use agent_auth_grant::{Grant, GrantConstraints, GrantStatus, ResourceGrant};
use agent_auth_http::{
    admin_credentials::{
        AdminCredentialOwner, AdminCredentialRecord, AdminCredentialResolver, AdminCredentialSet,
        MemoryAdminCredentialStore,
    },
    build_router, current_unix_secs,
    ports::{
        DisableStart, GrantStore, RefreshFamilyRecord, RefreshStore, ScimCreateOutcome,
        ScimGroupsStore, ScimUserInput, SessionRecord, SessionStore, UserStatus, UsersStore,
    },
    security_event::SecurityEventStore,
    AppState, Phase,
};
use axum::{
    body::{to_bytes, Body},
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode},
};
use serde_json::{json, Value};
use tower::ServiceExt;

const HOST: &str = "localhost";
const SCIM_TOKEN: &str = "dev-scim-token-not-for-prod";
const ADMIN_TOKEN: &str = "dev-admin-token-not-for-prod";
const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

struct HttpResult {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Value,
}

async fn response_result(response: axum::response::Response) -> HttpResult {
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    HttpResult {
        status,
        headers,
        body,
    }
}

async fn request(
    router: &axum::Router,
    method: Method,
    host: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> HttpResult {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", host);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if body.is_some() {
        request = request.header(header::CONTENT_TYPE, "application/scim+json");
    }
    let response = router
        .clone()
        .oneshot(
            request
                .body(body.map_or_else(Body::empty, |value| Body::from(value.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    response_result(response).await
}

fn create_body(external_id: &str, user_name: &str) -> Value {
    json!({
        "schemas": [USER_SCHEMA],
        "externalId": external_id,
        "userName": user_name,
        "displayName": "Alice Example",
        "active": true
    })
}

fn patch_active(active: bool) -> Value {
    json!({
        "schemas": [PATCH_SCHEMA],
        "Operations": [{
            "op": "replace",
            "path": "active",
            "value": active
        }]
    })
}

fn group_body(external_id: &str, display_name: &str, members: &[&str]) -> Value {
    json!({
        "schemas": [GROUP_SCHEMA],
        "externalId": external_id,
        "displayName": display_name,
        "members": members.iter().map(|value| json!({
            "value": value,
            "type": "User"
        })).collect::<Vec<_>>()
    })
}

fn assert_scim_content_type(result: &HttpResult) {
    assert_eq!(
        result.headers[header::CONTENT_TYPE],
        "application/scim+json"
    );
}

fn assert_scim_error(result: &HttpResult, status: StatusCode, scim_type: Option<&str>) {
    assert_eq!(result.status, status);
    assert_eq!(result.body["schemas"], json!([ERROR_SCHEMA]));
    assert_eq!(result.body["status"], status.as_u16().to_string());
    if let Some(scim_type) = scim_type {
        assert_eq!(result.body["scimType"], scim_type);
    }
    assert_scim_content_type(result);
}

#[tokio::test]
async fn service_provider_config_is_authenticated_and_truthful() {
    let (router, _) = build_router(AppState::dev(HOST));

    let missing = request(
        &router,
        Method::GET,
        HOST,
        "/scim/v2/ServiceProviderConfig",
        None,
        None,
    )
    .await;
    assert_eq!(missing.status, StatusCode::UNAUTHORIZED);
    assert_eq!(missing.headers[header::WWW_AUTHENTICATE], "Bearer");

    let admin = request(
        &router,
        Method::GET,
        HOST,
        "/scim/v2/ServiceProviderConfig",
        Some(ADMIN_TOKEN),
        None,
    )
    .await;
    assert_eq!(admin.status, StatusCode::UNAUTHORIZED);

    let result = request(
        &router,
        Method::GET,
        HOST,
        "/scim/v2/ServiceProviderConfig",
        Some(SCIM_TOKEN),
        None,
    )
    .await;
    assert_eq!(result.status, StatusCode::OK);
    assert_eq!(
        result.body["schemas"],
        json!(["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"])
    );
    assert_eq!(result.body["patch"]["supported"], true);
    assert_eq!(result.body["filter"]["supported"], true);
    assert_eq!(result.body["filter"]["maxResults"], 100);
    for capability in ["bulk", "changePassword", "sort", "etag"] {
        assert_eq!(result.body[capability]["supported"], false);
    }
    assert_eq!(
        result.body["authenticationSchemes"][0]["type"],
        "oauthbearertoken"
    );
    assert_scim_content_type(&result);
}

#[tokio::test]
async fn unsupported_methods_and_unknown_resources_use_authenticated_scim_errors() {
    let (router, _) = build_router(AppState::dev(HOST));

    let unauthorized_method = request(
        &router,
        Method::DELETE,
        HOST,
        "/scim/v2/Users/missing",
        None,
        None,
    )
    .await;
    assert_scim_error(&unauthorized_method, StatusCode::UNAUTHORIZED, None);
    assert_eq!(
        unauthorized_method.headers[header::WWW_AUTHENTICATE],
        "Bearer"
    );

    let unsupported_method = request(
        &router,
        Method::DELETE,
        HOST,
        "/scim/v2/Users/missing",
        Some(SCIM_TOKEN),
        None,
    )
    .await;
    assert_scim_error(&unsupported_method, StatusCode::METHOD_NOT_ALLOWED, None);

    let unauthorized_resource =
        request(&router, Method::GET, HOST, "/scim/v2/Schemas", None, None).await;
    assert_scim_error(&unauthorized_resource, StatusCode::UNAUTHORIZED, None);
    assert_eq!(
        unauthorized_resource.headers[header::WWW_AUTHENTICATE],
        "Bearer"
    );

    let unknown_resource = request(
        &router,
        Method::GET,
        HOST,
        "/scim/v2/Schemas",
        Some(SCIM_TOKEN),
        None,
    )
    .await;
    assert_scim_error(&unknown_resource, StatusCode::NOT_FOUND, None);

    let invalid_path_unauthorized =
        request(&router, Method::GET, HOST, "/scim/v2/Users/%FF", None, None).await;
    assert_scim_error(&invalid_path_unauthorized, StatusCode::UNAUTHORIZED, None);

    let invalid_path = request(
        &router,
        Method::GET,
        HOST,
        "/scim/v2/Users/%FF",
        Some(SCIM_TOKEN),
        None,
    )
    .await;
    assert_scim_error(&invalid_path, StatusCode::BAD_REQUEST, Some("invalidValue"));

    for (token, status, scim_type) in [
        (None, StatusCode::UNAUTHORIZED, None),
        (Some(SCIM_TOKEN), StatusCode::PAYLOAD_TOO_LARGE, None),
    ] {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri("/scim/v2/Users")
            .header("host", HOST)
            .header(header::CONTENT_TYPE, "application/scim+json");
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = router
            .clone()
            .oneshot(
                builder
                    .body(Body::from(vec![b'x'; 2 * 1024 * 1024 + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();
        let result = response_result(response).await;
        assert_scim_error(&result, status, scim_type);
    }
}

#[tokio::test]
async fn create_retry_get_filter_and_put_preserve_canonical_id() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());
    let first = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(create_body("directory-001", "Alice@Example.com")),
    )
    .await;
    assert_eq!(first.status, StatusCode::CREATED);
    assert_eq!(first.body["schemas"], json!([USER_SCHEMA]));
    assert_eq!(first.body["externalId"], "directory-001");
    assert_eq!(first.body["userName"], "alice@example.com");
    assert_eq!(first.body["active"], true);
    let id = first.body["id"].as_str().unwrap().to_string();
    let location = format!("https://{HOST}/scim/v2/Users/{id}");
    assert_eq!(first.body["meta"]["location"], location);
    assert_eq!(first.headers[header::LOCATION], location);
    assert_scim_content_type(&first);

    let retry = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(create_body("directory-001", "alice@example.com")),
    )
    .await;
    assert_eq!(retry.status, StatusCode::OK);
    assert_eq!(retry.body["id"], id);
    assert_eq!(retry.body["meta"]["created"], first.body["meta"]["created"]);

    let by_id = request(
        &router,
        Method::GET,
        HOST,
        &format!("/scim/v2/Users/{id}"),
        Some(SCIM_TOKEN),
        None,
    )
    .await;
    assert_eq!(by_id.status, StatusCode::OK);
    assert_eq!(by_id.body["id"], id);

    for filter in [
        "externalId%20eq%20%22directory-001%22",
        "USERNAME%20EQ%20%22ALICE%40EXAMPLE.COM%22",
    ] {
        let result = request(
            &router,
            Method::GET,
            HOST,
            &format!("/scim/v2/Users?filter={filter}"),
            Some(SCIM_TOKEN),
            None,
        )
        .await;
        assert_eq!(result.status, StatusCode::OK);
        assert_eq!(result.body["schemas"], json!([LIST_SCHEMA]));
        assert_eq!(result.body["totalResults"], 1);
        assert_eq!(result.body["Resources"][0]["id"], id);
    }

    let put = request(
        &router,
        Method::PUT,
        HOST,
        &format!("/scim/v2/Users/{id}"),
        Some(SCIM_TOKEN),
        Some(json!({
            "schemas": [USER_SCHEMA],
            "externalId": "directory-002",
            "userName": "alice.moved@example.com",
            "displayName": "Alice Moved",
            "active": true
        })),
    )
    .await;
    assert_eq!(put.status, StatusCode::OK);
    assert_eq!(put.body["id"], id);
    assert_eq!(put.body["externalId"], "directory-002");
    assert_eq!(put.body["userName"], "alice.moved@example.com");

    for stale_filter in [
        "externalId%20eq%20%22directory-001%22",
        "userName%20eq%20%22alice%40example.com%22",
    ] {
        let stale = request(
            &router,
            Method::GET,
            HOST,
            &format!("/scim/v2/Users?filter={stale_filter}"),
            Some(SCIM_TOKEN),
            None,
        )
        .await;
        assert_eq!(stale.body["totalResults"], 0);
    }
    let delayed_retry = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(create_body("directory-001", "alice@example.com")),
    )
    .await;
    assert_eq!(delayed_retry.status, StatusCode::OK);
    assert_eq!(delayed_retry.body["id"], id);
    assert_eq!(delayed_retry.body["externalId"], "directory-002");
    assert_eq!(delayed_retry.body["userName"], "alice.moved@example.com");

    let current_post = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(create_body("directory-002", "alice.moved@example.com")),
    )
    .await;
    assert_eq!(current_post.status, StatusCode::OK);
    assert_eq!(current_post.body["id"], id);

    let moved_again = request(
        &router,
        Method::PUT,
        HOST,
        &format!("/scim/v2/Users/{id}"),
        Some(SCIM_TOKEN),
        Some(json!({
            "schemas": [USER_SCHEMA],
            "externalId": "directory-003",
            "userName": "alice.final@example.com",
            "active": true
        })),
    )
    .await;
    assert_eq!(moved_again.status, StatusCode::OK);
    let delayed_current_retry = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(create_body("directory-002", "alice.moved@example.com")),
    )
    .await;
    assert_eq!(delayed_current_retry.status, StatusCode::OK);
    assert_eq!(delayed_current_retry.body["id"], id);
    assert_eq!(delayed_current_retry.body["externalId"], "directory-003");
    assert_eq!(
        delayed_current_retry.body["userName"],
        "alice.final@example.com"
    );

    let inactive_body = json!({
        "schemas": [USER_SCHEMA],
        "externalId": "directory-003",
        "userName": "alice.final@example.com",
        "displayName": "Alice Final",
        "active": false
    });
    for _ in 0..2 {
        let disabled = request(
            &router,
            Method::PUT,
            HOST,
            &format!("/scim/v2/Users/{id}"),
            Some(SCIM_TOKEN),
            Some(inactive_body.clone()),
        )
        .await;
        assert_eq!(disabled.status, StatusCode::OK);
        assert_eq!(disabled.body["active"], false);
    }
    let disable_events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap()
        .into_iter()
        .filter(|stored| stored.event.action == "user.disable")
        .collect::<Vec<_>>();
    assert_eq!(
        disable_events.len(),
        1,
        "PUT active=false retries must reuse one canonical account-disabled event"
    );
    assert_eq!(
        disable_events[0].event.event_id,
        agent_auth_http::security_event::scim_lifecycle_event_id("default", &id, "disable", 1,)
    );

    let audit = state.credential_audit.snapshot().join("\n");
    assert_eq!(
        audit
            .lines()
            .filter(|line| line.contains("SCIM_MUTATION action=create"))
            .count(),
        1,
        "an exact POST retry must not emit a second create mutation"
    );
    assert!(audit.contains("SCIM_MUTATION action=replace"));
    assert!(audit.contains("SCIM_MUTATION action=disable"));
    assert!(!audit.contains("ADMIN_BREAK_GLASS_USE"));
    assert!(!audit.contains("directory-001"));
    assert!(!audit.contains("directory-002"));
}

#[tokio::test]
async fn unfiltered_list_pages_stably_and_excludes_tombstones() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());
    for index in 0..4 {
        let created = request(
            &router,
            Method::POST,
            HOST,
            "/scim/v2/Users",
            Some(SCIM_TOKEN),
            Some(create_body(
                &format!("page-external-{index}"),
                &format!("page-{index}@example.com"),
            )),
        )
        .await;
        assert_eq!(created.status, StatusCode::CREATED);
    }

    let all = request(
        &router,
        Method::GET,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        None,
    )
    .await;
    assert_eq!(all.status, StatusCode::OK);
    assert_eq!(all.body["totalResults"], 4);
    assert_eq!(all.body["itemsPerPage"], 4);
    let all_ids: Vec<_> = all.body["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|resource| resource["id"].as_str().unwrap().to_string())
        .collect();

    let page = request(
        &router,
        Method::GET,
        HOST,
        "/scim/v2/Users?startIndex=2&count=2",
        Some(SCIM_TOKEN),
        None,
    )
    .await;
    assert_eq!(page.status, StatusCode::OK);
    assert_eq!(page.body["totalResults"], 4);
    assert_eq!(page.body["startIndex"], 2);
    assert_eq!(page.body["itemsPerPage"], 2);
    let page_ids: Vec<_> = page.body["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|resource| resource["id"].as_str().unwrap())
        .collect();
    assert_eq!(page_ids, [&all_ids[1], &all_ids[2]]);

    let count_only = request(
        &router,
        Method::GET,
        HOST,
        "/scim/v2/Users?count=0",
        Some(SCIM_TOKEN),
        None,
    )
    .await;
    assert_eq!(count_only.status, StatusCode::OK);
    assert_eq!(count_only.body["totalResults"], 4);
    assert_eq!(count_only.body["itemsPerPage"], 0);
    assert_eq!(count_only.body["Resources"], json!([]));

    let normalized_lower_bounds = request(
        &router,
        Method::GET,
        HOST,
        "/scim/v2/Users?startIndex=0&count=-1",
        Some(SCIM_TOKEN),
        None,
    )
    .await;
    assert_eq!(normalized_lower_bounds.status, StatusCode::OK);
    assert_eq!(normalized_lower_bounds.body["totalResults"], 4);
    assert_eq!(normalized_lower_bounds.body["startIndex"], 1);
    assert_eq!(normalized_lower_bounds.body["itemsPerPage"], 0);
    assert_eq!(normalized_lower_bounds.body["Resources"], json!([]));

    state
        .users
        .set_status("", &all_ids[0], UserStatus::Tombstoned, current_unix_secs())
        .await
        .unwrap();
    let after_tombstone = request(
        &router,
        Method::GET,
        HOST,
        "/scim/v2/Users?startIndex=3&count=2",
        Some(SCIM_TOKEN),
        None,
    )
    .await;
    assert_eq!(after_tombstone.status, StatusCode::OK);
    assert_eq!(after_tombstone.body["totalResults"], 3);
    assert_eq!(after_tombstone.body["itemsPerPage"], 1);
    assert!(after_tombstone.body["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .all(|resource| resource["id"] != all_ids[0]));
}

#[tokio::test]
async fn put_moves_email_alias_without_rebinding_the_old_local_identity() {
    let state = AppState::dev(HOST);
    let original_email = "ops/a^[x]|@example.com";
    let original_id = "user:ops/a^[x]|@example.com";
    state
        .users
        .create_or_get_by_email("", original_email, original_id, 1)
        .await
        .unwrap();
    let (router, _) = build_router(state.clone());

    let adopted = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(create_body("adopted-external", original_email)),
    )
    .await;
    assert_eq!(adopted.status, StatusCode::CREATED);
    assert_eq!(adopted.body["id"], original_id);
    let location = adopted.body["meta"]["location"].as_str().unwrap();
    assert_eq!(
        location,
        "https://localhost/scim/v2/Users/user:ops%2Fa%5E%5Bx%5D%7C@example.com"
    );
    assert_eq!(adopted.headers[header::LOCATION], location);
    let location_path = location.strip_prefix("https://localhost").unwrap();

    let by_location = request(
        &router,
        Method::GET,
        HOST,
        location_path,
        Some(SCIM_TOKEN),
        None,
    )
    .await;
    assert_eq!(by_location.status, StatusCode::OK);
    assert_eq!(by_location.body["id"], original_id);

    let moved = request(
        &router,
        Method::PUT,
        HOST,
        location_path,
        Some(SCIM_TOKEN),
        Some(create_body("adopted-external", "adopted.moved@example.com")),
    )
    .await;
    assert_eq!(moved.status, StatusCode::OK);
    assert_eq!(moved.body["id"], original_id);
    assert!(state
        .users
        .get_by_email("", original_email)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        state
            .users
            .get_by_email("", "adopted.moved@example.com")
            .await
            .unwrap()
            .unwrap()
            .user_id,
        original_id
    );

    let stale_login = state
        .users
        .create_or_get_by_email("", original_email, original_id, 2)
        .await;
    assert!(
        stale_login.is_err(),
        "the released email must not overwrite its stable canonical id"
    );
    let canonical = state
        .users
        .get_by_id("", original_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(canonical.email, "adopted.moved@example.com");
    assert_eq!(
        canonical.scim_external_id.as_deref(),
        Some("adopted-external")
    );
}

#[tokio::test]
async fn schema_filter_patch_and_alias_conflicts_use_scim_errors() {
    let state = AppState::dev(HOST);
    state
        .users
        .create_or_get_by_email("", "occupied@example.com", "user:occupied@example.com", 1)
        .await
        .unwrap();
    let (router, _) = build_router(state);
    let invalid_schema = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(json!({
            "schemas": ["urn:example:not-scim"],
            "externalId": "bad-schema",
            "userName": "bad@example.com"
        })),
    )
    .await;
    assert_scim_error(
        &invalid_schema,
        StatusCode::BAD_REQUEST,
        Some("invalidSyntax"),
    );

    let first = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(create_body("external-a", "one@example.com")),
    )
    .await;
    assert_eq!(first.status, StatusCode::CREATED);
    let id = first.body["id"].as_str().unwrap();

    let external_collision = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(create_body("external-a", "two@example.com")),
    )
    .await;
    assert_scim_error(
        &external_collision,
        StatusCode::CONFLICT,
        Some("uniqueness"),
    );

    let user_name_collision = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(create_body("external-b", "ONE@EXAMPLE.COM")),
    )
    .await;
    assert_scim_error(
        &user_name_collision,
        StatusCode::CONFLICT,
        Some("uniqueness"),
    );

    let local_user_name_collision = request(
        &router,
        Method::PUT,
        HOST,
        &format!("/scim/v2/Users/{id}"),
        Some(SCIM_TOKEN),
        Some(create_body("external-a", "occupied@example.com")),
    )
    .await;
    assert_scim_error(
        &local_user_name_collision,
        StatusCode::CONFLICT,
        Some("uniqueness"),
    );

    let unsupported_filter = request(
        &router,
        Method::GET,
        HOST,
        "/scim/v2/Users?filter=userName%20sw%20%22one%22",
        Some(SCIM_TOKEN),
        None,
    )
    .await;
    assert_scim_error(
        &unsupported_filter,
        StatusCode::BAD_REQUEST,
        Some("invalidFilter"),
    );

    let unsupported_patch = request(
        &router,
        Method::PATCH,
        HOST,
        &format!("/scim/v2/Users/{id}"),
        Some(SCIM_TOKEN),
        Some(json!({
            "schemas": [PATCH_SCHEMA],
            "Operations": [{
                "op": "replace",
                "path": "displayName",
                "value": "Unsupported"
            }]
        })),
    )
    .await;
    assert_scim_error(
        &unsupported_patch,
        StatusCode::BAD_REQUEST,
        Some("invalidPath"),
    );

    let pathless_extra = request(
        &router,
        Method::PATCH,
        HOST,
        &format!("/scim/v2/Users/{id}"),
        Some(SCIM_TOKEN),
        Some(json!({
            "schemas": [PATCH_SCHEMA],
            "Operations": [{
                "op": "replace",
                "value": {"Active": true, "displayName": "Unsupported"}
            }]
        })),
    )
    .await;
    assert_scim_error(
        &pathless_extra,
        StatusCode::BAD_REQUEST,
        Some("invalidPath"),
    );

    let case_insensitive_active = request(
        &router,
        Method::PATCH,
        HOST,
        &format!("/scim/v2/Users/{id}"),
        Some(SCIM_TOKEN),
        Some(json!({
            "schemas": [PATCH_SCHEMA],
            "Operations": [{
                "op": "replace",
                "value": {"Active": true}
            }]
        })),
    )
    .await;
    assert_eq!(case_insensitive_active.status, StatusCode::OK);
}

fn grant(grant_id: &str, user_id: &str, credential_epoch: u64) -> Grant {
    Grant {
        grant_id: grant_id.to_string(),
        user_id: user_id.to_string(),
        client_id: "scim-race-client".to_string(),
        per_resource: vec![ResourceGrant {
            resource: "https://mcp.example.com".to_string(),
            scopes: vec!["read".to_string()],
            authorization_details: vec![],
        }],
        effective_per_resource: vec![],
        effective_pv: 0,
        allowed_ip_cidrs: vec![],
        allowed_vpce: vec![],
        credential_epoch,
        revision: 0,
        constraints: GrantConstraints {
            max_act_chain: 1,
            actor_allowlist: vec![],
            expires_at: current_unix_secs() + 3_600,
        },
        status: GrantStatus::Active,
    }
}

#[tokio::test]
async fn disable_and_reenable_never_resurrect_old_epoch_artifacts() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    state
        .seed_dev_client("scim-race-client", "http://127.0.0.1/callback", None)
        .await;
    let (router, _) = build_router(state.clone());
    let created = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(create_body("lifecycle-001", "lifecycle@example.com")),
    )
    .await;
    let user_id = created.body["id"].as_str().unwrap().to_string();
    let now = current_unix_secs();

    state
        .sessions
        .create(
            "",
            SessionRecord {
                session_id: "before-disable".to_string(),
                user_id: user_id.clone(),
                credential_epoch: 0,
                auth_time: now,
                created_at: now,
                last_used_at: now,
                device: "Test browser".into(),
                expires_at: now + 3_600,
                acr: None,
                amr: vec!["pwd".to_string()],
            },
        )
        .await
        .unwrap();
    state
        .refresh
        .create(
            "",
            RefreshFamilyRecord {
                family_id: "before-disable-family".to_string(),
                current_version: 0,
                revoked: false,
                client_id: "scim-race-client".to_string(),
                cimd_snapshot: None,
                user_id: user_id.clone(),
                credential_epoch: 0,
                resources: vec!["https://mcp.example.com".to_string()],
                scope: vec!["read".to_string()],
                actor_allowlist: vec![],
                max_act_chain: 1,
                dpop_jkt: None,
                pkce_code_challenge: None,
                auth_time: None,
                acr: None,
                password_credential_version: None,
            },
        )
        .await
        .unwrap();
    state
        .grants
        .put("", grant("before-disable-grant", &user_id, 0))
        .await
        .unwrap();

    let disabled = request(
        &router,
        Method::PATCH,
        HOST,
        &format!("/scim/v2/Users/{user_id}"),
        Some(SCIM_TOKEN),
        Some(patch_active(false)),
    )
    .await;
    assert_eq!(disabled.status, StatusCode::OK);
    assert_eq!(disabled.body["active"], false);
    assert!(state
        .sessions
        .get("", "before-disable")
        .await
        .unwrap()
        .is_none());
    assert!(
        state
            .refresh
            .get("", "before-disable-family")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    assert_eq!(
        state
            .grants
            .get("", "before-disable-grant")
            .await
            .unwrap()
            .unwrap()
            .status,
        GrantStatus::Revoked
    );

    let delayed_create_retry = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(create_body("lifecycle-001", "lifecycle@example.com")),
    )
    .await;
    assert_eq!(delayed_create_retry.status, StatusCode::OK);
    assert_eq!(delayed_create_retry.body["id"], user_id);
    assert_eq!(
        delayed_create_retry.body["active"], false,
        "an old create retry must not re-enable a deprovisioned user"
    );

    let audit = state.credential_audit.snapshot().join("\n");
    assert!(audit.contains("SCIM_CREDENTIAL_USE"));
    assert!(audit.contains(&format!(
        "SCIM_MUTATION action=disable tenant=default user_id={user_id}"
    )));
    assert!(audit.contains("sessions=1 families=1 grants=1"));
    assert!(!audit.contains("externalId"));

    // Model an issuance that passed the active gate immediately before disable but
    // persisted after the cascade scan. It must stay stale after re-enable.
    state
        .sessions
        .create(
            "",
            SessionRecord {
                session_id: "late-old-session".to_string(),
                user_id: user_id.clone(),
                credential_epoch: 0,
                auth_time: now,
                created_at: now,
                last_used_at: now,
                device: "Test browser".into(),
                expires_at: now + 3_600,
                acr: None,
                amr: vec!["pwd".to_string()],
            },
        )
        .await
        .unwrap();
    state
        .refresh
        .create(
            "",
            RefreshFamilyRecord {
                family_id: "late-old-family".to_string(),
                current_version: 0,
                revoked: false,
                client_id: "scim-race-client".to_string(),
                cimd_snapshot: None,
                user_id: user_id.clone(),
                credential_epoch: 0,
                resources: vec!["https://mcp.example.com".to_string()],
                scope: vec!["read".to_string()],
                actor_allowlist: vec![],
                max_act_chain: 1,
                dpop_jkt: None,
                pkce_code_challenge: None,
                auth_time: None,
                acr: None,
                password_credential_version: None,
            },
        )
        .await
        .unwrap();
    state
        .grants
        .put("", grant("late-old-grant", &user_id, 0))
        .await
        .unwrap();

    let enabled = request(
        &router,
        Method::PATCH,
        HOST,
        &format!("/scim/v2/Users/{user_id}"),
        Some(SCIM_TOKEN),
        Some(patch_active(true)),
    )
    .await;
    assert_eq!(enabled.status, StatusCode::OK);
    assert_eq!(enabled.body["active"], true);

    let user = state.users.get_by_id("", &user_id).await.unwrap().unwrap();
    assert_eq!(user.credential_epoch, 1);
    assert!(!user.revocation_pending);
    assert!(state
        .credential_audit
        .snapshot()
        .join("\n")
        .contains(&format!(
            "SCIM_MUTATION action=enable tenant=default user_id={user_id}"
        )));

    let mut stale_headers = HeaderMap::new();
    stale_headers.insert(header::HOST, HeaderValue::from_static(HOST));
    stale_headers.insert(
        header::COOKIE,
        HeaderValue::from_static("__Host-agent_auth_session=late-old-session"),
    );
    assert!(
        agent_auth_http::login::current_session_full(&state, &stale_headers)
            .await
            .is_none(),
        "old-epoch login session must not authenticate after re-enable"
    );

    let refresh_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "grant_type=refresh_token&refresh_token=late-old-family.0&client_id=scim-race-client",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        refresh_response.status(),
        StatusCode::BAD_REQUEST,
        "old-epoch refresh family must not rotate after re-enable"
    );

    state
        .sessions
        .create(
            "",
            SessionRecord {
                session_id: "new-epoch-session".to_string(),
                user_id: user_id.clone(),
                credential_epoch: 1,
                auth_time: now + 1,
                created_at: now + 1,
                last_used_at: now + 1,
                device: "Test browser".into(),
                expires_at: now + 3_600,
                acr: None,
                amr: vec!["pwd".to_string()],
            },
        )
        .await
        .unwrap();
    let grant_list = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/grants")
                .header("host", HOST)
                .header("cookie", "__Host-agent_auth_session=new-epoch-session")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(grant_list.status(), StatusCode::OK);
    let grant_list = to_bytes(grant_list.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&grant_list).unwrap(),
        json!([]),
        "old-epoch active Grant must be hidden and unusable after re-enable"
    );

    assert!(
        agent_auth_http::user_gate::require_active_user_epoch(&state, "", &user_id, 0)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn repeated_disable_rescans_the_same_epoch_for_late_visible_artifacts() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());
    let created = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(create_body(
            "retry-disable-001",
            "retry-disable@example.com",
        )),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let user_id = created.body["id"].as_str().unwrap().to_string();
    let user_path = format!("/scim/v2/Users/{user_id}");

    let first = request(
        &router,
        Method::PATCH,
        HOST,
        &user_path,
        Some(SCIM_TOKEN),
        Some(patch_active(false)),
    )
    .await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.body["active"], false);
    let disabled = state.users.get_by_id("", &user_id).await.unwrap().unwrap();
    assert_eq!(disabled.credential_epoch, 1);
    assert!(!disabled.revocation_pending);

    // Model old-epoch records that committed before the first cleanup but were
    // not yet visible through DynamoDB's eventually consistent user indexes.
    let now = current_unix_secs();
    state
        .sessions
        .create(
            "",
            SessionRecord {
                session_id: "late-visible-session".to_string(),
                user_id: user_id.clone(),
                credential_epoch: 0,
                auth_time: now,
                created_at: now,
                last_used_at: now,
                device: "Test browser".into(),
                expires_at: now + 3_600,
                acr: None,
                amr: vec![],
            },
        )
        .await
        .unwrap();
    state
        .refresh
        .create(
            "",
            RefreshFamilyRecord {
                family_id: "late-visible-family".to_string(),
                current_version: 0,
                revoked: false,
                client_id: "retry-disable-client".to_string(),
                cimd_snapshot: None,
                user_id: user_id.clone(),
                credential_epoch: 0,
                resources: vec![],
                scope: vec![],
                actor_allowlist: vec![],
                max_act_chain: 1,
                dpop_jkt: None,
                pkce_code_challenge: None,
                auth_time: None,
                acr: None,
                password_credential_version: None,
            },
        )
        .await
        .unwrap();
    state
        .grants
        .put("", grant("late-visible-grant", &user_id, 0))
        .await
        .unwrap();

    let retry = request(
        &router,
        Method::PATCH,
        HOST,
        &user_path,
        Some(SCIM_TOKEN),
        Some(patch_active(false)),
    )
    .await;
    assert_eq!(retry.status, StatusCode::OK);
    assert_eq!(retry.body["active"], false);

    let retried = state.users.get_by_id("", &user_id).await.unwrap().unwrap();
    assert_eq!(
        retried.credential_epoch, disabled.credential_epoch,
        "a cleanup retry must resume, not advance, the disable generation"
    );
    let disable_events = state
        .security_events
        .list_by_tenant("default", 1, i64::MAX, 100)
        .await
        .unwrap()
        .into_iter()
        .filter(|stored| stored.event.action == "user.disable")
        .collect::<Vec<_>>();
    assert_eq!(
        disable_events.len(),
        1,
        "a retry of one SCIM disable generation must reuse its canonical event id"
    );
    assert_eq!(
        disable_events[0].event.event_id,
        agent_auth_http::security_event::scim_lifecycle_event_id(
            "default",
            &user_id,
            "disable",
            disabled.credential_epoch,
        )
    );
    assert_eq!(
        disable_events[0].event.correlation.operation_id.as_deref(),
        Some("scim-disable-generation-1")
    );
    assert!(!retried.revocation_pending);
    assert!(state
        .sessions
        .get("", "late-visible-session")
        .await
        .unwrap()
        .is_none());
    assert!(
        state
            .refresh
            .get("", "late-visible-family")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    assert_eq!(
        state
            .grants
            .get("", "late-visible-grant")
            .await
            .unwrap()
            .unwrap()
            .status,
        GrantStatus::Revoked
    );
    assert!(state
        .credential_audit
        .snapshot()
        .iter()
        .any(|line| line.contains("SCIM_MUTATION action=disable")
            && line.contains("sessions=1 families=1 grants=1")));

    state
        .sessions
        .create(
            "",
            SessionRecord {
                session_id: "late-visible-put-session".to_string(),
                user_id: user_id.clone(),
                credential_epoch: 0,
                auth_time: now,
                created_at: now,
                last_used_at: now,
                device: "Test browser".into(),
                expires_at: now + 3_600,
                acr: None,
                amr: vec![],
            },
        )
        .await
        .unwrap();
    let put_retry = request(
        &router,
        Method::PUT,
        HOST,
        &user_path,
        Some(SCIM_TOKEN),
        Some(json!({
            "schemas": [USER_SCHEMA],
            "externalId": "retry-disable-001",
            "userName": "retry-disable@example.com",
            "displayName": "Alice Example",
            "active": false
        })),
    )
    .await;
    assert_eq!(put_retry.status, StatusCode::OK);
    assert_eq!(put_retry.body["active"], false);
    assert_eq!(
        state
            .users
            .get_by_id("", &user_id)
            .await
            .unwrap()
            .unwrap()
            .credential_epoch,
        disabled.credential_epoch
    );
    assert!(state
        .sessions
        .get("", "late-visible-put-session")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn inactive_scim_adoption_cleans_legacy_disabled_epoch_zero() {
    let state = AppState::dev(HOST);
    let user_id = "user:legacy-scim@example.com";
    let now = current_unix_secs();
    state
        .users
        .create_or_get_by_email("", "legacy-scim@example.com", user_id, now)
        .await
        .unwrap();
    state
        .users
        .set_status("", user_id, UserStatus::Disabled, now)
        .await
        .unwrap();
    state
        .sessions
        .create(
            "",
            SessionRecord {
                session_id: "legacy-scim-session".to_string(),
                user_id: user_id.to_string(),
                credential_epoch: 0,
                auth_time: now,
                created_at: now,
                last_used_at: now,
                device: "Test browser".into(),
                expires_at: now + 3_600,
                acr: None,
                amr: vec![],
            },
        )
        .await
        .unwrap();
    state
        .refresh
        .create(
            "",
            RefreshFamilyRecord {
                family_id: "legacy-scim-family".to_string(),
                current_version: 0,
                revoked: false,
                client_id: "legacy-scim-client".to_string(),
                cimd_snapshot: None,
                user_id: user_id.to_string(),
                credential_epoch: 0,
                resources: vec![],
                scope: vec![],
                actor_allowlist: vec![],
                max_act_chain: 1,
                dpop_jkt: None,
                pkce_code_challenge: None,
                auth_time: None,
                acr: None,
                password_credential_version: None,
            },
        )
        .await
        .unwrap();
    state
        .grants
        .put("", grant("legacy-scim-grant", user_id, 0))
        .await
        .unwrap();

    let (router, _) = build_router(state.clone());
    let mut body = create_body("legacy-scim-external", "legacy-scim@example.com");
    body["active"] = json!(false);
    let adopted = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(body),
    )
    .await;
    assert_eq!(adopted.status, StatusCode::CREATED);
    assert_eq!(adopted.body["id"], user_id);
    assert_eq!(adopted.body["active"], false);

    let user = state.users.get_by_id("", user_id).await.unwrap().unwrap();
    assert_eq!(user.status, UserStatus::Disabled);
    assert_eq!(user.credential_epoch, 1);
    assert!(!user.revocation_pending);
    assert!(state
        .sessions
        .get("", "legacy-scim-session")
        .await
        .unwrap()
        .is_none());
    assert!(
        state
            .refresh
            .get("", "legacy-scim-family")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    assert_eq!(
        state
            .grants
            .get("", "legacy-scim-grant")
            .await
            .unwrap()
            .unwrap()
            .status,
        GrantStatus::Revoked
    );

    let enabled = request(
        &router,
        Method::PATCH,
        HOST,
        &format!("/scim/v2/Users/{user_id}"),
        Some(SCIM_TOKEN),
        Some(patch_active(true)),
    )
    .await;
    assert_eq!(enabled.status, StatusCode::OK);
    assert_eq!(enabled.body["active"], true);
    let user = state.users.get_by_id("", user_id).await.unwrap().unwrap();
    assert_eq!(user.status, UserStatus::Active);
    assert_eq!(user.credential_epoch, 1);
}

#[tokio::test]
async fn pending_disable_is_resumed_before_enable() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());
    let created = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(create_body("resume-001", "resume@example.com")),
    )
    .await;
    let user_id = created.body["id"].as_str().unwrap().to_string();
    let now = current_unix_secs();

    let epoch = match state.users.begin_disable("", &user_id, now).await.unwrap() {
        DisableStart::Ready { epoch, .. } => epoch,
        outcome => panic!("unexpected disable outcome: {outcome:?}"),
    };
    assert_eq!(epoch, 1);
    state
        .sessions
        .create(
            "",
            SessionRecord {
                session_id: "pending-session".to_string(),
                user_id: user_id.clone(),
                credential_epoch: 0,
                auth_time: now,
                created_at: now,
                last_used_at: now,
                device: "Test browser".into(),
                expires_at: now + 3_600,
                acr: None,
                amr: vec![],
            },
        )
        .await
        .unwrap();
    state
        .refresh
        .create(
            "",
            RefreshFamilyRecord {
                family_id: "pending-family".to_string(),
                current_version: 0,
                revoked: false,
                client_id: "resume-client".to_string(),
                cimd_snapshot: None,
                user_id: user_id.clone(),
                credential_epoch: 0,
                resources: vec![],
                scope: vec![],
                actor_allowlist: vec![],
                max_act_chain: 1,
                dpop_jkt: None,
                pkce_code_challenge: None,
                auth_time: None,
                acr: None,
                password_credential_version: None,
            },
        )
        .await
        .unwrap();
    state
        .grants
        .put("", grant("pending-grant", &user_id, 0))
        .await
        .unwrap();

    let enabled = request(
        &router,
        Method::PATCH,
        HOST,
        &format!("/scim/v2/Users/{user_id}"),
        Some(SCIM_TOKEN),
        Some(patch_active(true)),
    )
    .await;
    assert_eq!(enabled.status, StatusCode::OK);
    assert_eq!(enabled.body["active"], true);

    let user = state.users.get_by_id("", &user_id).await.unwrap().unwrap();
    assert_eq!(user.status, UserStatus::Active);
    assert_eq!(user.credential_epoch, epoch);
    assert!(!user.revocation_pending);
    assert!(state
        .sessions
        .get("", "pending-session")
        .await
        .unwrap()
        .is_none());
    assert!(
        state
            .refresh
            .get("", "pending-family")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    assert_eq!(
        state
            .grants
            .get("", "pending-grant")
            .await
            .unwrap()
            .unwrap()
            .status,
        GrantStatus::Revoked
    );
}

#[tokio::test]
async fn post_retry_resumes_a_pending_initial_deprovision() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());
    let body = create_body("pending-create-001", "pending-create@example.com");
    let created = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(body.clone()),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let user_id = created.body["id"].as_str().unwrap().to_string();

    state
        .users
        .begin_disable("", &user_id, current_unix_secs())
        .await
        .unwrap();
    let mut retry_body = body;
    retry_body["active"] = Value::Bool(false);
    let retry = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(retry_body),
    )
    .await;
    assert_eq!(retry.status, StatusCode::OK);
    assert_eq!(retry.body["id"], user_id);
    assert_eq!(retry.body["active"], false);
    let record = state.users.get_by_id("", &user_id).await.unwrap().unwrap();
    assert_eq!(record.status, UserStatus::Disabled);
    assert!(!record.revocation_pending);
}

#[tokio::test]
async fn inactive_post_commit_is_fail_closed_and_retry_finishes_cleanup() {
    let state = AppState::dev(HOST);
    let body = create_body("pre-disable-crash-001", "pre-disable-crash@example.com");
    let created = state
        .users
        .create_scim(
            "",
            ScimUserInput {
                user_id: "user:scim:pre-disable-crash".to_string(),
                external_id: "pre-disable-crash-001".to_string(),
                user_name: "pre-disable-crash@example.com".to_string(),
                display_name: Some("Pre-disable crash".to_string()),
                active: false,
                now: current_unix_secs(),
            },
        )
        .await
        .unwrap();
    let user_id = match created {
        ScimCreateOutcome::Created(record) => {
            assert_eq!(record.status, UserStatus::Disabled);
            assert_eq!(record.credential_epoch, 1);
            assert!(record.revocation_pending);
            record.user_id
        }
        outcome => panic!("unexpected create outcome: {outcome:?}"),
    };
    let (router, _) = build_router(state.clone());

    let mut retry_body = body;
    retry_body["active"] = Value::Bool(false);
    let retry = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(retry_body),
    )
    .await;
    assert_eq!(retry.status, StatusCode::OK);
    assert_eq!(retry.body["id"], user_id);
    assert_eq!(retry.body["active"], false);
    let record = state.users.get_by_id("", &user_id).await.unwrap().unwrap();
    assert_eq!(record.status, UserStatus::Disabled);
    assert_eq!(record.credential_epoch, 1);
    assert!(!record.revocation_pending);

    let enabled = request(
        &router,
        Method::PATCH,
        HOST,
        &format!("/scim/v2/Users/{user_id}"),
        Some(SCIM_TOKEN),
        Some(patch_active(true)),
    )
    .await;
    assert_eq!(enabled.status, StatusCode::OK);
    let moved = request(
        &router,
        Method::PUT,
        HOST,
        &format!("/scim/v2/Users/{user_id}"),
        Some(SCIM_TOKEN),
        Some(json!({
            "schemas": [USER_SCHEMA],
            "externalId": "pre-disable-crash-002",
            "userName": "pre-disable-crash-moved@example.com",
            "active": true
        })),
    )
    .await;
    assert_eq!(moved.status, StatusCode::OK);

    let mut historical_body = create_body("pre-disable-crash-001", "pre-disable-crash@example.com");
    historical_body["active"] = Value::Bool(false);
    let delayed_retry = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(historical_body),
    )
    .await;
    assert_eq!(delayed_retry.status, StatusCode::OK);
    assert_eq!(delayed_retry.body["id"], user_id);
    assert_eq!(delayed_retry.body["active"], true);
    assert_eq!(delayed_retry.body["externalId"], "pre-disable-crash-002");
}

#[tokio::test]
async fn inactive_post_adoption_commit_is_fail_closed_before_cleanup() {
    let state = AppState::dev(HOST);
    let now = current_unix_secs();
    let local_user_id = "user:inactive-adoption@example.com";
    state
        .users
        .create_or_get_by_email("", "inactive-adoption@example.com", local_user_id, now)
        .await
        .unwrap();

    let created = state
        .users
        .create_scim(
            "",
            ScimUserInput {
                user_id: "user:scim:must-not-replace-local".to_string(),
                external_id: "inactive-adoption-001".to_string(),
                user_name: "inactive-adoption@example.com".to_string(),
                display_name: Some("Inactive adoption".to_string()),
                active: false,
                now: now + 1,
            },
        )
        .await
        .unwrap();
    let ScimCreateOutcome::Created(record) = created else {
        panic!("unexpected create outcome: {created:?}");
    };
    assert_eq!(record.user_id, local_user_id);
    assert_eq!(record.status, UserStatus::Disabled);
    assert_eq!(record.credential_epoch, 1);
    assert!(record.revocation_pending);

    let (router, _) = build_router(state.clone());
    let mut retry_body = create_body("inactive-adoption-001", "inactive-adoption@example.com");
    retry_body["active"] = Value::Bool(false);
    let retried = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(retry_body),
    )
    .await;
    assert_eq!(retried.status, StatusCode::OK);
    assert_eq!(retried.body["id"], local_user_id);
    assert_eq!(retried.body["active"], false);
    let record = state
        .users
        .get_by_id("", local_user_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.status, UserStatus::Disabled);
    assert_eq!(record.credential_epoch, 1);
    assert!(!record.revocation_pending);
}

#[tokio::test]
async fn inactive_put_commit_is_fail_closed_and_retry_finishes_cleanup() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());
    let created = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(create_body("put-crash-001", "put-crash@example.com")),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let user_id = created.body["id"].as_str().unwrap().to_string();
    let now = current_unix_secs();
    state
        .sessions
        .create(
            "",
            SessionRecord {
                session_id: "put-crash-session".to_string(),
                user_id: user_id.clone(),
                credential_epoch: 0,
                auth_time: now,
                created_at: now,
                last_used_at: now,
                device: "Test browser".into(),
                expires_at: now + 3_600,
                acr: None,
                amr: vec![],
            },
        )
        .await
        .unwrap();
    state
        .refresh
        .create(
            "",
            RefreshFamilyRecord {
                family_id: "put-crash-family".to_string(),
                current_version: 0,
                revoked: false,
                client_id: "put-crash-client".to_string(),
                cimd_snapshot: None,
                user_id: user_id.clone(),
                credential_epoch: 0,
                resources: vec![],
                scope: vec![],
                actor_allowlist: vec![],
                max_act_chain: 1,
                dpop_jkt: None,
                pkce_code_challenge: None,
                auth_time: None,
                acr: None,
                password_credential_version: None,
            },
        )
        .await
        .unwrap();
    state
        .grants
        .put("", grant("put-crash-grant", &user_id, 0))
        .await
        .unwrap();

    let replaced = state
        .users
        .replace_scim(
            "",
            &user_id,
            agent_auth_http::ports::ScimReplaceInput {
                external_id: "put-crash-002".to_string(),
                user_name: "put-crash-moved@example.com".to_string(),
                display_name: Some("PUT crash".to_string()),
                active: false,
                now: now + 1,
            },
        )
        .await
        .unwrap();
    let agent_auth_http::ports::ScimReplaceOutcome::Updated(record) = replaced else {
        panic!("unexpected replace outcome: {replaced:?}");
    };
    assert_eq!(record.status, UserStatus::Disabled);
    assert_eq!(record.credential_epoch, 1);
    assert!(record.revocation_pending);
    assert!(state
        .sessions
        .get("", "put-crash-session")
        .await
        .unwrap()
        .is_some());
    assert!(
        !state
            .refresh
            .get("", "put-crash-family")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );

    let retried = request(
        &router,
        Method::PUT,
        HOST,
        &format!("/scim/v2/Users/{user_id}"),
        Some(SCIM_TOKEN),
        Some(json!({
            "schemas": [USER_SCHEMA],
            "externalId": "put-crash-002",
            "userName": "put-crash-moved@example.com",
            "displayName": "PUT crash",
            "active": false
        })),
    )
    .await;
    assert_eq!(retried.status, StatusCode::OK);
    assert_eq!(retried.body["active"], false);
    let record = state.users.get_by_id("", &user_id).await.unwrap().unwrap();
    assert_eq!(record.status, UserStatus::Disabled);
    assert_eq!(record.credential_epoch, 1);
    assert!(!record.revocation_pending);
    assert!(state
        .sessions
        .get("", "put-crash-session")
        .await
        .unwrap()
        .is_none());
    assert!(
        state
            .refresh
            .get("", "put-crash-family")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    assert_eq!(
        state
            .grants
            .get("", "put-crash-grant")
            .await
            .unwrap()
            .unwrap()
            .status,
        GrantStatus::Revoked
    );
}

#[tokio::test]
async fn put_enable_wins_over_an_inactive_post_that_crashed_before_disable() {
    let state = AppState::dev(HOST);
    let created = state
        .users
        .create_scim(
            "",
            ScimUserInput {
                user_id: "user:scim:put-before-disable".to_string(),
                external_id: "put-before-disable-001".to_string(),
                user_name: "put-before-disable@example.com".to_string(),
                display_name: Some("PUT before disable".to_string()),
                active: false,
                now: current_unix_secs(),
            },
        )
        .await
        .unwrap();
    let user_id = match created {
        ScimCreateOutcome::Created(record) => record.user_id,
        outcome => panic!("unexpected create outcome: {outcome:?}"),
    };
    state
        .sessions
        .create(
            "",
            SessionRecord {
                session_id: "put-before-disable-session".to_string(),
                user_id: user_id.clone(),
                credential_epoch: 0,
                auth_time: current_unix_secs(),
                created_at: current_unix_secs(),
                last_used_at: current_unix_secs(),
                device: "Test browser".into(),
                expires_at: current_unix_secs() + 3_600,
                acr: None,
                amr: vec![],
            },
        )
        .await
        .unwrap();
    let (router, _) = build_router(state.clone());

    let replaced = request(
        &router,
        Method::PUT,
        HOST,
        &format!("/scim/v2/Users/{user_id}"),
        Some(SCIM_TOKEN),
        Some(json!({
            "schemas": [USER_SCHEMA],
            "externalId": "put-before-disable-002",
            "userName": "put-before-disable-moved@example.com",
            "active": true
        })),
    )
    .await;
    assert_eq!(replaced.status, StatusCode::OK);
    assert_eq!(replaced.body["active"], true);
    assert!(state
        .sessions
        .get("", "put-before-disable-session")
        .await
        .unwrap()
        .is_none());
    assert!(state
        .credential_audit
        .snapshot()
        .iter()
        .any(|line| line.contains("SCIM_MUTATION action=disable")
            && line.contains("sessions=1 families=0 grants=0")));

    let mut historical = create_body("put-before-disable-001", "put-before-disable@example.com");
    historical["active"] = Value::Bool(false);
    let delayed_retry = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(historical),
    )
    .await;
    assert_eq!(delayed_retry.status, StatusCode::OK);
    assert_eq!(delayed_retry.body["id"], user_id);
    assert_eq!(delayed_retry.body["active"], true);
    assert_eq!(delayed_retry.body["externalId"], "put-before-disable-002");
    assert_eq!(
        delayed_retry.body["userName"],
        "put-before-disable-moved@example.com"
    );
}

#[tokio::test]
async fn patch_enable_wins_over_an_inactive_post_that_crashed_before_disable() {
    let state = AppState::dev(HOST);
    let created = state
        .users
        .create_scim(
            "",
            ScimUserInput {
                user_id: "user:scim:patch-before-disable".to_string(),
                external_id: "patch-before-disable-001".to_string(),
                user_name: "patch-before-disable@example.com".to_string(),
                display_name: Some("PATCH before disable".to_string()),
                active: false,
                now: current_unix_secs(),
            },
        )
        .await
        .unwrap();
    let user_id = match created {
        ScimCreateOutcome::Created(record) => record.user_id,
        outcome => panic!("unexpected create outcome: {outcome:?}"),
    };
    let (router, _) = build_router(state.clone());

    let enabled = request(
        &router,
        Method::PATCH,
        HOST,
        &format!("/scim/v2/Users/{user_id}"),
        Some(SCIM_TOKEN),
        Some(patch_active(true)),
    )
    .await;
    assert_eq!(enabled.status, StatusCode::OK);
    assert_eq!(enabled.body["active"], true);

    let mut historical = create_body(
        "patch-before-disable-001",
        "patch-before-disable@example.com",
    );
    historical["active"] = Value::Bool(false);
    let delayed_retry = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(historical),
    )
    .await;
    assert_eq!(delayed_retry.status, StatusCode::OK);
    assert_eq!(delayed_retry.body["id"], user_id);
    assert_eq!(delayed_retry.body["active"], true);
}

#[tokio::test]
async fn exact_post_retry_cannot_rebind_tombstoned_identity() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());
    let body = create_body("tombstone-001", "tombstone@example.com");
    let created = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(body.clone()),
    )
    .await;
    let user_id = created.body["id"].as_str().unwrap();
    state
        .users
        .set_status("", user_id, UserStatus::Tombstoned, current_unix_secs())
        .await
        .unwrap();

    let mut inactive_retry = body;
    inactive_retry["active"] = Value::Bool(false);
    let retry = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(inactive_retry),
    )
    .await;
    assert_scim_error(&retry, StatusCode::CONFLICT, Some("uniqueness"));
}

fn tenant_state() -> AppState {
    let now = current_unix_secs();
    let store = MemoryAdminCredentialStore::default();
    let platform_ref = "memory:platform";
    store.put_set(
        platform_ref,
        &AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            AdminCredentialRecord::explicit(
                "platform-v1",
                "platform-secret-value",
                now - 60,
                now - 60,
                now + 86_400,
            ),
        ),
        now,
    );
    let mut admin_refs = HashMap::new();
    let mut scim_refs = HashMap::new();
    for tenant in ["t1", "t2"] {
        let admin_ref = format!("memory:{tenant}:admin");
        admin_refs.insert(tenant.to_string(), admin_ref.clone());
        store.put_set(
            admin_ref,
            &AdminCredentialSet::single(
                AdminCredentialOwner::tenant(tenant),
                AdminCredentialRecord::explicit(
                    format!("{tenant}-admin-v1"),
                    format!("{tenant}-admin-secret-value"),
                    now - 60,
                    now - 60,
                    now + 86_400,
                ),
            ),
            now,
        );
        let scim_ref = format!("memory:{tenant}:scim");
        scim_refs.insert(tenant.to_string(), scim_ref.clone());
        store.put_set(
            scim_ref,
            &AdminCredentialSet::single(
                AdminCredentialOwner::scim_tenant(tenant),
                AdminCredentialRecord::explicit(
                    format!("{tenant}-scim-v1"),
                    format!("{tenant}-scim-secret-value"),
                    now - 60,
                    now - 60,
                    now + 86_400,
                ),
            ),
            now,
        );
    }
    let mut state = AppState::dev("t1.aws.example.com");
    state.form = agent_auth_discovery::Form::Saas {
        zone: "aws.example.com".to_string(),
        control_host: "c.aws.example.com".to_string(),
    };
    state.tenant_partitioning = true;
    state.saas_tenants = Arc::new(vec!["t1".to_string(), "t2".to_string()]);
    state.admin_credentials = Arc::new(AdminCredentialResolver::memory_scoped(
        Some(platform_ref.to_string()),
        admin_refs,
        scim_refs,
        store,
        Duration::ZERO,
    ));
    state
}

#[tokio::test]
async fn credentials_identifiers_filters_and_retries_are_tenant_isolated() {
    let (router, _) = build_router(tenant_state());
    let t1 = request(
        &router,
        Method::POST,
        "t1.aws.example.com",
        "/scim/v2/Users",
        Some("t1-scim-secret-value"),
        Some(create_body("shared-external", "shared@example.com")),
    )
    .await;
    let t2 = request(
        &router,
        Method::POST,
        "t2.aws.example.com",
        "/scim/v2/Users",
        Some("t2-scim-secret-value"),
        Some(create_body("shared-external", "shared@example.com")),
    )
    .await;
    assert_eq!(t1.status, StatusCode::CREATED);
    assert_eq!(t2.status, StatusCode::CREATED);
    assert_ne!(t1.body["id"], t2.body["id"]);

    let crossed_credential = request(
        &router,
        Method::GET,
        "t2.aws.example.com",
        "/scim/v2/Users?filter=externalId%20eq%20%22shared-external%22",
        Some("t1-scim-secret-value"),
        None,
    )
    .await;
    assert_eq!(crossed_credential.status, StatusCode::UNAUTHORIZED);

    let crossed_id = request(
        &router,
        Method::GET,
        "t2.aws.example.com",
        &format!("/scim/v2/Users/{}", t1.body["id"].as_str().unwrap()),
        Some("t2-scim-secret-value"),
        None,
    )
    .await;
    assert_scim_error(&crossed_id, StatusCode::NOT_FOUND, None);

    let t2_filter = request(
        &router,
        Method::GET,
        "t2.aws.example.com",
        "/scim/v2/Users?filter=externalId%20eq%20%22shared-external%22",
        Some("t2-scim-secret-value"),
        None,
    )
    .await;
    assert_eq!(t2_filter.body["totalResults"], 1);
    assert_eq!(t2_filter.body["Resources"][0]["id"], t2.body["id"]);

    let t1_retry = request(
        &router,
        Method::POST,
        "t1.aws.example.com",
        "/scim/v2/Users",
        Some("t1-scim-secret-value"),
        Some(create_body("shared-external", "shared@example.com")),
    )
    .await;
    assert_eq!(t1_retry.status, StatusCode::OK);
    assert_eq!(t1_retry.body["id"], t1.body["id"]);
}

#[tokio::test]
async fn groups_crud_retries_and_role_mapping_remain_separate_domains() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());
    let user_1 = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(create_body("group-user-1", "group-user-1@example.com")),
    )
    .await;
    let user_2 = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Users",
        Some(SCIM_TOKEN),
        Some(create_body("group-user-2", "group-user-2@example.com")),
    )
    .await;
    assert_eq!(user_1.status, StatusCode::CREATED);
    assert_eq!(user_2.status, StatusCode::CREATED);
    let user_1_id = user_1.body["id"].as_str().unwrap();
    let user_2_id = user_2.body["id"].as_str().unwrap();

    let rejected_role = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Groups",
        Some(SCIM_TOKEN),
        Some(json!({
            "schemas": [GROUP_SCHEMA],
            "externalId": "payload-role",
            "displayName": "Payload Role",
            "members": [{"value": user_1_id}],
            "role": "owner"
        })),
    )
    .await;
    assert_scim_error(&rejected_role, StatusCode::BAD_REQUEST, Some("invalidPath"));

    let created = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Groups",
        Some(SCIM_TOKEN),
        Some(group_body(
            "directory-admins",
            "Directory Admins",
            &[user_1_id],
        )),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert_eq!(created.body["schemas"], json!([GROUP_SCHEMA]));
    assert_eq!(created.body["members"][0]["value"], user_1_id);
    let group_id = created.body["id"].as_str().unwrap().to_string();

    let retry = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Groups",
        Some(SCIM_TOKEN),
        Some(group_body(
            "directory-admins",
            "Directory Admins",
            &[user_1_id],
        )),
    )
    .await;
    assert_eq!(retry.status, StatusCode::OK);
    assert_eq!(retry.body["id"], group_id);
    assert_eq!(retry.body["displayName"], "Directory Admins");
    assert_eq!(retry.body["members"][0]["value"], user_1_id);

    let conflicting_retry = request(
        &router,
        Method::POST,
        HOST,
        "/scim/v2/Groups",
        Some(SCIM_TOKEN),
        Some(group_body(
            "directory-admins",
            "Conflicting Retry",
            &[user_2_id],
        )),
    )
    .await;
    assert_scim_error(&conflicting_retry, StatusCode::CONFLICT, Some("uniqueness"));

    let by_filter = request(
        &router,
        Method::GET,
        HOST,
        "/scim/v2/Groups?filter=externalId%20eq%20%22directory-admins%22",
        Some(SCIM_TOKEN),
        None,
    )
    .await;
    assert_eq!(by_filter.status, StatusCode::OK);
    assert_eq!(by_filter.body["totalResults"], 1);
    assert_eq!(by_filter.body["Resources"][0]["id"], group_id);

    let replacement = group_body(
        "directory-admins",
        "Platform Admins",
        &[user_1_id, user_2_id],
    );
    let replaced = request(
        &router,
        Method::PUT,
        HOST,
        &format!("/scim/v2/Groups/{group_id}"),
        Some(SCIM_TOKEN),
        Some(replacement.clone()),
    )
    .await;
    assert_eq!(replaced.status, StatusCode::OK);
    assert_eq!(replaced.body["displayName"], "Platform Admins");
    assert_eq!(replaced.body["members"].as_array().unwrap().len(), 2);
    let replace_version = state
        .scim_groups
        .get("", &group_id)
        .await
        .unwrap()
        .unwrap()
        .version;
    let replace_retry = request(
        &router,
        Method::PUT,
        HOST,
        &format!("/scim/v2/Groups/{group_id}"),
        Some(SCIM_TOKEN),
        Some(replacement),
    )
    .await;
    assert_eq!(replace_retry.status, StatusCode::OK);
    assert_eq!(replace_retry.body, replaced.body);
    assert_eq!(
        state
            .scim_groups
            .get("", &group_id)
            .await
            .unwrap()
            .unwrap()
            .version,
        replace_version,
        "an exact PUT retry must not advance Group version"
    );

    let patch = json!({
        "schemas": [PATCH_SCHEMA],
        "Operations": [{
            "op": "remove",
            "path": format!("members[value eq \"{user_2_id}\"]")
        }]
    });
    let patched = request(
        &router,
        Method::PATCH,
        HOST,
        &format!("/scim/v2/Groups/{group_id}"),
        Some(SCIM_TOKEN),
        Some(patch.clone()),
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK);
    assert_eq!(patched.body["members"].as_array().unwrap().len(), 1);
    let version = state
        .scim_groups
        .get("", &group_id)
        .await
        .unwrap()
        .unwrap()
        .version;
    let patch_retry = request(
        &router,
        Method::PATCH,
        HOST,
        &format!("/scim/v2/Groups/{group_id}"),
        Some(SCIM_TOKEN),
        Some(patch),
    )
    .await;
    assert_eq!(patch_retry.status, StatusCode::OK);
    assert_eq!(
        state
            .scim_groups
            .get("", &group_id)
            .await
            .unwrap()
            .unwrap()
            .version,
        version,
        "an exact PATCH retry must not advance Group version"
    );

    let scim_cannot_map = request(
        &router,
        Method::PUT,
        HOST,
        "/admin/scim/group-role-mappings/directory-admins",
        Some(SCIM_TOKEN),
        Some(json!({"role": "admin"})),
    )
    .await;
    assert_eq!(scim_cannot_map.status, StatusCode::UNAUTHORIZED);

    let unmapped = request(
        &router,
        Method::GET,
        HOST,
        &format!("/admin/scim/effective-role/{user_1_id}"),
        Some(ADMIN_TOKEN),
        None,
    )
    .await;
    assert_eq!(unmapped.status, StatusCode::OK);
    assert!(unmapped.body["role"].is_null());

    state
        .users
        .put_attributes(
            "",
            user_1_id,
            "https://rs.example.com",
            BTreeMap::from([("role".to_string(), "owner".to_string())]),
            0,
        )
        .await
        .unwrap();
    let rs_attribute_ignored = request(
        &router,
        Method::GET,
        HOST,
        &format!("/admin/scim/effective-role/{user_1_id}"),
        Some(ADMIN_TOKEN),
        None,
    )
    .await;
    assert!(rs_attribute_ignored.body["role"].is_null());

    let unknown_role = request(
        &router,
        Method::PUT,
        HOST,
        "/admin/scim/group-role-mappings/directory-admins",
        Some(ADMIN_TOKEN),
        Some(json!({"role": "superadmin"})),
    )
    .await;
    assert_eq!(unknown_role.status, StatusCode::BAD_REQUEST);

    for role in ["member", "auditor", "admin", "owner"] {
        let mapped = request(
            &router,
            Method::PUT,
            HOST,
            "/admin/scim/group-role-mappings/directory-admins",
            Some(ADMIN_TOKEN),
            Some(json!({"role": role})),
        )
        .await;
        assert_eq!(mapped.status, StatusCode::OK);
        assert_eq!(mapped.body["role"], role);
        let effective = request(
            &router,
            Method::GET,
            HOST,
            &format!("/admin/scim/effective-role/{user_1_id}"),
            Some(ADMIN_TOKEN),
            None,
        )
        .await;
        assert_eq!(effective.body["role"], role);
        assert_eq!(
            effective.body["mappings"][0]["externalId"],
            "directory-admins"
        );
    }

    let mapping_removed = request(
        &router,
        Method::DELETE,
        HOST,
        "/admin/scim/group-role-mappings/directory-admins",
        Some(ADMIN_TOKEN),
        None,
    )
    .await;
    assert_eq!(mapping_removed.status, StatusCode::NO_CONTENT);
    let after_mapping_remove = request(
        &router,
        Method::GET,
        HOST,
        &format!("/admin/scim/effective-role/{user_1_id}"),
        Some(ADMIN_TOKEN),
        None,
    )
    .await;
    assert!(after_mapping_remove.body["role"].is_null());

    request(
        &router,
        Method::PUT,
        HOST,
        "/admin/scim/group-role-mappings/directory-admins",
        Some(ADMIN_TOKEN),
        Some(json!({"role": "owner"})),
    )
    .await;
    let deleted = request(
        &router,
        Method::DELETE,
        HOST,
        &format!("/scim/v2/Groups/{group_id}"),
        Some(SCIM_TOKEN),
        None,
    )
    .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    let delete_retry = request(
        &router,
        Method::DELETE,
        HOST,
        &format!("/scim/v2/Groups/{group_id}"),
        Some(SCIM_TOKEN),
        None,
    )
    .await;
    assert_eq!(delete_retry.status, StatusCode::NO_CONTENT);
    let after_group_delete = request(
        &router,
        Method::GET,
        HOST,
        &format!("/admin/scim/effective-role/{user_1_id}"),
        Some(ADMIN_TOKEN),
        None,
    )
    .await;
    assert!(after_group_delete.body["role"].is_null());
    let mappings = request(
        &router,
        Method::GET,
        HOST,
        "/admin/scim/group-role-mappings",
        Some(ADMIN_TOKEN),
        None,
    )
    .await;
    assert_eq!(mappings.body["mappings"], json!([]));
}

#[tokio::test]
async fn group_memberships_mappings_and_credentials_are_tenant_isolated() {
    let (router, _) = build_router(tenant_state());
    let t1_user = request(
        &router,
        Method::POST,
        "t1.aws.example.com",
        "/scim/v2/Users",
        Some("t1-scim-secret-value"),
        Some(create_body("t1-group-user", "group-user@example.com")),
    )
    .await;
    let t2_user = request(
        &router,
        Method::POST,
        "t2.aws.example.com",
        "/scim/v2/Users",
        Some("t2-scim-secret-value"),
        Some(create_body("t2-group-user", "group-user@example.com")),
    )
    .await;
    let t1_user_id = t1_user.body["id"].as_str().unwrap();
    let t2_user_id = t2_user.body["id"].as_str().unwrap();

    let t1_group = request(
        &router,
        Method::POST,
        "t1.aws.example.com",
        "/scim/v2/Groups",
        Some("t1-scim-secret-value"),
        Some(group_body("t1-owners", "T1 Owners", &[t1_user_id])),
    )
    .await;
    assert_eq!(t1_group.status, StatusCode::CREATED);
    let t1_group_id = t1_group.body["id"].as_str().unwrap();

    let crossed_credential = request(
        &router,
        Method::GET,
        "t2.aws.example.com",
        "/scim/v2/Groups",
        Some("t1-scim-secret-value"),
        None,
    )
    .await;
    assert_eq!(crossed_credential.status, StatusCode::UNAUTHORIZED);
    let crossed_group_id = request(
        &router,
        Method::GET,
        "t2.aws.example.com",
        &format!("/scim/v2/Groups/{t1_group_id}"),
        Some("t2-scim-secret-value"),
        None,
    )
    .await;
    assert_scim_error(&crossed_group_id, StatusCode::NOT_FOUND, None);

    let crossed_member = request(
        &router,
        Method::POST,
        "t2.aws.example.com",
        "/scim/v2/Groups",
        Some("t2-scim-secret-value"),
        Some(group_body("bad-cross-member", "Bad", &[t1_user_id])),
    )
    .await;
    assert_scim_error(
        &crossed_member,
        StatusCode::BAD_REQUEST,
        Some("invalidValue"),
    );

    let t2_cannot_map_t1 = request(
        &router,
        Method::PUT,
        "t2.aws.example.com",
        "/admin/scim/group-role-mappings/t1-owners",
        Some("t2-admin-secret-value"),
        Some(json!({"role": "owner"})),
    )
    .await;
    assert_eq!(t2_cannot_map_t1.status, StatusCode::NOT_FOUND);

    let t1_map = request(
        &router,
        Method::PUT,
        "t1.aws.example.com",
        "/admin/scim/group-role-mappings/t1-owners",
        Some("t1-admin-secret-value"),
        Some(json!({"role": "owner"})),
    )
    .await;
    assert_eq!(t1_map.status, StatusCode::OK);
    let t1_effective = request(
        &router,
        Method::GET,
        "t1.aws.example.com",
        &format!("/admin/scim/effective-role/{t1_user_id}"),
        Some("t1-admin-secret-value"),
        None,
    )
    .await;
    assert_eq!(t1_effective.body["role"], "owner");
    let t2_effective = request(
        &router,
        Method::GET,
        "t2.aws.example.com",
        &format!("/admin/scim/effective-role/{t2_user_id}"),
        Some("t2-admin-secret-value"),
        None,
    )
    .await;
    assert!(t2_effective.body["role"].is_null());
}
