use agent_auth_http::{
    build_router,
    ports::Signer,
    security_event::{SecurityEventOutcome, SecurityEventStore},
    ssf::{
        SignedSet, SsfAttemptResult, SsfDeliveryStatus, SsfStore, SsfStream,
        CAEP_SESSION_REVOKED_EVENT, RISC_ACCOUNT_DISABLED_EVENT, SSF_VERIFICATION_EVENT,
    },
    AppState,
};
use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use serde_json::{json, Value};
use tower::ServiceExt;

const HOST: &str = "localhost";
const ADMIN_TOKEN: &str = "dev-admin-token-not-for-prod";

async fn request(
    router: &axum::Router,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", HOST)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
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
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, value)
}

#[tokio::test]
async fn admin_stream_lifecycle_requires_access_manage_and_is_revision_safe() {
    let state = AppState::dev(HOST);
    let inspection = state.clone();
    let (router, _) = build_router(state);
    let create = json!({
        "endpoint": "https://receiver.example.net/events",
        "audience": "https://receiver.example.net",
        "event_types": [
            RISC_ACCOUNT_DISABLED_EVENT,
            CAEP_SESSION_REVOKED_EVENT
        ]
    });

    assert_eq!(
        request(
            &router,
            Method::POST,
            "/admin/ssf/streams",
            None,
            Some(create.clone()),
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, created) = request(
        &router,
        Method::POST,
        "/admin/ssf/streams",
        Some(ADMIN_TOKEN),
        Some(create),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["tenant_id"], "default");
    assert_eq!(created["revision"], 1);
    assert_eq!(created["status"], "enabled");
    let stream_id = created["stream_id"].as_str().unwrap();

    let (status, listed) = request(
        &router,
        Method::GET,
        "/admin/ssf/streams",
        Some(ADMIN_TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["streams"].as_array().unwrap().len(), 1);
    assert_eq!(listed["streams"][0]["stream_id"], stream_id);

    let replace_path = format!("/admin/ssf/streams/{stream_id}");
    let replacement = json!({
        "expected_revision": 9,
        "endpoint": "https://replacement.example.net/events",
        "audience": "https://replacement.example.net",
        "event_types": [RISC_ACCOUNT_DISABLED_EVENT]
    });
    assert_eq!(
        request(
            &router,
            Method::PUT,
            &replace_path,
            Some(ADMIN_TOKEN),
            Some(replacement),
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (status, replaced) = request(
        &router,
        Method::PUT,
        &replace_path,
        Some(ADMIN_TOKEN),
        Some(json!({
            "expected_revision": 1,
            "endpoint": "https://replacement.example.net/events",
            "audience": "https://replacement.example.net",
            "event_types": [RISC_ACCOUNT_DISABLED_EVENT]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{replaced}");
    assert_eq!(replaced["revision"], 2);
    assert_eq!(
        replaced["endpoint"],
        "https://replacement.example.net/events"
    );

    for (action, expected_revision, expected_status) in [
        ("pause", 2, "paused"),
        ("resume", 3, "enabled"),
        ("revoke", 4, "revoked"),
    ] {
        let (status, stream) = request(
            &router,
            Method::POST,
            &format!("/admin/ssf/streams/{stream_id}/{action}"),
            Some(ADMIN_TOKEN),
            Some(json!({ "expected_revision": expected_revision })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{action}: {stream}");
        assert_eq!(stream["revision"], expected_revision + 1);
        assert_eq!(stream["status"], expected_status);
    }
    assert_eq!(
        request(
            &router,
            Method::POST,
            &format!("/admin/ssf/streams/{stream_id}/resume"),
            Some(ADMIN_TOKEN),
            Some(json!({ "expected_revision": 5 })),
        )
        .await
        .0,
        StatusCode::GONE
    );

    let events = inspection
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    for action in [
        "ssf.stream.create",
        "ssf.stream.replace",
        "ssf.stream.pause",
        "ssf.stream.resume",
        "ssf.stream.revoke",
    ] {
        assert!(events.iter().any(|stored| {
            stored.event.action == action && stored.event.outcome == SecurityEventOutcome::Success
        }));
    }
    assert!(events.iter().any(|stored| {
        stored.event.action == "ssf.stream.replace"
            && stored.event.outcome == SecurityEventOutcome::Denied
    }));
}

#[tokio::test]
async fn standby_rejects_all_ssf_management_writes_but_keeps_reads_available() {
    let mut state = AppState::dev(HOST);
    let stream = SsfStream::new(
        "default",
        "standby-test-stream",
        "https://receiver.example.net/events".to_string(),
        "https://receiver.example.net".to_string(),
        vec![RISC_ACCOUNT_DISABLED_EVENT.to_string()],
        agent_auth_http::current_unix_secs(),
    )
    .unwrap();
    state.ssf.create_stream(stream).await.unwrap();
    state.ssf_management_enabled = false;
    let (router, _) = build_router(state);

    let writes = vec![
        (
            Method::POST,
            "/admin/ssf/streams".to_string(),
            Some(json!({
                "endpoint": "https://receiver.example.net/events",
                "audience": "https://receiver.example.net",
                "event_types": [RISC_ACCOUNT_DISABLED_EVENT]
            })),
        ),
        (
            Method::PUT,
            "/admin/ssf/streams/standby-test-stream".to_string(),
            Some(json!({
                "expected_revision": 1,
                "endpoint": "https://replacement.example.net/events",
                "audience": "https://replacement.example.net",
                "event_types": [RISC_ACCOUNT_DISABLED_EVENT]
            })),
        ),
        (
            Method::POST,
            "/admin/ssf/streams/standby-test-stream/pause".to_string(),
            Some(json!({ "expected_revision": 1 })),
        ),
        (
            Method::POST,
            "/admin/ssf/streams/standby-test-stream/resume".to_string(),
            Some(json!({ "expected_revision": 1 })),
        ),
        (
            Method::POST,
            "/admin/ssf/streams/standby-test-stream/revoke".to_string(),
            Some(json!({ "expected_revision": 1 })),
        ),
        (
            Method::POST,
            "/admin/ssf/streams/standby-test-stream/verify".to_string(),
            Some(json!({ "expected_revision": 1, "state": "receiver-state" })),
        ),
        (
            Method::POST,
            "/admin/ssf/streams/standby-test-stream/deliveries/1/event/redrive".to_string(),
            None,
        ),
    ];
    for (method, path, body) in writes {
        let (status, response) = request(&router, method, &path, Some(ADMIN_TOKEN), body).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{path}: {response}"
        );
        assert_eq!(
            response["error"],
            "SSF management unavailable in standby Region"
        );
    }

    assert_eq!(
        request(
            &router,
            Method::POST,
            "/admin/ssf/streams",
            None,
            Some(json!({
                "endpoint": "https://receiver.example.net/events",
                "audience": "https://receiver.example.net",
                "event_types": [RISC_ACCOUNT_DISABLED_EVENT]
            })),
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(
            &router,
            Method::GET,
            "/admin/ssf/streams",
            Some(ADMIN_TOKEN),
            None,
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(
            &router,
            Method::GET,
            "/admin/ssf/streams/standby-test-stream",
            Some(ADMIN_TOKEN),
            None,
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn stream_registration_quota_returns_conflict_and_denied_audit() {
    let state = AppState::dev(HOST);
    let inspection = state.clone();
    let (router, _) = build_router(state);
    for index in 0..agent_auth_http::ssf::SSF_MAX_REGISTERED_STREAMS_PER_TENANT {
        let (status, body) = request(
            &router,
            Method::POST,
            "/admin/ssf/streams",
            Some(ADMIN_TOKEN),
            Some(json!({
                "endpoint": format!("https://receiver-{index}.example.net/events"),
                "audience": format!("https://receiver-{index}.example.net"),
                "event_types": [RISC_ACCOUNT_DISABLED_EVENT]
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "stream {index}: {body}");
    }

    let (status, body) = request(
        &router,
        Method::POST,
        "/admin/ssf/streams",
        Some(ADMIN_TOKEN),
        Some(json!({
            "endpoint": "https://quota-exceeded.example.net/events",
            "audience": "https://quota-exceeded.example.net",
            "event_types": [RISC_ACCOUNT_DISABLED_EVENT]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "SSF stream quota exceeded");

    let events = inspection
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|stored| {
                stored.event.action == "ssf.stream.create"
                    && stored.event.outcome == SecurityEventOutcome::Success
            })
            .count(),
        agent_auth_http::ssf::SSF_MAX_REGISTERED_STREAMS_PER_TENANT
    );
    assert!(events.iter().any(|stored| {
        stored.event.action == "ssf.stream.create"
            && stored.event.outcome == SecurityEventOutcome::Denied
    }));
}

#[tokio::test]
async fn signing_key_rotation_is_canonical_and_rejects_key_arns() {
    let state = AppState::dev(HOST);
    let active_kid = state.signer.active_kid().await.unwrap();
    let inspection = state.clone();
    let (router, _) = build_router(state);
    let path = "/admin/ssf/signing-key-rotations";
    let rotation = json!({
        "phase": "retire",
        "old_kid": "old_kid_123",
        "new_kid": active_kid.clone(),
        "result": "success",
        "operation_id": "rotation_20260731_1"
    });

    assert_eq!(
        request(&router, Method::POST, path, None, Some(rotation.clone()))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(
            &router,
            Method::POST,
            path,
            Some(ADMIN_TOKEN),
            Some(json!({
                "phase": "activate",
                "old_kid": "arn:aws:kms:us-east-1:123456789012:key/old",
                "new_kid": active_kid.clone(),
                "result": "success",
                "operation_id": "rotation_20260731_1"
            })),
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(
            &router,
            Method::POST,
            path,
            Some(ADMIN_TOKEN),
            Some(json!({
                "phase": "activate",
                "old_kid": "old_kid_123",
                "new_kid": active_kid.clone(),
                "result": "success",
                "operation_id": "rotation_20260731_1"
            })),
        )
        .await
        .0,
        StatusCode::CONFLICT
    );

    let (status, recorded) = request(
        &router,
        Method::POST,
        path,
        Some(ADMIN_TOKEN),
        Some(rotation),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{recorded}");
    assert_eq!(recorded["category"], "key_secret");
    assert_eq!(recorded["action"], "key.signing.rotate.retire");
    assert_eq!(recorded["outcome"], "success");
    assert_eq!(
        recorded["actor"],
        json!({ "kind": "admin", "id": "break-glass:dev-platform-admin" })
    );
    assert_eq!(
        recorded["subject"],
        json!({ "kind": "credential", "id": active_kid })
    );
    assert_eq!(recorded["correlation"]["credential_id"], "old_kid_123");
    assert_eq!(
        recorded["correlation"]["operation_id"],
        "rotation_20260731_1"
    );
    assert!(!recorded.to_string().contains("arn:aws:kms"));

    let events = inspection
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    let recorded_event = serde_json::from_value(recorded).unwrap();
    assert!(events.iter().any(|stored| stored.event == recorded_event));
}

#[tokio::test]
async fn verification_and_redrive_use_the_same_auditable_delivery_outbox() {
    let state = AppState::dev(HOST);
    let inspection = state.clone();
    let (router, _) = build_router(state);
    let (_, stream) = request(
        &router,
        Method::POST,
        "/admin/ssf/streams",
        Some(ADMIN_TOKEN),
        Some(json!({
            "endpoint": "https://receiver.example.net/events",
            "audience": "https://receiver.example.net",
            "event_types": [RISC_ACCOUNT_DISABLED_EVENT]
        })),
    )
    .await;
    let stream_id = stream["stream_id"].as_str().unwrap();

    let (status, verification) = request(
        &router,
        Method::POST,
        &format!("/admin/ssf/streams/{stream_id}/verify"),
        Some(ADMIN_TOKEN),
        Some(json!({
            "expected_revision": 1,
            "state": "receiver-generated-state"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{verification}");
    assert_eq!(verification["event_uri"], SSF_VERIFICATION_EVENT);
    assert_eq!(
        verification["subject"],
        json!({ "format": "opaque", "id": stream_id })
    );
    assert_eq!(
        verification["payload"],
        json!({ "state": "receiver-generated-state" })
    );
    let event_id = verification["event_id"].as_str().unwrap();

    let (status, deliveries) = request(
        &router,
        Method::GET,
        &format!("/admin/ssf/streams/{stream_id}/deliveries"),
        Some(ADMIN_TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(deliveries["deliveries"].as_array().unwrap().len(), 1);
    let encoded = serde_json::to_string(&deliveries).unwrap();
    assert!(!encoded.contains("lease_"));

    let lease = inspection
        .ssf
        .acquire_due(agent_auth_http::current_unix_secs(), 30, 10)
        .await
        .unwrap()
        .pop()
        .unwrap();
    inspection
        .ssf
        .persist_signed_set(
            &lease,
            &SignedSet {
                compact_jws: "stable.compact.set".to_string(),
                jti: "set_stable".to_string(),
                kid: "kid-stable".to_string(),
            },
            agent_auth_http::current_unix_secs(),
            agent_auth_http::current_unix_secs(),
        )
        .await
        .unwrap();
    let terminal = inspection
        .ssf
        .finish_attempt(
            &lease,
            SsfAttemptResult::Terminal {
                status_code: 400,
                error_class: "receiver_rejected".to_string(),
            },
            agent_auth_http::current_unix_secs(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(terminal.status, SsfDeliveryStatus::Terminal);

    let (status, redriven) = request(
        &router,
        Method::POST,
        &format!("/admin/ssf/streams/{stream_id}/deliveries/1/{event_id}/redrive"),
        Some(ADMIN_TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{redriven}");
    assert_eq!(redriven["status"], "pending");
    assert!(redriven.get("compact_set").is_none());
    assert_eq!(
        inspection
            .ssf
            .get_delivery("default", stream_id, 1, event_id)
            .await
            .unwrap()
            .unwrap()
            .compact_set
            .as_deref(),
        Some("stable.compact.set")
    );
    let (status, exact) = request(
        &router,
        Method::GET,
        &format!("/admin/ssf/streams/{stream_id}/deliveries/1/{event_id}"),
        Some(ADMIN_TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{exact}");
    assert_eq!(exact["event_id"], event_id);
    assert_eq!(
        request(
            &router,
            Method::GET,
            &format!("/admin/ssf/streams/{stream_id}/deliveries?limit=0"),
            Some(ADMIN_TOKEN),
            None,
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    for state in ["page-two", "page-three"] {
        assert_eq!(
            request(
                &router,
                Method::POST,
                &format!("/admin/ssf/streams/{stream_id}/verify"),
                Some(ADMIN_TOKEN),
                Some(json!({
                    "expected_revision": 1,
                    "state": state
                })),
            )
            .await
            .0,
            StatusCode::ACCEPTED
        );
    }
    let (status, first_page) = request(
        &router,
        Method::GET,
        &format!("/admin/ssf/streams/{stream_id}/deliveries?limit=1"),
        Some(ADMIN_TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{first_page}");
    assert_eq!(first_page["deliveries"].as_array().unwrap().len(), 1);
    let cursor = first_page["next_cursor"].as_str().unwrap();
    let (status, second_page) = request(
        &router,
        Method::GET,
        &format!("/admin/ssf/streams/{stream_id}/deliveries?limit=1&cursor={cursor}"),
        Some(ADMIN_TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{second_page}");
    assert_eq!(second_page["deliveries"].as_array().unwrap().len(), 1);
    assert_ne!(
        first_page["deliveries"][0]["event_id"],
        second_page["deliveries"][0]["event_id"]
    );
    assert_eq!(
        request(
            &router,
            Method::GET,
            &format!("/admin/ssf/streams/{stream_id}/deliveries?cursor=not-a-cursor"),
            Some(ADMIN_TOKEN),
            None,
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );

    let events = inspection
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    assert!(events.iter().any(|stored| {
        stored.event.action == "ssf.stream.verify"
            && stored.event.outcome == SecurityEventOutcome::Success
    }));
    assert!(events.iter().any(|stored| {
        stored.event.action == "ssf.delivery.redrive"
            && stored.event.outcome == SecurityEventOutcome::Success
    }));
}
