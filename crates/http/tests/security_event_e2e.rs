use agent_auth_http::security_event::{
    MemorySecurityEventStore, SecurityActor, SecurityEvent, SecurityEventCategory,
    SecurityEventCorrelation, SecurityEventCursor, SecurityEventDelivery,
    SecurityEventDeliveryStatus, SecurityEventDraft, SecurityEventIngress, SecurityEventOutcome,
    SecurityEventStore, SecuritySubject, SECURITY_EVENT_HOT_RETENTION_DAYS,
    SECURITY_EVENT_SCHEMA_VERSION,
};
use agent_auth_http::{build_router, AppState};
use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use tower::ServiceExt;

fn fixture(event_id: &str, tenant: &str, occurred_at: i64) -> SecurityEvent {
    SecurityEvent::new_at(
        event_id,
        occurred_at,
        tenant,
        SecurityActor::user("user:admin@example.com"),
        Some(SecuritySubject::user("user:alice@example.com")),
        SecurityEventCategory::Credential,
        "credential.recovery.rotate",
        SecurityEventOutcome::Success,
        SecurityEventCorrelation {
            request_id: Some("request-123".into()),
            session_fingerprint: Some("session-hash".into()),
            credential_id: Some("recovery-set-v2".into()),
            ..Default::default()
        },
    )
    .expect("valid security event")
}

#[test]
fn envelope_is_versioned_tenant_scoped_and_has_typed_correlation() {
    let event = fixture("event-123", "", 1_785_415_471);
    let value = serde_json::to_value(event).expect("serialize security event");

    assert_eq!(value["schema_version"], SECURITY_EVENT_SCHEMA_VERSION);
    assert_eq!(value["event_id"], "event-123");
    assert_eq!(value["occurred_at"], 1_785_415_471);
    assert_eq!(value["tenant_id"], "default");
    assert_eq!(value["actor"]["kind"], "user");
    assert_eq!(value["actor"]["id"], "user:admin@example.com");
    assert_eq!(value["subject"]["kind"], "user");
    assert_eq!(value["subject"]["id"], "user:alice@example.com");
    assert_eq!(value["category"], "credential");
    assert_eq!(value["action"], "credential.recovery.rotate");
    assert_eq!(value["outcome"], "success");
    assert_eq!(value["correlation"]["request_id"], "request-123");
    assert_eq!(value["correlation"]["session_fingerprint"], "session-hash");
    assert_eq!(value["correlation"]["credential_id"], "recovery-set-v2");

    let serialized = value.to_string();
    for forbidden in [
        "password",
        "recovery_code",
        "client_secret",
        "access_token",
        "refresh_token",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "security envelope exposed forbidden field {forbidden}"
        );
    }
}

#[test]
fn envelope_rejects_event_ids_that_could_escape_the_archive_partition() {
    for event_id in ["../event", "tenant/other", "event id", "event\nid"] {
        assert!(
            SecurityEvent::new_at(
                event_id,
                1,
                "t1",
                SecurityActor::system("test"),
                None,
                SecurityEventCategory::Infrastructure,
                "test.invalid_event_id",
                SecurityEventOutcome::Failure,
                SecurityEventCorrelation::default(),
            )
            .is_err(),
            "event id must be safe as an S3 object-key segment: {event_id:?}"
        );
    }
}

#[test]
fn denied_authentication_does_not_attribute_the_attempt_to_the_target_user() {
    let event = SecurityEventDraft::authentication(
        "t1",
        Some("user:victim@example.com"),
        agent_auth_http::security_event::AuthenticationMethod::Password,
        SecurityEventOutcome::Denied,
    )
    .into_event_at("event-denied", 100)
    .unwrap();
    let value = serde_json::to_value(event).unwrap();

    assert_eq!(value["actor"]["kind"], "system");
    assert_eq!(value["actor"]["id"], "anonymous");
    assert_eq!(value["subject"]["kind"], "user");
    assert_eq!(value["subject"]["id"], "user:victim@example.com");
}

#[test]
fn authentication_without_a_known_target_has_a_typed_unknown_subject() {
    let event = SecurityEventDraft::authentication(
        "t1",
        None,
        agent_auth_http::security_event::AuthenticationMethod::Password,
        SecurityEventOutcome::Denied,
    )
    .into_event_at("event-unknown-target", 100)
    .unwrap();
    let value = serde_json::to_value(event).unwrap();

    assert_eq!(value["subject"]["kind"], "unknown");
    assert_eq!(value["subject"]["id"], "anonymous");
}

#[test]
fn emergency_log_payload_round_trips_the_complete_typed_ingress() {
    let ingress = SecurityEventIngress::new(fixture("event-emergency", "t1", 100));
    let encoded = agent_auth_http::security_event::encode_emergency_ingress(&ingress).unwrap();
    assert!(!encoded.contains("user:alice@example.com"));
    assert_eq!(
        agent_auth_http::security_event::decode_emergency_ingress(&encoded).unwrap(),
        ingress
    );
}

#[tokio::test]
async fn store_deduplicates_event_id_and_exports_only_the_requested_tenant() {
    let store = MemorySecurityEventStore::default();
    let first = fixture("event-1", "t1", 100);
    let duplicate = fixture("event-1", "t1", 100);
    let newer = fixture("event-2", "t1", 200);
    let other_tenant = fixture("event-3", "t2", 300);

    assert!(store.put(&first).await.unwrap());
    assert!(!store.put(&duplicate).await.unwrap());
    assert!(store.put(&newer).await.unwrap());
    assert!(store.put(&other_tenant).await.unwrap());

    let exported = store.list_by_tenant("t1", 0, 250, 100).await.unwrap();
    assert_eq!(
        exported
            .iter()
            .map(|event| event.event.event_id.as_str())
            .collect::<Vec<_>>(),
        ["event-2", "event-1"]
    );
    assert!(exported.iter().all(|event| event.event.tenant_id == "t1"));
    let latest = store.list_by_tenant("t1", 0, 250, 1).await.unwrap();
    assert_eq!(latest[0].event.event_id, "event-2");

    let first_page = store
        .list_by_tenant_page("t1", 0, 250, 1, None)
        .await
        .unwrap();
    assert_eq!(first_page.events[0].event.event_id, "event-2");
    let encoded = first_page.next_cursor.expect("continuation cursor");
    let cursor = SecurityEventCursor::decode_for_query(&encoded, "t1", 0, 250).unwrap();
    let second_page = store
        .list_by_tenant_page("t1", 0, 250, 1, Some(&cursor))
        .await
        .unwrap();
    assert_eq!(second_page.events[0].event.event_id, "event-1");
    assert!(second_page.next_cursor.is_none());
}

#[tokio::test]
async fn memory_store_preserves_preledger_delivery_history() {
    let store = MemorySecurityEventStore::default();
    let event = fixture("event-delivery", "t1", 100);
    let mut delivery = SecurityEventDelivery::pending(100);
    delivery.start_attempt(101);
    delivery.record(SecurityEventDeliveryStatus::Failed, 102);
    delivery.record(SecurityEventDeliveryStatus::Retrying, 103);

    assert!(store.put_with_delivery(&event, &delivery).await.unwrap());
    let stored = store.list_by_tenant("t1", 0, 250, 1).await.unwrap();
    assert_eq!(stored[0].delivery, delivery);
}

#[tokio::test]
async fn admin_export_is_authenticated_versioned_and_tenant_scoped() {
    let state = AppState::dev("localhost");
    state
        .record_security_event(
            SecurityEventDraft::new(
                "",
                SecurityActor::admin("break-glass:dev-platform-admin"),
                Some(SecuritySubject::user("user:alice@example.com")),
                SecurityEventCategory::UserLifecycle,
                "user.disable",
                SecurityEventOutcome::Success,
            )
            .correlated(SecurityEventCorrelation {
                operation_id: Some("disable-generation-2".into()),
                ..Default::default()
            }),
        )
        .await
        .expect("security event recorded");
    let (router, _) = build_router(state);

    let unauthorized = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/security-events?from=0&through=2000000000&limit=100")
                .header("host", "localhost")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/admin/security-events?from=0&through=2000000000&limit=100")
                .header("host", "localhost")
                .header("authorization", "Bearer dev-admin-token-not-for-prod")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["schema_version"], SECURITY_EVENT_SCHEMA_VERSION);
    assert_eq!(body["tenant_id"], "default");
    assert_eq!(
        body["hot_retention_days"],
        SECURITY_EVENT_HOT_RETENTION_DAYS
    );
    assert_eq!(body["total"], 3);
    let events = body["events"].as_array().unwrap();
    let user_event = events
        .iter()
        .find(|event| event["event"]["action"] == "user.disable")
        .expect("user lifecycle event");
    assert_eq!(user_event["event"]["tenant_id"], "default");
    assert_eq!(
        user_event["event"]["correlation"]["operation_id"],
        "disable-generation-2"
    );
    assert_eq!(user_event["delivery"]["status"], "pending");
    assert_eq!(user_event["delivery"]["history"][0]["status"], "pending");
    assert!(events
        .iter()
        .any(|event| event["event"]["action"] == "admin.break_glass.use"));
    assert!(events.iter().any(|event| {
        event["event"]["action"] == "authentication.admin" && event["event"]["outcome"] == "denied"
    }));
}

#[tokio::test]
async fn admin_export_enforces_documented_limit_bounds() {
    let (router, _) = build_router(AppState::dev("localhost"));

    for (limit, expected) in [
        (0, StatusCode::BAD_REQUEST),
        (1, StatusCode::OK),
        (500, StatusCode::OK),
        (501, StatusCode::BAD_REQUEST),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/admin/security-events?from=0&through=2000000000&limit={limit}"
                    ))
                    .header("host", "localhost")
                    .header("authorization", "Bearer dev-admin-token-not-for-prod")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "limit={limit}");
    }
}

#[tokio::test]
async fn issuer_mismatch_records_a_tenant_boundary_denial() {
    let mut state = AppState::dev("t1.aws.example.com");
    state.form = agent_auth_discovery::Form::Saas {
        zone: "aws.example.com".into(),
        control_host: "c.aws.example.com".into(),
    };
    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("t1.aws.example.com"));

    assert!(
        !agent_auth_http::tenant::issuer_belongs_to_request_tenant(
            &state,
            &headers,
            "https://t2.aws.example.com",
            SecurityActor::system("test-token-endpoint"),
        )
        .await
    );
    let events = state
        .security_events
        .list_by_tenant("t1", 0, i64::MAX, 100)
        .await
        .unwrap();
    let event = events
        .iter()
        .find(|stored| stored.event.action == "tenant.access_denied")
        .expect("tenant-boundary denial event");
    assert_eq!(event.event.category, SecurityEventCategory::TenantBoundary);
    assert_eq!(event.event.outcome, SecurityEventOutcome::Denied);
    let subject = serde_json::to_value(&event.event.subject).unwrap();
    assert_eq!(subject["kind"], "issuer");
    assert_eq!(subject["id"], "https://t2.aws.example.com");
}

#[tokio::test]
async fn account_session_revocation_is_visible_through_the_admin_export() {
    use agent_auth_http::ports::{SessionRecord, SessionStore};

    let state = AppState::dev("localhost");
    let now = agent_auth_http::current_unix_secs();
    for session_id in ["current-cookie-secret", "other-cookie-secret"] {
        state
            .sessions
            .create(
                "",
                SessionRecord {
                    session_id: session_id.to_string(),
                    user_id: "user:alice@example.com".to_string(),
                    credential_epoch: 0,
                    auth_time: now,
                    created_at: now,
                    last_used_at: now,
                    device: "Test browser".to_string(),
                    expires_at: now + 3600,
                    acr: None,
                    amr: vec!["pwd".to_string()],
                },
            )
            .await
            .unwrap();
    }
    let (router, _) = build_router(state);

    let revoked = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/account/sessions")
                .header("host", "localhost")
                .header(
                    header::COOKIE,
                    "__Host-agent_auth_session=current-cookie-secret",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);

    let export = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/admin/security-events?from={}&through={}&limit=100",
                    now - 1,
                    now + 1
                ))
                .header("host", "localhost")
                .header("authorization", "Bearer dev-admin-token-not-for-prod")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(export.status(), StatusCode::OK);
    let body = axum::body::to_bytes(export.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let events = body["events"].as_array().unwrap();
    let event = events
        .iter()
        .find(|event| event["event"]["action"] == "session.revoke_others")
        .expect("session revocation security event");
    assert_eq!(event["event"]["category"], "authentication");
    assert_eq!(event["event"]["outcome"], "success");
    assert_eq!(event["event"]["actor"]["id"], "user:alice@example.com");
    assert_eq!(event["event"]["subject"]["id"], "user:alice@example.com");
    let serialized = event.to_string();
    assert!(!serialized.contains("current-cookie-secret"));
    assert!(!serialized.contains("other-cookie-secret"));
}
