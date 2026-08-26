use agent_auth_http::adapters::memory::MemorySigner;
use agent_auth_http::credential::CredentialAuditEvent;
use agent_auth_http::ports::Signer;
use agent_auth_http::security_event::{
    SecurityActor, SecurityEvent, SecurityEventCategory, SecurityEventCorrelation,
    SecurityEventOutcome, SecuritySubject,
};
use agent_auth_http::ssf::{
    project_security_event, sign_delivery_set, sign_projected_set, MemorySsfStore,
    SetSigningContext, SignedSet, SsfAttemptResult, SsfDeliveryStatus, SsfRedriveOutcome, SsfStore,
    SsfStream, SsfStreamCreateOutcome, SsfStreamMutation, SsfStreamMutationOutcome,
    SsfStreamStatus, CAEP_CREDENTIAL_CHANGE_EVENT, CAEP_SESSION_REVOKED_EVENT,
    RISC_ACCOUNT_DISABLED_EVENT, SSF_MAX_REGISTERED_STREAMS_PER_TENANT, SSF_MAX_RETRY_AGE_SECS,
    SSF_SPEC_VERSION,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

fn event(action: &str, outcome: SecurityEventOutcome) -> SecurityEvent {
    SecurityEvent::new_at(
        "evt_account_disabled_1",
        1_725_000_100,
        "t1",
        SecurityActor::admin("admin:operator"),
        Some(SecuritySubject::user("user:alice@example.com")),
        SecurityEventCategory::UserLifecycle,
        action,
        outcome,
        SecurityEventCorrelation::default(),
    )
    .unwrap()
}

#[test]
fn account_disable_projects_to_the_final_risc_profile() {
    let projection = project_security_event(
        &event("user.disable", SecurityEventOutcome::Success),
        "https://t1.example.com",
    )
    .expect("successful account disable is externally shareable");

    assert_eq!(SSF_SPEC_VERSION, "1_0");
    assert_eq!(projection.event_uri, RISC_ACCOUNT_DISABLED_EVENT);
    assert_eq!(
        projection.subject,
        serde_json::json!({
            "format": "iss_sub",
            "iss": "https://t1.example.com",
            "sub": "user:alice@example.com"
        })
    );
    assert_eq!(
        projection.payload,
        serde_json::json!({ "event_timestamp": 1_725_000_100 })
    );
}

#[test]
fn projection_is_an_exact_successful_user_event_allowlist() {
    assert!(project_security_event(
        &event("user.disable", SecurityEventOutcome::Failure),
        "https://t1.example.com",
    )
    .is_none());
    assert!(project_security_event(
        &event("user.enable", SecurityEventOutcome::Success),
        "https://t1.example.com",
    )
    .is_none());

    let client_event = SecurityEvent::new_at(
        "evt_client_secret_1",
        1_725_000_101,
        "t1",
        SecurityActor::admin("admin:operator"),
        Some(SecuritySubject::client("client-1")),
        SecurityEventCategory::Credential,
        "credential.client_secret.update",
        SecurityEventOutcome::Success,
        SecurityEventCorrelation::default(),
    )
    .unwrap();
    assert!(
        project_security_event(&client_event, "https://t1.example.com").is_none(),
        "machine credentials are not account-risk events"
    );
}

#[test]
fn session_revocation_projects_only_when_a_session_was_revoked() {
    let effective = CredentialAuditEvent::UserSessionOperation {
        action: "revoke",
        tenant: "t1",
        actor: "user:alice@example.com",
        target: "stable-session-subject",
        result: "success",
        affected: Some(1),
    }
    .security_event()
    .into_event_at("evt_session_revoke_1", 1_725_000_110)
    .unwrap();
    let projection = project_security_event(&effective, "https://t1.example.com")
        .expect("effective session revocation is shareable");

    assert_eq!(projection.event_uri, CAEP_SESSION_REVOKED_EVENT);
    assert_eq!(
        projection.payload,
        serde_json::json!({ "event_timestamp": 1_725_000_110 })
    );
    assert_eq!(
        projection.subject,
        serde_json::json!({
            "format": "complex",
            "session": {
                "format": "opaque",
                "id": "stable-session-subject"
            },
            "user": {
                "format": "iss_sub",
                "iss": "https://t1.example.com",
                "sub": "user:alice@example.com"
            },
            "tenant": {
                "format": "opaque",
                "id": "t1"
            }
        })
    );

    let no_op = CredentialAuditEvent::UserSessionOperation {
        action: "revoke",
        tenant: "t1",
        actor: "user:alice@example.com",
        target: "missing-management-handle",
        result: "success",
        affected: Some(0),
    }
    .security_event()
    .into_event_at("evt_session_revoke_noop_1", 1_725_000_111)
    .unwrap();
    assert_eq!(no_op.action, "session.revoke_noop");
    assert!(project_security_event(&no_op, "https://t1.example.com").is_none());

    let revoke_others = CredentialAuditEvent::UserSessionOperation {
        action: "revoke_others",
        tenant: "t1",
        actor: "user:alice@example.com",
        target: "all_other",
        result: "success",
        affected: Some(2),
    }
    .security_event()
    .into_event_at("evt_session_revoke_others_1", 1_725_000_112)
    .unwrap();
    assert!(
        project_security_event(&revoke_others, "https://t1.example.com").is_none(),
        "CAEP cannot represent revoke-all-except-current as a user-level revocation"
    );
}

#[test]
fn credential_changes_project_with_exact_caep_types() {
    for (kind, action, credential_type, change_type) in [
        ("passkey", "register", "fido2-roaming", "create"),
        ("passkey", "delete", "fido2-roaming", "delete"),
        ("password", "set", "password", "update"),
        ("recovery", "rotate", "agent-auth-recovery-code", "update"),
    ] {
        let canonical = CredentialAuditEvent::UserCredentialOperation {
            action,
            tenant: "t1",
            actor: "user:alice@example.com",
            kind,
            target: "opaque",
            result: "success",
        }
        .security_event()
        .into_event_at(format!("evt_{kind}_{action}"), 1_725_000_120)
        .unwrap();
        let projection = project_security_event(&canonical, "https://t1.example.com")
            .expect("allowlisted credential change is shareable");

        assert_eq!(projection.event_uri, CAEP_CREDENTIAL_CHANGE_EVENT);
        assert_eq!(
            projection.payload,
            serde_json::json!({
                "credential_type": credential_type,
                "change_type": change_type,
                "event_timestamp": 1_725_000_120
            }),
            "{kind}.{action}"
        );
    }

    let admin_reset = SecurityEvent::new_at(
        "evt_password_reset",
        1_725_000_121,
        "t1",
        SecurityActor::admin("admin:operator"),
        Some(SecuritySubject::user("user:alice@example.com")),
        SecurityEventCategory::Credential,
        "credential.password.reset",
        SecurityEventOutcome::Success,
        SecurityEventCorrelation::default(),
    )
    .unwrap();
    let reset_projection = project_security_event(&admin_reset, "https://t1.example.com")
        .expect("password reset is shareable");
    assert_eq!(
        reset_projection.payload,
        serde_json::json!({
            "credential_type": "password",
            "change_type": "update",
            "event_timestamp": 1_725_000_121
        })
    );
}

#[tokio::test]
async fn stream_lifecycle_is_tenant_scoped_revisioned_and_permanently_revocable() {
    let store = MemorySsfStore::default();
    let stream = SsfStream::new(
        "t1",
        "stream_01J2SSF",
        "https://receiver.example.net/events",
        "https://receiver.example.net",
        vec![
            RISC_ACCOUNT_DISABLED_EVENT.to_string(),
            "https://receiver.example.net/custom-event".to_string(),
        ],
        1_725_000_000,
    )
    .unwrap();

    assert_eq!(
        store.create_stream(stream.clone()).await.unwrap(),
        SsfStreamCreateOutcome::Created(stream.clone())
    );
    assert_eq!(
        stream.requested_events,
        vec![
            RISC_ACCOUNT_DISABLED_EVENT.to_string(),
            "https://receiver.example.net/custom-event".to_string(),
        ]
    );
    assert_eq!(
        stream.delivered_events,
        vec![RISC_ACCOUNT_DISABLED_EVENT.to_string()]
    );
    assert_eq!(store.list_streams("t2").await.unwrap(), Vec::new());
    assert!(store
        .get_stream("t2", "stream_01J2SSF")
        .await
        .unwrap()
        .is_none());

    assert_eq!(
        store
            .mutate_stream(
                "t1",
                "stream_01J2SSF",
                0,
                SsfStreamMutation::Pause,
                1_725_000_010,
            )
            .await
            .unwrap(),
        SsfStreamMutationOutcome::RevisionConflict {
            current_revision: 1
        }
    );
    let replaced = store
        .mutate_stream(
            "t1",
            "stream_01J2SSF",
            1,
            SsfStreamMutation::Replace {
                endpoint: "https://new-receiver.example.net/events".to_string(),
                audience: "https://new-receiver.example.net".to_string(),
                requested_events: vec![CAEP_SESSION_REVOKED_EVENT.to_string()],
            },
            1_725_000_020,
        )
        .await
        .unwrap()
        .updated()
        .unwrap();
    assert_eq!(replaced.revision, 2);
    assert_eq!(replaced.activation_at, 1_725_000_020);
    assert_eq!(replaced.status, SsfStreamStatus::Enabled);

    let paused = store
        .mutate_stream(
            "t1",
            "stream_01J2SSF",
            2,
            SsfStreamMutation::Pause,
            1_725_000_030,
        )
        .await
        .unwrap()
        .updated()
        .unwrap();
    assert_eq!(paused.revision, 3);
    assert_eq!(paused.status, SsfStreamStatus::Paused);
    assert_eq!(paused.activation_at, 1_725_000_020);

    let resumed = store
        .mutate_stream(
            "t1",
            "stream_01J2SSF",
            3,
            SsfStreamMutation::Resume,
            1_725_000_040,
        )
        .await
        .unwrap()
        .updated()
        .unwrap();
    assert_eq!(resumed.revision, 4);
    assert_eq!(resumed.status, SsfStreamStatus::Enabled);
    assert_eq!(resumed.activation_at, 1_725_000_040);

    let revoked = store
        .mutate_stream(
            "t1",
            "stream_01J2SSF",
            4,
            SsfStreamMutation::Revoke,
            1_725_000_050,
        )
        .await
        .unwrap()
        .updated()
        .unwrap();
    assert_eq!(revoked.revision, 5);
    assert_eq!(revoked.status, SsfStreamStatus::Revoked);
    assert_eq!(
        store
            .mutate_stream(
                "t1",
                "stream_01J2SSF",
                5,
                SsfStreamMutation::Resume,
                1_725_000_060,
            )
            .await
            .unwrap(),
        SsfStreamMutationOutcome::Revoked
    );
    assert_eq!(
        store.create_stream(stream).await.unwrap(),
        SsfStreamCreateOutcome::AlreadyExists
    );
}

#[tokio::test]
async fn stream_registration_quota_is_concurrent_tenant_scoped_and_keeps_tombstones() {
    let store = MemorySsfStore::default();
    let mut creates = tokio::task::JoinSet::new();
    for index in 0..(SSF_MAX_REGISTERED_STREAMS_PER_TENANT * 2) {
        let store = store.clone();
        creates.spawn(async move {
            store
                .create_stream(
                    SsfStream::new(
                        "t1",
                        format!("stream_{index:03}"),
                        format!("https://receiver-{index}.example.net/events"),
                        format!("https://receiver-{index}.example.net"),
                        vec![RISC_ACCOUNT_DISABLED_EVENT.to_string()],
                        1_725_000_000,
                    )
                    .unwrap(),
                )
                .await
                .unwrap()
        });
    }

    let mut created = Vec::new();
    let mut quota_exceeded = 0;
    while let Some(outcome) = creates.join_next().await {
        match outcome.unwrap() {
            SsfStreamCreateOutcome::Created(stream) => created.push(stream),
            SsfStreamCreateOutcome::QuotaExceeded { limit } => {
                assert_eq!(limit, SSF_MAX_REGISTERED_STREAMS_PER_TENANT);
                quota_exceeded += 1;
            }
            SsfStreamCreateOutcome::AlreadyExists => panic!("all generated stream ids are unique"),
        }
    }
    assert_eq!(created.len(), SSF_MAX_REGISTERED_STREAMS_PER_TENANT);
    assert_eq!(quota_exceeded, SSF_MAX_REGISTERED_STREAMS_PER_TENANT);

    let first = created.first().unwrap();
    assert_eq!(
        store.create_stream(first.clone()).await.unwrap(),
        SsfStreamCreateOutcome::AlreadyExists
    );
    assert!(matches!(
        store
            .mutate_stream(
                "t1",
                &first.stream_id,
                first.revision,
                SsfStreamMutation::Revoke,
                1_725_000_001,
            )
            .await
            .unwrap(),
        SsfStreamMutationOutcome::Updated(_)
    ));
    assert_eq!(
        store
            .create_stream(
                SsfStream::new(
                    "t1",
                    "stream_after_revoke",
                    "https://after-revoke.example.net/events",
                    "https://after-revoke.example.net",
                    vec![RISC_ACCOUNT_DISABLED_EVENT.to_string()],
                    1_725_000_002,
                )
                .unwrap(),
            )
            .await
            .unwrap(),
        SsfStreamCreateOutcome::QuotaExceeded {
            limit: SSF_MAX_REGISTERED_STREAMS_PER_TENANT
        }
    );
    assert!(matches!(
        store
            .create_stream(
                SsfStream::new(
                    "t2",
                    "stream_other_tenant",
                    "https://other-tenant.example.net/events",
                    "https://other-tenant.example.net",
                    vec![RISC_ACCOUNT_DISABLED_EVENT.to_string()],
                    1_725_000_002,
                )
                .unwrap(),
            )
            .await
            .unwrap(),
        SsfStreamCreateOutcome::Created(_)
    ));
}

#[tokio::test]
async fn canonical_events_create_only_current_authorized_delivery_rows() {
    let store = MemorySsfStore::default();
    for (tenant, stream_id, event_uri, activation_at) in [
        ("t1", "account-stream", RISC_ACCOUNT_DISABLED_EVENT, 100),
        ("t1", "credential-stream", CAEP_CREDENTIAL_CHANGE_EVENT, 100),
        (
            "t2",
            "other-tenant-stream",
            RISC_ACCOUNT_DISABLED_EVENT,
            100,
        ),
    ] {
        store
            .create_stream(
                SsfStream::new(
                    tenant,
                    stream_id,
                    format!("https://{stream_id}.example.net/events"),
                    format!("https://{stream_id}.example.net"),
                    vec![event_uri.to_string()],
                    activation_at,
                )
                .unwrap(),
            )
            .await
            .unwrap();
    }

    let old = SecurityEvent::new_at(
        "evt_before_activation",
        99,
        "t1",
        SecurityActor::admin("admin:operator"),
        Some(SecuritySubject::user("user:alice@example.com")),
        SecurityEventCategory::UserLifecycle,
        "user.disable",
        SecurityEventOutcome::Success,
        SecurityEventCorrelation::default(),
    )
    .unwrap();
    assert!(store
        .enqueue_event(&old, "https://t1.example.com", 110)
        .await
        .unwrap()
        .is_empty());

    let current = SecurityEvent::new_at(
        "evt_after_activation",
        101,
        "t1",
        SecurityActor::admin("admin:operator"),
        Some(SecuritySubject::user("user:alice@example.com")),
        SecurityEventCategory::UserLifecycle,
        "user.disable",
        SecurityEventOutcome::Success,
        SecurityEventCorrelation::default(),
    )
    .unwrap();
    let created = store
        .enqueue_event(&current, "https://t1.example.com", 111)
        .await
        .unwrap();
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].tenant_id, "t1");
    assert_eq!(created[0].stream_id, "account-stream");
    assert_eq!(created[0].stream_revision, 1);
    assert_eq!(created[0].event_id, "evt_after_activation");
    assert_eq!(created[0].event_uri, RISC_ACCOUNT_DISABLED_EVENT);
    assert_eq!(created[0].status, SsfDeliveryStatus::Pending);
    assert_eq!(created[0].next_attempt_at, 111);
    assert_eq!(
        created[0].subject,
        serde_json::json!({
            "format": "iss_sub",
            "iss": "https://t1.example.com",
            "sub": "user:alice@example.com"
        })
    );
    assert!(store
        .enqueue_event(&current, "https://t1.example.com", 112)
        .await
        .unwrap()
        .is_empty());

    store
        .mutate_stream("t1", "account-stream", 1, SsfStreamMutation::Pause, 113)
        .await
        .unwrap();
    let after_pause = SecurityEvent::new_at(
        "evt_after_pause",
        114,
        "t1",
        SecurityActor::admin("admin:operator"),
        Some(SecuritySubject::user("user:alice@example.com")),
        SecurityEventCategory::UserLifecycle,
        "user.disable",
        SecurityEventOutcome::Success,
        SecurityEventCorrelation::default(),
    )
    .unwrap();
    assert!(store
        .enqueue_event(&after_pause, "https://t1.example.com", 114)
        .await
        .unwrap()
        .is_empty());
    assert!(store
        .list_deliveries("t2", "account-stream", 100, None)
        .await
        .unwrap()
        .deliveries
        .is_empty());
}

#[tokio::test]
async fn delivery_lease_retries_the_same_set_and_requires_explicit_terminal_redrive() {
    let store = MemorySsfStore::default();
    store
        .create_stream(
            SsfStream::new(
                "t1",
                "stream-delivery",
                "https://receiver.example.net/events",
                "https://receiver.example.net",
                vec![RISC_ACCOUNT_DISABLED_EVENT.to_string()],
                100,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let first_event = SecurityEvent::new_at(
        "evt_retry_then_accept",
        101,
        "t1",
        SecurityActor::admin("admin:operator"),
        Some(SecuritySubject::user("user:alice@example.com")),
        SecurityEventCategory::UserLifecycle,
        "user.disable",
        SecurityEventOutcome::Success,
        SecurityEventCorrelation::default(),
    )
    .unwrap();
    store
        .enqueue_event(&first_event, "https://t1.example.com", 110)
        .await
        .unwrap();

    let lease = store.acquire_due(110, 30, 10).await.unwrap().pop().unwrap();
    assert!(store.acquire_due(111, 30, 10).await.unwrap().is_empty());
    let immutable_set = SignedSet {
        compact_jws: "header.payload.signature".to_string(),
        jti: "set_stable".to_string(),
        kid: "kid-stable".to_string(),
    };
    assert!(store
        .persist_signed_set(&lease, &immutable_set, 110, 112)
        .await
        .unwrap());
    let retrying = store
        .finish_attempt(
            &lease,
            SsfAttemptResult::Retryable {
                status_code: Some(500),
                error_class: "server_error".to_string(),
            },
            113,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrying.status, SsfDeliveryStatus::RetryWait);
    assert_eq!(retrying.attempts, 1);
    assert!(retrying.next_attempt_at > 113);
    assert_eq!(
        retrying.compact_set.as_deref(),
        Some("header.payload.signature")
    );
    assert_eq!(
        retrying.attempt_history[0].set_sha256.as_deref(),
        Some("sha256:JW0E205eSsMIdR7QiFtyK3WGMFZ8U6cSXtn70Gjlw_Y")
    );
    assert_eq!(
        retrying.attempt_history[0].signing_kid.as_deref(),
        Some("kid-stable")
    );
    assert!(store
        .acquire_due(retrying.next_attempt_at - 1, 30, 10)
        .await
        .unwrap()
        .is_empty());

    let retry_lease = store
        .acquire_due(retrying.next_attempt_at, 30, 10)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        retry_lease.delivery.compact_set.as_deref(),
        Some("header.payload.signature")
    );
    let delivered = store
        .finish_attempt(
            &retry_lease,
            SsfAttemptResult::Accepted,
            retrying.next_attempt_at,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delivered.status, SsfDeliveryStatus::Delivered);
    assert_eq!(delivered.attempts, 2);

    let terminal_event = SecurityEvent::new_at(
        "evt_terminal_then_redrive",
        102,
        "t1",
        SecurityActor::admin("admin:operator"),
        Some(SecuritySubject::user("user:bob@example.com")),
        SecurityEventCategory::UserLifecycle,
        "user.disable",
        SecurityEventOutcome::Success,
        SecurityEventCorrelation::default(),
    )
    .unwrap();
    store
        .enqueue_event(&terminal_event, "https://t1.example.com", 200)
        .await
        .unwrap();
    let terminal_lease = store.acquire_due(200, 30, 10).await.unwrap().pop().unwrap();
    store
        .persist_signed_set(&terminal_lease, &immutable_set, 200, 201)
        .await
        .unwrap();
    let terminal = store
        .finish_attempt(
            &terminal_lease,
            SsfAttemptResult::Terminal {
                status_code: 400,
                error_class: "receiver_rejected".to_string(),
            },
            202,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(terminal.status, SsfDeliveryStatus::Terminal);
    assert!(store.acquire_due(300, 30, 10).await.unwrap().is_empty());
    assert!(matches!(
        store
            .redrive_delivery("t1", "stream-delivery", 1, "evt_terminal_then_redrive", 301,)
            .await
            .unwrap(),
        SsfRedriveOutcome::Redriven(_)
    ));
    let redrive = store.acquire_due(301, 30, 10).await.unwrap().pop().unwrap();
    assert_eq!(
        redrive.delivery.compact_set.as_deref(),
        Some("header.payload.signature")
    );
    let terminal_again = store
        .finish_attempt(
            &redrive,
            SsfAttemptResult::Terminal {
                status_code: 400,
                error_class: "receiver_rejected".to_string(),
            },
            302,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(terminal_again.status, SsfDeliveryStatus::Terminal);
    let set_deadline = 200 + SSF_MAX_RETRY_AGE_SECS;
    assert!(matches!(
        store
            .redrive_delivery(
                "t1",
                "stream-delivery",
                1,
                "evt_terminal_then_redrive",
                set_deadline - 1,
            )
            .await
            .unwrap(),
        SsfRedriveOutcome::Redriven(_)
    ));
    let final_window_lease = store
        .acquire_due(set_deadline - 1, 30, 10)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let exhausted_at_set_deadline = store
        .finish_attempt(
            &final_window_lease,
            SsfAttemptResult::Retryable {
                status_code: Some(500),
                error_class: "server_error".to_string(),
            },
            set_deadline - 1,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        exhausted_at_set_deadline.status,
        SsfDeliveryStatus::DeadLettered
    );
    assert!(store
        .acquire_due(set_deadline + 5, 30, 10)
        .await
        .unwrap()
        .is_empty());

    let expired_event = SecurityEvent::new_at(
        "evt_terminal_expired",
        103,
        "t1",
        SecurityActor::admin("admin:operator"),
        Some(SecuritySubject::user("user:carol@example.com")),
        SecurityEventCategory::UserLifecycle,
        "user.disable",
        SecurityEventOutcome::Success,
        SecurityEventCorrelation::default(),
    )
    .unwrap();
    store
        .enqueue_event(&expired_event, "https://t1.example.com", 400)
        .await
        .unwrap();
    let expired_lease = store.acquire_due(400, 30, 10).await.unwrap().pop().unwrap();
    store
        .persist_signed_set(&expired_lease, &immutable_set, 400, 401)
        .await
        .unwrap();
    store
        .finish_attempt(
            &expired_lease,
            SsfAttemptResult::Terminal {
                status_code: 400,
                error_class: "receiver_rejected".to_string(),
            },
            402,
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .redrive_delivery(
                "t1",
                "stream-delivery",
                1,
                "evt_terminal_expired",
                400 + SSF_MAX_RETRY_AGE_SECS,
            )
            .await
            .unwrap(),
        SsfRedriveOutcome::Expired
    );
}

#[tokio::test]
async fn verification_delivery_signs_from_its_persisted_stream_snapshot() {
    let store = MemorySsfStore::default();
    store
        .create_stream(
            SsfStream::new(
                "t1",
                "stream-verification",
                "https://receiver.example.net/events",
                "https://receiver.example.net",
                vec![RISC_ACCOUNT_DISABLED_EVENT.to_string()],
                100,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let delivery = store
        .enqueue_verification(
            "t1",
            "stream-verification",
            1,
            "evt_verification_1",
            "https://t1.example.com",
            Some("expected-state"),
            110,
        )
        .await
        .unwrap()
        .enqueued()
        .unwrap();
    let signer = MemorySigner::from_seed([26; 32]);
    let signed = sign_delivery_set(&signer, &delivery, 111)
        .await
        .expect("verification SET signs");
    let claims: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(signed.compact_jws.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();

    assert_eq!(
        claims["sub_id"],
        serde_json::json!({
            "format": "opaque",
            "id": "stream-verification"
        })
    );
    assert_eq!(
        claims["events"][agent_auth_http::ssf::SSF_VERIFICATION_EVENT],
        serde_json::json!({ "state": "expected-state" })
    );
    assert_eq!(claims["txn"], "evt_verification_1");
    assert_eq!(claims["iat"], 111);
}

#[tokio::test]
async fn signed_set_has_stable_identity_and_verifies_with_the_published_jwk() {
    let signer = MemorySigner::from_seed([25; 32]);
    let canonical = event("user.disable", SecurityEventOutcome::Success);
    let projection =
        project_security_event(&canonical, "https://t1.example.com").expect("shareable event");
    let context = SetSigningContext {
        issuer: "https://t1.example.com",
        audience: "https://receiver.example.net/events",
        stream_id: "stream_01J2SSF",
        stream_revision: 7,
        issued_at: 1_725_000_200,
    };

    let first = sign_projected_set(&signer, &canonical, &projection, &context)
        .await
        .expect("SET signs");
    let repeated = sign_projected_set(&signer, &canonical, &projection, &context)
        .await
        .expect("same SET signs");
    let next_revision = sign_projected_set(
        &signer,
        &canonical,
        &projection,
        &SetSigningContext {
            stream_revision: 8,
            ..context
        },
    )
    .await
    .expect("next revision signs");

    assert_eq!(first.jti, repeated.jti);
    assert_ne!(first.jti, next_revision.jti);
    assert_eq!(first.kid, signer.active_kid().await.unwrap());

    let parts = first.compact_jws.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3);
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();

    assert_eq!(
        header,
        serde_json::json!({
            "alg": "ES256",
            "kid": first.kid,
            "typ": "secevent+jwt"
        })
    );
    assert_eq!(claims["iss"], "https://t1.example.com");
    assert_eq!(claims["iat"], 1_725_000_200);
    assert_eq!(claims["jti"], first.jti);
    assert_eq!(claims["txn"], "evt_account_disabled_1");
    assert_eq!(claims["aud"], "https://receiver.example.net/events");
    assert_eq!(
        claims["sub_id"],
        serde_json::json!({
            "format": "iss_sub",
            "iss": "https://t1.example.com",
            "sub": "user:alice@example.com"
        })
    );
    assert_eq!(
        claims["events"][RISC_ACCOUNT_DISABLED_EVENT],
        serde_json::json!({ "event_timestamp": 1_725_000_100 })
    );
    assert!(claims.get("sub").is_none(), "SSF forbids top-level sub");
    assert!(claims.get("exp").is_none(), "SSF forbids exp");

    let jwk = signer
        .public_jwks()
        .await
        .unwrap()
        .into_iter()
        .find(|jwk| jwk.kid == first.kid)
        .expect("signing key is published");
    let x = URL_SAFE_NO_PAD.decode(jwk.x).unwrap();
    let y = URL_SAFE_NO_PAD.decode(jwk.y).unwrap();
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let verifying_key = VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
    verifying_key
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .expect("published JWK independently verifies the compact SET");
}
