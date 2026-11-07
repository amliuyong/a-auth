use super::{database, tenant};
use agent_auth_http::{
    adapters::{memory::MemoryGovernanceStore, postgres::PostgresGovernanceStore},
    governance::*,
    ports::GovernanceStore,
};
use std::sync::Arc;
use tokio::sync::Barrier;

fn user_data_state(
    base: agent_auth_http::adapters::postgres::PostgresStore,
) -> agent_auth_http::AppState {
    use agent_auth_http::{
        adapters::postgres::{
            PostgresCibaStore, PostgresGraceStore, PostgresInvitationStore, PostgresMessageOutbox,
            PostgresUsersStore, UserAuthorityKey,
        },
        state::*,
    };
    // Complete user-plane composition for contract testing. Production startup,
    // transport delivery and durable worker admission are separate acceptance.
    let mut state = agent_auth_http::AppState::dev("localhost");
    let users = PostgresUsersStore::new(base.clone(), UserAuthorityKey::new([0x57; 32]).unwrap());
    state.governance_hmac_key = Arc::new(vec![0x57; 32]);
    state.governance = Arc::new(GovernanceStoreImpl::Postgres(PostgresGovernanceStore::new(
        base.clone(),
    )));
    state.users = Arc::new(UsersStoreImpl::Postgres(users.clone()));
    state.codes = Arc::new(CodeStoreImpl::Postgres(base.clone()));
    state.sessions = Arc::new(SessionStoreImpl::Postgres(base.clone()));
    state.refresh = Arc::new(RefreshStoreImpl::Postgres(base.clone()));
    state.grace = Some(Arc::new(GraceStoreImpl::Postgres(
        PostgresGraceStore::new_delete_only(base.clone()),
    )));
    state.passkey_challenges = Arc::new(PasskeyChallengeStoreImpl::Postgres(base.clone()));
    state.passkeys = Arc::new(PasskeyStoreImpl::Postgres(base.clone()));
    state.grants = Arc::new(GrantStoreImpl::Postgres(base.clone()));
    state.jti_store = Some(Arc::new(JtiStoreImpl::Postgres(base.clone())));
    state.ciba = Arc::new(CibaStoreImpl::Postgres(PostgresCibaStore::new_delete_only(
        base.clone(),
    )));
    state.device = Arc::new(DeviceStoreImpl::Postgres(base.clone()));
    state.recovery = Arc::new(RecoveryStoreImpl::Postgres(base.clone()));
    state.passwords = Arc::new(PasswordStoreImpl::Postgres(base.clone()));
    state.magic_links = Arc::new(MagicLinkStoreImpl::Postgres(base.clone()));
    state.invitations = Arc::new(InvitationStoreImpl::Postgres(PostgresInvitationStore::new(
        users,
    )));
    state.messages = Arc::new(MessageOutboxImpl::Postgres(
        PostgresMessageOutbox::new_delete_only(base.clone()),
    ));
    state.scim_groups = Arc::new(ScimGroupsStoreImpl::Postgres(base.clone()));
    state.admin_auth = Arc::new(AdminAuthStoreImpl::Postgres(base.clone()));
    state.authz_sessions = Arc::new(AuthzSessionStoreImpl::Postgres(base));
    state
}

async fn start_user_erasure(state: &agent_auth_http::AppState, user_id: &str) -> String {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let (router, _) = agent_auth_http::build_router(state.clone());
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/data-governance/users/{user_id}/erasure"))
                .header("host", "localhost")
                .header("authorization", "Bearer dev-admin-token-not-for-prod")
                .header("x-agent-auth-purpose", "privacy-request:test")
                .header("x-agent-auth-confirm", "true")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    body["job_id"].as_str().unwrap().to_string()
}

fn tenant_data_state(
    base: agent_auth_http::adapters::postgres::PostgresStore,
) -> agent_auth_http::AppState {
    use agent_auth_http::{
        adapters::{mounted_crypto::EncryptionKeyring, postgres::PostgresSsfStore},
        state::*,
    };
    let mut state = user_data_state(base.clone());
    state.clients = Arc::new(ClientStoreImpl::Postgres(base.clone()));
    state.initial_access_tokens = Arc::new(InitialAccessTokenStoreImpl::Postgres(base.clone()));
    state.federation_config = Arc::new(FederationConfigStoreImpl::Postgres(base.clone()));
    state.federation_attribute_mappings =
        Arc::new(FederationAttributeMappingsStoreImpl::Postgres(base.clone()));
    state.workload_trust = Arc::new(WorkloadTrustStoreImpl::Postgres(base.clone()));
    state.federation_flow = Arc::new(FederationFlowStoreImpl::Postgres(base.clone()));
    state.par = Arc::new(ParStoreImpl::Postgres(base.clone()));
    state.replay_store = Some(Arc::new(ReplayStoreImpl::Postgres(base.clone())));
    state.domain_map = Arc::new(DomainMapStoreImpl::Postgres(base.clone()));
    state.policy_artifacts = Arc::new(PolicyArtifactStoreImpl::Postgres(base.clone()));
    state.policy_versions = Arc::new(PolicyVersionStoreImpl::Postgres(base.clone()));
    state.rate_limit = Some(Arc::new(RateLimitStoreImpl::Postgres(base.clone())));
    state.ssf = Arc::new(SsfStoreImpl::Postgres(PostgresSsfStore::new(
        base,
        EncryptionKeyring::new("fixture", vec![("fixture".into(), [0x71; 32])]).unwrap(),
    )));
    state
}

#[tokio::test]
async fn postgres_governance_tenant_offboarding_cleans_orphans_and_retains_ssf_audit() {
    use agent_auth_http::{
        governance_worker::{advance_tenant_offboarding_once, advance_user_erasure_once},
        ports::*,
        ssf::{SsfDeliveryStatus, SsfStore, SsfStreamStatus},
    };
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let (base, pool, admin, name, url) = super::ssf_contracts::isolated_database().await;
    let state = tenant_data_state(base);
    let other = tenant_data_state(
        agent_auth_http::adapters::postgres::PostgresStore::connect(&url, 8)
            .await
            .unwrap(),
    );
    let now = agent_auth_http::current_unix_secs();
    state
        .users
        .create_or_get_by_email("", "erased@example.com", "erase-user", now)
        .await
        .unwrap();
    state
        .clients
        .put(
            "",
            ClientRecord {
                client_id: "orphan-client".into(),
                token_endpoint_auth_method: "none".into(),
                last_used_day: Some(now / 86_400),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(state
        .initial_access_tokens
        .put_new("", super::initial_access_token("orphan-iat"))
        .await
        .unwrap());
    state
        .scim_groups
        .create(
            "",
            ScimGroupCreateInput {
                group_id: "orphan-group".into(),
                external_id: "orphan-group-external".into(),
                display_name: "Orphan fixture".into(),
                members: vec![],
                now,
            },
        )
        .await
        .unwrap();
    state
        .policy_artifacts
        .put("", 1, "fixture-policy".into(), "fixture-digest".into())
        .await
        .unwrap();
    assert_eq!(state.policy_versions.bump("").await.unwrap(), 1);
    assert!(state
        .domain_map
        .put_if_absent(DomainBinding {
            domain: "orphan.example.test".into(),
            resource_id: "fixture-resource".into(),
            tenant_id: "default".into(),
            client_id: "missing-client".into(),
        })
        .await
        .unwrap());
    assert!(state
        .replay_store
        .as_ref()
        .unwrap()
        .check_and_set("", "orphan-replay", now + 300)
        .await
        .unwrap());
    for key in ["orphan-client", "control\u{1f}control-client"] {
        assert!(
            state
                .rate_limit
                .as_ref()
                .unwrap()
                .try_consume(key, now, 10.0, 1.0, 1.0)
                .await
                .unwrap()
                .allowed
        );
    }
    // An orphan protocol record belongs to no surviving user or client.
    state
        .par
        .put(
            "",
            ParRecord {
                request_uri: "orphan-request".into(),
                client_id: "orphan-client".into(),
                raw_params: "private-orphan-fixture".into(),
                expires_at: now + 300,
            },
        )
        .await
        .unwrap();
    state
        .par
        .put(
            "control",
            ParRecord {
                request_uri: "control-request".into(),
                client_id: "control-client".into(),
                raw_params: "control-fixture".into(),
                expires_at: now + 300,
            },
        )
        .await
        .unwrap();
    state
        .ssf
        .create_stream(super::ssf_contracts::stream("default", "erase-stream"))
        .await
        .unwrap();
    state
        .ssf
        .enqueue_event(
            &super::ssf_contracts::event("default", "erase-event"),
            "https://localhost",
            now,
        )
        .await
        .unwrap();
    let (router, _) = agent_auth_http::build_router(state.clone());
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/data-governance/tenant/offboarding")
                .header("host", "localhost")
                .header("authorization", "Bearer dev-admin-token-not-for-prod")
                .header("x-agent-auth-purpose", "privacy-request:test")
                .header("x-agent-auth-confirm", "true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    let job_id = body["job_id"].as_str().unwrap();
    let mut reached_retention = false;
    let mut ssf_rollback_checked = false;
    for index in 0..64 {
        let step_now = now + index * 10 + 1;
        let actor = if index % 2 == 0 { &other } else { &state };
        let before = state
            .governance
            .get_job("default", job_id)
            .await
            .unwrap()
            .unwrap();
        if before.tenant_cleanup_stage == TenantCleanupStage::SharedSignals && !ssf_rollback_checked
        {
            sqlx::query(
                "ALTER TABLE a_auth.ssf_deliveries ADD CONSTRAINT issue142_keep_delivery \
                CHECK (status <> 'suppressed') NOT VALID",
            )
            .execute(&pool)
            .await
            .unwrap();
            let rejected = advance_tenant_offboarding_once(actor, "default", job_id, step_now)
                .await
                .unwrap();
            assert_eq!(rejected.state, GovernanceJobState::Retryable);
            assert_eq!(
                rejected.tenant_cleanup_stage,
                TenantCleanupStage::SharedSignals
            );
            let stream = state
                .ssf
                .get_stream("default", "erase-stream")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stream.status, SsfStreamStatus::Enabled);
            assert_eq!(stream.revision, 1);
            assert_eq!(
                state
                    .ssf
                    .list_deliveries("default", "erase-stream", 100, None)
                    .await
                    .unwrap()
                    .deliveries[0]
                    .status,
                SsfDeliveryStatus::Pending
            );
            sqlx::query("ALTER TABLE a_auth.ssf_deliveries DROP CONSTRAINT issue142_keep_delivery")
                .execute(&pool)
                .await
                .unwrap();
            ssf_rollback_checked = true;
        }
        let job = advance_tenant_offboarding_once(actor, "default", job_id, step_now + 1)
            .await
            .unwrap();
        assert_ne!(
            job.state,
            GovernanceJobState::Retryable,
            "{:?}",
            job.error_class
        );
        if let Some(child_id) = job.active_child_job_id.as_deref() {
            for phase in 0..5 {
                let child =
                    advance_user_erasure_once(actor, "default", child_id, step_now + phase + 2)
                        .await
                        .unwrap();
                assert_ne!(
                    child.state,
                    GovernanceJobState::Retryable,
                    "{:?}",
                    child.error_class
                );
            }
        }
        if job.state == GovernanceJobState::RetentionPending {
            assert_eq!(job.phase, GovernanceJobPhase::RetentionVerification);
            assert_eq!(job.tenant_cleanup_stage, TenantCleanupStage::Complete);
            reached_retention = true;
            break;
        }
    }
    assert!(
        reached_retention,
        "offboarding failed to reach retained verification"
    );
    assert!(ssf_rollback_checked);
    assert!(state
        .clients
        .get("", "orphan-client")
        .await
        .unwrap()
        .is_none());
    assert!(state
        .initial_access_tokens
        .get("", "orphan-iat")
        .await
        .unwrap()
        .is_none());
    assert!(state
        .scim_groups
        .get("", "orphan-group")
        .await
        .unwrap()
        .is_none());
    assert!(state.policy_artifacts.get("", 1).await.unwrap().is_none());
    assert_eq!(state.policy_versions.get("").await.unwrap(), 0);
    assert!(state
        .domain_map
        .get("orphan.example.test")
        .await
        .unwrap()
        .is_none());
    let remaining_rates: i64 = sqlx::query_scalar("SELECT count(*) FROM a_auth.rate_limits")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        remaining_rates, 1,
        "default cleanup must preserve a foreign tenant bucket"
    );
    assert!(state
        .users
        .get_by_id("", "erase-user")
        .await
        .unwrap()
        .is_none());
    assert!(state
        .par
        .consume("", "orphan-request", now + 100)
        .await
        .unwrap()
        .is_none());
    assert!(state
        .par
        .consume("control", "control-request", now + 100)
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        state
            .ssf
            .get_stream("default", "erase-stream")
            .await
            .unwrap()
            .unwrap()
            .status,
        SsfStreamStatus::Revoked
    );
    let deliveries = state
        .ssf
        .list_deliveries("default", "erase-stream", 100, None)
        .await
        .unwrap();
    assert_eq!(deliveries.deliveries.len(), 1);
    assert_eq!(
        deliveries.deliveries[0].status,
        SsfDeliveryStatus::Suppressed
    );
    assert!(state
        .users
        .create_or_get_by_id("", "replacement", now + 100)
        .await
        .is_err());
    pool.close().await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

async fn seed_user_authority(
    state: &agent_auth_http::AppState,
    base: agent_auth_http::adapters::postgres::PostgresStore,
    user_id: &str,
    now: i64,
) {
    use agent_auth_grant::{Grant, GrantConstraints, GrantStatus};
    use agent_auth_http::{
        adapters::{
            mounted_crypto::EncryptionKeyring,
            postgres::{PostgresCibaStore, PostgresGraceStore, PostgresMessageOutbox},
        },
        ports::*,
    };
    ClientStore::put(
        &base,
        "",
        ClientRecord {
            client_id: "client".into(),
            token_endpoint_auth_method: "none".into(),
            redirect_uris: vec!["https://client.example/callback".into()],
            last_used_day: Some(now / 86_400),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut code = super::code_record();
    code.code = "erase-code".into();
    code.user_id = user_id.into();
    code.authz_session_id = Some("erase-authz".into());
    code.credential_epoch = Some(0);
    code.expires_at = now + 300;
    state.codes.put("", code).await.unwrap();
    state
        .authz_sessions
        .create(
            "",
            AuthzSessionRecord {
                session_id: "erase-authz".into(),
                client_id: "client".into(),
                user_id: None,
                state: "created".into(),
                session_token_hash: "opaque".into(),
                sequence: 0,
                last_error: None,
                expires_at: now + 300,
            },
        )
        .await
        .unwrap();
    let mut family = super::refresh_record();
    family.family_id = "erase-family".into();
    family.user_id = user_id.into();
    family.credential_epoch = 0;
    state.refresh.create("", family).await.unwrap();
    // Seed encrypted records through the writing adapters, then erase using
    // the delete-only composition whose workers have no wrapping keys.
    let keys = EncryptionKeyring::new("fixture", vec![("fixture".into(), [0x71; 32])]).unwrap();
    PostgresGraceStore::new(base.clone(), keys.clone())
        .put(GraceCacheEntry {
            family_id: "erase-family".into(),
            version: 1,
            fingerprint: [7; 32],
            client_id: "client".into(),
            dpop_jkt: None,
            response: GraceCachedResponse {
                access_token: "private-access-fixture".into(),
                refresh_token: "private-refresh-fixture".into(),
                id_token: None,
                scope: None,
                expires_in: 300,
            },
            expires_at: now + 300,
        })
        .await
        .unwrap();
    let mut ciba = super::ciba_contracts::record("", "erase-ciba", user_id);
    ciba.expires_at = now + 300;
    let ciba_writer = PostgresCibaStore::new(base.clone(), keys.clone());
    ciba_writer.put("", ciba).await.unwrap();
    ciba_writer
        .try_arm_throttle("", user_id, now, 60)
        .await
        .unwrap();
    PostgresMessageOutbox::new(base, keys)
        .record_delivered(SentMessage {
            message_id: "erase-message".into(),
            tenant: "".into(),
            kind: "magic_link".into(),
            recipient: "erased@example.com".into(),
            body: "private-message-fixture".into(),
            created_at: now,
            ttl: now + 3600,
        })
        .await
        .unwrap();
    state
        .passkey_challenges
        .put(PasskeyChallenge {
            challenge_b64url: "erase-challenge".into(),
            tenant: "".into(),
            user_id: Some(user_id.into()),
            ceremony: PasskeyCeremony::Registration,
            rp_id: "localhost".into(),
            origin: "https://localhost".into(),
            expires_at: now + 300,
        })
        .await
        .unwrap();
    state
        .grants
        .put(
            "",
            Grant {
                grant_id: "erase-grant".into(),
                user_id: user_id.into(),
                client_id: "client".into(),
                per_resource: vec![],
                effective_per_resource: vec![],
                effective_pv: 0,
                allowed_ip_cidrs: vec![],
                allowed_vpce: vec![],
                credential_epoch: 0,
                revision: 1,
                constraints: GrantConstraints {
                    max_act_chain: 1,
                    actor_allowlist: vec![],
                    expires_at: now + 300,
                },
                status: GrantStatus::Active,
            },
        )
        .await
        .unwrap();
    state
        .jti_store
        .as_ref()
        .unwrap()
        .put(JtiRecord {
            delegation: None,
            jti: "erase-jti".into(),
            tenant_id: "default".into(),
            user_id: user_id.into(),
            family_id: Some("erase-family".into()),
            grant_id: Some("erase-grant".into()),
            expires_at: now + 300,
        })
        .await
        .unwrap();
    state
        .device
        .put(
            "",
            DeviceAuthGrant {
                device_code: "erase-device".into(),
                user_code: "ERASE123".into(),
                client_id: "client".into(),
                user_id: Some(user_id.into()),
                authz_session_id: None,
                scope: vec![],
                resources: vec![],
                interval: 5,
                last_poll_at: None,
                expires_at: now + 300,
                status: "approved".into(),
                consumed: false,
                password_credential_version: None,
            },
        )
        .await
        .unwrap();
    state
        .magic_links
        .put(
            "",
            MagicLinkRecord {
                link_id: "erase-link".into(),
                user_id: user_id.into(),
                email: "erased@example.com".into(),
                session_nonce: "nonce".into(),
                authorize_query: String::new(),
                next: String::new(),
                expires_at: now + 300,
            },
        )
        .await
        .unwrap();
    state
        .magic_links
        .mark_sent("", "erased@example.com", now)
        .await
        .unwrap();
    let mut invitation = super::invitation_contracts::record(user_id, "erased@example.com");
    invitation.locator = "erase-invitation".into();
    invitation.issued_at = now;
    invitation.expires_at = now + 300;
    assert_eq!(
        state.invitations.issue("", invitation).await.unwrap(),
        InvitationIssueOutcome::Issued
    );
    state
        .scim_groups
        .create(
            "",
            ScimGroupCreateInput {
                group_id: "erase-group".into(),
                external_id: "erase-group-external".into(),
                display_name: "Fixture group".into(),
                members: vec![user_id.into()],
                now,
            },
        )
        .await
        .unwrap();
    state
        .scim_groups
        .set_role_mapping("", "erase-group-external", Some(TenantRole::Admin), now)
        .await
        .unwrap();
    state
        .admin_auth
        .create_session(AdminSessionRecord {
            session_hash: "erase-admin-session".into(),
            tenant_id: "default".into(),
            user_id: user_id.into(),
            upstream_subject: "fixture-subject".into(),
            role: TenantRole::Owner,
            credential_epoch: 0,
            config_revision: 1,
            config_binding_id: "fixture-binding".into(),
            acr: None,
            auth_time: now,
            created_at: now,
            expires_at: now + 300,
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn postgres_governance_user_erasure_http_cleans_and_suppresses_across_pools() {
    use agent_auth_http::{
        governance_worker::advance_user_erasure_once,
        ports::{
            PasskeyStore, PasswordCredential, PasswordStore, RecoveryStore, ScimGroupCreateInput,
            ScimGroupsStore, ScimUserInput, SessionRecord, SessionStore, UserStatus, UsersStore,
        },
    };
    let (base, pool, admin, name, url) = super::ssf_contracts::isolated_database().await;
    let state = user_data_state(base.clone());
    let other = user_data_state(
        agent_auth_http::adapters::postgres::PostgresStore::connect(&url, 8)
            .await
            .unwrap(),
    );
    let now = agent_auth_http::current_unix_secs();
    let user_id = "user:erased@example.com";
    state
        .users
        .create_scim(
            "",
            ScimUserInput {
                user_id: user_id.into(),
                external_id: "erase-scim-external".into(),
                user_name: "erased@example.com".into(),
                display_name: Some("Fixture user".into()),
                active: true,
                now,
            },
        )
        .await
        .unwrap();
    seed_user_authority(&state, base, user_id, now).await;
    assert!(state
        .passwords
        .create_if_absent(
            "",
            PasswordCredential {
                user_id: user_id.into(),
                password_hash: agent_auth_authn::password::dummy_hash().clone(),
                must_change: false,
                revocation_pending: false,
                credential_change_id: None,
                version: 7,
                updated_at: now,
            },
        )
        .await
        .unwrap());
    state
        .sessions
        .create(
            "",
            SessionRecord {
                session_id: "erase-session".into(),
                user_id: user_id.into(),
                credential_epoch: 0,
                auth_time: now,
                created_at: now,
                last_used_at: now,
                device: "contract".into(),
                expires_at: now + 3600,
                acr: None,
                amr: vec!["email".into()],
            },
        )
        .await
        .unwrap();
    assert!(state
        .passkeys
        .put_new("", super::passkey_contracts::record("erase-key", user_id))
        .await
        .unwrap());
    let mut recovery = super::recovery_contracts::record("erase-lookup");
    recovery.user_id = user_id.into();
    state.recovery.put("", recovery).await.unwrap();
    state
        .users
        .create_or_get_by_email("", "neighbor@example.com", "neighbor", now)
        .await
        .unwrap();
    let mut neighbor_session = state
        .sessions
        .get("", "erase-session")
        .await
        .unwrap()
        .unwrap();
    neighbor_session.session_id = "neighbor-session".into();
    neighbor_session.user_id = "neighbor".into();
    state.sessions.create("", neighbor_session).await.unwrap();
    assert!(state
        .passkeys
        .put_new(
            "",
            super::passkey_contracts::record("neighbor-key", "neighbor")
        )
        .await
        .unwrap());
    state
        .scim_groups
        .create(
            "",
            ScimGroupCreateInput {
                group_id: "neighbor-group".into(),
                external_id: "neighbor-external".into(),
                display_name: "Neighbor group".into(),
                members: vec!["neighbor".into()],
                now,
            },
        )
        .await
        .unwrap();
    let job_id = start_user_erasure(&state, user_id).await;
    for (index, phase) in [
        GovernanceJobPhase::MutationFenced,
        GovernanceJobPhase::PrimaryCleanup,
        GovernanceJobPhase::SuppressionRecorded,
        GovernanceJobPhase::ReplicaVerification,
        GovernanceJobPhase::RetentionVerification,
    ]
    .into_iter()
    .enumerate()
    {
        let actor = if index % 2 == 0 { &other } else { &state };
        let job = advance_user_erasure_once(actor, "default", &job_id, now + index as i64 + 1)
            .await
            .unwrap();
        assert_eq!(job.phase, phase);
        if index == 0 {
            let user = state.users.get_by_id("", user_id).await.unwrap().unwrap();
            assert_eq!(user.status, UserStatus::Tombstoned);
            assert_eq!(user.credential_epoch, job.target_epoch);
            assert!(user.revocation_pending);
        }
        if index == 4 {
            assert_eq!(job.state, GovernanceJobState::RetentionPending);
        }
    }
    assert!(other.users.get_by_id("", user_id).await.unwrap().is_none());
    assert!(other.passwords.get("", user_id).await.unwrap().is_none());
    assert!(other
        .sessions
        .get("", "erase-session")
        .await
        .unwrap()
        .is_none());
    assert!(other.passkeys.get("", "erase-key").await.unwrap().is_none());
    assert!(other
        .recovery
        .get("", "erase-lookup")
        .await
        .unwrap()
        .is_none());
    assert!(matches!(
        other
            .users
            .create_or_get_by_email("", "erased@example.com", "replacement", now + 10)
            .await,
        Err(agent_auth_http::ports::StoreError::Permanent(_))
    ));
    assert!(matches!(
        other.users.create_or_get_by_id("", user_id, now + 10).await,
        Err(agent_auth_http::ports::StoreError::Permanent(_))
    ));
    assert!(matches!(
        other
            .users
            .create_scim(
                "",
                ScimUserInput {
                    user_id: "replacement".into(),
                    external_id: "erase-scim-external".into(),
                    user_name: "replacement@example.com".into(),
                    display_name: None,
                    active: true,
                    now: now + 10,
                }
            )
            .await,
        Err(agent_auth_http::ports::StoreError::Permanent(_))
    ));
    assert!(other
        .users
        .get_by_id("", "neighbor")
        .await
        .unwrap()
        .is_some());
    assert!(other
        .sessions
        .get("", "neighbor-session")
        .await
        .unwrap()
        .is_some());
    assert!(other
        .passkeys
        .get("", "neighbor-key")
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        other
            .scim_groups
            .get("", "neighbor-group")
            .await
            .unwrap()
            .unwrap()
            .members,
        ["neighbor"]
    );
    pool.close().await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

pub(super) fn evidence(job: &GovernanceJobRecord) -> GovernanceEvidenceRecord {
    GovernanceEvidenceRecord::new(GovernanceEvidencePayload {
        schema_version: GOVERNANCE_EVIDENCE_SCHEMA_VERSION.into(),
        tenant_id: job.tenant_id.clone(),
        job_id: job.job_id.clone(),
        job_kind: job.kind,
        job_state: GovernanceJobState::Completed,
        evidence_revision: job.evidence_revision,
        deployment_commit: "contract-fixture".into(),
        started_at: job.created_at,
        verification_at: job.updated_at,
        generated_at: job.updated_at,
        primary_erasure_at: job.primary_erasure_at.unwrap(),
        retention_deadline: job.retention_until.unwrap(),
        residency_jurisdiction: "local".into(),
        configured_regions: vec!["local".into()],
        active_writer_region: "local".into(),
        region_control_revision: 0,
        legal_hold: LegalHoldState::Disabled,
        live_counts: Default::default(),
        retained_counts: Default::default(),
        replica_live_counts: Default::default(),
        alias_tombstone_count: 1,
        retention_resources: Default::default(),
        external_actions: vec![GovernanceEvidenceAction {
            action_id: "optional-outcome".into(),
            kind: GovernanceExternalActionKind::SecretDeletion,
            ownership: GovernanceResourceOwnership::External,
            state: GovernanceExternalActionState::OperatorPending,
            outcome: None,
            retention_until: None,
        }],
        permanent_control_records: vec!["governance_evidence".into()],
    })
    .unwrap()
}

#[tokio::test]
async fn postgres_governance_user_cleanup_rolls_back_and_rejects_foreign_pool() {
    use agent_auth_http::{
        governance_worker::advance_user_erasure_once,
        ports::{PasskeyStore, ScimGroupsStore, UserStatus, UsersStore},
    };
    let (base, pool, admin, name, url) = super::ssf_contracts::isolated_database().await;
    let state = user_data_state(base.clone());
    let mut other = user_data_state(
        agent_auth_http::adapters::postgres::PostgresStore::connect(&url, 8)
            .await
            .unwrap(),
    );
    let now = agent_auth_http::current_unix_secs();
    let user_id = "user:erased@example.com";
    state
        .users
        .create_or_get_by_email("", "erased@example.com", user_id, now)
        .await
        .unwrap();
    seed_user_authority(&state, base, user_id, now).await;
    assert!(state
        .passkeys
        .put_new("", super::passkey_contracts::record("erase-key", user_id))
        .await
        .unwrap());
    let job_id = start_user_erasure(&state, user_id).await;

    // Even a separate pool to the same database cannot silently participate in
    // a transaction belonging to another pool's configured store graph.
    other.passkeys = state.passkeys.clone();
    let rejected = advance_user_erasure_once(&other, "default", &job_id, now + 1)
        .await
        .unwrap();
    assert_eq!(rejected.phase, GovernanceJobPhase::IntentRecorded);
    assert_eq!(rejected.state, GovernanceJobState::Retryable);
    assert_eq!(
        state
            .users
            .get_by_id("", user_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        UserStatus::Active
    );
    let mut other = user_data_state(
        agent_auth_http::adapters::postgres::PostgresStore::connect(&url, 8)
            .await
            .unwrap(),
    );
    other.governance_hmac_key = Arc::new(vec![0x58; 32]);
    let mismatched_key = advance_user_erasure_once(&other, "default", &job_id, now + 2)
        .await
        .unwrap();
    assert_eq!(mismatched_key.phase, GovernanceJobPhase::IntentRecorded);
    assert_eq!(mismatched_key.state, GovernanceJobState::Retryable);
    assert_eq!(
        state
            .users
            .get_by_id("", user_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        UserStatus::Active
    );
    other.governance_hmac_key = Arc::new(vec![0x57; 32]);
    assert_eq!(
        advance_user_erasure_once(&other, "default", &job_id, now + 2)
            .await
            .unwrap()
            .phase,
        GovernanceJobPhase::MutationFenced
    );

    // All earlier deletes must roll back when the final group write fails.
    sqlx::query(
        "ALTER TABLE a_auth.scim_groups ADD CONSTRAINT issue142_keep_members \
                 CHECK (cardinality(members) > 0) NOT VALID",
    )
    .execute(&pool)
    .await
    .unwrap();
    let tables = [
        "codes",
        "authz_sessions",
        "refresh_families",
        "grace_responses",
        "passkey_challenges",
        "passkey_credentials",
        "grants",
        "jti",
        "ciba_requests",
        "ciba_throttle",
        "device_grants",
        "magic_links",
        "magic_link_cooldowns",
        "invitations",
        "message_outbox",
        "admin_sessions",
    ];
    let mut before = Vec::new();
    for table in tables {
        let total: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM a_auth.{table}"))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(total > 0, "fixture failed to seed {table}");
        before.push(total);
    }
    let failed = advance_user_erasure_once(&state, "default", &job_id, now + 3)
        .await
        .unwrap();
    assert_eq!(failed.phase, GovernanceJobPhase::MutationFenced);
    assert_eq!(failed.state, GovernanceJobState::Retryable);
    for (table, expected) in tables.into_iter().zip(before) {
        let actual: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM a_auth.{table}"))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(actual, expected, "partial erasure committed for {table}");
    }
    assert_eq!(
        other
            .scim_groups
            .get("", "erase-group")
            .await
            .unwrap()
            .unwrap()
            .members,
        [user_id]
    );
    sqlx::query("ALTER TABLE a_auth.scim_groups DROP CONSTRAINT issue142_keep_members")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        advance_user_erasure_once(&other, "default", &job_id, now + 4)
            .await
            .unwrap()
            .phase,
        GovernanceJobPhase::PrimaryCleanup
    );
    assert!(state.passkeys.get("", "erase-key").await.unwrap().is_none());
    assert!(state
        .scim_groups
        .get("", "erase-group")
        .await
        .unwrap()
        .unwrap()
        .members
        .is_empty());
    pool.close().await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

#[tokio::test]
async fn postgres_governance_user_fence_expired_during_row_lock_rolls_back() {
    use agent_auth_http::{
        governance_worker::advance_user_erasure_once,
        ports::{UserStatus, UsersStore},
    };
    let (base, pool, admin, name, url) = super::ssf_contracts::isolated_database().await;
    let state = user_data_state(base);
    let other = user_data_state(
        agent_auth_http::adapters::postgres::PostgresStore::connect(&url, 8)
            .await
            .unwrap(),
    );
    let user_id = "user:erased@example.com";
    let now = agent_auth_http::current_unix_secs();
    state
        .users
        .create_or_get_by_email("", "erased@example.com", user_id, now)
        .await
        .unwrap();
    let job_id = start_user_erasure(&state, user_id).await;
    let mut held = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM a_auth.users WHERE tenant = $1 AND user_id = $2 FOR UPDATE")
        .bind(b"".as_slice())
        .bind(user_id.as_bytes())
        .fetch_one(&mut *held)
        .await
        .unwrap();
    // Public worker leases last 360 seconds. Capture a controlled historical
    // admission clock that leaves two seconds for a real SQL row-lock wait.
    let admission_time = agent_auth_http::current_unix_secs() - 358;
    let task_job = job_id.clone();
    let task = tokio::spawn(async move {
        advance_user_erasure_once(&other, "default", &task_job, admission_time)
            .await
            .unwrap()
    });
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity \
                 WHERE datname = current_database() AND wait_event_type = 'Lock' \
                 AND query LIKE 'SELECT user_id%FROM a_auth.users%FOR UPDATE')",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            if blocked {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("worker did not reach the identity row lock under a live lease");
    while agent_auth_http::current_unix_secs() < admission_time + 360 {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    held.commit().await.unwrap();
    let outcome = task.await.unwrap();
    assert_eq!(outcome.phase, GovernanceJobPhase::IntentRecorded);
    assert_eq!(outcome.state, GovernanceJobState::Retryable);
    let user = state.users.get_by_id("", user_id).await.unwrap().unwrap();
    assert_eq!(user.status, UserStatus::Active);
    assert_eq!(user.credential_epoch, 0);
    assert!(!user.revocation_pending);
    assert_eq!(
        advance_user_erasure_once(
            &state,
            "default",
            &job_id,
            agent_auth_http::current_unix_secs()
        )
        .await
        .unwrap()
        .phase,
        GovernanceJobPhase::MutationFenced
    );
    pool.close().await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

pub(super) fn job(tenant: &str, id: &str, kind: GovernanceJobKind) -> GovernanceJobRecord {
    GovernanceJobRecord {
        job_id: id.into(),
        tenant_id: tenant.into(),
        kind,
        target_id: (kind == GovernanceJobKind::UserErasure).then(|| "user-1".into()),
        target_aliases: vec![],
        verification_target: None,
        active_child_job_id: None,
        processed_records: 0,
        tenant_cleanup_stage: TenantCleanupStage::Users,
        target_epoch: 7,
        state: GovernanceJobState::Running,
        phase: GovernanceJobPhase::PrimaryCleanup,
        policy_revision: 0,
        tenant_revision: 0,
        revision: 1,
        created_at: 100,
        updated_at: 100,
        primary_erasure_at: None,
        retention_anchor_at: None,
        retention_until: None,
        evidence_revision: 0,
        error_class: None,
    }
}

async fn governance_contract(store: impl GovernanceStore + Clone + 'static) {
    let tenant = tenant();
    let foreign = format!("{tenant}-foreign");
    assert_eq!(store.get_policy(&tenant).await.unwrap(), None);
    let policy = GovernancePolicyRecord::default_for(&tenant);
    let policy = match store.put_policy(policy, 0).await.unwrap() {
        GovernancePolicyPutOutcome::Stored(value) => value,
        other => panic!("unexpected policy admission: {other:?}"),
    };
    assert_eq!(policy.revision, 1);
    assert!(matches!(
        store.put_policy(policy.clone(), 0).await.unwrap(),
        GovernancePolicyPutOutcome::Conflict(_)
    ));
    assert_eq!(store.get_policy(&foreign).await.unwrap(), None);
    let manifest = GovernanceExportManifest {
        export_id: "export".into(),
        tenant_id: tenant.clone(),
        actor: "auditor".into(),
        purpose: "port contract".into(),
        policy_revision: 1,
        region: "local".into(),
        region_revision: 0,
        sections: Default::default(),
        created_at: 100,
        expires_at: 150,
    };
    assert!(store.put_export_manifest(manifest.clone()).await.unwrap());
    let mut replacement = manifest.clone();
    replacement.purpose = "must not overwrite".into();
    assert!(!store.put_export_manifest(replacement).await.unwrap());
    assert_eq!(
        store
            .get_export_manifest(&tenant, "export", 149)
            .await
            .unwrap(),
        Some(manifest)
    );
    assert_eq!(
        store
            .get_export_manifest(&foreign, "export", 149)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .get_export_manifest(&tenant, "export", 150)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .get_export_manifest(&tenant, "export", 100)
            .await
            .unwrap(),
        None
    );
    let original = job(&tenant, "erase", GovernanceJobKind::UserErasure);
    let admitted = match store
        .start_or_resume_job(original.clone(), 1, false)
        .await
        .unwrap()
    {
        GovernanceJobStartOutcome::Stored(value) => value,
        other => panic!("unexpected job admission: {other:?}"),
    };
    assert_eq!(admitted.policy_revision, 1);
    assert_eq!(
        store.get_job(&tenant, "erase").await.unwrap(),
        Some(admitted.clone())
    );
    assert_eq!(store.get_job(&foreign, "erase").await.unwrap(), None);
    assert_eq!(store.list_jobs(&tenant).await.unwrap(), vec![admitted]);
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for actor in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .claim_job_lease(&tenant, "erase", 1, &format!("actor-{actor}"), 100, 200)
                .await
                .unwrap()
        }));
    }
    let mut winner = None;
    for task in tasks {
        match task.await.unwrap() {
            GovernanceJobLeaseOutcome::Acquired(value) => {
                assert!(winner.replace(value).is_none());
            }
            GovernanceJobLeaseOutcome::Conflict(_) => {}
            other => panic!("unexpected lease claim: {other:?}"),
        }
    }
    let lease = winner.unwrap();
    assert!(store
        .tenant_has_active_job_leases(&tenant, 101)
        .await
        .unwrap());
    assert!(!store
        .tenant_has_active_job_leases(&foreign, 101)
        .await
        .unwrap());
    let digest = suppression_digest(&[0x57; 32], &tenant, "user", "canonical_id", 1, "user-1");
    let suppression = GovernanceSuppressionRecord {
        tenant_id: tenant.clone(),
        target_class: "user".into(),
        key_version: 1,
        normalization_version: 1,
        digest: digest.clone(),
        target_epoch: 7,
        created_at: 101,
    };
    assert!(store
        .put_suppression(suppression.clone(), lease.destructive_fence(Some(7)), 101)
        .await
        .unwrap());
    assert!(!store
        .put_suppression(suppression, lease.destructive_fence(Some(7)), 102)
        .await
        .unwrap());
    assert!(store.is_suppressed(&tenant, "user", &digest).await.unwrap());
    assert!(!store
        .is_suppressed(&foreign, "user", &digest)
        .await
        .unwrap());
    assert_eq!(
        store
            .latest_suppression_epoch(&tenant, "user", &digest)
            .await
            .unwrap(),
        Some(7)
    );
    let renewed = match store
        .renew_job_lease(&tenant, lease.destructive_fence(Some(7)), 120, 250)
        .await
        .unwrap()
    {
        GovernanceJobLeaseOutcome::Renewed(value) => value,
        other => panic!("unexpected lease renewal: {other:?}"),
    };
    assert!(matches!(
        store
            .release_job_lease(&tenant, lease.destructive_fence(Some(7)))
            .await
            .unwrap(),
        GovernanceJobLeaseOutcome::Conflict(_)
    ));
    assert_eq!(
        store
            .release_job_lease(&tenant, renewed.destructive_fence(Some(7)))
            .await
            .unwrap(),
        GovernanceJobLeaseOutcome::Released
    );
    assert!(!store
        .tenant_has_active_job_leases(&tenant, 130)
        .await
        .unwrap());
    let mut checkpoint = store.get_job(&tenant, "erase").await.unwrap().unwrap();
    checkpoint.processed_records = 5;
    checkpoint.updated_at = 131;
    let checkpoint = match store.update_job(checkpoint, 1, 1).await.unwrap() {
        GovernanceJobUpdateOutcome::Stored(value) => value,
        other => panic!("unexpected job checkpoint: {other:?}"),
    };
    assert_eq!(checkpoint.revision, 2);
    assert!(matches!(
        store.update_job(checkpoint.clone(), 1, 1).await.unwrap(),
        GovernanceJobUpdateOutcome::Conflict(_)
    ));
    let mut completed = checkpoint;
    completed.state = GovernanceJobState::Completed;
    completed.phase = GovernanceJobPhase::Complete;
    completed.updated_at = 135;
    completed.primary_erasure_at = Some(134);
    completed.retention_until = Some(135);
    completed.evidence_revision = 1;
    completed.target_id = None;
    let proof = evidence(&completed);
    let completed = match store
        .complete_job_with_evidence(completed, proof.clone(), 2, 1)
        .await
        .unwrap()
    {
        GovernanceJobUpdateOutcome::Stored(value) => value,
        other => panic!("unexpected atomic completion: {other:?}"),
    };
    assert_eq!(completed.revision, 3);
    assert_eq!(
        store.latest_evidence(&tenant, "erase").await.unwrap(),
        Some(proof.clone())
    );
    assert_eq!(
        store.latest_evidence(&foreign, "erase").await.unwrap(),
        None
    );
    assert_eq!(
        store.put_evidence(proof.clone()).await.unwrap(),
        GovernanceEvidencePutOutcome::Existing(proof)
    );
    let mut next_proof = evidence(&completed).payload;
    next_proof.evidence_revision = 2;
    let next_proof = GovernanceEvidenceRecord::new(next_proof).unwrap();
    assert_eq!(
        store.put_evidence(next_proof.clone()).await.unwrap(),
        GovernanceEvidencePutOutcome::Stored(next_proof.clone())
    );
    assert_eq!(
        store.latest_evidence(&tenant, "erase").await.unwrap(),
        Some(next_proof)
    );
    let mut held = policy;
    held.legal_hold = LegalHoldState::Enabled;
    held.legal_hold_reason = Some("retained evidence".into());
    held.updated_at = 140;
    let held = match store.put_policy(held, 1).await.unwrap() {
        GovernancePolicyPutOutcome::Stored(value) => value,
        other => panic!("unexpected hold admission: {other:?}"),
    };
    assert!(matches!(
        store
            .claim_job_lease(&tenant, "erase", 1, "late", 140, 250)
            .await
            .unwrap(),
        GovernanceJobLeaseOutcome::Conflict(_)
    ));
    let blocked = job(&tenant, "blocked", GovernanceJobKind::UserErasure);
    let blocked = match store.start_or_resume_job(blocked, 2, false).await.unwrap() {
        GovernanceJobStartOutcome::Stored(value) => value,
        other => panic!("unexpected held job: {other:?}"),
    };
    assert_eq!(blocked.state, GovernanceJobState::BlockedLegalHold);
    let mut active = held;
    active.legal_hold = LegalHoldState::Disabled;
    active.legal_hold_reason = None;
    active.updated_at = 160;
    assert!(matches!(
        store.put_policy(active, 2).await.unwrap(),
        GovernancePolicyPutOutcome::Stored(_)
    ));
    let resumed = match store.start_or_resume_job(blocked, 3, false).await.unwrap() {
        GovernanceJobStartOutcome::Existing(value) => value,
        other => panic!("unexpected held-job resume: {other:?}"),
    };
    assert_eq!(resumed.state, GovernanceJobState::Queued);
    assert_eq!(resumed.revision, 2);
    assert_eq!(resumed.policy_revision, 3);
    let permit = TenantMutationPermit {
        tenant_id: tenant.clone(),
        permit_id: "writer".into(),
        deadline: 300,
    };
    assert_eq!(
        store
            .acquire_tenant_mutation_permit(permit.clone(), 160)
            .await
            .unwrap(),
        TenantMutationPermitAcquireOutcome::Acquired(permit.clone())
    );
    assert!(store
        .renew_tenant_mutation_permit(&permit, 180, 400)
        .await
        .unwrap());
    assert!(!store
        .release_tenant_mutation_permit(permit.clone(), 181)
        .await
        .unwrap());
    let mut offboard = job(&tenant, "offboard", GovernanceJobKind::TenantOffboarding);
    offboard.target_id = None;
    offboard.updated_at = 190;
    assert_eq!(
        store
            .start_or_resume_job(offboard.clone(), 3, true)
            .await
            .unwrap(),
        GovernanceJobStartOutcome::MutationConflict { active_permits: 1 }
    );
    let mut renewed_permit = permit;
    renewed_permit.deadline = 400;
    assert!(store
        .release_tenant_mutation_permit(renewed_permit, 191)
        .await
        .unwrap());
    offboard.updated_at = 192;
    let frozen = match store.start_or_resume_job(offboard, 3, true).await.unwrap() {
        GovernanceJobStartOutcome::Stored(value) => value,
        other => panic!("unexpected offboarding admission: {other:?}"),
    };
    assert_eq!(frozen.tenant_revision, 1);
    assert_eq!(
        store
            .get_tenant_lifecycle(&tenant)
            .await
            .unwrap()
            .unwrap()
            .state,
        TenantLifecycleState::Offboarding
    );
    assert_eq!(
        store
            .acquire_tenant_mutation_permit(
                TenantMutationPermit {
                    tenant_id: tenant.clone(),
                    permit_id: "too-late".into(),
                    deadline: 300,
                },
                193
            )
            .await
            .unwrap(),
        TenantMutationPermitAcquireOutcome::Frozen {
            lifecycle_revision: Some(1)
        }
    );
    assert_eq!(
        store
            .start_or_resume_job(
                job(&tenant, "new-user", GovernanceJobKind::UserErasure),
                3,
                false
            )
            .await
            .unwrap(),
        GovernanceJobStartOutcome::TenantFrozen {
            lifecycle_revision: 1
        }
    );
    let continuation = store
        .get_continuation(&tenant, "offboard")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(continuation.tenant_revision, 1);
    assert_eq!(continuation.resume_revision, 1);
    assert_eq!(
        store.get_continuation(&foreign, "offboard").await.unwrap(),
        None
    );
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .consume_continuation_resume(&tenant, "offboard", "one-time-digest", 1, 300)
                .await
                .unwrap()
        }));
    }
    let mut consumed = 0;
    for task in tasks {
        consumed += usize::from(task.await.unwrap());
    }
    assert_eq!(consumed, 1);
    let mut disabled = continuation;
    disabled.resume_enabled = false;
    disabled.updated_at = 194;
    assert!(matches!(
        store.update_continuation(disabled, 1).await.unwrap(),
        GovernanceContinuationUpdateOutcome::Stored(_)
    ));
    assert!(!store
        .consume_continuation_resume(&tenant, "offboard", "another-digest", 1, 300)
        .await
        .unwrap());
    let lease = match store
        .claim_job_lease(&tenant, "offboard", 1, "external-worker", 195, 300)
        .await
        .unwrap()
    {
        GovernanceJobLeaseOutcome::Acquired(value) => value,
        other => panic!("unexpected external worker lease: {other:?}"),
    };
    let action = GovernanceExternalActionRecord {
        action_id: "secret-delete".into(),
        tenant_id: tenant.clone(),
        job_id: "offboard".into(),
        kind: GovernanceExternalActionKind::SecretDeletion,
        resource_ref: "fixture-secret-reference".into(),
        resource_fingerprint: resource_fingerprint("fixture-secret-reference"),
        ownership: GovernanceResourceOwnership::ProductManaged,
        state: GovernanceExternalActionState::Prepared,
        revision: 1,
        created_at: 196,
        updated_at: 196,
        claim_token_digest: None,
        claim_deadline: None,
        committed_at: None,
        verified_at: None,
        retention_until: None,
        error_class: None,
    };
    let mut rebound = action.clone();
    rebound.resource_fingerprint = resource_fingerprint("another-secret-reference");
    assert!(matches!(
        store
            .prepare_external_action(rebound, lease.external_action_fence())
            .await,
        Err(agent_auth_http::ports::StoreError::Permanent(_))
    ));
    assert_eq!(
        store
            .prepare_external_action(action.clone(), lease.external_action_fence())
            .await
            .unwrap(),
        GovernanceExternalActionPutOutcome::Stored(action.clone())
    );
    assert_eq!(
        store
            .prepare_external_action(action.clone(), lease.external_action_fence())
            .await
            .unwrap(),
        GovernanceExternalActionPutOutcome::Existing(action.clone())
    );
    assert_eq!(
        store
            .get_external_action(&tenant, "offboard", "secret-delete")
            .await
            .unwrap(),
        Some(action.clone())
    );
    assert_eq!(
        store
            .get_external_action(&foreign, "offboard", "secret-delete")
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .list_external_actions(&tenant, "offboard")
            .await
            .unwrap(),
        vec![action.clone()]
    );
    assert_eq!(
        store.list_tenant_external_actions(&tenant).await.unwrap(),
        vec![action.clone()]
    );
    let mut claimed = action;
    claimed.state = GovernanceExternalActionState::Claimed;
    claimed.claim_token_digest = Some("external-claim-digest".into());
    claimed.claim_deadline = Some(290);
    claimed.updated_at = 197;
    let claimed = match store
        .update_external_action(claimed, 1, lease.external_action_fence())
        .await
        .unwrap()
    {
        GovernanceExternalActionUpdateOutcome::Stored(value) => value,
        other => panic!("unexpected external claim: {other:?}"),
    };
    assert_eq!(claimed.revision, 2);
    let mut verified = claimed;
    verified.state = GovernanceExternalActionState::Verified;
    verified.verified_at = Some(198);
    verified.updated_at = 198;
    let verified = match store
        .reconcile_external_action(
            verified,
            2,
            GovernanceExternalActionReconcileFence {
                job_id: "offboard".into(),
                tenant_revision: 1,
                claim_token_digest: "external-claim-digest".into(),
            },
        )
        .await
        .unwrap()
    {
        GovernanceExternalActionUpdateOutcome::Stored(value) => value,
        other => panic!("unexpected external reconciliation: {other:?}"),
    };
    assert_eq!(verified.revision, 3);
    assert_eq!(
        store.list_tenant_external_actions(&tenant).await.unwrap(),
        vec![verified]
    );
}

#[tokio::test]
async fn memory_governance_contract() {
    governance_contract(MemoryGovernanceStore::default()).await;
}

#[tokio::test]
async fn postgres_governance_contract() {
    governance_contract(agent_auth_http::governance::GovernanceStoreImpl::Postgres(
        PostgresGovernanceStore::new(database().await),
    ))
    .await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_governance_contract() {
    use agent_auth_http::adapters::aws::DynamoGovernanceStore;
    use aws_sdk_dynamodb::types::ScalarAttributeType;
    let (db, governance) =
        super::aws_contract_database::table_with_range("pk", Some("sk"), vec![], vec![]).await;
    let (_, suppression) = super::aws_contract_database::table_with_typed_range(
        "pk",
        Some(("epoch", ScalarAttributeType::N)),
        vec![],
        vec![],
    )
    .await;
    governance_contract(DynamoGovernanceStore::new(
        db.clone(),
        &governance,
        &suppression,
    ))
    .await;
    for table in [governance, suppression] {
        db.delete_table().table_name(table).send().await.unwrap();
    }
}
