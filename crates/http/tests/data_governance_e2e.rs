use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use agent_auth_grant::{Grant, GrantConstraints, GrantStatus};
use agent_auth_http::{
    admin_credentials::{
        AdminCredentialOwner, AdminCredentialRecord, AdminCredentialResolver, AdminCredentialSet,
        MemoryAdminCredentialStore,
    },
    build_router,
    governance::{
        GovernanceConfig, GovernanceEvidencePayload, GovernanceEvidenceRecord,
        GovernanceExternalActionState, GovernanceJobPhase, GovernanceJobState,
        GovernanceReplicaEvidence, GovernanceResourceOwnership, LegalHoldState, TenantCleanupStage,
    },
    governance_worker::{
        advance_tenant_offboarding_once, advance_user_erasure_once, run_retention_pass,
    },
    ports::{
        AdminAuthStore, AdminOidcConfig, AdminOidcFlow, AdminSessionRecord, AuthzSessionRecord,
        AuthzSessionStore, CibaAuthRequest, CibaStore, ClientStore, CodeRecord, CodeStore,
        DeviceAuthGrant, DeviceStore, DomainBinding, DomainMapStore, FederationConfigStore,
        FederationFlowState, FederationFlowStore, GovernanceStore, GraceCacheEntry,
        GraceCachedResponse, GraceStore, GrantStore, InitialAccessTokenStore,
        InvitationAcceptOutcome, InvitationAcceptRequest, InvitationIssueOutcome, InvitationRecord,
        InvitationStore, JtiRecord, JtiStore, LeaseAcquire, MagicLinkRecord, MagicLinkStore,
        MessageOutbox, Notifier, ParRecord, ParStore, PasskeyCeremony, PasskeyChallenge,
        PasskeyChallengeStore, PasskeyStore, PasswordCredential, PasswordStore,
        PolicyArtifactStore, PolicyVersionStore, RateLimitStore, RecoveryRecord, RecoveryStore,
        RefreshFamilyRecord, RefreshStore, ReplayStore, ScimGroupCreateInput, ScimGroupsStore,
        ScimUserInput, SessionRecord, SessionStore, TenantRole, UserStatus, UsersStore,
        WorkloadTrustStore,
    },
    region::RegionRuntime,
    ssf::{
        SsfDeliveryStatus, SsfStore, SsfStream, SsfStreamCreateOutcome, SsfStreamStatus,
        CAEP_SESSION_REVOKED_EVENT,
    },
    AppState,
};
use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use tower::ServiceExt;

const CONTROL: &str = "control.example.com";
const T1_HOST: &str = "t1.example.com";
const T2_HOST: &str = "t2.example.com";
const T1_TOKEN: &str = "test-t1-governance-token";
const T2_TOKEN: &str = "test-t2-governance-token";

async fn seed_governance_invitation(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    email: &str,
    locator: &str,
    now: i64,
) -> InvitationAcceptRequest {
    let verifier_hash = format!("verifier-{locator}");
    assert_eq!(
        state
            .invitations
            .issue(
                tenant,
                InvitationRecord {
                    locator: locator.into(),
                    activation_id: state.region.issue_id("invitation"),
                    user_id: user_id.into(),
                    email: email.into(),
                    verifier_hash: verifier_hash.clone(),
                    credential_epoch: 0,
                    issued_at: now,
                    expires_at: now + 3_600,
                },
            )
            .await
            .unwrap(),
        InvitationIssueOutcome::Issued
    );
    InvitationAcceptRequest {
        locator: locator.into(),
        activation_id: state.region.issue_id("invitation"),
        verifier_hash,
        session_id: format!("session-{locator}"),
        device: "Governance test".into(),
        now: now + 1,
    }
}

fn active_set(owner: AdminCredentialOwner, id: &str, token: &str) -> AdminCredentialSet {
    let now = agent_auth_http::current_unix_secs();
    AdminCredentialSet::single(
        owner,
        AdminCredentialRecord::explicit(id, token, now - 60, now - 60, now + 86_400),
    )
}

async fn seed_offboarding_orphans(state: &AppState, now: i64) {
    for (flow_state, tenant_id) in [
        ("offboard-federation-flow", "default"),
        ("control-federation-flow", "control"),
    ] {
        state
            .federation_flow
            .put(FederationFlowState {
                state: flow_state.into(),
                nonce: format!("{flow_state}-nonce"),
                code_verifier: format!("{flow_state}-verifier"),
                tenant_id: tenant_id.into(),
                upstream_idp_id: "offboard-idp".into(),
                original_authz_request: "client_id=orphan-client".into(),
                required_max_age_secs: None,
                expires_at: now + 3600,
            })
            .await
            .unwrap();
    }
    for (challenge, tenant) in [
        ("offboard-orphan-challenge", ""),
        ("control-orphan-challenge", "control"),
    ] {
        state
            .passkey_challenges
            .put(PasskeyChallenge {
                challenge_b64url: challenge.into(),
                tenant: tenant.into(),
                user_id: None,
                ceremony: PasskeyCeremony::Authentication,
                rp_id: "localhost".into(),
                origin: "https://localhost".into(),
                expires_at: now + 3600,
            })
            .await
            .unwrap();
    }
    let password_hash = agent_auth_authn::password::hash_password("Orphan password 123!").unwrap();
    for (tenant, logical_tenant, prefix) in [
        ("", "default", "offboard"),
        ("control", "control", "control"),
    ] {
        let user_id = format!("{prefix}-orphan-user");
        let email = format!("{prefix}-orphan@example.com");
        let family_id = format!("{prefix}-orphan-family");
        state
            .codes
            .put(
                tenant,
                CodeRecord {
                    code: format!("{prefix}-orphan-code"),
                    client_id: "orphan-client".into(),
                    cimd_snapshot: None,
                    redirect_uri: "https://client.example/callback".into(),
                    code_challenge: "challenge".into(),
                    resources: vec![],
                    user_id: user_id.clone(),
                    scope: vec!["openid".into()],
                    expires_at: now + 3600,
                    authz_session_id: None,
                    nonce: None,
                    auth_time: now,
                    authorization_details: vec![],
                    acr: None,
                    amr: vec![],
                    credential_epoch: Some(0),
                    password_credential_version: Some(1),
                },
            )
            .await
            .unwrap();
        state
            .sessions
            .create(
                tenant,
                SessionRecord {
                    session_id: format!("{prefix}-orphan-session"),
                    user_id: user_id.clone(),
                    credential_epoch: 0,
                    auth_time: now,
                    created_at: now,
                    last_used_at: now,
                    device: "Orphan browser".into(),
                    expires_at: now + 3600,
                    acr: None,
                    amr: vec![],
                },
            )
            .await
            .unwrap();
        state
            .refresh
            .create(
                tenant,
                RefreshFamilyRecord {
                    family_id: family_id.clone(),
                    current_version: 0,
                    revoked: false,
                    client_id: "orphan-client".into(),
                    cimd_snapshot: None,
                    user_id: user_id.clone(),
                    credential_epoch: 0,
                    resources: vec![],
                    scope: vec!["openid".into()],
                    actor_allowlist: vec![],
                    max_act_chain: 1,
                    dpop_jkt: None,
                    pkce_code_challenge: None,
                    auth_time: Some(now),
                    acr: None,
                    password_credential_version: Some(1),
                },
            )
            .await
            .unwrap();
        state
            .grace
            .as_ref()
            .unwrap()
            .put(GraceCacheEntry {
                family_id: family_id.clone(),
                version: 0,
                fingerprint: [7; 32],
                client_id: "orphan-client".into(),
                dpop_jkt: None,
                response: GraceCachedResponse {
                    access_token: format!("{prefix}-stale-access"),
                    refresh_token: format!("{prefix}-stale-refresh"),
                    id_token: None,
                    scope: Some("openid".into()),
                    expires_in: 300,
                },
                expires_at: now + 3600,
            })
            .await
            .unwrap();
        assert!(state
            .passkeys
            .put_new(
                tenant,
                agent_auth_authn::passkey::PasskeyCredential {
                    credential_id: format!("{prefix}-orphan-passkey"),
                    user_id: user_id.clone(),
                    rp_id: "localhost".into(),
                    public_key_sec1: vec![4; 65],
                    sign_count: 0,
                    name: "Orphan key".into(),
                    created_at: now,
                },
            )
            .await
            .unwrap());
        state
            .jti_store
            .as_ref()
            .unwrap()
            .put(JtiRecord {
                jti: format!("{prefix}-orphan-jti"),
                tenant_id: logical_tenant.into(),
                user_id: user_id.clone(),
                family_id: Some(family_id),
                grant_id: None,
                expires_at: now + 3600,
            })
            .await
            .unwrap();
        assert!(state
            .passwords
            .create_if_absent(
                tenant,
                PasswordCredential {
                    user_id: user_id.clone(),
                    password_hash: password_hash.clone(),
                    must_change: false,
                    revocation_pending: false,
                    credential_change_id: None,
                    version: 1,
                    updated_at: now,
                },
            )
            .await
            .unwrap());
        state
            .recovery
            .put(
                tenant,
                RecoveryRecord {
                    user_lookup: format!("{prefix}-orphan-lookup"),
                    user_id: user_id.clone(),
                    activation_id: "orphan-activation".into(),
                    code_hashes: vec![],
                    attempt_count: 0,
                    locked_until: 0,
                },
            )
            .await
            .unwrap();
        state
            .magic_links
            .put(
                tenant,
                MagicLinkRecord {
                    link_id: format!("{prefix}-orphan-link"),
                    user_id,
                    email: email.clone(),
                    session_nonce: "orphan-nonce".into(),
                    authorize_query: String::new(),
                    next: String::new(),
                    expires_at: now + 3600,
                },
            )
            .await
            .unwrap();
        state
            .magic_links
            .mark_sent(tenant, &email, now)
            .await
            .unwrap();
        state
            .notifier
            .send_magic_link(tenant, &email, "https://localhost/orphan")
            .await
            .unwrap();
    }
    for (auth_req_id, tenant) in [
        ("offboard-orphan-ciba", ""),
        ("control-orphan-ciba", "control"),
    ] {
        state
            .ciba
            .put(
                tenant,
                CibaAuthRequest {
                    auth_req_id: auth_req_id.into(),
                    tenant: tenant.into(),
                    client_id: "orphan-client".into(),
                    user_id: "orphan-user".into(),
                    authz_session_id: None,
                    scope: vec![],
                    resources: vec![],
                    binding_message: None,
                    interval: 5,
                    last_poll_at: None,
                    expires_at: now + 3600,
                    status: "pending".into(),
                    consumed: false,
                    delivery_mode: None,
                    notification_endpoint: None,
                    client_notification_token: None,
                    password_credential_version: None,
                },
            )
            .await
            .unwrap();
        assert!(state
            .ciba
            .try_arm_throttle(tenant, "orphan-user", now, 3600)
            .await
            .unwrap());
    }
    for (device_code, tenant) in [
        ("offboard-orphan-device", ""),
        ("control-orphan-device", "control"),
    ] {
        state
            .device
            .put(
                tenant,
                DeviceAuthGrant {
                    device_code: device_code.into(),
                    user_code: format!("{device_code}-user"),
                    client_id: "orphan-client".into(),
                    user_id: None,
                    authz_session_id: None,
                    scope: vec![],
                    resources: vec![],
                    interval: 5,
                    last_poll_at: None,
                    expires_at: now + 3600,
                    status: "pending".into(),
                    consumed: false,
                    password_credential_version: None,
                },
            )
            .await
            .unwrap();
    }
    for (request_uri, tenant) in [
        ("urn:test:offboard-par", ""),
        ("urn:test:control-par", "control"),
    ] {
        state
            .par
            .put(
                tenant,
                ParRecord {
                    request_uri: request_uri.into(),
                    client_id: "orphan-client".into(),
                    raw_params: "scope=openid".into(),
                    expires_at: now + 3600,
                },
            )
            .await
            .unwrap();
    }
    let replay = state.replay_store.as_ref().unwrap();
    assert!(replay
        .check_and_set("", "offboard-orphan-replay", now + 3600)
        .await
        .unwrap());
    assert!(replay
        .check_and_set("control", "control-orphan-replay", now + 3600)
        .await
        .unwrap());
    for (session_id, tenant) in [
        ("offboard-orphan-authz", ""),
        ("control-orphan-authz", "control"),
    ] {
        state
            .authz_sessions
            .create(
                tenant,
                AuthzSessionRecord {
                    session_id: session_id.into(),
                    client_id: "orphan-client".into(),
                    user_id: None,
                    state: "pending".into(),
                    session_token_hash: format!("{session_id}-hash"),
                    sequence: 1,
                    last_error: None,
                    expires_at: now + 3600,
                },
            )
            .await
            .unwrap();
    }
    for (tenant, grant_id) in [
        ("", "offboard-orphan-grant"),
        ("control", "control-orphan-grant"),
    ] {
        state
            .grants
            .put(
                tenant,
                Grant {
                    grant_id: grant_id.into(),
                    user_id: "orphan-user".into(),
                    client_id: "orphan-client".into(),
                    per_resource: vec![],
                    effective_per_resource: vec![],
                    effective_pv: 1,
                    allowed_ip_cidrs: vec![],
                    allowed_vpce: vec![],
                    credential_epoch: 0,
                    revision: 1,
                    constraints: GrantConstraints {
                        max_act_chain: 1,
                        actor_allowlist: vec![],
                        expires_at: now + 3600,
                    },
                    status: GrantStatus::Active,
                },
            )
            .await
            .unwrap();
        state
            .policy_artifacts
            .put(
                tenant,
                1,
                "permit(principal, action, resource);".into(),
                format!("{grant_id}-digest"),
            )
            .await
            .unwrap();
        assert_eq!(state.policy_versions.bump(tenant).await.unwrap(), 1);
        state
            .current_pv_cache
            .lock()
            .await
            .insert(tenant.into(), (1, now));
    }
    for (domain, tenant_id) in [
        ("offboard-orphan.example.com", "default"),
        ("control-orphan.example.com", "control"),
    ] {
        assert!(state
            .domain_map
            .put_if_absent(DomainBinding {
                domain: domain.into(),
                resource_id: format!("https://{domain}"),
                tenant_id: tenant_id.into(),
                client_id: "absent-owner-client".into(),
            })
            .await
            .unwrap());
    }
    for (tenant_id, stream_id, event_id) in [
        ("default", "offboard-stream", "offboard-verification"),
        ("control", "control-stream", "control-verification"),
    ] {
        let stream = SsfStream::new(
            tenant_id,
            stream_id,
            "https://receiver.example.com/events",
            "https://receiver.example.com",
            vec![CAEP_SESSION_REVOKED_EVENT.into()],
            now,
        )
        .unwrap();
        assert!(matches!(
            state.ssf.create_stream(stream).await.unwrap(),
            SsfStreamCreateOutcome::Created(_)
        ));
        assert!(state
            .ssf
            .enqueue_verification(
                tenant_id,
                stream_id,
                1,
                event_id,
                "https://issuer.example.com",
                None,
                now,
            )
            .await
            .unwrap()
            .enqueued()
            .is_some());
    }
}

fn tenant_credentials_with_store() -> (
    Arc<AdminCredentialResolver>,
    MemoryAdminCredentialStore,
    HashMap<String, String>,
) {
    let now = agent_auth_http::current_unix_secs();
    let store = MemoryAdminCredentialStore::default();
    let platform_ref =
        "arn:aws:secretsmanager:us-east-1:000000000000:secret:agent-auth/platform-admin-IjKl";
    store.put_set(
        platform_ref,
        &active_set(
            AdminCredentialOwner::platform(),
            "platform-credential",
            "test-platform-governance-token",
        ),
        now,
    );
    let mut refs = HashMap::new();
    for (tenant, token, suffix) in [("t1", T1_TOKEN, "AbCd"), ("t2", T2_TOKEN, "EfGh")] {
        let secret_ref = format!(
            "arn:aws:secretsmanager:us-east-1:000000000000:secret:agent-auth/saas/{tenant}-admin-{suffix}"
        );
        refs.insert(tenant.to_string(), secret_ref.clone());
        store.put_set(
            &secret_ref,
            &active_set(
                AdminCredentialOwner::tenant(tenant),
                &format!("{tenant}-credential"),
                token,
            ),
            now,
        );
    }
    (
        Arc::new(AdminCredentialResolver::memory(
            Some(platform_ref.into()),
            refs.clone(),
            store.clone(),
            Duration::ZERO,
        )),
        store,
        refs,
    )
}

fn tenant_credentials() -> Arc<AdminCredentialResolver> {
    tenant_credentials_with_store().0
}

fn saas_state() -> AppState {
    let mut state = AppState::dev("localhost");
    state.form = agent_auth_discovery::Form::Saas {
        zone: "example.com".into(),
        control_host: CONTROL.into(),
    };
    state.tenant_partitioning = true;
    state.saas_tenants = Arc::new(vec!["t1".into(), "t2".into()]);
    state.admin_credentials = tenant_credentials();
    state.governance_config = Arc::new(
        GovernanceConfig::parse_json(
            r#"{
                "t1":{"jurisdiction":"us","allowed_regions":["local"]},
                "t2":{"jurisdiction":"eu","allowed_regions":["local"]}
            }"#,
            &state.saas_tenants,
        )
        .unwrap(),
    );
    state
}

struct TestResponse {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Value,
}

#[allow(clippy::too_many_arguments)]
fn send<'a>(
    router: &'a axum::Router,
    method: Method,
    host: &'a str,
    path: &'a str,
    bearer: Option<&'a str>,
    cookie: Option<&'a str>,
    governance_confirmation: bool,
    body: Option<Value>,
) -> Pin<Box<dyn Future<Output = TestResponse> + Send + 'a>> {
    Box::pin(async move {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("host", host)
            .header(
                header::CONTENT_TYPE,
                if path.starts_with("/scim/") {
                    "application/scim+json"
                } else {
                    "application/json"
                },
            );
        if let Some(token) = bearer {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        if governance_confirmation {
            builder = builder
                .header("x-agent-auth-purpose", "privacy-request:test")
                .header("x-agent-auth-confirm", "true");
        }
        let request = builder
            .body(body.map_or_else(Body::empty, |value| {
                Body::from(serde_json::to_vec(&value).unwrap())
            }))
            .unwrap();
        let response = Box::pin(router.clone().oneshot(request)).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        TestResponse {
            status,
            headers,
            body,
        }
    })
}

#[tokio::test]
async fn user_export_is_tenant_scoped_and_redacts_active_credential_material() {
    let state = saas_state();
    let now = agent_auth_http::current_unix_secs();
    let t1_user = state
        .users
        .create_or_get_by_email("t1", "same@example.com", "t1-user", now)
        .await
        .unwrap();
    let t2_user = state
        .users
        .create_or_get_by_email("t2", "same@example.com", "t2-user", now)
        .await
        .unwrap();
    state
        .sessions
        .create(
            "t1",
            SessionRecord {
                session_id: "must-not-leak-session-cookie".into(),
                user_id: t1_user.user_id.clone(),
                credential_epoch: t1_user.credential_epoch,
                auth_time: now,
                created_at: now,
                last_used_at: now,
                device: "Test browser".into(),
                expires_at: now + 3600,
                acr: Some(agent_auth_authn::assurance::STRONG_ACR.into()),
                amr: vec!["pwd".into()],
            },
        )
        .await
        .unwrap();
    state
        .passkeys
        .put_new(
            "t1",
            agent_auth_authn::passkey::PasskeyCredential {
                credential_id: "must-not-leak-passkey-id".into(),
                user_id: t1_user.user_id.clone(),
                rp_id: T1_HOST.into(),
                public_key_sec1: b"must-not-leak-passkey-public-key".to_vec(),
                sign_count: 7,
                name: "Work laptop".into(),
                created_at: now,
            },
        )
        .await
        .unwrap();
    state
        .grants
        .put(
            "t1",
            Grant {
                grant_id: "grant-safe-metadata".into(),
                user_id: t1_user.user_id.clone(),
                client_id: "client-1".into(),
                per_resource: vec![],
                effective_per_resource: vec![],
                effective_pv: 0,
                allowed_ip_cidrs: vec![],
                allowed_vpce: vec![],
                credential_epoch: t1_user.credential_epoch,
                revision: 1,
                constraints: GrantConstraints {
                    max_act_chain: 1,
                    actor_allowlist: vec![],
                    expires_at: now + 3600,
                },
                status: GrantStatus::Active,
            },
        )
        .await
        .unwrap();

    let (router, _) = build_router(state.clone());
    let missing_confirmation = send(
        &router,
        Method::GET,
        T1_HOST,
        "/admin/data-governance/users/t1-user/export",
        Some(T1_TOKEN),
        None,
        false,
        None,
    )
    .await;
    assert_eq!(missing_confirmation.status, StatusCode::FORBIDDEN);

    let t1 = send(
        &router,
        Method::GET,
        T1_HOST,
        "/admin/data-governance/users/t1-user/export",
        Some(T1_TOKEN),
        None,
        true,
        None,
    )
    .await;
    assert_eq!(t1.status, StatusCode::OK);
    assert_eq!(t1.body["tenant_id"], "t1");
    assert_eq!(t1.body["identity"]["user_id"], "t1-user");
    assert_eq!(t1.body["identity"]["email"], "same@example.com");
    assert_eq!(t1.body["passkeys"][0]["name"], "Work laptop");
    assert_eq!(t1.body["login_sessions"][0]["device"], "Test browser");
    let serialized = serde_json::to_string(&t1.body).unwrap();
    for forbidden in [
        T1_TOKEN,
        T2_TOKEN,
        "must-not-leak-session-cookie",
        "must-not-leak-passkey-id",
        "must-not-leak-passkey-public-key",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "export leaked forbidden material: {forbidden}"
        );
    }

    let cross_tenant = send(
        &router,
        Method::GET,
        T1_HOST,
        "/admin/data-governance/users/t2-user/export",
        Some(T1_TOKEN),
        None,
        true,
        None,
    )
    .await;
    assert_eq!(cross_tenant.status, StatusCode::NOT_FOUND);

    let t2 = send(
        &router,
        Method::GET,
        T2_HOST,
        "/admin/data-governance/users/t2-user/export",
        Some(T2_TOKEN),
        None,
        true,
        None,
    )
    .await;
    assert_eq!(t2.status, StatusCode::OK);
    assert_eq!(t2.body["identity"]["user_id"], t2_user.user_id);
    assert_eq!(t2.body["tenant_id"], "t2");
}

fn admin_session_hash(state: &AppState, raw: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&state.server_secret).expect("HMAC accepts any key");
    mac.update(b"admin-session:");
    mac.update(raw.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

async fn add_admin_session(
    state: &AppState,
    role: TenantRole,
    suffix: &str,
    strong: bool,
) -> String {
    let now = agent_auth_http::current_unix_secs();
    let user_id = format!("admin-{suffix}");
    let external_id = format!("external-{suffix}");
    let user_name = format!("{suffix}@example.com");
    let group_external_id = format!("group-external-{suffix}");
    state
        .users
        .create_scim(
            "",
            ScimUserInput {
                user_id: user_id.clone(),
                external_id,
                user_name,
                display_name: None,
                active: true,
                now,
            },
        )
        .await
        .unwrap();
    state
        .scim_groups
        .create(
            "",
            ScimGroupCreateInput {
                group_id: format!("group-{suffix}"),
                external_id: group_external_id.clone(),
                display_name: format!("{suffix} group"),
                members: vec![user_id.clone()],
                now,
            },
        )
        .await
        .unwrap();
    state
        .scim_groups
        .set_role_mapping("", &group_external_id, Some(role), now)
        .await
        .unwrap();

    let raw = format!("admin-session-{suffix}");
    state
        .admin_auth
        .create_session(AdminSessionRecord {
            session_hash: admin_session_hash(state, &raw),
            tenant_id: "default".into(),
            user_id,
            upstream_subject: format!("upstream-{suffix}"),
            role,
            credential_epoch: 0,
            config_revision: 1,
            config_binding_id: "governance-admin-binding".into(),
            acr: strong.then(|| agent_auth_authn::assurance::STRONG_ACR.into()),
            auth_time: now,
            created_at: now,
            expires_at: now + 3600,
        })
        .await
        .unwrap();
    format!("__Host-agent_auth_admin_session={raw}")
}

async fn rbac_state() -> (AppState, HashMap<&'static str, String>) {
    let state = AppState::dev("localhost");
    state
        .admin_auth
        .put_config(
            AdminOidcConfig {
                tenant_id: "default".into(),
                binding_id: "governance-admin-binding".into(),
                issuer: "https://admin-idp.example.com".into(),
                client_id: "admin-client".into(),
                client_secret_ref: "secret-ref-never-exported".into(),
                authorization_endpoint: "https://admin-idp.example.com/authorize".into(),
                token_endpoint: "https://admin-idp.example.com/token".into(),
                jwks_uri: "https://admin-idp.example.com/jwks".into(),
                redirect_uri: "https://localhost/admin/sso/callback".into(),
                scopes: vec!["openid".into()],
                strong_acr_values: vec!["urn:test:mfa".into()],
                identity_claim: "email".into(),
                identity_field: agent_auth_http::ports::AdminIdentityField::UserName,
                revision: 1,
                updated_at: agent_auth_http::current_unix_secs(),
            },
            0,
        )
        .await
        .unwrap();
    state
        .users
        .create_or_get_by_email(
            "",
            "target@example.com",
            "governance-target",
            agent_auth_http::current_unix_secs(),
        )
        .await
        .unwrap();
    state
        .users
        .create_or_get_by_email(
            "",
            "late-erasure@example.com",
            "late-erasure-target",
            agent_auth_http::current_unix_secs(),
        )
        .await
        .unwrap();
    let sessions = HashMap::from([
        (
            "auditor",
            add_admin_session(&state, TenantRole::Auditor, "auditor", true).await,
        ),
        (
            "admin_baseline",
            add_admin_session(&state, TenantRole::Admin, "admin-baseline", false).await,
        ),
        (
            "admin_strong",
            add_admin_session(&state, TenantRole::Admin, "admin-strong", true).await,
        ),
        (
            "owner_strong",
            add_admin_session(&state, TenantRole::Owner, "owner-strong", true).await,
        ),
    ]);
    (state, sessions)
}

#[tokio::test]
async fn governance_actions_enforce_role_and_recent_strong_authentication() {
    let (state, sessions) = rbac_state().await;
    let (router, _) = build_router(state);
    let path = "/admin/data-governance/users/governance-target/export";

    let auditor = send(
        &router,
        Method::GET,
        "localhost",
        path,
        None,
        Some(&sessions["auditor"]),
        false,
        None,
    )
    .await;
    assert_eq!(auditor.status, StatusCode::FORBIDDEN);

    let baseline = send(
        &router,
        Method::GET,
        "localhost",
        path,
        None,
        Some(&sessions["admin_baseline"]),
        false,
        None,
    )
    .await;
    assert_eq!(baseline.status, StatusCode::UNAUTHORIZED);
    assert!(baseline
        .headers
        .get(header::WWW_AUTHENTICATE)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("insufficient_user_authentication"));

    let admin = send(
        &router,
        Method::GET,
        "localhost",
        path,
        None,
        Some(&sessions["admin_strong"]),
        false,
        None,
    )
    .await;
    assert_eq!(admin.status, StatusCode::OK);

    let admin_tenant_export = send(
        &router,
        Method::POST,
        "localhost",
        "/admin/data-governance/exports",
        None,
        Some(&sessions["admin_strong"]),
        false,
        Some(json!({"purpose":"privacy-request:test","sections":["users"]})),
    )
    .await;
    assert_eq!(admin_tenant_export.status, StatusCode::FORBIDDEN);

    let owner_tenant_export = send(
        &router,
        Method::POST,
        "localhost",
        "/admin/data-governance/exports",
        None,
        Some(&sessions["owner_strong"]),
        false,
        Some(json!({"purpose":"privacy-request:test","sections":["users"]})),
    )
    .await;
    assert_eq!(owner_tenant_export.status, StatusCode::CREATED);
}

#[tokio::test]
async fn tenant_configuration_secret_and_key_exports_are_redacted() {
    let (state, sessions) = rbac_state().await;
    let (router, _) = build_router(state);
    let created = send(
        &router,
        Method::POST,
        "localhost",
        "/admin/data-governance/exports",
        None,
        Some(&sessions["owner_strong"]),
        false,
        Some(json!({
            "purpose":"privacy-request:test",
            "sections":["tenant_configuration","secret_metadata","signing_keys"]
        })),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let export_id = created.body["export_id"].as_str().unwrap();

    for (section, expected_type) in [
        ("tenant_configuration", "admin_oidc"),
        ("secret_metadata", "tenant_secret"),
        ("signing_keys", "governance_suppression_key"),
    ] {
        let page = send(
            &router,
            Method::GET,
            "localhost",
            &format!("/admin/data-governance/exports/{export_id}?section={section}&limit=100"),
            None,
            Some(&sessions["owner_strong"]),
            false,
            None,
        )
        .await;
        assert_eq!(page.status, StatusCode::OK, "{section}: {}", page.body);
        assert_eq!(page.body["section"], section);
        assert_eq!(page.body["residency_jurisdiction"], "local");
        assert_eq!(page.body["active_writer_region"], "local");
        assert_eq!(page.body["region_control_revision"], 0);
        assert_eq!(page.body["view_consistency"], "live_keyset");
        assert!(page.body["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["record_type"] == expected_type));
        let serialized = serde_json::to_string(&page.body).unwrap();
        for forbidden in [
            "secret-ref-never-exported",
            "memory:default-scim",
            "secret_ref",
            "resource_fingerprint",
            "key_arn",
            "public_jwk",
        ] {
            assert!(
                !serialized.contains(forbidden),
                "{section} export leaked {forbidden}"
            );
        }
    }
}

#[tokio::test]
async fn legal_hold_blocks_then_resumes_one_job_and_offboarding_freezes_mutations() {
    let mut state = AppState::dev("localhost");
    state.passkey_enabled = true;
    let queue = match state.governance_jobs.as_ref() {
        agent_auth_http::governance::GovernanceJobQueueImpl::Memory(queue) => queue.clone(),
        _ => panic!("dev state must use the memory governance queue"),
    };
    state
        .users
        .create_or_get_by_email(
            "",
            "erase@example.com",
            "erase-target",
            agent_auth_http::current_unix_secs(),
        )
        .await
        .unwrap();
    let (router, _) = build_router(state.clone());
    let auth = Some("dev-admin-token-not-for-prod");

    let held = send(
        &router,
        Method::PUT,
        "localhost",
        "/admin/data-governance/policy",
        auth,
        None,
        true,
        Some(json!({
            "expected_revision": 0,
            "legal_hold": true,
            "reason": "case-1234"
        })),
    )
    .await;
    assert_eq!(held.status, StatusCode::OK);
    assert_eq!(held.body["legal_hold"], "enabled");
    let held_revision = held.body["revision"].as_u64().unwrap();

    let reconciled_hold = send(
        &router,
        Method::PUT,
        "localhost",
        "/admin/data-governance/policy",
        auth,
        None,
        true,
        Some(json!({
            "expected_revision": 0,
            "legal_hold": true,
            "reason": "case-1234"
        })),
    )
    .await;
    assert_eq!(reconciled_hold.status, StatusCode::OK);
    assert_eq!(reconciled_hold.body["legal_hold"], "enabled");
    assert_eq!(reconciled_hold.body["revision"], held_revision);

    let blocked = send(
        &router,
        Method::POST,
        "localhost",
        "/admin/data-governance/users/erase-target/erasure",
        auth,
        None,
        true,
        None,
    )
    .await;
    assert_eq!(blocked.status, StatusCode::CONFLICT);
    assert_eq!(blocked.body["state"], "blocked_legal_hold");
    let job_id = blocked.body["job_id"].as_str().unwrap().to_string();

    let blocked_offboarding = send(
        &router,
        Method::POST,
        "localhost",
        "/admin/data-governance/tenant/offboarding",
        auth,
        None,
        true,
        None,
    )
    .await;
    assert_eq!(blocked_offboarding.status, StatusCode::CONFLICT);
    assert_eq!(blocked_offboarding.body["state"], "blocked_legal_hold");
    assert_eq!(blocked_offboarding.body["tenant_lifecycle_revision"], 0);
    let offboarding_job_id = blocked_offboarding.body["job_id"]
        .as_str()
        .unwrap()
        .to_string();

    let released = send(
        &router,
        Method::PUT,
        "localhost",
        "/admin/data-governance/policy",
        auth,
        None,
        true,
        Some(json!({
            "expected_revision": held_revision,
            "legal_hold": false
        })),
    )
    .await;
    assert_eq!(released.status, StatusCode::OK);
    assert_eq!(released.body["legal_hold"], "disabled");
    let released_revision = released.body["revision"].as_u64().unwrap();

    let reconciled_release = send(
        &router,
        Method::PUT,
        "localhost",
        "/admin/data-governance/policy",
        auth,
        None,
        true,
        Some(json!({
            "expected_revision": held_revision,
            "legal_hold": false
        })),
    )
    .await;
    assert_eq!(reconciled_release.status, StatusCode::OK);
    assert_eq!(reconciled_release.body["revision"], released_revision);

    let too_stale_release = send(
        &router,
        Method::PUT,
        "localhost",
        "/admin/data-governance/policy",
        auth,
        None,
        true,
        Some(json!({
            "expected_revision": held_revision.saturating_sub(1),
            "legal_hold": false
        })),
    )
    .await;
    assert_eq!(too_stale_release.status, StatusCode::CONFLICT);

    let resumed = send(
        &router,
        Method::POST,
        "localhost",
        "/admin/data-governance/users/erase-target/erasure",
        auth,
        None,
        true,
        None,
    )
    .await;
    assert_eq!(resumed.status, StatusCode::ACCEPTED);
    assert_eq!(resumed.body["job_id"], job_id);
    assert_eq!(resumed.body["state"], "queued");
    assert_eq!(resumed.body["revision"], 2);

    let retry = send(
        &router,
        Method::POST,
        "localhost",
        "/admin/data-governance/users/erase-target/erasure",
        auth,
        None,
        true,
        None,
    )
    .await;
    assert_eq!(retry.status, StatusCode::ACCEPTED);
    assert_eq!(retry.body["job_id"], job_id);
    assert_eq!(retry.body["revision"], 2);
    let commands = queue.commands().await;
    assert_eq!(commands.len(), 2);
    assert!(commands.iter().all(|command| {
        command.tenant_id == "default"
            && command.job_id == job_id
            && command.expected_revision == 2
            && command.failure_attempt == 0
    }));

    let offboarding = send(
        &router,
        Method::POST,
        "localhost",
        "/admin/data-governance/tenant/offboarding",
        auth,
        None,
        true,
        None,
    )
    .await;
    assert_eq!(offboarding.status, StatusCode::ACCEPTED);
    assert_eq!(offboarding.body["job_id"], offboarding_job_id);
    assert_eq!(offboarding.body["tenant_lifecycle_revision"], 1);
    assert!(state
        .governance
        .get_continuation("default", &offboarding_job_id)
        .await
        .unwrap()
        .is_some());

    let normal_mutation = send(
        &router,
        Method::POST,
        "localhost",
        "/admin/users",
        auth,
        None,
        false,
        Some(json!({"email":"new@example.com"})),
    )
    .await;
    assert_eq!(normal_mutation.status, StatusCode::CONFLICT);
    assert_eq!(normal_mutation.body["error"], "tenant_offboarding");

    for method in [Method::GET, Method::HEAD] {
        let late_challenge = send(
            &router,
            method.clone(),
            "localhost",
            "/passkey/authenticate/begin?login_hint=late@example.com",
            None,
            None,
            false,
            None,
        )
        .await;
        assert_eq!(
            late_challenge.status,
            StatusCode::CONFLICT,
            "{method} must not create authority after the offboarding inventory fence"
        );
        if method == Method::GET {
            assert_eq!(late_challenge.body["error"], "tenant_offboarding");
        }
    }

    let discovery = send(
        &router,
        Method::GET,
        "localhost",
        "/.well-known/openid-configuration",
        None,
        None,
        false,
        None,
    )
    .await;
    assert_eq!(discovery.status, StatusCode::OK);

    let late_erasure = send(
        &router,
        Method::POST,
        "localhost",
        "/admin/data-governance/users/late-erasure-target/erasure",
        auth,
        None,
        true,
        None,
    )
    .await;
    assert_eq!(late_erasure.status, StatusCode::CONFLICT);
    assert_eq!(late_erasure.body["error"], "tenant_offboarding");
    assert_eq!(late_erasure.body["lifecycle_revision"], 1);
    assert_eq!(queue.commands().await.len(), 3);

    let status = send(
        &router,
        Method::GET,
        "localhost",
        &format!("/admin/data-governance/jobs/{job_id}"),
        auth,
        None,
        true,
        None,
    )
    .await;
    assert_eq!(status.status, StatusCode::OK);
    assert_eq!(status.body["job_id"], job_id);
    assert!(status.body.get("target_id").is_none());
}

#[tokio::test]
async fn suppressed_user_erasure_resumes_after_post_primary_legal_hold() {
    let state = AppState::dev("localhost");
    let now = agent_auth_http::current_unix_secs();
    let user_id = "user:post-primary-hold@example.com";
    state
        .users
        .create_or_get_by_email("", "post-primary-hold@example.com", user_id, now)
        .await
        .unwrap();
    let (router, _) = build_router(state.clone());
    let auth = Some("dev-admin-token-not-for-prod");

    let started = send(
        &router,
        Method::POST,
        "localhost",
        &format!("/admin/data-governance/users/{user_id}/erasure"),
        auth,
        None,
        true,
        None,
    )
    .await;
    assert_eq!(started.status, StatusCode::ACCEPTED);
    let job_id = started.body["job_id"].as_str().unwrap();
    for expected_phase in [
        GovernanceJobPhase::MutationFenced,
        GovernanceJobPhase::PrimaryCleanup,
        GovernanceJobPhase::SuppressionRecorded,
        GovernanceJobPhase::ReplicaVerification,
    ] {
        let job = advance_user_erasure_once(&state, "default", job_id, now + 1)
            .await
            .unwrap();
        assert_eq!(job.phase, expected_phase);
    }
    assert!(state.users.get_by_id("", user_id).await.unwrap().is_none());

    let held = send(
        &router,
        Method::PUT,
        "localhost",
        "/admin/data-governance/policy",
        auth,
        None,
        true,
        Some(json!({
            "expected_revision": 0,
            "legal_hold": true,
            "reason": "post-primary-hold"
        })),
    )
    .await;
    assert_eq!(held.status, StatusCode::OK);
    assert_eq!(held.body["legal_hold"], "enabled");
    let held_revision = held.body["revision"].as_u64().unwrap();

    let blocked = advance_user_erasure_once(&state, "default", job_id, now + 2)
        .await
        .unwrap();
    assert_eq!(blocked.state, GovernanceJobState::BlockedLegalHold);
    assert_eq!(blocked.phase, GovernanceJobPhase::ReplicaVerification);

    let released = send(
        &router,
        Method::PUT,
        "localhost",
        "/admin/data-governance/policy",
        auth,
        None,
        true,
        Some(json!({
            "expected_revision": held_revision,
            "legal_hold": false
        })),
    )
    .await;
    assert_eq!(released.status, StatusCode::OK);
    assert_eq!(released.body["legal_hold"], "disabled");
    let released_revision = released.body["revision"].as_u64().unwrap();
    let queued_before_resume = match state.governance_jobs.as_ref() {
        agent_auth_http::governance::GovernanceJobQueueImpl::Memory(queue) => {
            queue.commands().await
        }
        _ => panic!("dev state must use the in-memory governance queue"),
    };

    let resumed = send(
        &router,
        Method::POST,
        "localhost",
        &format!("/admin/data-governance/users/{user_id}/erasure"),
        auth,
        None,
        true,
        None,
    )
    .await;
    assert_eq!(resumed.status, StatusCode::ACCEPTED);
    assert_eq!(resumed.body["job_id"], job_id);
    assert_eq!(resumed.body["state"], "queued");
    assert_eq!(resumed.body["policy_revision"], released_revision);
    let queued_after_resume = match state.governance_jobs.as_ref() {
        agent_auth_http::governance::GovernanceJobQueueImpl::Memory(queue) => {
            queue.commands().await
        }
        _ => panic!("dev state must use the in-memory governance queue"),
    };
    assert_eq!(queued_after_resume.len(), queued_before_resume.len() + 1);
    assert_eq!(queued_after_resume.last().unwrap().job_id, job_id);

    advance_user_erasure_once(&state, "default", job_id, now + 3)
        .await
        .unwrap();
    let terminal = send(
        &router,
        Method::GET,
        "localhost",
        &format!("/admin/data-governance/jobs/{job_id}"),
        auth,
        None,
        true,
        None,
    )
    .await;
    assert_eq!(terminal.status, StatusCode::OK);
    assert_eq!(terminal.body["job_id"], job_id);
    assert_eq!(terminal.body["state"], "retention_pending");
    assert_eq!(terminal.body["phase"], "retention_verification");

    let terminal_retry = send(
        &router,
        Method::POST,
        "localhost",
        &format!("/admin/data-governance/users/{user_id}/erasure"),
        auth,
        None,
        true,
        None,
    )
    .await;
    assert_eq!(terminal_retry.status, StatusCode::ACCEPTED);
    assert_eq!(terminal_retry.body["job_id"], job_id);
    assert_eq!(terminal_retry.body["state"], "retention_pending");
    let queued_after_terminal_retry = match state.governance_jobs.as_ref() {
        agent_auth_http::governance::GovernanceJobQueueImpl::Memory(queue) => {
            queue.commands().await
        }
        _ => panic!("dev state must use the in-memory governance queue"),
    };
    assert_eq!(queued_after_terminal_retry, queued_after_resume);
}

#[tokio::test]
async fn platform_continuation_survives_tenant_admin_removal_and_rejects_replay() {
    let state = saas_state();
    let queue = match state.governance_jobs.as_ref() {
        agent_auth_http::governance::GovernanceJobQueueImpl::Memory(queue) => queue.clone(),
        _ => panic!("dev state must use the memory governance queue"),
    };
    let (tenant_router, _) = build_router(state.clone());
    let started = send(
        &tenant_router,
        Method::POST,
        T1_HOST,
        "/admin/data-governance/tenant/offboarding",
        Some(T1_TOKEN),
        None,
        true,
        None,
    )
    .await;
    assert_eq!(started.status, StatusCode::ACCEPTED);
    let job_id = started.body["job_id"].as_str().unwrap().to_string();

    let mut restarted = state.clone();
    let (credentials, credential_store, credential_refs) = tenant_credentials_with_store();
    restarted.admin_credentials = credentials;
    credential_store.remove(&credential_refs["t1"]);
    restarted
        .admin_auth
        .delete_all_by_tenant("t1")
        .await
        .unwrap();
    let (router, _) = build_router(restarted.clone());

    let removed_tenant_authority = send(
        &router,
        Method::GET,
        T1_HOST,
        &format!("/admin/data-governance/jobs/{job_id}"),
        Some(T1_TOKEN),
        None,
        true,
        None,
    )
    .await;
    assert_ne!(removed_tenant_authority.status, StatusCode::OK);

    let issue_status = send(
        &router,
        Method::POST,
        CONTROL,
        &format!("/admin/control/data-governance/tenants/t1/jobs/{job_id}/continuation-tokens"),
        Some("test-platform-governance-token"),
        None,
        true,
        Some(json!({"action":"status"})),
    )
    .await;
    assert_eq!(issue_status.status, StatusCode::CREATED);
    assert_eq!(
        issue_status
            .headers
            .get(header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap(),
        "no-store"
    );
    let old_status_token = issue_status.body["continuation_token"]
        .as_str()
        .unwrap()
        .to_string();

    let status = send(
        &router,
        Method::GET,
        CONTROL,
        &format!("/admin/control/data-governance/tenants/t1/jobs/{job_id}"),
        Some(&old_status_token),
        None,
        false,
        None,
    )
    .await;
    assert_eq!(status.status, StatusCode::OK);
    assert_eq!(status.body["job_id"], job_id);
    assert!(status.body.get("target_id").is_none());

    let cross_tenant = send(
        &router,
        Method::GET,
        CONTROL,
        &format!("/admin/control/data-governance/tenants/t2/jobs/{job_id}"),
        Some(&old_status_token),
        None,
        false,
        None,
    )
    .await;
    assert_eq!(cross_tenant.status, StatusCode::UNAUTHORIZED);

    let issue_resume = send(
        &router,
        Method::POST,
        CONTROL,
        &format!("/admin/control/data-governance/tenants/t1/jobs/{job_id}/continuation-tokens"),
        Some("test-platform-governance-token"),
        None,
        true,
        Some(json!({"action":"resume"})),
    )
    .await;
    assert_eq!(issue_resume.status, StatusCode::CREATED);
    let resume_token = issue_resume.body["continuation_token"]
        .as_str()
        .unwrap()
        .to_string();
    let resumed = send(
        &router,
        Method::POST,
        CONTROL,
        &format!("/admin/control/data-governance/tenants/t1/jobs/{job_id}/resume"),
        Some(&resume_token),
        None,
        false,
        None,
    )
    .await;
    assert_eq!(resumed.status, StatusCode::ACCEPTED);
    let replayed = send(
        &router,
        Method::POST,
        CONTROL,
        &format!("/admin/control/data-governance/tenants/t1/jobs/{job_id}/resume"),
        Some(&resume_token),
        None,
        false,
        None,
    )
    .await;
    assert_eq!(replayed.status, StatusCode::CONFLICT);
    assert_eq!(queue.commands().await.len(), 2);

    let rotated = send(
        &router,
        Method::PUT,
        CONTROL,
        &format!("/admin/control/data-governance/tenants/t1/jobs/{job_id}/continuation"),
        Some("test-platform-governance-token"),
        None,
        true,
        Some(json!({
            "expected_revision": 1,
            "rotate_read": true
        })),
    )
    .await;
    assert_eq!(rotated.status, StatusCode::OK);
    assert_eq!(rotated.body["read_revision"], 2);
    assert_eq!(rotated.body["revision"], 2);
    let revoked_status = send(
        &router,
        Method::GET,
        CONTROL,
        &format!("/admin/control/data-governance/tenants/t1/jobs/{job_id}"),
        Some(&old_status_token),
        None,
        false,
        None,
    )
    .await;
    assert_eq!(revoked_status.status, StatusCode::UNAUTHORIZED);

    let mut job = restarted
        .governance
        .get_job("t1", &job_id)
        .await
        .unwrap()
        .unwrap();
    let expected_revision = job.revision;
    let completed_at = agent_auth_http::current_unix_secs();
    job.state = GovernanceJobState::Completed;
    job.phase = GovernanceJobPhase::Complete;
    job.primary_erasure_at = Some(completed_at - 1);
    job.retention_until = Some(completed_at);
    job.evidence_revision = 1;
    job.updated_at = completed_at;
    job.target_id = None;
    job.target_aliases.clear();
    job.verification_target = None;
    let job = match restarted
        .governance
        .update_job(job, expected_revision, 0)
        .await
        .unwrap()
    {
        agent_auth_http::governance::GovernanceJobUpdateOutcome::Stored(job) => job,
        outcome => panic!("unexpected completion update: {outcome:?}"),
    };
    let evidence = GovernanceEvidenceRecord::new(GovernanceEvidencePayload {
        schema_version: agent_auth_http::governance::GOVERNANCE_EVIDENCE_SCHEMA_VERSION.into(),
        tenant_id: "t1".into(),
        job_id: job_id.clone(),
        job_kind: job.kind,
        job_state: GovernanceJobState::Completed,
        evidence_revision: 1,
        deployment_commit: "dev".into(),
        started_at: job.created_at,
        verification_at: completed_at,
        generated_at: completed_at,
        primary_erasure_at: completed_at - 1,
        retention_deadline: completed_at,
        residency_jurisdiction: "us".into(),
        configured_regions: vec!["local".into()],
        active_writer_region: "local".into(),
        region_control_revision: 0,
        legal_hold: LegalHoldState::Disabled,
        live_counts: BTreeMap::from([("tenant_live_authority".into(), 0)]),
        retained_counts: BTreeMap::new(),
        replica_live_counts: BTreeMap::from([(
            "local".into(),
            GovernanceReplicaEvidence {
                verification_state: "verified".into(),
                verified_at: Some(completed_at),
                live_counts: BTreeMap::from([("tenant_live_authority".into(), 0)]),
                retained_counts: BTreeMap::new(),
            },
        )]),
        alias_tombstone_count: 0,
        retention_resources: BTreeMap::new(),
        external_actions: vec![],
        permanent_control_records: vec!["governance_evidence".into()],
    })
    .unwrap();
    restarted.governance.put_evidence(evidence).await.unwrap();

    let resume_after_retention = send(
        &router,
        Method::POST,
        CONTROL,
        &format!("/admin/control/data-governance/tenants/t1/jobs/{job_id}/continuation-tokens"),
        Some("test-platform-governance-token"),
        None,
        true,
        Some(json!({"action":"resume"})),
    )
    .await;
    assert_eq!(resume_after_retention.status, StatusCode::CONFLICT);

    let issue_evidence = send(
        &router,
        Method::POST,
        CONTROL,
        &format!("/admin/control/data-governance/tenants/t1/jobs/{job_id}/continuation-tokens"),
        Some("test-platform-governance-token"),
        None,
        true,
        Some(json!({"action":"evidence"})),
    )
    .await;
    assert_eq!(issue_evidence.status, StatusCode::CREATED);
    let evidence_token = issue_evidence.body["continuation_token"]
        .as_str()
        .unwrap()
        .to_string();
    let evidence = send(
        &router,
        Method::GET,
        CONTROL,
        &format!("/admin/control/data-governance/tenants/t1/jobs/{job_id}/evidence"),
        Some(&evidence_token),
        None,
        false,
        None,
    )
    .await;
    assert_eq!(evidence.status, StatusCode::OK);
    assert_eq!(evidence.body["payload"]["tenant_id"], "t1");
    assert_eq!(evidence.body["payload"]["job_id"], job_id);
}

#[tokio::test]
async fn user_erasure_resumes_each_phase_and_physically_removes_subject_state() {
    let state = AppState::dev("localhost");
    let now = agent_auth_http::current_unix_secs();
    let user_id = "user:erase-complete@example.com";
    let email = "erase-complete@example.com";

    seed_user_erasure_scim_user(&state, now, user_id, email).await;
    let invitation =
        seed_governance_invitation(&state, "", user_id, email, "erase-invitation", now).await;
    seed_user_erasure_session(&state, now, user_id).await;
    seed_user_erasure_admin_session(&state, now, user_id).await;
    seed_user_erasure_refresh_family(&state, now, user_id).await;
    seed_user_erasure_code(&state, now, user_id).await;
    seed_user_erasure_passkey_challenge(&state, now, user_id).await;
    seed_user_erasure_passkey(&state, now, user_id).await;
    seed_user_erasure_grant(&state, now, user_id).await;
    seed_user_erasure_jti(&state, now, user_id).await;
    seed_user_erasure_magic_link(&state, now, user_id, email).await;
    seed_user_erasure_ciba(&state, now, user_id).await;
    seed_user_erasure_device(&state, now, user_id).await;
    seed_user_erasure_scim_group(&state, now, user_id).await;
    run_user_erasure_scenario(&state, now, user_id, email).await;
    assert_eq!(
        state.invitations.accept("", invitation).await.unwrap(),
        InvitationAcceptOutcome::Invalid
    );
}

#[inline(never)]
async fn seed_user_erasure_scim_user(state: &AppState, now: i64, user_id: &str, email: &str) {
    state
        .users
        .create_scim(
            "",
            ScimUserInput {
                user_id: user_id.into(),
                external_id: "erase-external".into(),
                user_name: email.into(),
                display_name: Some("Erase Complete".into()),
                active: true,
                now,
            },
        )
        .await
        .unwrap();
}

#[inline(never)]
async fn seed_user_erasure_session(state: &AppState, now: i64, user_id: &str) {
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
                device: "Test browser".into(),
                expires_at: now + 3_600,
                acr: None,
                amr: vec![],
            },
        )
        .await
        .unwrap();
}

#[inline(never)]
async fn seed_user_erasure_admin_session(state: &AppState, now: i64, user_id: &str) {
    state
        .admin_auth
        .create_session(AdminSessionRecord {
            session_hash: "erase-admin-session".into(),
            tenant_id: "default".into(),
            user_id: user_id.into(),
            upstream_subject: "erase-upstream-subject".into(),
            role: TenantRole::Owner,
            credential_epoch: 0,
            config_revision: 1,
            config_binding_id: "erase-admin-binding".into(),
            acr: None,
            auth_time: now,
            created_at: now,
            expires_at: now + 3_600,
        })
        .await
        .unwrap();
}

#[inline(never)]
async fn seed_user_erasure_refresh_family(state: &AppState, now: i64, user_id: &str) {
    state
        .refresh
        .create(
            "",
            RefreshFamilyRecord {
                family_id: "erase-family".into(),
                current_version: 0,
                revoked: false,
                client_id: "erase-client".into(),
                cimd_snapshot: None,
                user_id: user_id.into(),
                credential_epoch: 0,
                resources: vec![],
                scope: vec!["openid".into()],
                actor_allowlist: vec![],
                max_act_chain: 1,
                dpop_jkt: None,
                pkce_code_challenge: None,
                auth_time: Some(now),
                acr: None,
                password_credential_version: None,
            },
        )
        .await
        .unwrap();
}

#[inline(never)]
async fn seed_user_erasure_code(state: &AppState, now: i64, user_id: &str) {
    state
        .codes
        .put(
            "",
            CodeRecord {
                code: "erase-code".into(),
                client_id: "erase-client".into(),
                cimd_snapshot: None,
                redirect_uri: "https://client.example/callback".into(),
                code_challenge: "challenge".into(),
                resources: vec![],
                user_id: user_id.into(),
                scope: vec!["openid".into()],
                expires_at: now + 300,
                authz_session_id: None,
                nonce: None,
                auth_time: now,
                authorization_details: vec![],
                acr: None,
                amr: vec![],
                credential_epoch: Some(0),
                password_credential_version: None,
            },
        )
        .await
        .unwrap();
}

#[inline(never)]
async fn seed_user_erasure_passkey_challenge(state: &AppState, now: i64, user_id: &str) {
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
}

#[inline(never)]
async fn seed_user_erasure_passkey(state: &AppState, now: i64, user_id: &str) {
    state
        .passkeys
        .put_new(
            "",
            agent_auth_authn::passkey::PasskeyCredential {
                credential_id: "erase-passkey".into(),
                user_id: user_id.into(),
                rp_id: "localhost".into(),
                public_key_sec1: vec![4; 65],
                sign_count: 0,
                name: "Erase key".into(),
                created_at: now,
            },
        )
        .await
        .unwrap();
}

#[inline(never)]
async fn seed_user_erasure_grant(state: &AppState, now: i64, user_id: &str) {
    state
        .grants
        .put(
            "",
            Grant {
                grant_id: "erase-grant".into(),
                user_id: user_id.into(),
                client_id: "erase-client".into(),
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
                    expires_at: now + 3_600,
                },
                status: GrantStatus::Active,
            },
        )
        .await
        .unwrap();
}

#[inline(never)]
async fn seed_user_erasure_jti(state: &AppState, now: i64, user_id: &str) {
    state
        .jti_store
        .as_ref()
        .unwrap()
        .put(JtiRecord {
            jti: "erase-jti".into(),
            tenant_id: "default".into(),
            user_id: user_id.into(),
            family_id: Some("erase-family".into()),
            grant_id: Some("erase-grant".into()),
            expires_at: now + 300,
        })
        .await
        .unwrap();
}

#[inline(never)]
async fn seed_user_erasure_magic_link(state: &AppState, now: i64, user_id: &str, email: &str) {
    state
        .magic_links
        .put(
            "",
            MagicLinkRecord {
                link_id: "erase-link".into(),
                user_id: user_id.into(),
                email: email.into(),
                session_nonce: "nonce".into(),
                authorize_query: String::new(),
                next: String::new(),
                expires_at: now + 300,
            },
        )
        .await
        .unwrap();
    state.magic_links.mark_sent("", email, now).await.unwrap();
}

#[inline(never)]
async fn seed_user_erasure_ciba(state: &AppState, now: i64, user_id: &str) {
    state
        .ciba
        .put(
            "",
            CibaAuthRequest {
                auth_req_id: "erase-ciba".into(),
                tenant: "".into(),
                client_id: "erase-client".into(),
                user_id: user_id.into(),
                authz_session_id: None,
                scope: vec![],
                resources: vec![],
                binding_message: None,
                interval: 5,
                last_poll_at: None,
                expires_at: now + 300,
                status: "pending".into(),
                consumed: false,
                delivery_mode: None,
                notification_endpoint: None,
                client_notification_token: None,
                password_credential_version: None,
            },
        )
        .await
        .unwrap();
}

#[inline(never)]
async fn seed_user_erasure_device(state: &AppState, now: i64, user_id: &str) {
    state
        .device
        .put(
            "",
            DeviceAuthGrant {
                device_code: "erase-device".into(),
                user_code: "ERASE123".into(),
                client_id: "erase-client".into(),
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
}

#[inline(never)]
async fn seed_user_erasure_scim_group(state: &AppState, now: i64, user_id: &str) {
    state
        .scim_groups
        .create(
            "",
            ScimGroupCreateInput {
                group_id: "erase-group".into(),
                external_id: "erase-group-external".into(),
                display_name: "Erase group".into(),
                members: vec![user_id.into()],
                now,
            },
        )
        .await
        .unwrap();
}

#[inline(never)]
async fn run_user_erasure_scenario(state: &AppState, now: i64, user_id: &str, email: &str) {
    let (router, _) = build_router(state.clone());
    let started = send(
        &router,
        Method::POST,
        "localhost",
        &format!("/admin/data-governance/users/{user_id}/erasure"),
        Some("dev-admin-token-not-for-prod"),
        None,
        true,
        None,
    )
    .await;
    assert_eq!(started.status, StatusCode::ACCEPTED);
    let job_id = started.body["job_id"].as_str().unwrap().to_string();
    Box::pin(advance_user_erasure_and_verify_cleanup(
        state, &router, now, user_id, email, &job_id,
    ))
    .await;
}

#[inline(never)]
async fn advance_user_erasure_and_verify_cleanup(
    state: &AppState,
    router: &axum::Router,
    now: i64,
    user_id: &str,
    email: &str,
    job_id: &str,
) {
    let expected = [
        GovernanceJobPhase::MutationFenced,
        GovernanceJobPhase::PrimaryCleanup,
        GovernanceJobPhase::SuppressionRecorded,
        GovernanceJobPhase::ReplicaVerification,
        GovernanceJobPhase::RetentionVerification,
    ];
    for (index, expected_phase) in expected.into_iter().enumerate() {
        let job = advance_user_erasure_once(state, "default", job_id, now + index as i64 + 1)
            .await
            .unwrap();
        assert_eq!(job.phase, expected_phase);
        assert_eq!(
            job.state,
            if expected_phase == GovernanceJobPhase::RetentionVerification {
                GovernanceJobState::RetentionPending
            } else {
                GovernanceJobState::Running
            }
        );
    }

    assert!(state.users.get_by_id("", user_id).await.unwrap().is_none());
    assert!(state
        .sessions
        .get("", "erase-session")
        .await
        .unwrap()
        .is_none());
    assert!(state
        .admin_auth
        .get_session("erase-admin-session", now)
        .await
        .unwrap()
        .is_none());
    assert!(state
        .refresh
        .get("", "erase-family")
        .await
        .unwrap()
        .is_none());
    assert!(matches!(
        state
            .codes
            .acquire_lease("", "erase-code", "erase-owner", now, now + 10)
            .await
            .unwrap(),
        LeaseAcquire::NotFound
    ));
    assert!(state
        .passkeys
        .list_by_user("", user_id)
        .await
        .unwrap()
        .is_empty());
    assert!(state
        .grants
        .list_by_user("", user_id)
        .await
        .unwrap()
        .is_empty());
    assert!(state
        .passkey_challenges
        .consume("", "erase-challenge")
        .await
        .unwrap()
        .is_none());
    assert!(state
        .jti_store
        .as_ref()
        .unwrap()
        .get("default", "erase-jti")
        .await
        .unwrap()
        .is_none());
    assert!(state.ciba.get("", "erase-ciba").await.unwrap().is_none());
    assert!(state
        .device
        .get("", "erase-device")
        .await
        .unwrap()
        .is_none());
    assert!(state
        .magic_links
        .get("", "erase-link")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        state.magic_links.last_sent_at("", email).await.unwrap(),
        None
    );
    assert!(state
        .scim_groups
        .get("", "erase-group")
        .await
        .unwrap()
        .unwrap()
        .members
        .is_empty());

    Box::pin(verify_user_erasure_suppression_and_retention(
        state, router, user_id, email, job_id,
    ))
    .await;
}

#[inline(never)]
async fn verify_user_erasure_suppression_and_retention(
    state: &AppState,
    router: &axum::Router,
    user_id: &str,
    email: &str,
    job_id: &str,
) {
    let restarted = send(
        router,
        Method::POST,
        "localhost",
        &format!("/admin/data-governance/users/{user_id}/erasure"),
        Some("dev-admin-token-not-for-prod"),
        None,
        true,
        None,
    )
    .await;
    assert_eq!(restarted.status, StatusCode::ACCEPTED);
    assert_eq!(restarted.body["job_id"], job_id);
    assert_eq!(restarted.body["state"], "retention_pending");

    let admin_recreate = send(
        router,
        Method::POST,
        "localhost",
        "/admin/users",
        Some("dev-admin-token-not-for-prod"),
        None,
        false,
        Some(json!({
            "email": email,
            "initial_password": "Initial password 123!"
        })),
    )
    .await;
    assert_eq!(admin_recreate.status, StatusCode::CONFLICT);

    let scim_recreate = send(
        router,
        Method::POST,
        "localhost",
        "/scim/v2/Users",
        Some("dev-scim-token-not-for-prod"),
        None,
        false,
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "externalId": "erase-external",
            "userName": email,
            "active": true
        })),
    )
    .await;
    assert_eq!(scim_recreate.status, StatusCode::CONFLICT);
    assert!(state
        .users
        .get_scim_by_external_id("", "erase-external")
        .await
        .unwrap()
        .is_none());

    let retention_deadline = state
        .governance
        .get_job("default", job_id)
        .await
        .unwrap()
        .unwrap()
        .retention_until
        .unwrap();
    assert_eq!(
        run_retention_pass(state, retention_deadline - 1)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        run_retention_pass(state, retention_deadline).await.unwrap(),
        1
    );
    let completed = state
        .governance
        .get_job("default", job_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(completed.state, GovernanceJobState::Completed);
    assert_eq!(completed.phase, GovernanceJobPhase::Complete);
    assert_eq!(completed.evidence_revision, 2);
    assert!(completed.verification_target.is_none());

    let evidence = send(
        router,
        Method::GET,
        "localhost",
        &format!("/admin/data-governance/jobs/{job_id}/evidence"),
        Some("dev-admin-token-not-for-prod"),
        None,
        true,
        None,
    )
    .await;
    assert_eq!(evidence.status, StatusCode::OK);
    assert_eq!(evidence.body["payload"]["evidence_revision"], 2);
    assert!(evidence.body["payload_sha256"].as_str().unwrap().len() >= 43);
    assert!(!evidence.body.to_string().contains(user_id));
}

#[tokio::test]
async fn tenant_offboarding_fences_legacy_zero_epoch_tombstone() {
    let state = AppState::dev("localhost");
    let now = agent_auth_http::current_unix_secs();
    let user_id = "user:legacy-tombstone@example.com";
    state
        .users
        .create_or_get_by_email("", "legacy-tombstone@example.com", user_id, now)
        .await
        .unwrap();
    state
        .users
        .set_status("", user_id, UserStatus::Tombstoned, now + 1)
        .await
        .unwrap();
    let legacy = state.users.get_by_id("", user_id).await.unwrap().unwrap();
    assert_eq!(legacy.status, UserStatus::Tombstoned);
    assert_eq!(legacy.credential_epoch, 0);

    let (router, _) = build_router(state.clone());
    let started = send(
        &router,
        Method::POST,
        "localhost",
        "/admin/data-governance/tenant/offboarding",
        Some("dev-admin-token-not-for-prod"),
        None,
        true,
        None,
    )
    .await;
    assert_eq!(started.status, StatusCode::ACCEPTED);
    let parent_id = started.body["job_id"].as_str().unwrap();

    advance_tenant_offboarding_once(&state, "default", parent_id, now + 2)
        .await
        .unwrap();
    let parent = advance_tenant_offboarding_once(&state, "default", parent_id, now + 3)
        .await
        .unwrap();
    let child_id = parent
        .active_child_job_id
        .expect("offboarding should start a child erasure");

    let child = advance_user_erasure_once(&state, "default", &child_id, now + 4)
        .await
        .unwrap();
    assert_eq!(child.state, GovernanceJobState::Running);
    assert_eq!(child.phase, GovernanceJobPhase::MutationFenced);
    assert_eq!(child.error_class, None);
}

#[tokio::test]
async fn tenant_offboarding_restarts_between_immutable_first_page_user_children() {
    let state = AppState::dev("localhost");
    let now = agent_auth_http::current_unix_secs();
    for (user_id, email) in [
        ("user:offboard-a@example.com", "offboard-a@example.com"),
        ("user:offboard-b@example.com", "offboard-b@example.com"),
    ] {
        state
            .users
            .create_or_get_by_email("", email, user_id, now)
            .await
            .unwrap();
    }
    state
        .scim_groups
        .create(
            "",
            ScimGroupCreateInput {
                group_id: "offboard-group".into(),
                external_id: "offboard-group-external".into(),
                display_name: "Offboard group".into(),
                members: vec!["user:offboard-a@example.com".into()],
                now,
            },
        )
        .await
        .unwrap();
    state
        .scim_groups
        .set_role_mapping("", "offboard-group-external", Some(TenantRole::Admin), now)
        .await
        .unwrap();

    state
        .seed_dev_client(
            "offboard-client",
            "https://client.example.com/callback",
            None,
        )
        .await;
    state
        .domain_map
        .put_if_absent(DomainBinding {
            domain: "resource.example.com".into(),
            resource_id: "https://resource.example.com".into(),
            tenant_id: "default".into(),
            client_id: "offboard-client".into(),
        })
        .await
        .unwrap();
    state
        .authz_sessions
        .create(
            "",
            AuthzSessionRecord {
                session_id: "offboard-authz-session".into(),
                client_id: "offboard-client".into(),
                user_id: None,
                state: "pending".into(),
                session_token_hash: "opaque-hash".into(),
                sequence: 1,
                last_error: None,
                expires_at: now + 3600,
            },
        )
        .await
        .unwrap();
    state
        .rate_limit
        .as_ref()
        .unwrap()
        .try_consume("offboard-client", now, 10.0, 1.0, 1.0)
        .await
        .unwrap();

    let token_id = "offboard-iat";
    state
        .initial_access_tokens
        .put_new(
            "",
            agent_auth_http::credential::InitialAccessTokenRecord {
                token_id: token_id.into(),
                credential: agent_auth_http::credential::new_credential_record(
                    &state.server_secret,
                    agent_auth_http::credential::CredentialKind::InitialAccessToken,
                    "",
                    token_id.into(),
                    "offboarding-test".into(),
                    "offboarding-secret",
                    now,
                    now + 3600,
                    "test".into(),
                    None,
                ),
                scopes: vec!["dcr:register".into()],
                rate_limit_per_minute: 30,
                one_time: false,
                used_at: None,
                version: 1,
            },
        )
        .await
        .unwrap();

    state
        .federation_config
        .put(agent_auth_authn::federation::FederationConfig {
            tenant_id: "default".into(),
            upstream_idp_id: "offboard-idp".into(),
            protocol: agent_auth_authn::federation::UpstreamProtocol::Oidc,
            upstream_issuer: "https://idp.example.com".into(),
            strong_acr_values: vec![],
            oidc: Some(agent_auth_authn::federation::OidcRpParams {
                client_id: "offboard-federation-client".into(),
                client_secret_ref: "external-secret-reference".into(),
                authorization_endpoint: "https://idp.example.com/authorize".into(),
                token_endpoint: "https://idp.example.com/token".into(),
                jwks_uri: "https://idp.example.com/jwks".into(),
                scopes: vec!["openid".into()],
            }),
        })
        .await
        .unwrap();
    state
        .workload_trust
        .put(
            "",
            "offboard-binding".into(),
            agent_auth_workload::TrustBinding {
                tenant_id: "default".into(),
                mechanism: agent_auth_workload::TrustMechanism::SpiffeJwt {
                    trust_domain: "example.org".into(),
                    jwks_uri: "https://bundle.example.org/jwks".into(),
                    spiffe_id_pattern: "spiffe://example.org/workload".into(),
                },
                mapped_client_id: "offboard-client".into(),
            },
        )
        .await
        .unwrap();

    state
        .admin_auth
        .put_config(
            AdminOidcConfig {
                tenant_id: "default".into(),
                binding_id: "offboard-admin-binding".into(),
                issuer: "https://admin-idp.example.com".into(),
                client_id: "offboard-admin-client".into(),
                client_secret_ref: "external-admin-secret".into(),
                authorization_endpoint: "https://admin-idp.example.com/authorize".into(),
                token_endpoint: "https://admin-idp.example.com/token".into(),
                jwks_uri: "https://admin-idp.example.com/jwks".into(),
                redirect_uri: "https://localhost/admin/sso/callback".into(),
                scopes: vec!["openid".into()],
                strong_acr_values: vec![],
                identity_claim: "email".into(),
                identity_field: agent_auth_http::ports::AdminIdentityField::UserName,
                revision: 1,
                updated_at: now,
            },
            0,
        )
        .await
        .unwrap();
    state
        .admin_auth
        .put_flow(AdminOidcFlow {
            state_hash: "offboard-flow".into(),
            nonce: "offboard-nonce".into(),
            code_verifier: "offboard-verifier".into(),
            tenant_id: "default".into(),
            config_revision: 1,
            config_binding_id: "offboard-admin-binding".into(),
            required_acr: None,
            required_max_age_secs: None,
            expires_at: now + 3600,
        })
        .await
        .unwrap();
    state
        .admin_auth
        .create_session(AdminSessionRecord {
            session_hash: "offboard-admin-session".into(),
            tenant_id: "default".into(),
            user_id: "user:offboard-a@example.com".into(),
            upstream_subject: "offboard-subject".into(),
            role: TenantRole::Owner,
            credential_epoch: 0,
            config_revision: 1,
            config_binding_id: "offboard-admin-binding".into(),
            acr: Some(agent_auth_authn::assurance::STRONG_ACR.into()),
            auth_time: now,
            created_at: now,
            expires_at: now + 3600,
        })
        .await
        .unwrap();

    let invitation = seed_governance_invitation(
        &state,
        "",
        "user:offboard-a@example.com",
        "offboard-a@example.com",
        "offboard-invitation",
        now,
    )
    .await;
    seed_offboarding_orphans(&state, now).await;

    let (router, _) = build_router(state.clone());
    let started = send(
        &router,
        Method::POST,
        "localhost",
        "/admin/data-governance/tenant/offboarding",
        Some("dev-admin-token-not-for-prod"),
        None,
        true,
        None,
    )
    .await;
    assert_eq!(started.status, StatusCode::ACCEPTED);
    let job_id = started.body["job_id"].as_str().unwrap().to_string();

    let restarted = state.clone();
    let parent = advance_tenant_offboarding_once(&restarted, "default", &job_id, now + 1)
        .await
        .unwrap();
    assert_eq!(parent.phase, GovernanceJobPhase::MutationFenced);

    for processed in 1..=2 {
        let parent =
            advance_tenant_offboarding_once(&state, "default", &job_id, now + processed * 10)
                .await
                .unwrap();
        let child_id = parent
            .active_child_job_id
            .clone()
            .expect("one immutable first-page child");
        for phase in 0..5 {
            advance_user_erasure_once(
                &state,
                "default",
                &child_id,
                now + processed * 10 + phase + 1,
            )
            .await
            .unwrap();
        }
        let restarted = state.clone();
        let parent = advance_tenant_offboarding_once(
            &restarted,
            "default",
            &job_id,
            now + processed * 10 + 6,
        )
        .await
        .unwrap();
        assert_eq!(parent.processed_records, processed as u64);
        assert!(parent.active_child_job_id.is_none());
    }

    let parent = advance_tenant_offboarding_once(&state, "default", &job_id, now + 40)
        .await
        .unwrap();
    assert_eq!(parent.phase, GovernanceJobPhase::PrimaryCleanup);
    assert!(state
        .users
        .list(
            "",
            1,
            None,
            None,
            agent_auth_http::ports::UserListStatusFilter::All,
        )
        .await
        .unwrap()
        .0
        .is_empty());
    assert!(state
        .governance
        .get_job("default", &job_id)
        .await
        .unwrap()
        .is_some());

    let mut parent = parent;
    for checkpoint in 0..32 {
        parent = advance_tenant_offboarding_once(&state, "default", &job_id, now + 50 + checkpoint)
            .await
            .unwrap();
        if parent.tenant_cleanup_stage == TenantCleanupStage::SigningKeysAndSecrets {
            break;
        }
    }
    assert_eq!(
        parent.tenant_cleanup_stage,
        TenantCleanupStage::SigningKeysAndSecrets
    );
    for checkpoint in 0..32 {
        parent =
            advance_tenant_offboarding_once(&state, "default", &job_id, now + 200 + checkpoint)
                .await
                .unwrap();
        if parent.state == GovernanceJobState::RetentionPending {
            break;
        }
    }
    assert_eq!(parent.tenant_cleanup_stage, TenantCleanupStage::Complete);
    assert_eq!(parent.phase, GovernanceJobPhase::RetentionVerification);
    assert_eq!(parent.state, GovernanceJobState::RetentionPending);
    assert!(parent
        .retention_until
        .is_some_and(|deadline| deadline > now));

    assert!(state.clients.list("").await.unwrap().is_empty());
    assert!(state
        .initial_access_tokens
        .list("")
        .await
        .unwrap()
        .is_empty());
    assert!(state
        .domain_map
        .list_by_client("offboard-client")
        .await
        .unwrap()
        .is_empty());
    assert!(state
        .authz_sessions
        .list_by_client("", "offboard-client")
        .await
        .unwrap()
        .is_empty());
    assert_eq!(state.scim_groups.list("", 0, 10).await.unwrap().1, 0);
    assert!(state
        .federation_config
        .list_by_tenant("default")
        .await
        .unwrap()
        .is_empty());
    assert!(state
        .workload_trust
        .list_by_tenant("default")
        .await
        .unwrap()
        .is_empty());
    assert!(state
        .admin_auth
        .get_config("default")
        .await
        .unwrap()
        .is_none());
    assert!(state
        .admin_auth
        .get_session("offboard-admin-session", now + 100)
        .await
        .unwrap()
        .is_none());
    assert!(state
        .federation_flow
        .consume("offboard-federation-flow")
        .await
        .unwrap()
        .is_none());
    assert!(state
        .federation_flow
        .consume("control-federation-flow")
        .await
        .unwrap()
        .is_some());
    assert!(state
        .passkey_challenges
        .consume("", "offboard-orphan-challenge")
        .await
        .unwrap()
        .is_none());
    assert!(state
        .passkey_challenges
        .consume("control", "control-orphan-challenge")
        .await
        .unwrap()
        .is_some());
    assert!(matches!(
        state
            .codes
            .acquire_lease(
                "",
                "offboard-orphan-code",
                "offboard-owner",
                now + 1,
                now + 30,
            )
            .await
            .unwrap(),
        LeaseAcquire::NotFound
    ));
    assert!(matches!(
        state
            .codes
            .acquire_lease(
                "control",
                "control-orphan-code",
                "control-owner",
                now + 1,
                now + 30,
            )
            .await
            .unwrap(),
        LeaseAcquire::Acquired(_)
    ));
    assert!(state
        .sessions
        .get("", "offboard-orphan-session")
        .await
        .unwrap()
        .is_none());
    assert!(state
        .sessions
        .get("control", "control-orphan-session")
        .await
        .unwrap()
        .is_some());
    assert!(state
        .refresh
        .get("", "offboard-orphan-family")
        .await
        .unwrap()
        .is_none());
    assert!(state
        .refresh
        .get("control", "control-orphan-family")
        .await
        .unwrap()
        .is_some());
    assert!(state
        .grace
        .as_ref()
        .unwrap()
        .get("offboard-orphan-family", 0)
        .await
        .unwrap()
        .is_none());
    assert!(state
        .grace
        .as_ref()
        .unwrap()
        .get("control-orphan-family", 0)
        .await
        .unwrap()
        .is_some());
    assert!(state
        .passkeys
        .get("", "offboard-orphan-passkey")
        .await
        .unwrap()
        .is_none());
    assert!(state
        .passkeys
        .get("control", "control-orphan-passkey")
        .await
        .unwrap()
        .is_some());
    assert!(state
        .jti_store
        .as_ref()
        .unwrap()
        .get("default", "offboard-orphan-jti")
        .await
        .unwrap()
        .is_none());
    assert!(state
        .jti_store
        .as_ref()
        .unwrap()
        .get("control", "control-orphan-jti")
        .await
        .unwrap()
        .is_some());
    assert!(state
        .passwords
        .get("", "offboard-orphan-user")
        .await
        .unwrap()
        .is_none());
    assert!(state
        .passwords
        .get("control", "control-orphan-user")
        .await
        .unwrap()
        .is_some());
    assert!(state
        .recovery
        .get("", "offboard-orphan-lookup")
        .await
        .unwrap()
        .is_none());
    assert!(state
        .recovery
        .get("control", "control-orphan-lookup")
        .await
        .unwrap()
        .is_some());
    assert!(state
        .magic_links
        .get("", "offboard-orphan-link")
        .await
        .unwrap()
        .is_none());
    assert!(state
        .magic_links
        .consume_bound("control", "control-orphan-link", "orphan-nonce")
        .await
        .unwrap()
        .is_some());
    assert!(state.messages.list_recent("", 10).await.unwrap().is_empty());
    assert_eq!(
        state
            .messages
            .list_recent("control", 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(state
        .ciba
        .get("", "offboard-orphan-ciba")
        .await
        .unwrap()
        .is_none());
    assert!(state
        .ciba
        .get("control", "control-orphan-ciba")
        .await
        .unwrap()
        .is_some());
    assert!(state
        .ciba
        .try_arm_throttle("", "orphan-user", now + 1, 3600)
        .await
        .unwrap());
    assert!(!state
        .ciba
        .try_arm_throttle("control", "orphan-user", now + 1, 3600)
        .await
        .unwrap());
    assert!(state
        .device
        .get("", "offboard-orphan-device")
        .await
        .unwrap()
        .is_none());
    assert!(state
        .device
        .get("control", "control-orphan-device")
        .await
        .unwrap()
        .is_some());
    assert!(state
        .par
        .consume("", "urn:test:offboard-par", now + 1)
        .await
        .unwrap()
        .is_none());
    assert!(state
        .par
        .consume("control", "urn:test:control-par", now + 1)
        .await
        .unwrap()
        .is_some());
    let replay = state.replay_store.as_ref().unwrap();
    assert!(replay
        .check_and_set("", "offboard-orphan-replay", now + 3600)
        .await
        .unwrap());
    assert!(!replay
        .check_and_set("control", "control-orphan-replay", now + 3600)
        .await
        .unwrap());
    assert!(state
        .authz_sessions
        .get("", "offboard-orphan-authz")
        .await
        .unwrap()
        .is_none());
    assert!(state
        .authz_sessions
        .get("control", "control-orphan-authz")
        .await
        .unwrap()
        .is_some());
    assert!(state
        .grants
        .get("", "offboard-orphan-grant")
        .await
        .unwrap()
        .is_none());
    assert!(state
        .grants
        .get("control", "control-orphan-grant")
        .await
        .unwrap()
        .is_some());
    assert!(state
        .domain_map
        .get("offboard-orphan.example.com")
        .await
        .unwrap()
        .is_none());
    assert!(state
        .domain_map
        .get("control-orphan.example.com")
        .await
        .unwrap()
        .is_some());
    assert_eq!(state.policy_versions.get("").await.unwrap(), 0);
    assert_eq!(state.policy_versions.get("control").await.unwrap(), 1);
    assert!(state.policy_artifacts.get("", 1).await.unwrap().is_none());
    assert!(state
        .policy_artifacts
        .get("control", 1)
        .await
        .unwrap()
        .is_some());
    let policy_cache = state.current_pv_cache.lock().await;
    assert!(!policy_cache.contains_key(""));
    assert!(policy_cache.contains_key("control"));
    drop(policy_cache);
    let offboard_stream = state
        .ssf
        .get_stream("default", "offboard-stream")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(offboard_stream.status, SsfStreamStatus::Revoked);
    assert_eq!(offboard_stream.revision, 2);
    let control_stream = state
        .ssf
        .get_stream("control", "control-stream")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(control_stream.status, SsfStreamStatus::Enabled);
    assert_eq!(
        state
            .ssf
            .get_delivery("default", "offboard-stream", 1, "offboard-verification",)
            .await
            .unwrap()
            .unwrap()
            .status,
        SsfDeliveryStatus::Suppressed
    );
    assert_eq!(
        state
            .ssf
            .get_delivery("control", "control-stream", 1, "control-verification")
            .await
            .unwrap()
            .unwrap()
            .status,
        SsfDeliveryStatus::Pending
    );
    let due = state.ssf.acquire_due(now + 100, 30, 100).await.unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].delivery.tenant_id, "control");

    let actions = state
        .governance
        .list_external_actions("default", &job_id)
        .await
        .unwrap();
    assert_eq!(actions.len(), 4);
    assert!(actions.iter().all(|action| {
        action.ownership == GovernanceResourceOwnership::External
            && action.state == GovernanceExternalActionState::Verified
    }));
    assert_eq!(
        state.invitations.accept("", invitation).await.unwrap(),
        InvitationAcceptOutcome::Invalid
    );
}

#[tokio::test]
async fn legal_hold_fences_a_stale_erasure_worker_before_the_first_mutation() {
    let state = AppState::dev("localhost");
    let now = agent_auth_http::current_unix_secs();
    state
        .users
        .create_or_get_by_email("", "hold-race@example.com", "hold-race-user", now)
        .await
        .unwrap();
    let (router, _) = build_router(state.clone());
    let auth = Some("dev-admin-token-not-for-prod");

    let started = send(
        &router,
        Method::POST,
        "localhost",
        "/admin/data-governance/users/hold-race-user/erasure",
        auth,
        None,
        true,
        None,
    )
    .await;
    assert_eq!(started.status, StatusCode::ACCEPTED);
    let job_id = started.body["job_id"].as_str().unwrap();

    let held = send(
        &router,
        Method::PUT,
        "localhost",
        "/admin/data-governance/policy",
        auth,
        None,
        true,
        Some(json!({
            "expected_revision": 0,
            "legal_hold": true,
            "reason": "case-stale-worker"
        })),
    )
    .await;
    assert_eq!(held.status, StatusCode::OK);
    let held_revision = held.body["revision"].as_u64().unwrap();

    let blocked = advance_user_erasure_once(&state, "default", job_id, now + 1)
        .await
        .unwrap();
    assert_eq!(blocked.state, GovernanceJobState::BlockedLegalHold);
    assert_eq!(blocked.phase, GovernanceJobPhase::IntentRecorded);
    assert_eq!(
        state
            .users
            .get_by_id("", "hold-race-user")
            .await
            .unwrap()
            .unwrap()
            .status,
        agent_auth_http::ports::UserStatus::Active
    );

    let released = send(
        &router,
        Method::PUT,
        "localhost",
        "/admin/data-governance/policy",
        auth,
        None,
        true,
        Some(json!({
            "expected_revision": held_revision,
            "legal_hold": false
        })),
    )
    .await;
    assert_eq!(released.status, StatusCode::OK);
    let resumed = send(
        &router,
        Method::POST,
        "localhost",
        "/admin/data-governance/users/hold-race-user/erasure",
        auth,
        None,
        true,
        None,
    )
    .await;
    assert_eq!(resumed.status, StatusCode::ACCEPTED);
    assert_eq!(resumed.body["job_id"], job_id);

    let fenced = advance_user_erasure_once(&state, "default", job_id, now + 2)
        .await
        .unwrap();
    assert_eq!(fenced.phase, GovernanceJobPhase::MutationFenced);
}

#[tokio::test]
async fn secondary_residency_region_allows_export_but_rejects_destructive_governance() {
    let mut state = saas_state();
    state.region = RegionRuntime::single_region_in("us-west-2").unwrap();
    state.governance_config = Arc::new(
        GovernanceConfig::parse_json(
            r#"{
                "t1":{
                    "jurisdiction":"us",
                    "allowed_regions":["us-east-1","us-west-2"],
                    "governance_region":"us-east-1"
                },
                "t2":{
                    "jurisdiction":"eu",
                    "allowed_regions":["us-east-1","us-west-2"],
                    "governance_region":"us-east-1"
                }
            }"#,
            &state.saas_tenants,
        )
        .unwrap(),
    );
    state
        .users
        .create_or_get_by_email(
            "t1",
            "secondary@example.com",
            "secondary-user",
            agent_auth_http::current_unix_secs(),
        )
        .await
        .unwrap();
    let (router, _) = build_router(state);

    let export = send(
        &router,
        Method::GET,
        T1_HOST,
        "/admin/data-governance/users/secondary-user/export",
        Some(T1_TOKEN),
        None,
        true,
        None,
    )
    .await;
    assert_eq!(export.status, StatusCode::OK);
    assert_eq!(export.body["active_writer_region"], "us-west-2");

    let policy = send(
        &router,
        Method::GET,
        T1_HOST,
        "/admin/data-governance/policy",
        Some(T1_TOKEN),
        None,
        true,
        None,
    )
    .await;
    assert_eq!(policy.status, StatusCode::OK);
    assert_eq!(policy.body["active_writer_region"], "us-west-2");
    assert_eq!(policy.body["governance_region"], "us-east-1");

    let erasure = send(
        &router,
        Method::POST,
        T1_HOST,
        "/admin/data-governance/users/secondary-user/erasure",
        Some(T1_TOKEN),
        None,
        true,
        None,
    )
    .await;
    assert_eq!(erasure.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(erasure.body["error"], "governance_region_inactive");

    let legal_hold = send(
        &router,
        Method::PUT,
        T1_HOST,
        "/admin/data-governance/policy",
        Some(T1_TOKEN),
        None,
        true,
        Some(json!({
            "expected_revision": 0,
            "legal_hold": true,
            "reason": "case-secondary"
        })),
    )
    .await;
    assert_eq!(legal_hold.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(legal_hold.body["error"], "governance_region_inactive");
}
