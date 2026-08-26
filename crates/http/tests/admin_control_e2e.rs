use std::{collections::HashMap, sync::Arc, time::Duration};

use agent_auth_http::{
    admin_credentials::{
        AdminCredentialOwner, AdminCredentialRecord, AdminCredentialResolver,
        AdminCredentialRotation, AdminCredentialSet, MemoryAdminCredentialStore,
    },
    build_router, current_unix_secs,
    ports::{SessionRecord, SessionStore, UsersStore},
    security_event::{SecurityEventCategory, SecurityEventOutcome, SecurityEventStore},
    state::AppState,
    tenant_keys::TenantKeyCommandSinkImpl,
};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use serde_json::Value;
use tower::ServiceExt;

const CONTROL: &str = "c.aws.example.com";
const T1: &str = "t1.aws.example.com";
const T2: &str = "t2.aws.example.com";
const PLATFORM_TOKEN: &str = "platform-admin-secret";
const T1_TOKEN: &str = "t1-admin-secret-v1";
const T2_TOKEN: &str = "t2-admin-secret-v1";
const T1_ARN: &str =
    "arn:aws:secretsmanager:us-east-1:123456789012:secret:agent-auth/saas/t1-admin-AbCd";
const T2_ARN: &str =
    "arn:aws:secretsmanager:us-east-1:123456789012:secret:agent-auth/saas/t2-admin-EfGh";

fn active_set(owner: AdminCredentialOwner, id: &str, token: &str) -> AdminCredentialSet {
    let now = current_unix_secs();
    AdminCredentialSet::single(
        owner,
        AdminCredentialRecord::explicit(id, token, now - 60, now - 60, now + 86_400),
    )
}

fn credentials(
    platform_token: &str,
    tenants: &[(&str, &str, &str)],
) -> Arc<AdminCredentialResolver> {
    let now = current_unix_secs();
    let platform_ref =
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:agent-auth/platform-admin-IjKl";
    let store = MemoryAdminCredentialStore::default();
    store.put_set(
        platform_ref,
        &active_set(
            AdminCredentialOwner::platform(),
            "platform-v1",
            platform_token,
        ),
        now,
    );
    let mut tenant_refs = HashMap::new();
    for (tenant, token, secret_ref) in tenants {
        tenant_refs.insert((*tenant).to_string(), (*secret_ref).to_string());
        store.put_set(
            *secret_ref,
            &active_set(
                AdminCredentialOwner::tenant(*tenant),
                &format!("{tenant}-v1"),
                token,
            ),
            now,
        );
    }
    Arc::new(AdminCredentialResolver::memory(
        Some(platform_ref.to_string()),
        tenant_refs,
        store,
        Duration::ZERO,
    ))
}

fn state_with(platform_token: &str, tenants: &[(&str, &str, &str)]) -> AppState {
    let mut state = AppState::dev("localhost");
    state.form = agent_auth_discovery::Form::Saas {
        zone: "aws.example.com".to_string(),
        control_host: CONTROL.to_string(),
    };
    state.tenant_partitioning = true;
    state.admin_credentials = credentials(platform_token, tenants);
    // 故意逆序,验证响应稳定排序。
    state.saas_tenants = Arc::new(vec!["t2".to_string(), "t1".to_string()]);
    state
}

fn state() -> AppState {
    state_with(
        PLATFORM_TOKEN,
        &[("t1", T1_TOKEN, T1_ARN), ("t2", T2_TOKEN, T2_ARN)],
    )
}

async fn get(host: &str, path: &str, token: Option<&str>) -> (StatusCode, Value) {
    let (router, _) = build_router(state());
    let mut req = Request::builder()
        .method("GET")
        .uri(path)
        .header("host", host);
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let response = router
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn platform_token_reads_sorted_control_directory_without_secret_values() {
    let (status, body) = get(CONTROL, "/admin/control/tenants", Some(PLATFORM_TOKEN)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["tenants"][0]["tenant_id"], "t1");
    assert_eq!(body["tenants"][0]["issuer"], "https://t1.aws.example.com");
    assert_eq!(
        body["tenants"][0]["admin_url"],
        "https://t1.aws.example.com/admin"
    );
    assert_eq!(body["tenants"][0]["admin_secret_arn"], T1_ARN);
    assert_eq!(body["tenants"][1]["tenant_id"], "t2");
    let encoded = serde_json::to_string(&body).unwrap();
    assert!(!encoded.contains(PLATFORM_TOKEN));
    assert!(!encoded.contains(T1_TOKEN));
    assert!(!encoded.contains(T2_TOKEN));
}

#[tokio::test]
async fn control_endpoint_rejects_tenant_tokens_sessions_and_non_control_hosts() {
    for token in [None, Some(T1_TOKEN), Some(T2_TOKEN)] {
        assert_eq!(
            get(CONTROL, "/admin/control/tenants", token).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        get(T1, "/admin/control/tenants", Some(PLATFORM_TOKEN))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(T2, "/admin/control/tenants", Some(T2_TOKEN)).await.0,
        StatusCode::NOT_FOUND
    );

    let state = state();
    let now = current_unix_secs();
    let user_id = "user:session@example.com";
    state
        .users
        .create_or_get_by_email("t1", "session@example.com", user_id, now)
        .await
        .unwrap();
    state
        .sessions
        .create(
            "t1",
            SessionRecord {
                session_id: "valid-t1-user-session".to_string(),
                user_id: user_id.to_string(),
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
    let (router, _) = build_router(state);
    for (host, path) in [(CONTROL, "/admin/control/tenants"), (T1, "/admin/overview")] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("host", host)
                    .header("cookie", "__Host-agent_auth_session=valid-t1-user-session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "a valid user session must not authorize {host}{path}"
        );
    }
}

#[tokio::test]
async fn platform_and_tenant_tokens_have_disjoint_admin_domains() {
    assert_eq!(
        get(T1, "/admin/overview", Some(T1_TOKEN)).await.0,
        StatusCode::OK
    );
    assert_eq!(
        get(T2, "/admin/overview", Some(T2_TOKEN)).await.0,
        StatusCode::OK
    );
    for host in [T1, T2] {
        assert_eq!(
            get(host, "/admin/overview", Some(PLATFORM_TOKEN)).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        get(T2, "/admin/overview", Some(T1_TOKEN)).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get(T1, "/admin/overview", Some(T2_TOKEN)).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn platform_controls_tenant_key_lifecycle_only_on_control_host() {
    let state = state();
    let tenant_keys = state.tenant_keys.clone();
    let (router, _) = build_router(state);

    let status = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/control/tenants/t1/keys")
                .header("host", CONTROL)
                .header("authorization", format!("Bearer {PLATFORM_TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    let body = to_bytes(status.into_body(), usize::MAX).await.unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["lifecycle"], "unprovisioned");
    assert_eq!(body["ready"], false);

    let accepted = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/control/tenants/t1/keys/ensure")
                .header("host", CONTROL)
                .header("authorization", format!("Bearer {PLATFORM_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"operation_id":"onboard-t1-v1"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let commands = match tenant_keys.command_sink() {
        TenantKeyCommandSinkImpl::Memory(sink) => sink.commands().await,
        TenantKeyCommandSinkImpl::Disabled => panic!("expected memory command sink"),
        #[cfg(feature = "aws")]
        TenantKeyCommandSinkImpl::Sqs(_) => panic!("expected memory command sink"),
    };
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].tenant_id, "t1");
    assert_eq!(commands[0].operation_id, "onboard-t1-v1");

    let emergency = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/control/tenants/t1/keys/emergency-revoke")
                .header("host", CONTROL)
                .header("authorization", format!("Bearer {PLATFORM_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"operation_id":"rotate-t1-v2"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(emergency.status(), StatusCode::ACCEPTED);
    let commands = match tenant_keys.command_sink() {
        TenantKeyCommandSinkImpl::Memory(sink) => sink.commands().await,
        TenantKeyCommandSinkImpl::Disabled => panic!("expected memory command sink"),
        #[cfg(feature = "aws")]
        TenantKeyCommandSinkImpl::Sqs(_) => panic!("expected memory command sink"),
    };
    assert_eq!(commands.len(), 2);
    assert_eq!(
        commands[1].action,
        agent_auth_http::tenant_keys::TenantKeyCommandAction::EmergencyRevoke
    );
    assert_eq!(commands[1].operation_id, "rotate-t1-v2");

    for request in [
        Request::builder()
            .method("POST")
            .uri("/admin/control/tenants/t3/keys/ensure")
            .header("host", CONTROL)
            .header("authorization", format!("Bearer {PLATFORM_TOKEN}"))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"operation_id":"onboard-t3-v1"}"#))
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri("/admin/control/tenants/t1/keys/rotate")
            .header("host", T1)
            .header("authorization", format!("Bearer {PLATFORM_TOKEN}"))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"operation_id":"rotate-t1-v2"}"#))
            .unwrap(),
    ] {
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn tenant_admin_cannot_select_another_tenant_from_path_or_body() {
    let state = state();
    let (router, _) = build_router(state.clone());
    let federation = serde_json::json!({
        "tenant_id": "t2",
        "upstream_idp_id": "okta",
        "upstream_issuer": "https://okta.example.com",
        "client_id": "as-rp",
        "client_secret_ref": "secretsmanager:fed/okta",
        "authorization_endpoint": "https://okta.example.com/authorize",
        "token_endpoint": "https://okta.example.com/token",
        "jwks_uri": "https://okta.example.com/jwks",
        "scopes": ["openid"]
    });
    let workload = serde_json::json!({
        "binding_id": "b1",
        "tenant_id": "t2",
        "platform_issuer": "https://token.actions.githubusercontent.com",
        "jwks_uri": "https://token.actions.githubusercontent.com/.well-known/jwks",
        "subject_pattern": "repo:acme/agent:*",
        "mapped_client_id": "wl-agent"
    });

    for (method, path, body) in [
        ("GET", "/admin/workload-trust/t2", None),
        ("POST", "/admin/workload-trust", Some(workload)),
        ("GET", "/admin/federation/t2", None),
        ("PUT", "/admin/federation", Some(federation)),
        ("DELETE", "/admin/federation/t2/okta", None),
    ] {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", T1)
            .header("authorization", format!("Bearer {T1_TOKEN}"));
        if body.is_some() {
            request = request.header("content-type", "application/json");
        }
        let response = router
            .clone()
            .oneshot(
                request
                    .body(
                        body.map(|value| Body::from(value.to_string()))
                            .unwrap_or(Body::empty()),
                    )
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "t1 admin must not select t2 through {method} {path}"
        );
    }

    let denials = state
        .security_events
        .list_by_tenant("t1", 0, i64::MAX, 100)
        .await
        .unwrap()
        .into_iter()
        .filter(|stored| {
            stored.event.category == SecurityEventCategory::TenantBoundary
                && stored.event.outcome == SecurityEventOutcome::Denied
                && {
                    let subject = serde_json::to_value(&stored.event.subject).unwrap();
                    subject["kind"] == "tenant" && subject["id"] == "t2"
                }
        })
        .count();
    assert_eq!(
        denials, 5,
        "every cross-tenant Admin denial must be audited"
    );
}

#[tokio::test]
async fn incomplete_or_shared_secret_arn_configuration_fails_closed() {
    for broken in [
        "missing",
        "duplicate-arn",
        "duplicate-token",
        "platform-token",
    ] {
        let state = match broken {
            "missing" => state_with(PLATFORM_TOKEN, &[("t1", T1_TOKEN, T1_ARN)]),
            "duplicate-arn" => state_with(
                PLATFORM_TOKEN,
                &[("t1", T1_TOKEN, T1_ARN), ("t2", T2_TOKEN, T1_ARN)],
            ),
            "duplicate-token" => state_with(
                PLATFORM_TOKEN,
                &[("t1", T1_TOKEN, T1_ARN), ("t2", T1_TOKEN, T2_ARN)],
            ),
            "platform-token" => state_with(
                T1_TOKEN,
                &[("t1", T1_TOKEN, T1_ARN), ("t2", T2_TOKEN, T2_ARN)],
            ),
            _ => unreachable!(),
        };
        let (router, _) = build_router(state);
        let mut targets = vec![
            (
                CONTROL,
                "/admin/control/tenants",
                if broken == "platform-token" {
                    T1_TOKEN
                } else {
                    PLATFORM_TOKEN
                },
            ),
            (T2, "/admin/overview", T2_TOKEN),
        ];
        if broken != "missing" {
            targets.push((T1, "/admin/overview", T1_TOKEN));
        }
        // A missing t2 reference is rejected at production startup by the
        // SAAS_TENANTS/TENANT_ADMIN_SECRET_ARNS set-equality gate. This
        // hand-built state can still prove control and the missing owner fail
        // closed; configured duplicate identities invalidate every owner.
        for (host, path, token) in targets {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header("host", host)
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "{broken} registry must fail closed on {host}{path}"
            );
        }
    }
}

#[tokio::test]
async fn platform_and_two_tenants_rotate_with_bounded_overlap_and_retirement() {
    let now = current_unix_secs();
    let platform_ref =
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:agent-auth/platform-admin-IjKl";
    let store = MemoryAdminCredentialStore::default();
    let rotating = |owner, prefix: &str, old: &str, new: &str| {
        AdminCredentialSet::rotating(
            owner,
            2,
            AdminCredentialRecord::explicit(
                format!("{prefix}-v1"),
                old,
                now - 300,
                now - 300,
                now + 120,
            ),
            AdminCredentialRecord::explicit(
                format!("{prefix}-v2"),
                new,
                now - 60,
                now - 60,
                now + 86_400,
            ),
            AdminCredentialRotation {
                overlap_starts_at: now - 60,
                cutover_at: now + 30,
                retire_current_at: now + 60,
            },
        )
    };
    store.put_set(
        platform_ref,
        &rotating(
            AdminCredentialOwner::platform(),
            "platform",
            "platform-old-secret",
            "platform-new-secret",
        ),
        now,
    );
    store.put_set(
        T1_ARN,
        &rotating(
            AdminCredentialOwner::tenant("t1"),
            "t1",
            "t1-old-admin-secret",
            "t1-new-admin-secret",
        ),
        now,
    );
    store.put_set(
        T2_ARN,
        &rotating(
            AdminCredentialOwner::tenant("t2"),
            "t2",
            "t2-old-admin-secret",
            "t2-new-admin-secret",
        ),
        now,
    );
    let resolver = Arc::new(AdminCredentialResolver::memory(
        Some(platform_ref.to_string()),
        HashMap::from([
            ("t1".to_string(), T1_ARN.to_string()),
            ("t2".to_string(), T2_ARN.to_string()),
        ]),
        store.clone(),
        Duration::ZERO,
    ));
    let mut state = state();
    state.admin_credentials = resolver;
    let audit = state.credential_audit.clone();
    let (router, _) = build_router(state);

    for token in ["platform-old-secret", "platform-new-secret"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/control/tenants")
                    .header("host", CONTROL)
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    for (host, old, new) in [
        (T1, "t1-old-admin-secret", "t1-new-admin-secret"),
        (T2, "t2-old-admin-secret", "t2-new-admin-secret"),
    ] {
        for token in [old, new] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/admin/overview")
                        .header("host", host)
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
    }
    let audit_snapshot = audit.snapshot();
    let break_glass: Vec<_> = audit_snapshot
        .iter()
        .filter(|line| line.contains("ADMIN_BREAK_GLASS_USE priority=high"))
        .collect();
    assert_eq!(break_glass.len(), 6);
    for (tenant, credential_id) in [
        ("platform", "platform-v1"),
        ("platform", "platform-v2"),
        ("t1", "t1-v1"),
        ("t1", "t1-v2"),
        ("t2", "t2-v1"),
        ("t2", "t2-v2"),
    ] {
        assert_eq!(
            break_glass
                .iter()
                .filter(|line| {
                    line.contains(&format!("tenant={tenant} "))
                        && line.contains(&format!("credential_id={credential_id} "))
                })
                .count(),
            1
        );
    }
    let audit_lines = audit_snapshot.join("\n");
    for token in [
        "platform-old-secret",
        "platform-new-secret",
        "t1-old-admin-secret",
        "t1-new-admin-secret",
        "t2-old-admin-secret",
        "t2-new-admin-secret",
    ] {
        assert!(!audit_lines.contains(token));
    }

    let retired = |owner, prefix: &str, old_token: &str, token: &str| {
        let mut set = AdminCredentialSet::single(
            owner,
            AdminCredentialRecord::explicit(
                format!("{prefix}-v2"),
                token,
                now - 60,
                now - 60,
                now + 86_400,
            ),
        );
        set.revision = 3;
        set.retired
            .push(agent_auth_http::admin_credentials::AdminRetiredCredential {
                credential_id: format!("{prefix}-v1"),
                secret_sha256: agent_auth_http::admin_credentials::secret_sha256(old_token),
                retired_at: now,
            });
        set
    };
    store.put_set(
        platform_ref,
        &retired(
            AdminCredentialOwner::platform(),
            "platform",
            "platform-old-secret",
            "platform-new-secret",
        ),
        now + 1,
    );
    store.put_set(
        T1_ARN,
        &retired(
            AdminCredentialOwner::tenant("t1"),
            "t1",
            "t1-old-admin-secret",
            "t1-new-admin-secret",
        ),
        now + 1,
    );
    store.put_set(
        T2_ARN,
        &retired(
            AdminCredentialOwner::tenant("t2"),
            "t2",
            "t2-old-admin-secret",
            "t2-new-admin-secret",
        ),
        now + 1,
    );

    for (host, old) in [
        (CONTROL, "platform-old-secret"),
        (T1, "t1-old-admin-secret"),
        (T2, "t2-old-admin-secret"),
    ] {
        let path = if host == CONTROL {
            "/admin/control/tenants"
        } else {
            "/admin/overview"
        };
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("host", host)
                    .header("authorization", format!("Bearer {old}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn expired_owner_invalidates_the_whole_registry() {
    let now = current_unix_secs();
    let platform_ref =
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:agent-auth/platform-admin-IjKl";
    let store = MemoryAdminCredentialStore::default();
    for (secret_ref, owner, id, token) in [
        (
            platform_ref,
            AdminCredentialOwner::platform(),
            "platform-expired",
            PLATFORM_TOKEN,
        ),
        (
            T1_ARN,
            AdminCredentialOwner::tenant("t1"),
            "t1-expired",
            T1_TOKEN,
        ),
        (
            T2_ARN,
            AdminCredentialOwner::tenant("t2"),
            "t2-active",
            T2_TOKEN,
        ),
    ] {
        let expires_at = if id.ends_with("expired") {
            now
        } else {
            now + 86_400
        };
        store.put_set(
            secret_ref,
            &AdminCredentialSet::single(
                owner,
                AdminCredentialRecord::explicit(id, token, now - 100, now - 100, expires_at),
            ),
            now,
        );
    }
    let mut state = state();
    state.admin_credentials = Arc::new(AdminCredentialResolver::memory(
        Some(platform_ref.to_string()),
        HashMap::from([
            ("t1".to_string(), T1_ARN.to_string()),
            ("t2".to_string(), T2_ARN.to_string()),
        ]),
        store,
        Duration::ZERO,
    ));
    let (router, _) = build_router(state);

    for (host, path, token) in [
        (CONTROL, "/admin/control/tenants", PLATFORM_TOKEN),
        (T1, "/admin/overview", T1_TOKEN),
        (T2, "/admin/overview", T2_TOKEN),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("host", host)
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
