use agent_auth_grant::{Grant, GrantConstraints, GrantStatus, ResourceGrant};
use agent_auth_http::ports::{
    AuthzSessionStore, CibaAuthRequest, CibaStore, CodeRecord, CodeStore, DeviceAuthGrant,
    DeviceStore, GrantStore, MessageOutbox, PasswordCredential, PasswordStore, RateLimitStore,
    RefreshFamilyRecord, RefreshStore, ScimCreateOutcome, ScimReplaceInput, ScimReplaceOutcome,
    ScimUserInput, SessionRecord, SessionStore, UserStatus, UsersStore,
};
use agent_auth_http::security_event::{SecurityEventOutcome, SecurityEventStore};
use agent_auth_http::{build_router, AppState, Phase};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use tower::ServiceExt;

const HOST: &str = "localhost";
const ADMIN: &str = "dev-admin-token-not-for-prod";
const INITIAL: &str = "Initial password 123!";
const PERMANENT: &str = "Permanent password 456!";
const RESET_TEMPORARY: &str = "Reset temporary password 789!";

fn password_account_digest(state: &AppState, tenant: &str, email: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(&state.server_secret)
        .expect("HMAC accepts the configured server secret");
    mac.update(b"password-account\0");
    mac.update(tenant.as_bytes());
    mac.update(b"\0");
    mac.update(email.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn password_account_key(state: &AppState, tenant: &str, email: &str) -> String {
    format!(
        "pwd:account:{tenant}:{}",
        password_account_digest(state, tenant, email)
    )
}

fn password_fallback_user_id(state: &AppState, tenant: &str, email: &str) -> String {
    format!(
        "user:invalid:{}",
        password_account_digest(state, tenant, email)
    )
}

async fn assert_no_password_login_session(state: &AppState, tenant: &str, email: &str) {
    let now = agent_auth_http::token::current_unix_secs_pub();
    for user_id in [
        format!("user:{email}"),
        password_fallback_user_id(state, tenant, email),
    ] {
        assert_eq!(
            state
                .sessions
                .count_by_user(tenant, &user_id, now)
                .await
                .unwrap(),
            0,
            "{email} failure must not leave a session for {user_id}"
        );
    }
}

fn assert_positive_retry_after(response: &axum::response::Response) {
    assert!(
        response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|seconds| seconds >= 1),
        "throttling must advertise a positive Retry-After"
    );
}

async fn prefill_account_failure_budget(state: &AppState, tenant: &str, email: &str, count: usize) {
    let store = state.rate_limit.as_ref().expect("rate-limit store");
    let future_now = agent_auth_http::token::current_unix_secs_pub() + 3600;
    for _ in 0..count {
        assert!(
            store
                .try_consume(
                    &password_account_key(state, tenant, email),
                    future_now,
                    5.0,
                    1.0 / 60.0,
                    1.0,
                )
                .await
                .unwrap()
                .allowed
        );
    }
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn cookie(response: &axum::response::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| {
            value
                .strip_prefix(&format!("{name}="))
                .map(|rest| rest.split(';').next().unwrap_or("").to_string())
        })
}

async fn admin_create(
    router: &axum::Router,
    email: &str,
    password: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users")
                .header("host", HOST)
                .header("authorization", format!("Bearer {ADMIN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "email": email,
                        "initial_password": password,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn admin_reset(
    router: &axum::Router,
    user_id: &str,
    temporary_password: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/users/{user_id}/reset-password"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {ADMIN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "temporary_password": temporary_password }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn password_request(
    router: &axum::Router,
    path: &str,
    body: Value,
    xff: Option<&str>,
    trusted_source_ip: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("host", HOST)
        .header("content-type", "application/json");
    if let Some(xff) = xff {
        builder = builder.header("x-forwarded-for", xff);
    }
    let mut request = builder.body(Body::from(body.to_string())).unwrap();
    if let Some(source_ip) = trusted_source_ip {
        request
            .extensions_mut()
            .insert(agent_auth_http::mtls::TrustedSourceIp(
                source_ip.to_string(),
            ));
    }
    router.clone().oneshot(request).await.unwrap()
}

async fn password_request_with_exact_body(
    router: &axum::Router,
    host: &str,
    path: &str,
    body: String,
    trusted_source_ip: Option<&str>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header("host", host)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    if let Some(source_ip) = trusted_source_ip {
        request
            .extensions_mut()
            .insert(agent_auth_http::mtls::TrustedSourceIp(
                source_ip.to_string(),
            ));
    }
    router.clone().oneshot(request).await.unwrap()
}

fn password_json_with_exact_len(fields: &[(&str, &str)], len: usize) -> String {
    let mut object = serde_json::Map::new();
    for (name, value) in fields {
        object.insert((*name).to_string(), Value::String((*value).to_string()));
    }
    object.insert("padding".to_string(), Value::String(String::new()));
    let base = Value::Object(object.clone()).to_string();
    let padding = len
        .checked_sub(base.len())
        .unwrap_or_else(|| panic!("base password request is larger than {len} bytes"));
    object.insert("padding".to_string(), Value::String("x".repeat(padding)));
    let body = Value::Object(object).to_string();
    assert_eq!(body.len(), len);
    body
}

async fn login(router: &axum::Router, email: &str, password: &str) -> axum::response::Response {
    password_request(
        router,
        "/login/password",
        serde_json::json!({ "email": email, "password": password }),
        None,
        None,
    )
    .await
}

async fn change(
    router: &axum::Router,
    email: &str,
    current: &str,
    new_password: &str,
) -> axum::response::Response {
    password_request(
        router,
        "/login/password/change",
        serde_json::json!({
            "email": email,
            "current_password": current,
            "new_password": new_password,
        }),
        None,
        None,
    )
    .await
}

#[tokio::test]
async fn admin_create_first_login_change_and_active_login() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());
    let email = "alice@example.com";
    let user_id = "user:alice@example.com";

    let created = admin_create(&router, email, INITIAL).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created_body = body_json(created).await;
    assert!(!created_body.to_string().contains(INITIAL));
    assert!(!created_body.to_string().contains("argon2"));

    // A lost 201 response can be retried with the same temporary password.
    assert_eq!(
        admin_create(&router, email, INITIAL).await.status(),
        StatusCode::CREATED
    );
    assert_eq!(
        admin_create(&router, email, "Different initial password!")
            .await
            .status(),
        StatusCode::CONFLICT
    );

    let detail = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/admin/users/{user_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {ADMIN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let detail_body = body_json(detail).await;
    assert_eq!(detail_body["password_status"], "change_required");
    assert!(!detail_body.to_string().contains("password_hash"));
    assert!(!detail_body.to_string().contains("argon2"));

    let temporary = login(&router, email, INITIAL).await;
    assert_eq!(temporary.status(), StatusCode::OK);
    assert!(cookie(&temporary, "__Host-agent_auth_session").is_none());
    assert_eq!(
        body_json(temporary).await,
        serde_json::json!({
            "authenticated": false,
            "password_change_required": true,
        })
    );
    assert_eq!(
        state
            .users
            .get_by_id("", user_id)
            .await
            .unwrap()
            .unwrap()
            .last_login_at,
        None,
        "change-required 不是成功登录,不得记录最后登录时间"
    );

    let same = change(&router, email, INITIAL, INITIAL).await;
    assert_eq!(same.status(), StatusCode::BAD_REQUEST);
    assert!(cookie(&same, "__Host-agent_auth_session").is_none());
    assert!(state
        .sessions
        .list_by_user("", user_id, agent_auth_http::token::current_unix_secs_pub(),)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        state
            .users
            .get_by_id("", user_id)
            .await
            .unwrap()
            .unwrap()
            .last_login_at,
        None,
        "改密失败未建立会话,不得记录最后登录时间"
    );

    let weak = change(&router, email, INITIAL, "too short").await;
    assert_eq!(weak.status(), StatusCode::BAD_REQUEST);
    assert!(cookie(&weak, "__Host-agent_auth_session").is_none());
    let pending = state.passwords.get("", user_id).await.unwrap().unwrap();
    assert!(pending.must_change);
    assert_eq!(pending.version, 1);
    assert!(state
        .sessions
        .list_by_user("", user_id, agent_auth_http::token::current_unix_secs_pub(),)
        .await
        .unwrap()
        .is_empty());

    let changed = change(&router, email, INITIAL, PERMANENT).await;
    assert_eq!(changed.status(), StatusCode::OK);
    let changed_session_id =
        cookie(&changed, "__Host-agent_auth_session").expect("password session cookie");
    let changed_session = state
        .sessions
        .get("", &changed_session_id)
        .await
        .unwrap()
        .expect("password session record");
    assert_eq!(changed_session.amr, vec!["pwd"]);
    let credential = state.passwords.get("", user_id).await.unwrap().unwrap();
    assert!(!credential.must_change);
    assert_eq!(credential.version, 2);
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 500)
        .await
        .unwrap();
    assert!(events.iter().any(|stored| {
        stored.event.action == "credential.password.set"
            && stored.event.outcome == SecurityEventOutcome::Success
            && serde_json::to_value(&stored.event.subject).unwrap()["id"] == user_id
    }));
    assert!(
        state
            .users
            .get_by_id("", user_id)
            .await
            .unwrap()
            .unwrap()
            .last_login_at
            .is_some(),
        "密码改密成功并建立会话后应记录最后登录时间"
    );

    let old = login(&router, email, INITIAL).await;
    assert_eq!(old.status(), StatusCode::UNAUTHORIZED);
    let active = login(&router, email, PERMANENT).await;
    assert_eq!(active.status(), StatusCode::OK);
    assert!(cookie(&active, "__Host-agent_auth_session").is_some());
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 500)
        .await
        .unwrap();
    assert!(events.iter().any(|stored| {
        stored.event.action == "authentication.password"
            && stored.event.outcome == SecurityEventOutcome::Success
    }));
    assert!(events.iter().any(|stored| {
        stored.event.action == "authentication.password"
            && stored.event.outcome == SecurityEventOutcome::Denied
    }));
}

#[tokio::test]
async fn password_login_follows_a_scim_moved_email_alias() {
    let state = AppState::dev(HOST);
    let (users, passwords) = match (state.users.as_ref(), state.passwords.as_ref()) {
        (
            agent_auth_http::state::UsersStoreImpl::Memory(users),
            agent_auth_http::state::PasswordStoreImpl::Memory(passwords),
        ) => (users, passwords),
        #[allow(unreachable_patterns)]
        _ => panic!("dev state must use memory user and password stores"),
    };
    let (router, _) = build_router(state.clone());
    let old_email = "password-old@example.com";
    let new_email = "password-new@example.com";
    let user_id = format!("user:{old_email}");

    assert_eq!(
        admin_create(&router, old_email, INITIAL).await.status(),
        StatusCode::CREATED
    );
    assert_eq!(
        change(&router, old_email, INITIAL, PERMANENT)
            .await
            .status(),
        StatusCode::OK
    );
    assert!(matches!(
        state
            .users
            .create_scim(
                "",
                ScimUserInput {
                    user_id: "unused-random-id".to_string(),
                    external_id: "password-directory-id".to_string(),
                    user_name: old_email.to_string(),
                    display_name: None,
                    active: true,
                    now: 2,
                },
            )
            .await
            .unwrap(),
        ScimCreateOutcome::Created(record) if record.user_id == user_id
    ));
    assert!(matches!(
        state
            .users
            .replace_scim(
                "",
                &user_id,
                agent_auth_http::ports::ScimReplaceInput {
                    external_id: "password-directory-id".to_string(),
                    user_name: new_email.to_string(),
                    display_name: None,
                    active: true,
                    now: 3,
                },
            )
            .await
            .unwrap(),
        ScimReplaceOutcome::Updated(record) if record.user_id == user_id
    ));

    let miss_user_reads = users.get_by_email_calls();
    let miss_password_reads = passwords.get_requests().await.len();
    assert_eq!(
        login(&router, old_email, PERMANENT).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(users.get_by_email_calls(), miss_user_reads + 1);
    assert_eq!(
        &passwords.get_requests().await[miss_password_reads..],
        &[(
            "".to_string(),
            password_fallback_user_id(&state, "", old_email)
        )],
        "an ordinary alias miss must perform one fallback credential read"
    );

    let hit_user_reads = users.get_by_email_calls();
    let hit_password_reads = passwords.get_requests().await.len();
    let renamed = login(&router, new_email, PERMANENT).await;
    assert_eq!(renamed.status(), StatusCode::OK);
    assert!(cookie(&renamed, "__Host-agent_auth_session").is_some());
    assert_eq!(users.get_by_email_calls(), hit_user_reads + 1);
    let hit_requests = passwords.get_requests().await;
    let hit_requests = &hit_requests[hit_password_reads..];
    assert!(
        !hit_requests.is_empty()
            && hit_requests
                .iter()
                .all(|request| request == &("".to_string(), user_id.clone())),
        "the fixed pre-Argon2 read and any later session-authority recheck must use the canonical user id"
    );

    assert_eq!(
        admin_create(&router, new_email, INITIAL).await.status(),
        StatusCode::CONFLICT
    );
    assert!(state
        .passwords
        .get("", &format!("user:{new_email}"))
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        admin_reset(&router, &user_id, RESET_TEMPORARY)
            .await
            .status(),
        StatusCode::OK
    );
    let reset_login = login(&router, new_email, RESET_TEMPORARY).await;
    assert_eq!(reset_login.status(), StatusCode::OK);
    assert_eq!(
        body_json(reset_login).await["password_change_required"],
        true
    );
}

#[tokio::test]
async fn random_scim_canonical_id_obeys_password_version_fencing() {
    let state = AppState::dev(HOST);
    let email = "random-scim-password@example.com";
    let user_id = "user:scim:random-password-canonical-id";
    assert!(matches!(
        state
            .users
            .create_scim(
                "",
                ScimUserInput {
                    user_id: user_id.to_string(),
                    external_id: "random-scim-password-external".to_string(),
                    user_name: email.to_string(),
                    display_name: None,
                    active: true,
                    now: 1,
                },
            )
            .await
            .unwrap(),
        ScimCreateOutcome::Created(record) if record.user_id == user_id
    ));
    let (router, _) = build_router(state.clone());

    assert_eq!(
        admin_create(&router, email, INITIAL).await.status(),
        StatusCode::CREATED
    );
    let changed = change(&router, email, INITIAL, PERMANENT).await;
    assert_eq!(changed.status(), StatusCode::OK);
    let session_id = cookie(&changed, "__Host-agent_auth_session").unwrap();
    let approved_version =
        agent_auth_http::user_gate::password_authority_snapshot(&state, "", user_id)
            .await
            .unwrap();
    assert_eq!(approved_version, Some(2));

    assert_eq!(
        admin_reset(&router, user_id, RESET_TEMPORARY)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        agent_auth_http::user_gate::require_password_authority_version(
            &state,
            "",
            user_id,
            approved_version,
        )
        .await,
        agent_auth_http::user_gate::PasswordGate::ChangeRequired
    );
    assert!(
        state.sessions.get("", &session_id).await.unwrap().is_none(),
        "password reset must revoke the SCIM user's existing session"
    );
}

#[tokio::test]
async fn admin_reset_replaces_password_and_revokes_authentication_state() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());
    let email = "reset@example.com";
    let user_id = "user:reset@example.com";

    assert_eq!(
        admin_create(&router, email, INITIAL).await.status(),
        StatusCode::CREATED
    );
    assert_eq!(
        change(&router, email, INITIAL, PERMANENT).await.status(),
        StatusCode::OK
    );
    let active_login = login(&router, email, PERMANENT).await;
    let session_id =
        cookie(&active_login, "__Host-agent_auth_session").expect("active password session");
    let epoch_before_reset = state
        .users
        .get_by_id("", user_id)
        .await
        .unwrap()
        .unwrap()
        .credential_epoch;
    state
        .refresh
        .create(
            "",
            RefreshFamilyRecord {
                family_id: "reset-family".to_string(),
                current_version: 0,
                revoked: false,
                client_id: "reset-client".to_string(),
                cimd_snapshot: None,
                user_id: user_id.to_string(),
                credential_epoch: 0,
                resources: vec![],
                scope: vec!["openid".to_string()],
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
        .put(
            "",
            Grant {
                grant_id: "reset-consent-grant".to_string(),
                user_id: user_id.to_string(),
                client_id: "reset-client".to_string(),
                per_resource: vec![ResourceGrant {
                    resource: "https://api.example".to_string(),
                    scopes: vec!["read".to_string()],
                    authorization_details: vec![],
                }],
                effective_per_resource: vec![],
                effective_pv: 0,
                allowed_ip_cidrs: vec![],
                allowed_vpce: vec![],
                credential_epoch: 0,
                revision: 0,
                constraints: GrantConstraints {
                    max_act_chain: 1,
                    actor_allowlist: vec![],
                    expires_at: 4_000_000_000,
                },
                status: GrantStatus::Active,
            },
        )
        .await
        .unwrap();

    let same_password = admin_reset(&router, user_id, PERMANENT).await;
    assert_eq!(same_password.status(), StatusCode::BAD_REQUEST);
    let unchanged = state.passwords.get("", user_id).await.unwrap().unwrap();
    assert!(!unchanged.must_change);
    assert_eq!(unchanged.version, 2);
    assert!(state.sessions.get("", &session_id).await.unwrap().is_some());

    let reset = admin_reset(&router, user_id, RESET_TEMPORARY).await;
    assert_eq!(reset.status(), StatusCode::OK);
    let reset_body = body_json(reset).await;
    assert!(!reset_body.to_string().contains(RESET_TEMPORARY));
    assert!(!reset_body.to_string().contains("argon2"));

    let credential = state.passwords.get("", user_id).await.unwrap().unwrap();
    assert!(credential.must_change);
    assert!(!credential.revocation_pending);
    assert_eq!(credential.version, 3);
    assert!(agent_auth_authn::password::verify_password(
        RESET_TEMPORARY,
        &credential.password_hash,
    )
    .unwrap());
    let user_after_reset = state.users.get_by_id("", user_id).await.unwrap().unwrap();
    assert_eq!(
        user_after_reset.credential_epoch,
        epoch_before_reset + 1,
        "admin reset must advance the shared authentication authority"
    );
    assert!(!user_after_reset.revocation_pending);
    assert!(state.sessions.get("", &session_id).await.unwrap().is_none());
    assert!(
        state
            .refresh
            .get("", "reset-family")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    assert_eq!(
        state
            .grants
            .get("", "reset-consent-grant")
            .await
            .unwrap()
            .unwrap()
            .status,
        GrantStatus::Active
    );

    let retry = admin_reset(&router, user_id, RESET_TEMPORARY).await;
    assert_eq!(
        retry.status(),
        StatusCode::OK,
        "an exact retry after a completed reset must be idempotent"
    );
    let retried_credential = state.passwords.get("", user_id).await.unwrap().unwrap();
    let retried_user = state.users.get_by_id("", user_id).await.unwrap().unwrap();
    assert_eq!(retried_credential.version, credential.version);
    assert_eq!(
        retried_user.credential_epoch,
        user_after_reset.credential_epoch
    );
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 500)
        .await
        .unwrap();
    assert!(events.iter().any(|stored| {
        stored.event.action == "credential.password.reset"
            && stored.event.outcome == SecurityEventOutcome::Success
            && serde_json::to_value(&stored.event.subject).unwrap()["id"] == user_id
    }));

    assert_eq!(
        login(&router, email, PERMANENT).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let temporary = login(&router, email, RESET_TEMPORARY).await;
    assert_eq!(temporary.status(), StatusCode::OK);
    assert!(cookie(&temporary, "__Host-agent_auth_session").is_none());
    assert_eq!(
        body_json(temporary).await,
        serde_json::json!({
            "authenticated": false,
            "password_change_required": true,
        })
    );
}

#[tokio::test]
async fn authorization_code_issued_before_reset_cannot_be_exchanged_after_password_change() {
    let state = AppState::dev(HOST);
    let client_id = "password-reset-code-client";
    let redirect_uri = "https://app.example.com/callback";
    state.seed_dev_client(client_id, redirect_uri, None).await;
    let (router, _) = build_router(state.clone());
    let email = "reset-code@example.com";
    let user_id = "user:reset-code@example.com";
    let verifier = "0123456789012345678901234567890123456789abc";

    assert_eq!(
        admin_create(&router, email, INITIAL).await.status(),
        StatusCode::CREATED
    );
    assert_eq!(
        change(&router, email, INITIAL, PERMANENT).await.status(),
        StatusCode::OK
    );
    let credential = state.passwords.get("", user_id).await.unwrap().unwrap();
    assert_eq!(credential.version, 2);

    for (code, password_credential_version) in [
        ("code-issued-before-reset", Some(credential.version)),
        ("legacy-code-without-password-version", None),
    ] {
        state
            .codes
            .put(
                "",
                CodeRecord {
                    code: code.to_string(),
                    client_id: client_id.to_string(),
                    cimd_snapshot: None,
                    redirect_uri: redirect_uri.to_string(),
                    code_challenge: agent_auth_client::s256_challenge(verifier),
                    resources: vec![],
                    user_id: user_id.to_string(),
                    scope: vec!["openid".to_string()],
                    expires_at: 4_000_000_000,
                    authz_session_id: None,
                    nonce: None,
                    auth_time: 1,
                    authorization_details: vec![],
                    acr: None,
                    amr: vec!["pwd".to_string()],
                    credential_epoch: (!code.starts_with("legacy")).then_some(0),
                    password_credential_version,
                },
            )
            .await
            .unwrap();
    }

    assert_eq!(
        admin_reset(&router, user_id, RESET_TEMPORARY)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        change(
            &router,
            email,
            RESET_TEMPORARY,
            "Post-reset permanent password 012!"
        )
        .await
        .status(),
        StatusCode::OK
    );

    for code in [
        "code-issued-before-reset",
        "legacy-code-without-password-version",
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header("host", HOST)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "grant_type=authorization_code&code={code}\
                         &code_verifier={verifier}&redirect_uri={redirect_uri}&client_id={client_id}"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{code}");
        assert_eq!(
            body_json(response).await["error"],
            "invalid_grant",
            "{code}"
        );
    }
}

#[tokio::test]
async fn password_reset_invalidates_preexisting_device_and_ciba_approvals() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    let client_id = "password-reset-async-client";
    state
        .seed_dev_client(client_id, "https://app.example.com/callback", None)
        .await;
    let (router, _) = build_router(state.clone());
    let email = "reset-async@example.com";
    let user_id = "user:reset-async@example.com";

    assert_eq!(
        admin_create(&router, email, INITIAL).await.status(),
        StatusCode::CREATED
    );
    assert_eq!(
        change(&router, email, INITIAL, PERMANENT).await.status(),
        StatusCode::OK
    );
    let password_version = state
        .passwords
        .get("", user_id)
        .await
        .unwrap()
        .unwrap()
        .version;
    assert_eq!(password_version, 2);

    state
        .device
        .put(
            "",
            DeviceAuthGrant {
                device_code: "pre-reset-device".to_string(),
                user_code: "RESET001".to_string(),
                client_id: client_id.to_string(),
                user_id: Some(user_id.to_string()),
                authz_session_id: None,
                scope: vec!["openid".to_string()],
                resources: vec![],
                interval: 5,
                last_poll_at: None,
                expires_at: i64::MAX,
                status: "approved".to_string(),
                consumed: false,
                password_credential_version: Some(password_version),
            },
        )
        .await
        .unwrap();
    state
        .ciba
        .put(
            "",
            CibaAuthRequest {
                auth_req_id: "pre-reset-ciba".to_string(),
                tenant: String::new(),
                client_id: client_id.to_string(),
                user_id: user_id.to_string(),
                authz_session_id: None,
                scope: vec!["openid".to_string()],
                resources: vec![],
                binding_message: None,
                interval: 5,
                last_poll_at: None,
                expires_at: i64::MAX,
                status: "approved".to_string(),
                consumed: false,
                delivery_mode: None,
                notification_endpoint: None,
                client_notification_token: None,
                password_credential_version: Some(password_version),
            },
        )
        .await
        .unwrap();

    assert_eq!(
        admin_reset(&router, user_id, RESET_TEMPORARY)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        change(
            &router,
            email,
            RESET_TEMPORARY,
            "Post-reset async password 012!"
        )
        .await
        .status(),
        StatusCode::OK
    );

    for form in [
        format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code\
             &device_code=pre-reset-device&client_id={client_id}"
        ),
        format!(
            "grant_type=urn:openid:params:grant-type:ciba\
             &auth_req_id=pre-reset-ciba&client_id={client_id}"
        ),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header("host", HOST)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(response).await["error"], "invalid_grant");
    }
}

#[tokio::test]
async fn legacy_refresh_family_without_password_version_fails_closed() {
    let state = AppState::dev(HOST);
    let client_id = "legacy-refresh-client";
    state
        .seed_dev_client(client_id, "https://app.example.com/callback", None)
        .await;
    let (router, _) = build_router(state.clone());
    let email = "legacy-refresh@example.com";
    let user_id = "user:legacy-refresh@example.com";

    assert_eq!(
        admin_create(&router, email, INITIAL).await.status(),
        StatusCode::CREATED
    );
    assert_eq!(
        change(&router, email, INITIAL, PERMANENT).await.status(),
        StatusCode::OK
    );
    state
        .refresh
        .create(
            "",
            RefreshFamilyRecord {
                family_id: "legacy-refresh-family".to_string(),
                current_version: 0,
                revoked: false,
                client_id: client_id.to_string(),
                cimd_snapshot: None,
                user_id: user_id.to_string(),
                credential_epoch: 0,
                resources: vec![],
                scope: vec!["openid".to_string()],
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

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token=legacy-refresh-family.0\
                     &client_id={client_id}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "invalid_grant");
    let family = state
        .refresh
        .get("", "legacy-refresh-family")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        family.current_version, 0,
        "rejection must happen before rotation"
    );
}

#[tokio::test]
async fn admin_reset_rejects_legacy_markerless_pending_password() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());
    let email = "pending-reset@example.com";
    let user_id = "user:pending-reset@example.com";

    assert_eq!(
        admin_create(&router, email, INITIAL).await.status(),
        StatusCode::CREATED
    );
    assert_eq!(
        change(&router, email, INITIAL, PERMANENT).await.status(),
        StatusCode::OK
    );
    let pending_version = state
        .passwords
        .reset_temporary(
            "",
            user_id,
            agent_auth_authn::password::hash_password(RESET_TEMPORARY).unwrap(),
            Some(2),
            3,
        )
        .await
        .unwrap();
    assert_eq!(pending_version, Some(3));

    assert_eq!(
        change(
            &router,
            email,
            RESET_TEMPORARY,
            "Replacement after pending reset 123!"
        )
        .await
        .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    assert_eq!(
        admin_reset(&router, user_id, RESET_TEMPORARY)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let pending = state.passwords.get("", user_id).await.unwrap().unwrap();
    assert_eq!(pending.version, 3);
    assert!(pending.must_change);
    assert!(pending.revocation_pending);
    assert!(pending.credential_change_id.is_none());
}

#[tokio::test]
async fn admin_reset_allows_disabled_local_but_rejects_missing_tombstoned_and_federated() {
    let state = AppState::dev(HOST);
    let disabled_id = "user:disabled-reset@example.com";
    state
        .users
        .create_or_get_by_email("", "disabled-reset@example.com", disabled_id, 1)
        .await
        .unwrap();
    state
        .users
        .set_status("", disabled_id, UserStatus::Disabled, 2)
        .await
        .unwrap();

    let tombstoned_id = "user:tombstoned-reset@example.com";
    state
        .users
        .create_or_get_by_email("", "tombstoned-reset@example.com", tombstoned_id, 1)
        .await
        .unwrap();
    state
        .users
        .set_status("", tombstoned_id, UserStatus::Tombstoned, 2)
        .await
        .unwrap();
    state
        .users
        .create_or_get_by_id("", "user:fed:reset-target", 1)
        .await
        .unwrap();
    let (router, _) = build_router(state.clone());

    assert_eq!(
        admin_reset(&router, disabled_id, RESET_TEMPORARY)
            .await
            .status(),
        StatusCode::OK
    );
    assert!(
        state
            .passwords
            .get("", disabled_id)
            .await
            .unwrap()
            .unwrap()
            .must_change
    );
    assert_eq!(
        login(&router, "disabled-reset@example.com", RESET_TEMPORARY)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    for (user_id, expected) in [
        ("user:missing@example.com", StatusCode::NOT_FOUND),
        (tombstoned_id, StatusCode::CONFLICT),
        ("user:fed:reset-target", StatusCode::CONFLICT),
    ] {
        assert_eq!(
            admin_reset(&router, user_id, RESET_TEMPORARY)
                .await
                .status(),
            expected,
            "{user_id}"
        );
        assert!(state.passwords.get("", user_id).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn admin_create_recovers_from_credential_first_partial_write() {
    let state = AppState::dev(HOST);
    let email = "partial@example.com";
    let user_id = "user:partial@example.com";
    state
        .passwords
        .create_if_absent(
            "",
            PasswordCredential {
                user_id: user_id.to_string(),
                password_hash: agent_auth_authn::password::hash_password(INITIAL).unwrap(),
                must_change: true,
                revocation_pending: true,
                credential_change_id: None,
                version: 1,
                updated_at: 1,
            },
        )
        .await
        .unwrap();
    let (router, _) = build_router(state.clone());

    let unknown = request_magic_link(&router, email).await;
    assert_eq!(unknown.status(), StatusCode::OK);
    assert!(state.users.get_by_id("", user_id).await.unwrap().is_none());
    assert!(state.messages.list_recent("", 10).await.unwrap().is_empty());

    assert_eq!(
        admin_create(&router, email, "Different initial password!")
            .await
            .status(),
        StatusCode::CONFLICT
    );
    assert!(state.users.get_by_id("", user_id).await.unwrap().is_none());

    assert_eq!(
        admin_create(&router, email, INITIAL).await.status(),
        StatusCode::CREATED
    );
    assert!(state.users.get_by_id("", user_id).await.unwrap().is_some());
    assert!(
        !state
            .passwords
            .get("", user_id)
            .await
            .unwrap()
            .unwrap()
            .revocation_pending,
        "a retry must finish the fail-closed initial provisioning marker"
    );
}

#[tokio::test]
async fn pending_initial_credential_stays_blocked_and_resumes_after_scim_alias_move() {
    let state = AppState::dev(HOST);
    let old_email = "pending-scim-old@example.com";
    let new_email = "pending-scim-new@example.com";
    let user_id = "user:scim:pending-password-canonical-id";
    assert!(matches!(
        state
            .users
            .create_scim(
                "",
                ScimUserInput {
                    user_id: user_id.to_string(),
                    external_id: "pending-scim-external-old".to_string(),
                    user_name: old_email.to_string(),
                    display_name: None,
                    active: true,
                    now: 1,
                },
            )
            .await
            .unwrap(),
        ScimCreateOutcome::Created(record) if record.user_id == user_id
    ));
    state
        .passwords
        .create_if_absent(
            "",
            PasswordCredential {
                user_id: user_id.to_string(),
                password_hash: agent_auth_authn::password::hash_password(INITIAL).unwrap(),
                must_change: true,
                revocation_pending: true,
                credential_change_id: None,
                version: 1,
                updated_at: 1,
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        state
            .users
            .replace_scim(
                "",
                user_id,
                ScimReplaceInput {
                    external_id: "pending-scim-external-new".to_string(),
                    user_name: new_email.to_string(),
                    display_name: None,
                    active: true,
                    now: 2,
                },
            )
            .await
            .unwrap(),
        ScimReplaceOutcome::Updated(record) if record.user_id == user_id
    ));
    let (router, _) = build_router(state.clone());

    let blocked_change = change(&router, new_email, INITIAL, PERMANENT).await;
    assert_eq!(blocked_change.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(cookie(&blocked_change, "__Host-agent_auth_session").is_none());

    assert_eq!(
        admin_create(&router, new_email, INITIAL).await.status(),
        StatusCode::CREATED
    );
    let resumed = state.passwords.get("", user_id).await.unwrap().unwrap();
    assert!(!resumed.revocation_pending);
    assert!(resumed.must_change);
    assert_eq!(resumed.version, 1);
}

#[tokio::test]
async fn admin_initial_password_revokes_existing_legacy_sessions() {
    let state = AppState::dev(HOST);
    let email = "legacy-session@example.com";
    let user_id = "user:legacy-session@example.com";
    state.seed_dev_user(email).await;
    state
        .sessions
        .create(
            "",
            SessionRecord {
                session_id: "legacy-email-session".to_string(),
                user_id: user_id.to_string(),
                credential_epoch: 0,
                auth_time: 1,
                created_at: 1,
                last_used_at: 1,
                device: "Test browser".into(),
                expires_at: agent_auth_http::token::current_unix_secs_pub() + 60,
                acr: None,
                amr: vec!["email".to_string()],
            },
        )
        .await
        .unwrap();
    let (router, _) = build_router(state.clone());

    assert_eq!(
        admin_create(&router, email, INITIAL).await.status(),
        StatusCode::CREATED
    );
    assert!(
        state
            .sessions
            .get("", "legacy-email-session")
            .await
            .unwrap()
            .is_none(),
        "adding a temporary credential must revoke legacy passwordless sessions"
    );
}

#[tokio::test]
async fn tombstoned_user_cannot_retain_a_stale_password_credential() {
    let state = AppState::dev(HOST);
    let email = "tombstone-race@example.com";
    let user_id = "user:tombstone-race@example.com";
    state
        .users
        .create_or_get_by_email("", email, user_id, 1)
        .await
        .unwrap();
    state
        .users
        .set_status("", user_id, UserStatus::Tombstoned, 2)
        .await
        .unwrap();
    state
        .passwords
        .create_if_absent(
            "",
            PasswordCredential {
                user_id: user_id.to_string(),
                password_hash: agent_auth_authn::password::hash_password(INITIAL).unwrap(),
                must_change: true,
                revocation_pending: false,
                credential_change_id: None,
                version: 1,
                updated_at: 2,
            },
        )
        .await
        .unwrap();
    let (router, _) = build_router(state.clone());

    assert_eq!(
        admin_create(&router, email, INITIAL).await.status(),
        StatusCode::CONFLICT
    );
    assert!(state.passwords.get("", user_id).await.unwrap().is_none());
}

#[tokio::test]
async fn temporary_login_does_not_advance_authz_session_but_change_does() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());
    let email = "authorize@example.com";
    admin_create(&router, email, INITIAL).await;
    let (authz_session_id, _) = agent_auth_http::authz_session::create_session(
        &state,
        "",
        "password-client",
        agent_auth_authn::authz_session::AuthzState::PendingUserAuthentication,
        agent_auth_http::token::current_unix_secs_pub(),
    )
    .await
    .unwrap();
    let authorize_query = format!("authz_session_id={authz_session_id}");

    let temporary = password_request(
        &router,
        "/login/password",
        serde_json::json!({
            "email": email,
            "password": INITIAL,
            "authorize_query": authorize_query,
        }),
        None,
        None,
    )
    .await;
    assert_eq!(temporary.status(), StatusCode::OK);
    assert!(cookie(&temporary, "__Host-agent_auth_session").is_none());
    let user_id = "user:authorize@example.com";
    let now = agent_auth_http::token::current_unix_secs_pub();
    assert!(state
        .sessions
        .list_by_user("", user_id, now)
        .await
        .unwrap()
        .is_empty());
    assert!(!state
        .codes
        .has_unexpired_by_client("", "password-client", now)
        .await
        .unwrap());
    assert!(state
        .grants
        .list_by_user("", user_id)
        .await
        .unwrap()
        .is_empty());
    let before_change = state
        .authz_sessions
        .get("", &authz_session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        before_change.state,
        agent_auth_authn::authz_session::AuthzState::PendingUserAuthentication.as_str()
    );

    let changed = password_request(
        &router,
        "/login/password/change",
        serde_json::json!({
            "email": email,
            "current_password": INITIAL,
            "new_password": PERMANENT,
            "authorize_query": format!("authz_session_id={authz_session_id}"),
        }),
        None,
        None,
    )
    .await;
    assert_eq!(changed.status(), StatusCode::OK);
    assert!(cookie(&changed, "__Host-agent_auth_session").is_some());
    let login_sessions = state
        .sessions
        .list_by_user("", user_id, agent_auth_http::token::current_unix_secs_pub())
        .await
        .unwrap();
    assert_eq!(login_sessions.len(), 1);
    assert_eq!(login_sessions[0].amr, vec!["pwd"]);
    let after_change = state
        .authz_sessions
        .get("", &authz_session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        after_change.state,
        agent_auth_authn::authz_session::AuthzState::PendingConsent.as_str()
    );
}

#[tokio::test]
async fn unknown_unconfigured_wrong_disabled_and_tombstoned_are_identical() {
    let state = AppState::dev(HOST);
    state
        .users
        .create_or_get_by_email(
            "",
            "nopassword@example.com",
            "user:nopassword@example.com",
            1,
        )
        .await
        .unwrap();
    let (router, _) = build_router(state.clone());
    admin_create(&router, "wrong@example.com", INITIAL).await;
    admin_create(&router, "disabled@example.com", INITIAL).await;
    admin_create(&router, "deleted@example.com", INITIAL).await;
    state
        .users
        .set_status("", "user:disabled@example.com", UserStatus::Disabled, 2)
        .await
        .unwrap();
    state
        .users
        .set_status("", "user:deleted@example.com", UserStatus::Tombstoned, 2)
        .await
        .unwrap();

    let cases = [
        ("unknown@example.com", "Any wrong password!"),
        ("nopassword@example.com", "Any wrong password!"),
        ("wrong@example.com", "Any wrong password!"),
        ("disabled@example.com", INITIAL),
        ("deleted@example.com", INITIAL),
    ];
    let mut expected = None;
    for (email, password) in cases {
        prefill_account_failure_budget(&state, "", email, 4).await;
        let response = login(&router, email, password).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "no-store",
            "{email}"
        );
        assert!(cookie(&response, "__Host-agent_auth_session").is_none());
        let body = body_json(response).await;
        assert_eq!(
            body,
            serde_json::json!({ "message": "invalid credentials" })
        );
        assert_no_password_login_session(&state, "", email).await;
        if let Some(expected) = &expected {
            assert_eq!(&body, expected);
        } else {
            expected = Some(body);
        }

        let throttled = login(&router, email, password).await;
        assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_positive_retry_after(&throttled);
        assert_no_password_login_session(&state, "", email).await;
    }
    assert!(
        state
            .users
            .get_by_email("", "unknown@example.com")
            .await
            .unwrap()
            .is_none(),
        "password login must not JIT-create an unknown local user"
    );
}

#[tokio::test]
async fn alias_failure_still_performs_one_fallback_credential_read() {
    let state = AppState::dev(HOST);
    let (users, passwords) = match (state.users.as_ref(), state.passwords.as_ref()) {
        (
            agent_auth_http::state::UsersStoreImpl::Memory(users),
            agent_auth_http::state::PasswordStoreImpl::Memory(passwords),
        ) => (users, passwords),
        #[allow(unreachable_patterns)]
        _ => panic!("dev state must use memory user and password stores"),
    };
    let user_reads = users.get_by_email_calls();
    let password_reads = passwords.get_requests().await.len();
    users.fail_next_get_by_email();
    let (router, _) = build_router(state.clone());
    let email = "alias-read-failure@example.com";

    let response = login(&router, email, "Any wrong password!").await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(users.get_by_email_calls(), user_reads + 1);
    assert_eq!(
        &passwords.get_requests().await[password_reads..],
        &[("".to_string(), password_fallback_user_id(&state, "", email))],
        "alias lookup failure must perform one fallback credential read"
    );
    assert_no_password_login_session(&state, "", email).await;
}

#[tokio::test]
async fn concurrent_first_change_has_one_winner() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());
    let email = "race@example.com";
    admin_create(&router, email, INITIAL).await;
    prefill_account_failure_budget(&state, "", email, 4).await;

    let first = change(&router, email, INITIAL, "First permanent password!");
    let second = change(&router, email, INITIAL, "Second permanent password!");
    let (first, second) = tokio::join!(first, second);
    assert_eq!(
        [&first, &second]
            .into_iter()
            .filter(|response| cookie(response, "__Host-agent_auth_session").is_some())
            .count(),
        1
    );
    let mut statuses = [first.status(), second.status()];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::CONFLICT]);
    let credential = state
        .passwords
        .get("", "user:race@example.com")
        .await
        .unwrap()
        .unwrap();
    assert!(!credential.must_change);
    assert_eq!(credential.version, 2);
    let sessions = state
        .sessions
        .list_by_user(
            "",
            "user:race@example.com",
            agent_auth_http::token::current_unix_secs_pub(),
        )
        .await
        .unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].amr, vec!["pwd"]);

    assert_eq!(
        login(&router, email, INITIAL).await.status(),
        StatusCode::UNAUTHORIZED,
        "the successful change and CAS loser must not consume the last failure token"
    );
    let throttled = login(&router, email, INITIAL).await;
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_positive_retry_after(&throttled);
}

#[tokio::test]
async fn rate_limit_store_errors_fail_closed_before_and_after_authentication() {
    let state = AppState::dev(HOST);
    let rate_limit = match state.rate_limit.as_deref() {
        Some(agent_auth_http::state::RateLimitStoreImpl::Memory(store)) => store,
        #[allow(unreachable_patterns)]
        _ => panic!("dev state must use the memory rate-limit store"),
    };
    let (router, _) = build_router(state.clone());
    let email = "rate-store-error@example.com";
    admin_create(&router, email, INITIAL).await;

    rate_limit.fail_next_check_available();
    let pre_auth = login(&router, email, INITIAL).await;
    assert_eq!(pre_auth.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_no_password_login_session(&state, "", email).await;

    rate_limit.fail_next_account_consume();
    let post_auth = login(&router, email, "Wrong password 123!").await;
    assert_eq!(post_auth.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_no_password_login_session(&state, "", email).await;
}

#[tokio::test]
async fn missing_rate_limit_store_fails_closed_before_login() {
    let mut state = AppState::dev(HOST);
    state.rate_limit = None;
    let (router, _) = build_router(state.clone());
    let email = "rate-store-unavailable@example.com";
    admin_create(&router, email, INITIAL).await;
    let response = login(&router, email, INITIAL).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(cookie(&response, "__Host-agent_auth_session").is_none());
    assert_eq!(
        state
            .sessions
            .count_by_user(
                "",
                &format!("user:{email}"),
                agent_auth_http::token::current_unix_secs_pub(),
            )
            .await
            .unwrap(),
        0,
        "rate-limit dependency failure must reject before creating a session"
    );
}

#[tokio::test]
async fn successful_logins_do_not_consume_the_account_failure_budget() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());
    let email = "repeat-success@example.com";
    admin_create(&router, email, INITIAL).await;

    for attempt in 1..=6 {
        let response = login(&router, email, INITIAL).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "change-required authentication attempt {attempt} exhausted the account failure budget"
        );
        assert!(cookie(&response, "__Host-agent_auth_session").is_none());
        assert_eq!(
            body_json(response).await,
            serde_json::json!({
                "authenticated": false,
                "password_change_required": true,
            })
        );
    }
    assert_eq!(
        change(&router, email, INITIAL, PERMANENT).await.status(),
        StatusCode::OK
    );

    for attempt in 1..=6 {
        let response = login(&router, email, PERMANENT).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "successful login attempt {attempt} exhausted the account failure budget"
        );
        assert!(cookie(&response, "__Host-agent_auth_session").is_some());
    }
}

#[tokio::test]
async fn failed_logins_still_exhaust_the_account_failure_budget() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state);
    let email = "repeat-failure@example.com";
    admin_create(&router, email, INITIAL).await;

    for attempt in 1..=5 {
        assert_eq!(
            login(&router, email, "Wrong password 123!").await.status(),
            StatusCode::UNAUTHORIZED,
            "failed login attempt {attempt} should remain within the account budget"
        );
    }
    let throttled = login(&router, email, "Wrong password 123!").await;
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_positive_retry_after(&throttled);
}

#[tokio::test]
async fn password_change_parameter_failures_do_not_consume_the_account_failure_budget() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());
    let email = "change-parameter-budget@example.com";
    admin_create(&router, email, INITIAL).await;
    prefill_account_failure_budget(&state, "", email, 4).await;

    assert_eq!(
        change(&router, email, INITIAL, INITIAL).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        change(&router, email, INITIAL, "too short").await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_no_password_login_session(&state, "", email).await;

    assert_eq!(
        login(&router, email, "Wrong password 123!").await.status(),
        StatusCode::UNAUTHORIZED,
        "parameter failures after valid authentication must leave the last failure token"
    );
    let throttled = login(&router, email, "Wrong password 123!").await;
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_positive_retry_after(&throttled);
}

#[tokio::test]
async fn session_persistence_failure_does_not_consume_the_account_failure_budget() {
    let state = AppState::dev(HOST);
    let sessions = match state.sessions.as_ref() {
        agent_auth_http::state::SessionStoreImpl::Memory(store) => store,
        #[allow(unreachable_patterns)]
        _ => panic!("dev state must use the memory session store"),
    };
    let (router, _) = build_router(state.clone());
    let email = "session-failure-budget@example.com";
    let user_id = format!("user:{email}");
    admin_create(&router, email, INITIAL).await;
    assert_eq!(
        change(&router, email, INITIAL, PERMANENT).await.status(),
        StatusCode::OK
    );
    state.sessions.delete_by_user("", &user_id).await.unwrap();
    prefill_account_failure_budget(&state, "", email, 4).await;

    sessions.fail_next_create();
    let unavailable = login(&router, email, PERMANENT).await;
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_no_password_login_session(&state, "", email).await;

    assert_eq!(
        login(&router, email, INITIAL).await.status(),
        StatusCode::UNAUTHORIZED,
        "session persistence failure after valid authentication must leave the last failure token"
    );
    let throttled = login(&router, email, INITIAL).await;
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_positive_retry_after(&throttled);

    let change_email = "change-session-failure-budget@example.com";
    admin_create(&router, change_email, INITIAL).await;
    prefill_account_failure_budget(&state, "", change_email, 4).await;

    sessions.fail_next_create();
    let unavailable = change(&router, change_email, INITIAL, PERMANENT).await;
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_no_password_login_session(&state, "", change_email).await;

    assert_eq!(
        login(&router, change_email, INITIAL).await.status(),
        StatusCode::UNAUTHORIZED,
        "password-change session failure after CAS must leave the last failure token"
    );
    let throttled = login(&router, change_email, INITIAL).await;
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_positive_retry_after(&throttled);
}

#[tokio::test]
async fn extractor_rejections_are_never_cached() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());
    let malformed = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login/password")
                .header("host", HOST)
                .header("content-type", "application/json")
                .body(Body::from("{"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(malformed.status().is_client_error());
    assert_eq!(malformed.headers()[header::CACHE_CONTROL], "no-store");

    for (path, fields) in [
        (
            "/login/password",
            vec![
                ("email", "body-limit-login@example.com"),
                ("password", "Any wrong password!"),
            ],
        ),
        (
            "/login/password/change",
            vec![
                ("email", "body-limit-change@example.com"),
                ("current_password", "Any wrong password!"),
                ("new_password", PERMANENT),
            ],
        ),
    ] {
        let accepted = password_request_with_exact_body(
            &router,
            HOST,
            path,
            password_json_with_exact_len(&fields, 4096),
            None,
        )
        .await;
        assert_eq!(
            accepted.status(),
            StatusCode::UNAUTHORIZED,
            "{path} must accept a 4096-byte JSON request and reach authentication"
        );
        assert_eq!(accepted.headers()[header::CACHE_CONTROL], "no-store");

        let rejected = password_request_with_exact_body(
            &router,
            HOST,
            path,
            password_json_with_exact_len(&fields, 4097),
            None,
        )
        .await;
        assert_eq!(
            rejected.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "{path} must reject a 4097-byte JSON request"
        );
        assert_eq!(rejected.headers()[header::CACHE_CONTROL], "no-store");
    }
}

async fn exhaust_bucket(state: &AppState, key: &str, capacity: usize, refill_per_sec: f64) {
    let store = state.rate_limit.as_ref().expect("rate-limit store");
    let future_now = agent_auth_http::token::current_unix_secs_pub() + 3600;
    for _ in 0..capacity {
        assert!(
            store
                .try_consume(key, future_now, capacity as f64, refill_per_sec, 1.0,)
                .await
                .unwrap()
                .allowed
        );
    }
    assert!(
        !store
            .try_consume(key, future_now, capacity as f64, refill_per_sec, 1.0,)
            .await
            .unwrap()
            .allowed
    );
}

async fn leave_one_bucket_token(state: &AppState, key: &str, capacity: usize, refill_per_sec: f64) {
    let store = state.rate_limit.as_ref().expect("rate-limit store");
    let future_now = agent_auth_http::token::current_unix_secs_pub() + 3600;
    for _ in 1..capacity {
        assert!(
            store
                .try_consume(key, future_now, capacity as f64, refill_per_sec, 1.0,)
                .await
                .unwrap()
                .allowed
        );
    }
    assert!(
        store
            .check_available(key, future_now, capacity as f64, refill_per_sec, 1.0,)
            .await
            .unwrap()
            .allowed,
        "test setup must leave exactly one request available"
    );
}

async fn assert_password_change_throttled(
    router: &axum::Router,
    state: &AppState,
    email: &str,
    trusted_source_ip: Option<&str>,
) {
    let response = password_request(
        router,
        "/login/password/change",
        serde_json::json!({
            "email": email,
            "current_password": INITIAL,
            "new_password": PERMANENT,
        }),
        None,
        trusted_source_ip,
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|seconds| seconds >= 1),
        "password change throttling must advertise a positive Retry-After"
    );
    assert!(cookie(&response, "__Host-agent_auth_session").is_none());
    assert_eq!(
        state
            .sessions
            .count_by_user(
                "",
                &format!("user:{email}"),
                agent_auth_http::token::current_unix_secs_pub(),
            )
            .await
            .unwrap(),
        0,
        "a throttled password change must not create an authoritative session"
    );
}

async fn consume_last_gate_token_with_invalid_change(
    router: &axum::Router,
    email: &str,
    trusted_source_ip: Option<&str>,
) {
    let response = password_request(
        router,
        "/login/password/change",
        serde_json::json!({
            "email": email,
            "current_password": "Wrong password 123!",
            "new_password": PERMANENT,
        }),
        None,
        trusted_source_ip,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "the request consuming the last gate token must still reach authentication"
    );
}

#[tokio::test]
async fn password_change_shares_account_ip_tenant_and_global_attempt_gates() {
    let email = "change-gates@example.com";

    let account_state = AppState::dev(HOST);
    let (account_router, _) = build_router(account_state.clone());
    admin_create(&account_router, email, INITIAL).await;
    for attempt in 1..=5 {
        assert_eq!(
            login(&account_router, email, "Wrong password 123!")
                .await
                .status(),
            StatusCode::UNAUTHORIZED,
            "failed login attempt {attempt} should fill the shared account budget"
        );
    }
    let account_permits = account_state.password_workers.available_permits();
    let _account_workers = account_state
        .password_workers
        .clone()
        .acquire_many_owned(account_permits as u32)
        .await
        .unwrap();
    assert_password_change_throttled(&account_router, &account_state, email, None).await;

    let ip_state = AppState::dev(HOST);
    leave_one_bucket_token(&ip_state, "pwd:ip::203.0.113.20", 30, 0.5).await;
    let (ip_router, _) = build_router(ip_state.clone());
    admin_create(&ip_router, email, INITIAL).await;
    consume_last_gate_token_with_invalid_change(&ip_router, email, Some("203.0.113.20")).await;
    let ip_permits = ip_state.password_workers.available_permits();
    let _ip_workers = ip_state
        .password_workers
        .clone()
        .acquire_many_owned(ip_permits as u32)
        .await
        .unwrap();
    assert_password_change_throttled(&ip_router, &ip_state, email, Some("203.0.113.20")).await;

    let tenant_state = AppState::dev(HOST);
    leave_one_bucket_token(&tenant_state, "pwd:tenant:", 200, 5.0).await;
    let (tenant_router, _) = build_router(tenant_state.clone());
    admin_create(&tenant_router, email, INITIAL).await;
    consume_last_gate_token_with_invalid_change(&tenant_router, email, None).await;
    let tenant_permits = tenant_state.password_workers.available_permits();
    let _tenant_workers = tenant_state
        .password_workers
        .clone()
        .acquire_many_owned(tenant_permits as u32)
        .await
        .unwrap();
    assert_password_change_throttled(&tenant_router, &tenant_state, email, None).await;

    let global_state = AppState::dev(HOST);
    leave_one_bucket_token(&global_state, "pwd:deployment-global", 500, 10.0).await;
    let (global_router, _) = build_router(global_state.clone());
    admin_create(&global_router, email, INITIAL).await;
    consume_last_gate_token_with_invalid_change(&global_router, email, None).await;
    let global_permits = global_state.password_workers.available_permits();
    let _global_workers = global_state
        .password_workers
        .clone()
        .acquire_many_owned(global_permits as u32)
        .await
        .unwrap();
    assert_password_change_throttled(&global_router, &global_state, email, None).await;
}

#[tokio::test]
async fn forged_xff_cannot_evade_trusted_source_ip_bucket() {
    let state = AppState::dev(HOST);
    exhaust_bucket(&state, "pwd:ip::203.0.113.10", 30, 0.5).await;
    let (router, _) = build_router(state);

    let response = password_request(
        &router,
        "/login/password",
        serde_json::json!({
            "email": "xff@example.com",
            "password": "Any wrong password!",
        }),
        Some("198.51.100.99"),
        Some("203.0.113.10"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_positive_retry_after(&response);
}

#[tokio::test]
async fn tenant_rate_limit_bucket_is_isolated() {
    let mut state = AppState::dev(HOST);
    state.form = agent_auth_discovery::Form::Saas {
        zone: "aws.example.com".to_string(),
        control_host: "c.aws.example.com".to_string(),
    };
    state.saas_tenants = std::sync::Arc::new(vec!["t1".to_string(), "t2".to_string()]);
    state.tenant_partitioning = true;
    exhaust_bucket(&state, "pwd:tenant:t1", 200, 5.0).await;
    let (router, _) = build_router(state.clone());

    let t1 = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login/password")
                .header("host", "t1.aws.example.com")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "email": "unknown@example.com",
                        "password": "Any wrong password!",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(t1.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_positive_retry_after(&t1);

    let t2 = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login/password")
                .header("host", "t2.aws.example.com")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "email": "unknown@example.com",
                        "password": "Any wrong password!",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(t2.status(), StatusCode::UNAUTHORIZED);

    let trusted_ip = "203.0.113.44";
    exhaust_bucket(&state, &format!("pwd:ip:t1:{trusted_ip}"), 30, 0.5).await;

    let t1_ip = password_request_with_exact_body(
        &router,
        "t1.aws.example.com",
        "/login/password",
        serde_json::json!({
            "email": "ip-isolation-a@example.com",
            "password": "Any wrong password!",
        })
        .to_string(),
        Some(trusted_ip),
    )
    .await;
    assert_eq!(t1_ip.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_positive_retry_after(&t1_ip);

    let t2_ip = password_request_with_exact_body(
        &router,
        "t2.aws.example.com",
        "/login/password",
        serde_json::json!({
            "email": "ip-isolation-b@example.com",
            "password": "Any wrong password!",
        })
        .to_string(),
        Some(trusted_ip),
    )
    .await;
    assert_eq!(
        t2_ip.status(),
        StatusCode::UNAUTHORIZED,
        "the same trusted source IP must use an independent tenant-qualified bucket"
    );
}

#[tokio::test]
async fn deployment_global_rate_limit_bucket_is_enforced() {
    let mut state = AppState::dev(HOST);
    state.form = agent_auth_discovery::Form::Saas {
        zone: "aws.example.com".to_string(),
        control_host: "c.aws.example.com".to_string(),
    };
    state.saas_tenants = std::sync::Arc::new(vec!["t1".to_string(), "t2".to_string()]);
    state.tenant_partitioning = true;
    exhaust_bucket(&state, "pwd:deployment-global", 500, 10.0).await;
    let (router, _) = build_router(state);

    for (host, email) in [
        ("t1.aws.example.com", "global-a@example.com"),
        ("t2.aws.example.com", "global-b@example.com"),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login/password")
                    .header("host", host)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "email": email,
                            "password": "Any wrong password!",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "the deployment-global bucket must span tenants and stop random-email rotation"
        );
        assert_positive_retry_after(&response);
    }
}

#[tokio::test]
async fn password_worker_saturation_fails_without_queueing() {
    let state = AppState::dev(HOST);
    state
        .users
        .create_or_get_by_email(
            "",
            "busy-nopassword@example.com",
            "user:busy-nopassword@example.com",
            1,
        )
        .await
        .unwrap();
    let (router, _) = build_router(state.clone());
    admin_create(&router, "busy-wrong@example.com", INITIAL).await;
    admin_create(&router, "busy-disabled@example.com", INITIAL).await;
    admin_create(&router, "busy-deleted@example.com", INITIAL).await;
    state
        .users
        .set_status(
            "",
            "user:busy-disabled@example.com",
            UserStatus::Disabled,
            2,
        )
        .await
        .unwrap();
    state
        .users
        .set_status(
            "",
            "user:busy-deleted@example.com",
            UserStatus::Tombstoned,
            2,
        )
        .await
        .unwrap();

    let permits = state.password_workers.available_permits();
    assert!(permits > 0);
    let _all_workers = state
        .password_workers
        .clone()
        .acquire_many_owned(permits as u32)
        .await
        .unwrap();

    for (email, password) in [
        ("busy-unknown@example.com", "Any wrong password!"),
        ("busy-nopassword@example.com", "Any wrong password!"),
        ("busy-wrong@example.com", "Any wrong password!"),
        ("busy-disabled@example.com", INITIAL),
        ("busy-deleted@example.com", INITIAL),
    ] {
        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                login(&router, email, password),
            )
            .await
            .expect("saturated password worker gate must reject without queueing")
            .status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{email} must reach the same saturated Argon2 worker gate"
        );
        assert_no_password_login_session(&state, "", email).await;
    }
}

async fn request_magic_link(router: &axum::Router, email: &str) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login/magic-link")
                .header("host", HOST)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "email": email }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

fn magic_link_callback_shape(callback_url: &url::Url) -> (&str, Vec<String>) {
    (
        callback_url.path(),
        callback_url
            .query_pairs()
            .map(|(key, _)| key.into_owned())
            .collect(),
    )
}

#[tokio::test]
async fn magic_link_does_not_register_unknown_or_bypass_temporary_password() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());

    let unknown = request_magic_link(&router, "unknown-link@example.com").await;
    assert_eq!(unknown.status(), StatusCode::OK);
    let unknown_content_type = unknown.headers()[header::CONTENT_TYPE].clone();
    let unknown_nonce =
        cookie(&unknown, "__Host-agent_auth_login_nonce").expect("generic response nonce");
    let unknown_body = body_json(unknown).await;
    assert_eq!(unknown_body["sent"], true);
    let unknown_link = unknown_body["dev_link"]
        .as_str()
        .expect("generic response dev link");
    let unknown_callback_url = url::Url::parse(unknown_link).expect("absolute dev_link");
    let unknown_callback_shape = magic_link_callback_shape(&unknown_callback_url);
    assert_eq!(
        unknown_callback_shape,
        (
            "/login/callback",
            vec!["link_id".to_string(), "tag".to_string()]
        )
    );
    let unknown_callback = format!("?{}", unknown_callback_url.query().expect("callback query"));
    let unknown_callback_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/login/callback{unknown_callback}"))
                .header("host", HOST)
                .header(
                    "cookie",
                    format!("__Host-agent_auth_login_nonce={unknown_nonce}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        unknown_callback_response.status(),
        StatusCode::BAD_REQUEST,
        "the equal-shape development link for an unknown user must be unredeemable"
    );
    assert!(cookie(&unknown_callback_response, "__Host-agent_auth_session").is_none());
    assert!(state
        .users
        .get_by_email("", "unknown-link@example.com")
        .await
        .unwrap()
        .is_none());
    assert!(state.messages.list_recent("", 10).await.unwrap().is_empty());

    admin_create(&router, "temporary@example.com", INITIAL).await;
    let temporary = request_magic_link(&router, "temporary@example.com").await;
    assert_eq!(temporary.status(), StatusCode::OK);
    let temporary_nonce =
        cookie(&temporary, "__Host-agent_auth_login_nonce").expect("generic response nonce");
    let temporary_body = body_json(temporary).await;
    let temporary_link = temporary_body["dev_link"]
        .as_str()
        .expect("generic response dev link");
    assert!(state.messages.list_recent("", 10).await.unwrap().is_empty());
    let temporary_url = url::Url::parse(temporary_link).expect("absolute dev_link");
    let temporary_callback = format!("?{}", temporary_url.query().expect("callback query"));
    let temporary_callback_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/login/callback{temporary_callback}"))
                .header("host", HOST)
                .header(
                    "cookie",
                    format!("__Host-agent_auth_login_nonce={temporary_nonce}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        temporary_callback_response.status(),
        StatusCode::BAD_REQUEST
    );
    assert!(cookie(&temporary_callback_response, "__Host-agent_auth_session").is_none());
    assert!(state
        .sessions
        .list_by_user(
            "",
            "user:temporary@example.com",
            agent_auth_http::token::current_unix_secs_pub(),
        )
        .await
        .unwrap()
        .is_empty());

    // A pre-provisioned legacy user without a temporary credential may still
    // use magic-link; this proves the suppressed responses above were not sent.
    state
        .users
        .create_or_get_by_email(
            "",
            "active-link@example.com",
            "user:active-link@example.com",
            1,
        )
        .await
        .unwrap();
    let active = request_magic_link(&router, "active-link@example.com").await;
    assert_eq!(active.status(), StatusCode::OK);
    assert_eq!(active.headers()[header::CONTENT_TYPE], unknown_content_type);
    let active_body = body_json(active).await;
    assert_eq!(active_body["sent"], true);
    let mut unknown_keys = unknown_body
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    let mut active_keys = active_body
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    unknown_keys.sort();
    active_keys.sort();
    assert_eq!(
        unknown_keys, active_keys,
        "unknown and eligible magic-link requests must expose the same JSON shape"
    );
    let active_link = active_body["dev_link"]
        .as_str()
        .expect("eligible response dev link");
    let active_callback_url = url::Url::parse(active_link).expect("absolute dev_link");
    assert_eq!(
        magic_link_callback_shape(&active_callback_url),
        unknown_callback_shape
    );
    assert_ne!(active_link, unknown_link);
    assert_eq!(state.messages.list_recent("", 10).await.unwrap().len(), 1);

    state
        .users
        .create_or_get_by_email(
            "",
            "moved-link@example.com",
            "user:moved-link@example.com",
            1,
        )
        .await
        .unwrap();
    assert!(matches!(
        state
            .users
            .create_scim(
                "",
                ScimUserInput {
                    user_id: "unused-moved-link-id".to_string(),
                    external_id: "moved-link-directory-id".to_string(),
                    user_name: "moved-link@example.com".to_string(),
                    display_name: None,
                    active: true,
                    now: 2,
                },
            )
            .await
            .unwrap(),
        ScimCreateOutcome::Created(_)
    ));
    assert!(matches!(
        state
            .users
            .replace_scim(
                "",
                "user:moved-link@example.com",
                agent_auth_http::ports::ScimReplaceInput {
                    external_id: "moved-link-directory-id".to_string(),
                    user_name: "moved-link-new@example.com".to_string(),
                    display_name: None,
                    active: true,
                    now: 3,
                },
            )
            .await
            .unwrap(),
        ScimReplaceOutcome::Updated(_)
    ));
    let old_alias = request_magic_link(&router, "moved-link@example.com").await;
    assert_eq!(old_alias.status(), StatusCode::OK);
    assert_eq!(state.messages.list_recent("", 10).await.unwrap().len(), 1);
    let new_alias = request_magic_link(&router, "moved-link-new@example.com").await;
    assert_eq!(new_alias.status(), StatusCode::OK);
    assert_eq!(state.messages.list_recent("", 10).await.unwrap().len(), 2);
}
