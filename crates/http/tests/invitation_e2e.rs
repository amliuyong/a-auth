use std::{collections::HashMap, sync::Arc, time::Duration};

use agent_auth_http::{
    admin_credentials::{
        AdminCredentialOwner, AdminCredentialRecord, AdminCredentialResolver, AdminCredentialSet,
        MemoryAdminCredentialStore,
    },
    build_router, current_unix_secs,
    ports::{MessageOutbox, PasswordStore, SessionStore, UsersStore},
    security_event::SecurityEventStore,
    AppState,
};
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use serde_json::Value;
use tower::ServiceExt;

const HOST: &str = "localhost";
const ADMIN: &str = "dev-admin-token-not-for-prod";
const PASSWORD: &str = "Initial password 123!";

fn app() -> (axum::Router, AppState) {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());
    (router, state)
}

fn saas_admin_credentials(tokens: &[(&str, &str)]) -> Arc<AdminCredentialResolver> {
    let now = current_unix_secs();
    let store = MemoryAdminCredentialStore::default();
    let platform_ref = "memory:platform";
    store.put_set(
        platform_ref,
        &AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            AdminCredentialRecord::explicit("platform-v1", ADMIN, now - 60, now - 60, now + 86_400),
        ),
        now,
    );
    let mut tenant_refs = HashMap::new();
    for (tenant, token) in tokens {
        let secret_ref = format!("memory:tenant:{tenant}");
        tenant_refs.insert((*tenant).to_string(), secret_ref.clone());
        store.put_set(
            secret_ref,
            &AdminCredentialSet::single(
                AdminCredentialOwner::tenant(*tenant),
                AdminCredentialRecord::explicit(
                    format!("{tenant}-v1"),
                    *token,
                    now - 60,
                    now - 60,
                    now + 86_400,
                ),
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

fn saas_app() -> (axum::Router, AppState) {
    let mut state = AppState::dev(HOST);
    state.form = agent_auth_discovery::Form::Saas {
        zone: "aws.example.com".to_string(),
        control_host: "c.aws.example.com".to_string(),
    };
    state.saas_tenants = Arc::new(vec!["t1".to_string(), "t2".to_string()]);
    state.tenant_partitioning = true;
    state.admin_credentials =
        saas_admin_credentials(&[("t1", "t1-admin-secret-v1"), ("t2", "t2-admin-secret-v1")]);
    let (router, _) = build_router(state.clone());
    (router, state)
}

async fn json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
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

fn assert_no_store(response: &axum::response::Response) {
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store"),
        "all invitation responses must be non-cacheable"
    );
}

fn assert_no_session_cookie(response: &axum::response::Response) {
    assert!(
        cookie(response, "__Host-agent_auth_session").is_none(),
        "a rejected invitation must not create a login cookie"
    );
}

async fn post_json(
    router: &axum::Router,
    path: &str,
    body: Value,
    admin: bool,
) -> axum::response::Response {
    post_json_as(router, path, body, HOST, admin.then_some(ADMIN)).await
}

async fn post_json_as(
    router: &axum::Router,
    path: &str,
    body: Value,
    host: &str,
    bearer: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("host", host)
        .header("content-type", "application/json");
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    router
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

async fn create_invitation(router: &axum::Router, email: &str) -> (Value, String) {
    create_invitation_as(router, email, HOST, ADMIN).await
}

async fn create_invitation_as(
    router: &axum::Router,
    email: &str,
    host: &str,
    admin_token: &str,
) -> (Value, String) {
    let response = post_json_as(
        router,
        "/admin/users",
        serde_json::json!({
            "email": email,
            "issue_invitation": true,
        }),
        host,
        Some(admin_token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_no_store(&response);
    let body = json(response).await;
    let url = body["invitation"]["invitation_url"]
        .as_str()
        .expect("show-once invitation URL");
    assert!(
        url.starts_with(&format!("https://{host}/invite#token=")),
        "invitation URL must use the authenticated browser host: {url}"
    );
    let token = url
        .split_once("#token=")
        .expect("fragment token")
        .1
        .to_string();
    assert!(
        !url.contains('?'),
        "bearer must not be in the request target"
    );
    (body, token)
}

async fn accept(router: &axum::Router, token: &str) -> axum::response::Response {
    accept_as(router, token, HOST).await
}

async fn accept_as(router: &axum::Router, token: &str, host: &str) -> axum::response::Response {
    post_json_as(
        router,
        "/login/invitation",
        serde_json::json!({ "token": token }),
        host,
        None,
    )
    .await
}

#[tokio::test]
async fn create_requires_exactly_one_bootstrap_and_preserves_password_mode() {
    let (router, state) = app();
    for body in [
        serde_json::json!({ "email": "neither@example.com" }),
        serde_json::json!({
            "email": "both@example.com",
            "initial_password": PASSWORD,
            "issue_invitation": true,
        }),
    ] {
        let response = post_json(&router, "/admin/users", body, true).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store"),
            "all create-user responses must be non-cacheable"
        );
    }

    let response = post_json(
        &router,
        "/admin/users",
        serde_json::json!({
            "email": "password@example.com",
            "initial_password": PASSWORD,
        }),
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json(response).await;
    assert!(body["invitation"].is_null());
    let credential = state
        .passwords
        .get("", "user:password@example.com")
        .await
        .unwrap()
        .expect("temporary credential");
    assert!(credential.must_change);
}

#[tokio::test]
async fn invitation_create_is_show_once_and_leaves_password_not_configured() {
    let (router, state) = app();
    let before = current_unix_secs();
    let (body, token) = create_invitation(&router, "invitee@example.com").await;
    assert_eq!(body["email"], "invitee@example.com");
    let expires_at = body["invitation"]["expires_at"]
        .as_i64()
        .expect("invitation expiry");
    let after = current_unix_secs();
    assert!(
        expires_at >= before + 86_400 && expires_at <= after + 86_400,
        "default invitation validity must be exactly 24 hours"
    );
    assert_eq!(token.split('.').count(), 2);
    let security_events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 500)
        .await
        .unwrap();
    assert!(
        !serde_json::to_string(&security_events)
            .unwrap()
            .contains(&token),
        "the show-once bearer must not enter the structured security audit"
    );
    assert!(
        state
            .messages
            .list_recent("", 100)
            .await
            .unwrap()
            .is_empty(),
        "invitation issuance must not enter the notifier or message outbox path"
    );
    assert!(state
        .passwords
        .get("", "user:invitee@example.com")
        .await
        .unwrap()
        .is_none());

    let detail = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/users/user:invitee@example.com")
                .header("host", HOST)
                .header("authorization", format!("Bearer {ADMIN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let detail = json(detail).await;
    assert_eq!(detail["password_status"], "not_configured");
    let serialized = detail.to_string();
    for forbidden in [&token, "invitation_url", "verifier_hash"] {
        assert!(
            !serialized.contains(forbidden),
            "the Admin detail endpoint must not retrieve show-once invitation material: {forbidden}"
        );
    }
}

#[tokio::test]
async fn regeneration_and_create_retry_supersede_every_previous_secret() {
    let (router, state) = app();
    let (_, first) = create_invitation(&router, "regen@example.com").await;
    let (_, second) = create_invitation(&router, "regen@example.com").await;
    assert_ne!(first, second);
    let rejected_first = accept(&router, &first).await;
    assert_eq!(rejected_first.status(), StatusCode::BAD_REQUEST);
    assert_no_store(&rejected_first);
    assert_no_session_cookie(&rejected_first);
    assert!(state
        .sessions
        .list_by_user("", "user:regen@example.com", current_unix_secs())
        .await
        .unwrap()
        .is_empty());

    let response = post_json(
        &router,
        "/admin/users/user:regen@example.com/invitation",
        Value::Null,
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_no_store(&response);
    let body = json(response).await;
    let third = body["invitation_url"]
        .as_str()
        .unwrap()
        .split_once("#token=")
        .unwrap()
        .1
        .to_string();
    let rejected_second = accept(&router, &second).await;
    assert_eq!(rejected_second.status(), StatusCode::BAD_REQUEST);
    assert_no_store(&rejected_second);
    assert_no_session_cookie(&rejected_second);
    assert!(state
        .sessions
        .list_by_user("", "user:regen@example.com", current_unix_secs())
        .await
        .unwrap()
        .is_empty());
    assert_eq!(accept(&router, &third).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn acceptance_sets_invite_session_and_replay_fails() {
    let (router, state) = app();
    let (_, continuation_token) = create_invitation(&router, "continuation@example.com").await;
    let rejected_continuation = post_json(
        &router,
        "/login/invitation",
        serde_json::json!({
            "token": continuation_token,
            "next": "https://attacker.example/callback",
        }),
        false,
    )
    .await;
    assert_eq!(
        rejected_continuation.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "caller-controlled continuations must be rejected"
    );
    assert_no_store(&rejected_continuation);
    assert_no_session_cookie(&rejected_continuation);
    assert!(state
        .sessions
        .list_by_user("", "user:continuation@example.com", current_unix_secs())
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        accept(&router, &continuation_token).await.status(),
        StatusCode::OK,
        "a rejected continuation must not consume the invitation"
    );

    let (_, token) = create_invitation(&router, "accept@example.com").await;
    let response = accept(&router, &token).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_store(&response);
    let session_id =
        cookie(&response, "__Host-agent_auth_session").expect("host-only login session");
    let body = json(response).await;
    assert_eq!(body["redirect_to"], "/account");
    let session = state
        .sessions
        .get("", &session_id)
        .await
        .unwrap()
        .expect("persisted session");
    assert_eq!(session.amr, vec!["invite"]);
    assert_eq!(session.acr, None);
    assert_eq!(session.user_id, "user:accept@example.com");
    let last_login_after_acceptance = state
        .users
        .get_by_id("", "user:accept@example.com")
        .await
        .unwrap()
        .expect("invited user")
        .last_login_at;
    assert_eq!(last_login_after_acceptance, Some(session.auth_time));
    let replay = accept(&router, &token).await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert_no_store(&replay);
    assert_no_session_cookie(&replay);
    assert_eq!(
        state
            .users
            .get_by_id("", "user:accept@example.com")
            .await
            .unwrap()
            .expect("invited user")
            .last_login_at,
        last_login_after_acceptance,
        "invitation replay 未建立新会话,不得再次推进最后登录时间"
    );
}

#[tokio::test]
async fn invitation_and_session_are_owned_by_the_exact_region_activation() {
    use agent_auth_http::region::{
        MemoryRegionControlStore, RegionControlRecord, RegionControlStoreImpl, RegionRuntime,
    };

    let control = MemoryRegionControlStore::with_record(RegionControlRecord {
        active: true,
        activation_not_before: 1,
        revision: 1,
    });
    let mut state = AppState::dev(HOST);
    state.region =
        RegionRuntime::controlled("us-east-1", RegionControlStoreImpl::Memory(control.clone()))
            .unwrap();
    let stale_state = state.clone();
    let (router, _) = build_router(state);

    let (_, stale) = create_invitation(&router, "stale-activation@example.com").await;
    control
        .set(Some(RegionControlRecord {
            active: true,
            activation_not_before: 2,
            revision: 2,
        }))
        .await;
    let rejected = accept(&router, &stale).await;
    assert_eq!(
        rejected.status(),
        StatusCode::BAD_REQUEST,
        "an invitation issued by an older activation must not revive"
    );
    assert_no_store(&rejected);
    assert_no_session_cookie(&rejected);
    assert!(stale_state
        .sessions
        .list_by_user("", "user:stale-activation@example.com", current_unix_secs())
        .await
        .unwrap()
        .is_empty());

    let (_, current) = create_invitation(&router, "current-activation@example.com").await;
    let response = accept(&router, &current).await;
    assert_eq!(response.status(), StatusCode::OK);
    let session_id =
        cookie(&response, "__Host-agent_auth_session").expect("host-only login session");
    assert!(
        session_id.starts_with("r1_us-east-1_2_"),
        "invitation sessions must carry the exact activation owner: {session_id}"
    );
}

#[tokio::test]
async fn concurrent_acceptance_has_exactly_one_winner() {
    let (router, state) = app();
    let (_, token) = create_invitation(&router, "race@example.com").await;
    let (left, right) = tokio::join!(accept(&router, &token), accept(&router, &token));
    assert_no_store(&left);
    assert_no_store(&right);
    let responses = [left, right];
    let statuses = responses.each_ref().map(|response| response.status());
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::BAD_REQUEST)
            .count(),
        1
    );
    let loser = responses
        .iter()
        .find(|response| response.status() == StatusCode::BAD_REQUEST)
        .expect("one concurrent loser");
    assert_no_session_cookie(loser);
    assert_eq!(
        state
            .sessions
            .list_by_user("", "user:race@example.com", current_unix_secs())
            .await
            .unwrap()
            .len(),
        1,
        "concurrent acceptance must persist exactly one session"
    );
}

#[tokio::test]
async fn expiry_disable_and_tombstone_fail_closed() {
    let mut state = AppState::dev(HOST);
    state.invitation_ttl_secs = -1;
    let expired_state = state.clone();
    let (expired_router, _) = build_router(state);
    let (_, expired) = create_invitation(&expired_router, "expired@example.com").await;
    let rejected = accept(&expired_router, &expired).await;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    assert_no_store(&rejected);
    assert_no_session_cookie(&rejected);
    assert!(expired_state
        .sessions
        .list_by_user("", "user:expired@example.com", current_unix_secs())
        .await
        .unwrap()
        .is_empty());

    for (email, action, method) in [
        ("disabled@example.com", "disable", "POST"),
        ("deleted@example.com", "", "DELETE"),
    ] {
        let (router, state) = app();
        let (_, token) = create_invitation(&router, email).await;
        let path = if action.is_empty() {
            format!("/admin/users/user:{email}")
        } else {
            format!("/admin/users/user:{email}/{action}")
        };
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("host", HOST)
                    .header("authorization", format!("Bearer {ADMIN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let rejected = accept(&router, &token).await;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        assert_no_store(&rejected);
        assert_no_session_cookie(&rejected);
        assert!(state
            .sessions
            .list_by_user("", &format!("user:{email}"), current_unix_secs())
            .await
            .unwrap()
            .is_empty());
    }
}

#[tokio::test]
async fn password_bootstrap_invalidates_invitation_and_federated_users_are_ineligible() {
    let (router, state) = app();
    let (_, token) = create_invitation(&router, "password-after-invite@example.com").await;
    assert_eq!(
        post_json(
            &router,
            "/admin/users",
            serde_json::json!({
                "email": "password-after-invite@example.com",
                "initial_password": PASSWORD,
            }),
            true,
        )
        .await
        .status(),
        StatusCode::CREATED
    );
    let rejected = accept(&router, &token).await;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    assert_no_store(&rejected);
    assert_no_session_cookie(&rejected);
    assert!(state
        .sessions
        .list_by_user(
            "",
            "user:password-after-invite@example.com",
            current_unix_secs()
        )
        .await
        .unwrap()
        .is_empty());

    state
        .users
        .create_or_get_by_id("", "user:fed:subject", current_unix_secs())
        .await
        .unwrap();
    let rejected = post_json(
        &router,
        "/admin/users/user:fed:subject/invitation",
        Value::Null,
        true,
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::CONFLICT);
    assert_no_store(&rejected);
    assert_no_session_cookie(&rejected);
    assert!(state
        .sessions
        .list_by_user("", "user:fed:subject", current_unix_secs())
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn invitation_acceptance_is_tenant_isolated_through_http() {
    let (router, state) = saas_app();
    let (_, t1_token) = create_invitation_as(
        &router,
        "same@example.com",
        "t1.aws.example.com",
        "t1-admin-secret-v1",
    )
    .await;
    let (_, t2_token) = create_invitation_as(
        &router,
        "same@example.com",
        "t2.aws.example.com",
        "t2-admin-secret-v1",
    )
    .await;

    let foreign = accept_as(&router, &t1_token, "t2.aws.example.com").await;
    assert_eq!(foreign.status(), StatusCode::BAD_REQUEST);
    assert_no_store(&foreign);
    assert_no_session_cookie(&foreign);
    assert!(state
        .sessions
        .list_by_user("t2", "user:same@example.com", current_unix_secs())
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        accept_as(&router, &t1_token, "t1.aws.example.com")
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        accept_as(&router, &t2_token, "t2.aws.example.com")
            .await
            .status(),
        StatusCode::OK
    );
}
