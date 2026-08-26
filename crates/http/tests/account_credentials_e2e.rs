use agent_auth_authn::{
    passkey::PasskeyCredential,
    password::{hash_password, verify_password},
};
use agent_auth_http::{
    build_router,
    ports::{
        CodeRecord, CodeStore, CredentialChangeStart, PasskeyStore, PasswordCredential,
        PasswordStore, RecoveryCodeEntry, RecoveryRecord, RecoveryStore, RefreshFamilyRecord,
        RefreshStore, SessionRecord, SessionStore, UserStatus, UsersStore,
    },
    AppState,
};
use axum::{
    body::Body,
    http::{header, Request, Response, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const HOST: &str = "localhost";
const COOKIE: &str = "__Host-agent_auth_session";

fn recovery_lookup(user_id: &str) -> String {
    let digest = Sha256::digest(user_id.as_bytes());
    URL_SAFE_NO_PAD.encode(&digest[..16])
}

async fn app() -> (axum::Router, AppState) {
    let state = AppState::dev(HOST);
    let now = agent_auth_http::current_unix_secs();
    state
        .users
        .create_or_get_by_email("", "alice@example.com", "user:alice@example.com", now)
        .await
        .unwrap();
    state
        .users
        .create_or_get_by_email("", "bob@example.com", "user:bob@example.com", now)
        .await
        .unwrap();
    let observable = state.clone();
    let (router, _) = build_router(state);
    (router, observable)
}

async fn session(state: &AppState, id: &str, user_id: &str, auth_time: i64) {
    let credential_epoch = state
        .users
        .get_by_id("", user_id)
        .await
        .unwrap()
        .unwrap()
        .credential_epoch;
    state
        .sessions
        .create(
            "",
            SessionRecord {
                session_id: id.to_string(),
                user_id: user_id.to_string(),
                credential_epoch,
                auth_time,
                created_at: auth_time,
                last_used_at: auth_time,
                device: "Test browser".to_string(),
                expires_at: agent_auth_http::current_unix_secs() + 3_600,
                acr: None,
                amr: vec!["email".to_string()],
            },
        )
        .await
        .unwrap();
}

async fn request(
    router: &axum::Router,
    method: &str,
    path: &str,
    session_id: &str,
    body: Option<Value>,
) -> Response<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", HOST)
        .header(header::COOKIE, format!("{COOKIE}={session_id}"));
    let body = if let Some(body) = body {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
        Body::from(body.to_string())
    } else {
        Body::empty()
    };
    router
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap()
}

async fn json_body(response: Response<Body>) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn summary(router: &axum::Router, session_id: &str) -> (StatusCode, Value) {
    let response = request(router, "GET", "/account/credentials", session_id, None).await;
    let status = response.status();
    (status, json_body(response).await)
}

async fn password_login(router: &axum::Router, email: &str, password: &str) -> Response<Body> {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login/password")
                .header("host", HOST)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "email": email,
                        "password": password,
                        "authorize_query": ""
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn recover(router: &axum::Router, code: &str) -> Response<Body> {
    let operation_id = URL_SAFE_NO_PAD.encode(Sha256::digest(code.as_bytes()));
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/recovery/verify")
                .header("host", HOST)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "code": code, "operation_id": operation_id }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn summary_is_redacted_and_stale_authentication_cannot_mutate() {
    let (router, state) = app().await;
    let now = agent_auth_http::current_unix_secs();
    session(&state, "fresh", "user:alice@example.com", now).await;
    session(&state, "stale", "user:alice@example.com", now - 301).await;
    state
        .passkeys
        .put_new(
            "",
            PasskeyCredential {
                credential_id: "raw-webauthn-credential-id".to_string(),
                user_id: "user:alice@example.com".to_string(),
                rp_id: HOST.to_string(),
                public_key_sec1: vec![4; 65],
                sign_count: 7,
                name: "Laptop".to_string(),
                created_at: now - 10,
            },
        )
        .await
        .unwrap();

    let (status, body) = summary(&router, "fresh").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["password_status"], "not_configured");
    assert_eq!(body["passkeys"][0]["name"], "Laptop");
    assert_eq!(body["reauthenticated"], true);
    let encoded = body.to_string();
    assert!(!encoded.contains("raw-webauthn-credential-id"));
    assert!(!encoded.contains("public_key"));
    assert!(!encoded.contains("sign_count"));

    let handle = body["passkeys"][0]["id"].as_str().unwrap();
    let response = request(
        &router,
        "PATCH",
        &format!("/account/passkeys/{handle}"),
        "stale",
        Some(json!({ "name": "Renamed" })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json_body(response).await["error"],
        "reauthentication_required"
    );
    assert_eq!(
        state
            .passkeys
            .get("", "raw-webauthn-credential-id")
            .await
            .unwrap()
            .unwrap()
            .name,
        "Laptop"
    );
}

#[tokio::test]
async fn all_credential_mutations_require_recent_reauthentication() {
    let (router, state) = app().await;
    let now = agent_auth_http::current_unix_secs();
    let user_id = "user:alice@example.com";
    session(&state, "fresh-for-handle", user_id, now).await;
    session(&state, "stale-for-mutations", user_id, now - 301).await;
    state
        .passkeys
        .put_new(
            "",
            PasskeyCredential {
                credential_id: "reauth-passkey".to_string(),
                user_id: user_id.to_string(),
                rp_id: HOST.to_string(),
                public_key_sec1: vec![4; 65],
                sign_count: 0,
                name: "Original name".to_string(),
                created_at: now,
            },
        )
        .await
        .unwrap();
    let (_, body) = summary(&router, "fresh-for-handle").await;
    let handle = body["passkeys"][0]["id"].as_str().unwrap().to_string();

    for (method, path, body) in [
        (
            "PATCH",
            format!("/account/passkeys/{handle}"),
            Some(json!({ "name": "Renamed" })),
        ),
        ("DELETE", format!("/account/passkeys/{handle}"), None),
        (
            "PUT",
            "/account/password".to_string(),
            Some(json!({ "new_password": "New active password 123!" })),
        ),
        ("POST", "/recovery/generate".to_string(), None),
    ] {
        let response = request(&router, method, &path, "stale-for-mutations", body).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");
        let body = json_body(response).await;
        assert_eq!(body["error"], "reauthentication_required");
        assert_eq!(body["max_age"], 300);
        assert_eq!(body["reauthenticate_url"], "/login?next=%2Faccount");
    }

    let passkey = state
        .passkeys
        .get("", "reauth-passkey")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(passkey.name, "Original name");
    assert!(state.passwords.get("", user_id).await.unwrap().is_none());
    assert!(state
        .recovery
        .get("", &recovery_lookup(user_id))
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        summary(&router, "stale-for-mutations").await.0,
        StatusCode::OK,
        "reauthentication denial must not consume the login session"
    );
}

#[tokio::test]
async fn local_password_enrollment_rotation_and_concurrent_retry_are_fenced() {
    let (router, state) = app().await;
    let now = agent_auth_http::current_unix_secs();
    session(&state, "enroll", "user:alice@example.com", now).await;

    let first = "First active password 123!";
    let response = request(
        &router,
        "PUT",
        "/account/password",
        "enroll",
        Some(json!({ "new_password": first })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.starts_with(&format!("{COOKIE}=")) && value.contains("Max-Age=0")));
    assert_eq!(summary(&router, "enroll").await.0, StatusCode::UNAUTHORIZED);
    let credential = state
        .passwords
        .get("", "user:alice@example.com")
        .await
        .unwrap()
        .unwrap();
    assert!(!credential.must_change);
    assert_eq!(credential.version, 1);
    assert!(verify_password(first, &credential.password_hash).unwrap());

    session(&state, "rotate", "user:alice@example.com", now).await;
    let second = "Second active password 456!";
    assert_eq!(
        request(
            &router,
            "PUT",
            "/account/password",
            "rotate",
            Some(json!({ "new_password": second })),
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    let credential = state
        .passwords
        .get("", "user:alice@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(credential.version, 2);
    assert!(!verify_password(first, &credential.password_hash).unwrap());
    assert!(verify_password(second, &credential.password_hash).unwrap());

    session(&state, "concurrent", "user:alice@example.com", now).await;
    let third = "Third active password 789!";
    let (left, right) = tokio::join!(
        request(
            &router,
            "PUT",
            "/account/password",
            "concurrent",
            Some(json!({ "new_password": third })),
        ),
        request(
            &router,
            "PUT",
            "/account/password",
            "concurrent",
            Some(json!({ "new_password": third })),
        ),
    );
    let statuses = [left.status(), right.status()];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::NO_CONTENT)
            .count(),
        1
    );
    assert!(statuses.iter().all(|status| {
        matches!(
            *status,
            StatusCode::NO_CONTENT | StatusCode::UNAUTHORIZED | StatusCode::CONFLICT
        )
    }));
    let credential = state
        .passwords
        .get("", "user:alice@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(credential.version, 3);
    assert!(verify_password(third, &credential.password_hash).unwrap());

    let audit = state.credential_audit.snapshot().join("\n");
    for secret in [first, second, third, "$argon2"] {
        assert!(!audit.contains(secret));
    }
}

#[tokio::test]
async fn denied_credential_operations_are_audited_without_sensitive_values() {
    let (router, state) = app().await;
    let now = agent_auth_http::current_unix_secs();
    let user_id = "user:alice@example.com";
    session(&state, "denials", user_id, now).await;

    let weak_password = "weak-secret";
    let response = request(
        &router,
        "PUT",
        "/account/password",
        "denials",
        Some(json!({ "new_password": weak_password })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await["error"],
        "password_policy_violation"
    );

    let active_password = "Existing active password 123!";
    assert!(state
        .passwords
        .create_if_absent(
            "",
            PasswordCredential {
                user_id: user_id.to_string(),
                password_hash: hash_password(active_password).unwrap(),
                must_change: false,
                revocation_pending: false,
                credential_change_id: None,
                version: 1,
                updated_at: now,
            },
        )
        .await
        .unwrap());
    let response = request(
        &router,
        "PUT",
        "/account/password",
        "denials",
        Some(json!({ "new_password": active_password })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await["error"], "password_unchanged");

    let invalid_handle = "not-a-valid-encrypted-passkey-handle";
    let response = request(
        &router,
        "PATCH",
        &format!("/account/passkeys/{invalid_handle}"),
        "denials",
        Some(json!({ "name": "Renamed" })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let audit = state.credential_audit.snapshot().join("\n");
    assert!(audit.contains("kind=password target=self result=policy_rejected"));
    assert!(audit.contains("kind=password target=self result=unchanged"));
    assert!(audit.contains("kind=passkey target=invalid result=not_found"));
    for sensitive in [weak_password, active_password, invalid_handle, "$argon2"] {
        assert!(!audit.contains(sensitive));
    }
}

#[tokio::test]
async fn passkey_management_is_owner_scoped_and_prevents_lockout() {
    let (router, state) = app().await;
    let now = agent_auth_http::current_unix_secs();
    session(&state, "alice", "user:alice@example.com", now).await;
    session(&state, "bob", "user:bob@example.com", now).await;
    state
        .passkeys
        .put_new(
            "",
            PasskeyCredential {
                credential_id: "alice-passkey".to_string(),
                user_id: "user:alice@example.com".to_string(),
                rp_id: HOST.to_string(),
                public_key_sec1: vec![4; 65],
                sign_count: 0,
                name: "Phone".to_string(),
                created_at: now,
            },
        )
        .await
        .unwrap();
    let (_, body) = summary(&router, "alice").await;
    let handle = body["passkeys"][0]["id"].as_str().unwrap().to_string();

    assert_eq!(
        request(
            &router,
            "PATCH",
            &format!("/account/passkeys/{handle}"),
            "bob",
            Some(json!({ "name": "Stolen" })),
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(
            &router,
            "PATCH",
            &format!("/account/passkeys/{handle}"),
            "alice",
            Some(json!({ "name": "Work phone" })),
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        state
            .passkeys
            .get("", "alice-passkey")
            .await
            .unwrap()
            .unwrap()
            .name,
        "Work phone"
    );

    let response = request(
        &router,
        "DELETE",
        &format!("/account/passkeys/{handle}"),
        "alice",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(response).await["error"], "last_viable_factor");
    assert!(state
        .passkeys
        .get("", "alice-passkey")
        .await
        .unwrap()
        .is_some());

    state
        .passkeys
        .put_new(
            "",
            PasskeyCredential {
                credential_id: "alice-stale-rp-passkey".to_string(),
                user_id: "user:alice@example.com".to_string(),
                rp_id: "old.example.com".to_string(),
                public_key_sec1: vec![4; 65],
                sign_count: 0,
                name: "Old domain".to_string(),
                created_at: now - 1,
            },
        )
        .await
        .unwrap();
    let response = request(
        &router,
        "DELETE",
        &format!("/account/passkeys/{handle}"),
        "alice",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(response).await["error"], "last_viable_factor");

    state
        .recovery
        .put(
            "",
            RecoveryRecord {
                user_lookup: recovery_lookup("user:alice@example.com"),
                user_id: "user:alice@example.com".to_string(),
                activation_id: "recovery".to_string(),
                code_hashes: vec![RecoveryCodeEntry {
                    hash_b64: "not-credential-material".to_string(),
                    consumed: false,
                }],
                attempt_count: 0,
                locked_until: 0,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        request(
            &router,
            "DELETE",
            &format!("/account/passkeys/{handle}"),
            "alice",
            None,
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    assert!(state
        .passkeys
        .get("", "alice-passkey")
        .await
        .unwrap()
        .is_none());
    assert_eq!(summary(&router, "alice").await.0, StatusCode::UNAUTHORIZED);
    session(&state, "alice-after-delete", "user:alice@example.com", now).await;
    assert_eq!(
        request(
            &router,
            "PATCH",
            &format!("/account/passkeys/{handle}"),
            "alice-after-delete",
            Some(json!({ "name": "Missing" })),
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );

    let audit = state.credential_audit.snapshot().join("\n");
    assert!(audit.contains("lockout_prevented"));
    assert!(!audit.contains("alice-passkey"));
}

#[tokio::test]
async fn federated_only_identity_cannot_enroll_a_local_password() {
    let state = AppState::dev(HOST);
    let now = agent_auth_http::current_unix_secs();
    state
        .users
        .create_or_get_by_id("", "user:fed:subject", now)
        .await
        .unwrap();
    session(&state, "federated", "user:fed:subject", now).await;
    let observable = state.clone();
    let (router, _) = build_router(state);

    assert_eq!(
        request(
            &router,
            "PUT",
            "/account/password",
            "federated",
            Some(json!({ "new_password": "Federated password 123!" })),
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert!(observable
        .passwords
        .get("", "user:fed:subject")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn unknown_disabled_and_tombstoned_identities_cannot_enroll_a_password() {
    let state = AppState::dev(HOST);
    let now = agent_auth_http::current_unix_secs();
    for (email, status, session_id) in [
        ("disabled@example.com", UserStatus::Disabled, "disabled"),
        (
            "tombstoned@example.com",
            UserStatus::Tombstoned,
            "tombstoned",
        ),
    ] {
        let user_id = format!("user:{email}");
        state
            .users
            .create_or_get_by_email("", email, &user_id, now)
            .await
            .unwrap();
        assert!(state
            .users
            .set_status("", &user_id, status, now + 1)
            .await
            .unwrap());
        session(&state, session_id, &user_id, now + 2).await;
    }
    state
        .sessions
        .create(
            "",
            SessionRecord {
                session_id: "unknown".to_string(),
                user_id: "user:unknown@example.com".to_string(),
                credential_epoch: 0,
                auth_time: now,
                created_at: now,
                last_used_at: now,
                device: "Test browser".to_string(),
                expires_at: now + 3_600,
                acr: None,
                amr: vec!["email".to_string()],
            },
        )
        .await
        .unwrap();
    let observable = state.clone();
    let (router, _) = build_router(state);

    for (session_id, expected) in [
        ("unknown", StatusCode::FORBIDDEN),
        ("disabled", StatusCode::UNAUTHORIZED),
        ("tombstoned", StatusCode::UNAUTHORIZED),
    ] {
        assert_eq!(
            request(
                &router,
                "PUT",
                "/account/password",
                session_id,
                Some(json!({ "new_password": "Rejected password 123!" })),
            )
            .await
            .status(),
            expected
        );
    }
    for user_id in [
        "user:unknown@example.com",
        "user:disabled@example.com",
        "user:tombstoned@example.com",
    ] {
        assert!(observable
            .passwords
            .get("", user_id)
            .await
            .unwrap()
            .is_none());
    }
}

#[tokio::test]
async fn temporary_password_state_is_not_overwritten_by_self_service() {
    let (router, state) = app().await;
    let now = agent_auth_http::current_unix_secs();
    state
        .passwords
        .create_if_absent(
            "",
            PasswordCredential {
                user_id: "user:alice@example.com".to_string(),
                password_hash: hash_password("Temporary password 123!").unwrap(),
                must_change: true,
                revocation_pending: false,
                credential_change_id: None,
                version: 1,
                updated_at: now,
            },
        )
        .await
        .unwrap();
    session(&state, "temporary", "user:alice@example.com", now).await;

    // Session authority rejects temporary-password accounts before the
    // credential endpoint can overwrite the mandatory first-login lifecycle.
    assert_eq!(
        request(
            &router,
            "PUT",
            "/account/password",
            "temporary",
            Some(json!({ "new_password": "Bypass password 456!" })),
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(
        state
            .passwords
            .get("", "user:alice@example.com")
            .await
            .unwrap()
            .unwrap()
            .must_change
    );
}

#[tokio::test]
async fn pending_credential_fence_blocks_password_login() {
    let (router, state) = app().await;
    let now = agent_auth_http::current_unix_secs();
    let password = "Active password before fence 123!";
    assert!(state
        .passwords
        .create_if_absent(
            "",
            PasswordCredential {
                user_id: "user:alice@example.com".to_string(),
                password_hash: hash_password(password).unwrap(),
                must_change: false,
                revocation_pending: false,
                credential_change_id: None,
                version: 1,
                updated_at: now,
            },
        )
        .await
        .unwrap());
    assert_eq!(
        state
            .users
            .begin_credential_change("", "user:alice@example.com", 0, "pending-owner", now)
            .await
            .unwrap(),
        CredentialChangeStart::Started { epoch: 1 }
    );

    let response = password_login(&router, "alice@example.com", password).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .next()
        .is_none());
    assert_eq!(
        state
            .sessions
            .count_by_user("", "user:alice@example.com", now)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn last_recovery_code_and_last_passkey_removal_linearize_without_stranding_user() {
    use agent_auth_authn::recovery::{code_hash, format_code, SECRET_BYTES};

    let (router, state) = app().await;
    let now = agent_auth_http::current_unix_secs();
    let user_id = "user:alice@example.com";
    session(&state, "factor-race", user_id, now).await;
    state
        .passkeys
        .put_new(
            "",
            PasskeyCredential {
                credential_id: "factor-race-passkey".to_string(),
                user_id: user_id.to_string(),
                rp_id: HOST.to_string(),
                public_key_sec1: vec![4; 65],
                sign_count: 0,
                name: "Only passkey".to_string(),
                created_at: now,
            },
        )
        .await
        .unwrap();
    let lookup = recovery_lookup(user_id);
    let code = format_code(&lookup, &[7; SECRET_BYTES]);
    state
        .recovery
        .put(
            "",
            RecoveryRecord {
                user_lookup: lookup.clone(),
                user_id: user_id.to_string(),
                activation_id: "recovery".to_string(),
                code_hashes: vec![RecoveryCodeEntry {
                    hash_b64: URL_SAFE_NO_PAD.encode(code_hash(&state.server_secret, &code)),
                    consumed: false,
                }],
                attempt_count: 0,
                locked_until: 0,
            },
        )
        .await
        .unwrap();
    let (_, body) = summary(&router, "factor-race").await;
    let handle = body["passkeys"][0]["id"].as_str().unwrap().to_string();
    let delete_path = format!("/account/passkeys/{handle}");

    let (deletion, recovery) = tokio::join!(
        request(&router, "DELETE", &delete_path, "factor-race", None),
        recover(&router, &code),
    );
    let deletion_succeeded = deletion.status() == StatusCode::NO_CONTENT;
    let recovery_succeeded = recovery.status() == StatusCode::OK;
    let recovered_session = recovery
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| {
            value
                .strip_prefix(&format!("{COOKIE}="))
                .and_then(|value| value.split(';').next())
                .map(str::to_string)
        });

    let passkey_exists = state
        .passkeys
        .get("", "factor-race-passkey")
        .await
        .unwrap()
        .is_some();
    let code_consumed = state
        .recovery
        .get("", &lookup)
        .await
        .unwrap()
        .unwrap()
        .code_hashes[0]
        .consumed;
    let recovered_session_authoritative = match recovered_session.as_deref() {
        Some(session_id) => summary(&router, session_id).await.0 == StatusCode::OK,
        None => false,
    };
    assert!(deletion_succeeded || recovery_succeeded);
    assert!(
        passkey_exists || !code_consumed || recovered_session_authoritative,
        "if deletion linearizes before recovery consumption, recovery must return an \
         authoritative post-fence session"
    );
    assert_eq!(!passkey_exists, deletion_succeeded);
    assert_eq!(code_consumed, recovery_succeeded);
}

#[tokio::test]
async fn credential_epoch_rejects_code_and_refresh_family_that_escaped_cleanup() {
    let state = AppState::dev(HOST);
    let now = agent_auth_http::current_unix_secs();
    let client_id = "credential-epoch-client";
    let user_id = "user:epoch@example.com";
    state.seed_dev_user("epoch@example.com").await;
    state
        .seed_dev_client(client_id, "https://app.example.com/callback", None)
        .await;
    state
        .refresh
        .create(
            "",
            RefreshFamilyRecord {
                family_id: "escaped-old-family".to_string(),
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
                password_credential_version: Some(0),
            },
        )
        .await
        .unwrap();
    let verifier = "0123456789012345678901234567890123456789abc";
    state
        .codes
        .put(
            "",
            CodeRecord {
                code: "escaped-old-code".to_string(),
                client_id: client_id.to_string(),
                cimd_snapshot: None,
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_challenge: agent_auth_client::s256_challenge(verifier),
                resources: vec![],
                user_id: user_id.to_string(),
                scope: vec!["openid".to_string()],
                expires_at: now + 3_600,
                authz_session_id: None,
                nonce: None,
                auth_time: now,
                authorization_details: vec![],
                acr: None,
                amr: vec!["email".to_string()],
                credential_epoch: Some(0),
                password_credential_version: Some(0),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        state
            .users
            .begin_credential_change("", user_id, 0, "refresh-owner", now)
            .await
            .unwrap(),
        CredentialChangeStart::Started { epoch: 1 }
    );
    assert!(state
        .users
        .complete_credential_change(
            "",
            user_id,
            agent_auth_http::ports::CredentialChangeOwner {
                epoch: 1,
                operation_id: "refresh-owner",
            },
            now + 1,
        )
        .await
        .unwrap());
    assert!(
        !state
            .refresh
            .get("", "escaped-old-family")
            .await
            .unwrap()
            .unwrap()
            .revoked,
        "the test intentionally models an eventually consistent cleanup miss"
    );
    let (router, _) = build_router(state.clone());

    let code_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code=escaped-old-code\
                     &code_verifier={verifier}\
                     &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback\
                     &client_id={client_id}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(code_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(code_response).await["error"], "invalid_grant");

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token=escaped-old-family.0\
                     &client_id={client_id}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await["error"], "invalid_grant");
    assert_eq!(
        state
            .refresh
            .get("", "escaped-old-family")
            .await
            .unwrap()
            .unwrap()
            .current_version,
        0,
        "epoch rejection must happen before refresh rotation"
    );
}
