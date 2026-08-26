use agent_auth_http::ports::{ClientStore, InitialAccessTokenStore, RateLimitStore};
use agent_auth_http::state::DcrMode;
use agent_auth_http::{build_router, AppState};
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};
use tower::ServiceExt;

const HOST: &str = "auth.example.com";
const ADMIN: &str = "Bearer dev-admin-token-not-for-prod";

async fn json_body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
}

async fn admin_post(router: &axum::Router, path: &str, body: Value) -> (StatusCode, Value) {
    admin_request(router, "POST", path, body).await
}

async fn admin_request(
    router: &axum::Router,
    method: &str,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("host", HOST)
                .header("authorization", ADMIN)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (status, json_body(response).await)
}

async fn create_secret_client(router: &axum::Router) -> (String, String, u64) {
    let (status, body) = admin_post(
        router,
        "/admin/clients",
        json!({
            "redirect_uris": ["https://client.example/callback"],
            "token_endpoint_auth_method": "client_secret_basic"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    (
        body["client_id"].as_str().unwrap().to_string(),
        body["client_secret"].as_str().unwrap().to_string(),
        body["client_secret_credentials"]["version"]
            .as_u64()
            .unwrap(),
    )
}

async fn revoke_with_basic(router: &axum::Router, client_id: &str, secret: &str) -> StatusCode {
    let basic = STANDARD.encode(format!("{client_id}:{secret}"));
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/revoke")
                .header("host", HOST)
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("token=opaque"))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn auth_method_roundtrip_keeps_versions_monotonic_and_rejects_stale_snapshot() {
    let state = AppState::dev(HOST);
    let clients = state.clients.clone();
    let (router, _) = build_router(state);
    let (client_id, old_secret, version) = create_secret_client(&router).await;
    let stale_client = clients.get("", &client_id).await.unwrap().unwrap();

    let (status, disabled) = admin_request(
        &router,
        "PATCH",
        &format!("/admin/clients/{client_id}"),
        json!({
            "token_endpoint_auth_method": "none",
            "confirm_downgrade": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        disabled["client_secret_credentials"]["version"],
        version + 1
    );
    assert!(disabled["client_secret_credentials"]["current"].is_null());

    let (status, enabled) = admin_request(
        &router,
        "PATCH",
        &format!("/admin/clients/{client_id}"),
        json!({"token_endpoint_auth_method": "client_secret_basic"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(enabled["client_secret_credentials"]["version"], version + 2);
    let new_secret = enabled["client_secret"].as_str().unwrap();

    assert!(!clients
        .put_if_credential_versions("", stale_client, version, 0)
        .await
        .unwrap());
    assert_eq!(
        revoke_with_basic(&router, &client_id, &old_secret).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        revoke_with_basic(&router, &client_id, new_secret).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn client_secret_rotation_concurrent_cutover_and_revoke() {
    let state = AppState::dev(HOST);
    let audit = state.credential_audit.clone();
    let (router, _) = build_router(state);
    let (client_id, old_secret, version) = create_secret_client(&router).await;

    let (status, rotated) = admin_post(
        &router,
        &format!("/admin/clients/{client_id}/credentials/client-secret/rotate"),
        json!({
            "rotation_request_id": "rotation-1",
            "expected_version": version,
            "expires_in_seconds": 3600,
            "overlap_seconds": 300
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let new_secret = rotated["credential"].as_str().unwrap().to_string();
    let next_id = rotated["credentials"]["next"]["credential_id"]
        .as_str()
        .unwrap()
        .to_string();
    let rotated_version = rotated["credentials"]["version"].as_u64().unwrap();

    assert_eq!(
        revoke_with_basic(&router, &client_id, &old_secret).await,
        StatusCode::OK
    );
    assert_eq!(
        revoke_with_basic(&router, &client_id, &new_secret).await,
        StatusCode::OK
    );

    // Retrying rotate is idempotent and does not reveal the plaintext again.
    let (status, retry) = admin_post(
        &router,
        &format!("/admin/clients/{client_id}/credentials/client-secret/rotate"),
        json!({
            "rotation_request_id": "rotation-1",
            "expected_version": version,
            "expires_in_seconds": 3600,
            "overlap_seconds": 300
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(retry["replayed"], true);
    assert!(retry.get("credential").is_none());

    let cutover_path = format!("/admin/clients/{client_id}/credentials/client-secret/cutover");
    let cutover_body = json!({
        "credential_id": next_id,
        "expected_version": rotated_version
    });
    let first = admin_post(&router, &cutover_path, cutover_body.clone());
    let second = admin_post(&router, &cutover_path, cutover_body);
    let ((first_status, _), (second_status, _)) = tokio::join!(first, second);
    assert!([first_status, second_status]
        .iter()
        .any(|status| *status == StatusCode::OK));
    assert!([StatusCode::OK, StatusCode::CONFLICT].contains(&first_status));
    assert!([StatusCode::OK, StatusCode::CONFLICT].contains(&second_status));

    assert_eq!(
        revoke_with_basic(&router, &client_id, &old_secret).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        revoke_with_basic(&router, &client_id, &new_secret).await,
        StatusCode::OK
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/admin/clients/{client_id}"))
                .header("host", HOST)
                .header("authorization", ADMIN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let current = json_body(response).await;
    let current_id = current["client_secret_credentials"]["current"]["credential_id"]
        .as_str()
        .unwrap();
    let current_version = current["client_secret_credentials"]["version"]
        .as_u64()
        .unwrap();
    let (status, _) = admin_post(
        &router,
        &format!("/admin/clients/{client_id}/credentials/client-secret/revoke"),
        json!({
            "credential_id": current_id,
            "expected_version": current_version
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        revoke_with_basic(&router, &client_id, &new_secret).await,
        StatusCode::UNAUTHORIZED
    );
    let audit = audit.snapshot().join("\n");
    assert!(audit.contains("ADMIN_CREDENTIAL_ROTATE"));
    assert!(audit.contains("ADMIN_CREDENTIAL_CUTOVER"));
    assert!(audit.contains("ADMIN_CREDENTIAL_REVOKE"));
    assert!(!audit.contains(&old_secret));
    assert!(!audit.contains(&new_secret));
    assert!(!audit.contains("verifier"));
}

#[tokio::test]
async fn automatic_cutover_reports_next_expiry_and_never_restores_old_secret() {
    let state = AppState::dev(HOST);
    let clients = state.clients.clone();
    let (router, _) = build_router(state);
    let (client_id, old_secret, version) = create_secret_client(&router).await;
    let stale_client = clients.get("", &client_id).await.unwrap().unwrap();

    let (status, rotated) = admin_post(
        &router,
        &format!("/admin/clients/{client_id}/credentials/client-secret/rotate"),
        json!({
            "rotation_request_id": "automatic-cutover",
            "expected_version": version,
            "expires_in_seconds": 3600,
            "overlap_seconds": 300
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let next_id = rotated["credentials"]["next"]["credential_id"]
        .as_str()
        .unwrap()
        .to_string();
    let next_expires_at = rotated["credentials"]["next"]["expires_at"]
        .as_i64()
        .unwrap();
    let rotated_version = rotated["credentials"]["version"].as_u64().unwrap();
    assert!(!clients
        .put_if_credential_versions("", stale_client, version, 0,)
        .await
        .unwrap());
    assert_eq!(
        revoke_with_basic(&router, &client_id, rotated["credential"].as_str().unwrap()).await,
        StatusCode::OK
    );

    let mut client = clients.get("", &client_id).await.unwrap().unwrap();
    client.client_secret_credentials.overlap_expires_at =
        Some(agent_auth_http::current_unix_secs() - 1);
    assert!(clients
        .replace_credential_set(
            "",
            &client_id,
            agent_auth_http::credential::CredentialKind::ClientSecret,
            rotated_version,
            client.client_secret_credentials,
        )
        .await
        .unwrap());

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/admin/clients/{client_id}"))
                .header("host", HOST)
                .header("authorization", ADMIN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let view = json_body(response).await;
    assert_eq!(view["client_secret_expires_at"], next_expires_at);
    assert_eq!(
        revoke_with_basic(&router, &client_id, &old_secret).await,
        StatusCode::UNAUTHORIZED
    );

    let (status, _) = admin_post(
        &router,
        &format!("/admin/clients/{client_id}/credentials/client-secret/revoke"),
        json!({
            "credential_id": next_id,
            "expected_version": rotated_version
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        revoke_with_basic(&router, &client_id, &old_secret).await,
        StatusCode::UNAUTHORIZED
    );

    let (status, replacement) = admin_post(
        &router,
        &format!("/admin/clients/{client_id}/credentials/client-secret/rotate"),
        json!({
            "rotation_request_id": "post-cutover-replacement",
            "expected_version": rotated_version + 1,
            "expires_in_seconds": 3600,
            "overlap_seconds": 300
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(replacement["credentials"]["next"].is_null());
    assert_eq!(
        revoke_with_basic(&router, &client_id, &old_secret).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        revoke_with_basic(
            &router,
            &client_id,
            replacement["credential"].as_str().unwrap()
        )
        .await,
        StatusCode::OK
    );
}

async fn dcr_register(router: &axum::Router, token: Option<&str>) -> axum::response::Response {
    let mut request = Request::builder()
        .method("POST")
        .uri("/register")
        .header("host", HOST)
        .header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    router
        .clone()
        .oneshot(
            request
                .body(Body::from(
                    json!({"redirect_uris": ["https://client.example/callback"]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn registration_get(router: &axum::Router, client_id: &str, token: &str) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/register/{client_id}"))
                .header("host", HOST)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn registration_token_rotates_revokes_and_never_leaks_verifiers() {
    let state = AppState::dev(HOST);
    let audit = state.credential_audit.clone();
    let (router, _) = build_router(state);
    let created = dcr_register(&router, None).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = json_body(created).await;
    let client_id = created["client_id"].as_str().unwrap();
    let old_token = created["registration_access_token"].as_str().unwrap();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/admin/clients/{client_id}"))
                .header("host", HOST)
                .header("authorization", ADMIN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let view = json_body(response).await;
    let version = view["registration_token_credentials"]["version"]
        .as_u64()
        .unwrap();
    let (status, rotated) = admin_post(
        &router,
        &format!("/admin/clients/{client_id}/credentials/registration-token/rotate"),
        json!({
            "rotation_request_id": "rat-rotation-1",
            "expected_version": version,
            "expires_in_seconds": 3600,
            "overlap_seconds": 300
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let new_token = rotated["credential"].as_str().unwrap();
    assert_eq!(
        registration_get(&router, client_id, old_token).await,
        StatusCode::OK
    );
    assert_eq!(
        registration_get(&router, client_id, new_token).await,
        StatusCode::OK
    );
    assert!(!rotated.to_string().contains("verifier"));

    let (status, cutover) = admin_post(
        &router,
        &format!("/admin/clients/{client_id}/credentials/registration-token/cutover"),
        json!({
            "credential_id": rotated["credentials"]["next"]["credential_id"],
            "expected_version": rotated["credentials"]["version"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        registration_get(&router, client_id, old_token).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        registration_get(&router, client_id, new_token).await,
        StatusCode::OK
    );
    let (status, _) = admin_post(
        &router,
        &format!("/admin/clients/{client_id}/credentials/registration-token/revoke"),
        json!({
            "credential_id": cutover["credentials"]["current"]["credential_id"],
            "expected_version": cutover["credentials"]["version"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        registration_get(&router, client_id, new_token).await,
        StatusCode::UNAUTHORIZED
    );
    let audit = audit.snapshot().join("\n");
    assert!(audit.contains("ADMIN_CREDENTIAL_ROTATE"));
    assert!(audit.contains("ADMIN_CREDENTIAL_CUTOVER"));
    assert!(audit.contains("ADMIN_CREDENTIAL_REVOKE"));
    assert!(!audit.contains(old_token));
    assert!(!audit.contains(new_token));
    assert!(!audit.contains("verifier"));
}

#[tokio::test]
async fn legacy_registration_token_is_lazily_migrated_with_expiry() {
    let state = AppState::dev(HOST);
    let clients = state.clients.clone();
    let server_secret = state.server_secret.clone();
    let (router, _) = build_router(state);
    let token = "legacy-registration-token";
    let client_id = "legacy-registration-client";
    clients
        .put(
            "",
            agent_auth_http::ports::ClientRecord {
                client_id: client_id.to_string(),
                redirect_uris: vec!["https://client.example/callback".to_string()],
                token_endpoint_auth_method: "none".to_string(),
                reg_token_hash: Some(agent_auth_http::admin::reg_token_hash(
                    &server_secret,
                    token,
                )),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(
        registration_get(&router, client_id, token).await,
        StatusCode::OK
    );
    let migrated = clients.get("", client_id).await.unwrap().unwrap();
    assert!(migrated.reg_token_hash.is_none());
    let current = migrated
        .registration_token_credentials
        .current
        .as_ref()
        .unwrap();
    assert_eq!(
        current.verifier_version,
        agent_auth_http::credential::VerifierVersion::LegacyRegistrationTokenV0
    );
    assert!(current.expires_at > agent_auth_http::current_unix_secs());
    assert!(!format!("{migrated:?}").contains(token));
}

#[tokio::test]
async fn expired_client_and_registration_credentials_are_rejected() {
    let state = AppState::dev(HOST);
    let clients = state.clients.clone();
    let (router, _) = build_router(state);
    let now = agent_auth_http::current_unix_secs();

    let (client_id, client_secret, _) = create_secret_client(&router).await;
    let mut client = clients.get("", &client_id).await.unwrap().unwrap();
    let client_version = client.client_secret_credentials.version;
    client
        .client_secret_credentials
        .current
        .as_mut()
        .unwrap()
        .expires_at = now - 1;
    assert!(clients
        .replace_credential_set(
            "",
            &client_id,
            agent_auth_http::credential::CredentialKind::ClientSecret,
            client_version,
            client.client_secret_credentials,
        )
        .await
        .unwrap());
    assert_eq!(
        revoke_with_basic(&router, &client_id, &client_secret).await,
        StatusCode::UNAUTHORIZED
    );

    let created = dcr_register(&router, None).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = json_body(created).await;
    let dcr_client_id = created["client_id"].as_str().unwrap().to_string();
    let registration_token = created["registration_access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let mut client = clients.get("", &dcr_client_id).await.unwrap().unwrap();
    let registration_version = client.registration_token_credentials.version;
    client
        .registration_token_credentials
        .current
        .as_mut()
        .unwrap()
        .expires_at = now - 1;
    assert!(clients
        .replace_credential_set(
            "",
            &dcr_client_id,
            agent_auth_http::credential::CredentialKind::RegistrationAccessToken,
            registration_version,
            client.registration_token_credentials,
        )
        .await
        .unwrap());
    assert_eq!(
        registration_get(&router, &dcr_client_id, &registration_token).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn legacy_client_secret_is_lazily_migrated_without_rewriting_creation_time() {
    let state = AppState::dev(HOST);
    let clients = state.clients.clone();
    let now = agent_auth_http::current_unix_secs();
    let created_at = now - 1_000;
    let client_id = "legacy-secret-client";
    let secret = "legacy-client-secret";
    clients
        .put(
            "",
            agent_auth_http::ports::ClientRecord {
                client_id: client_id.to_string(),
                token_endpoint_auth_method: "client_secret_basic".to_string(),
                client_secret: Some(secret.to_string()),
                created_at,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (router, _) = build_router(state);

    assert_eq!(
        revoke_with_basic(&router, client_id, secret).await,
        StatusCode::OK
    );
    let migrated = clients.get("", client_id).await.unwrap().unwrap();
    assert!(migrated.client_secret.is_none());
    let current = migrated.client_secret_credentials.current.as_ref().unwrap();
    assert_eq!(current.created_at, created_at);
    assert!(current.expires_at > now);
    assert!(!format!("{migrated:?}").contains(secret));
}

#[tokio::test]
async fn metadata_update_preserves_and_migrates_legacy_client_secret() {
    let state = AppState::dev(HOST);
    let clients = state.clients.clone();
    let now = agent_auth_http::current_unix_secs();
    let created_at = now - 1_000;
    let client_id = "legacy-secret-update-client";
    let secret = "legacy-client-secret";
    clients
        .put(
            "",
            agent_auth_http::ports::ClientRecord {
                client_id: client_id.to_string(),
                redirect_uris: vec!["https://client.example/callback".into()],
                token_endpoint_auth_method: "client_secret_basic".to_string(),
                client_secret: Some(secret.to_string()),
                created_at,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (router, _) = build_router(state);

    let (status, updated) = admin_request(
        &router,
        "PATCH",
        &format!("/admin/clients/{client_id}"),
        json!({
            "redirect_uris": ["https://client.example/new-callback"],
            "confirm_downgrade": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(updated.get("client_secret").is_none());

    let migrated = clients.get("", client_id).await.unwrap().unwrap();
    assert!(migrated.client_secret.is_none());
    assert_eq!(migrated.client_secret_credentials.version, 1);
    let current = migrated.client_secret_credentials.current.as_ref().unwrap();
    assert_eq!(current.created_at, created_at);
    assert!(!format!("{migrated:?}").contains(secret));
    assert_eq!(
        revoke_with_basic(&router, client_id, secret).await,
        StatusCode::OK
    );
}

async fn create_iat(
    router: &axum::Router,
    owner: &str,
    scopes: &[&str],
    one_time: bool,
    rate_limit_per_minute: u32,
) -> Value {
    let (status, body) = admin_post(
        router,
        "/admin/initial-access-tokens",
        json!({
            "owner": owner,
            "scopes": scopes,
            "expires_in_seconds": 3600,
            "rate_limit_per_minute": rate_limit_per_minute,
            "one_time": one_time
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    body
}

#[tokio::test]
async fn initial_access_tokens_enforce_lifecycle_and_reversible_bounded_handoff() {
    let mut state = AppState::dev(HOST);
    state.dcr_mode = DcrMode::InitialAccessToken;
    let audit = state.credential_audit.clone();
    let store = state.initial_access_tokens.clone();
    let server_secret = state.server_secret.clone();
    let (router, _) = build_router(state);

    let (invalid_owner_status, _) = admin_post(
        &router,
        "/admin/initial-access-tokens",
        json!({
            "owner": "forged\nADMIN_IAT_REVOKE",
            "scopes": ["dcr:register"],
            "expires_in_seconds": 3600,
            "rate_limit_per_minute": 30,
            "one_time": false
        }),
    )
    .await;
    assert_eq!(invalid_owner_status, StatusCode::BAD_REQUEST);

    let one_time = create_iat(&router, "bootstrap-job", &["dcr:register"], true, 30).await;
    let one_time_token = one_time["token"].as_str().unwrap();
    let one_time_id = one_time["token_id"].as_str().unwrap();
    assert_eq!(one_time["owner"], "bootstrap-job");
    assert_eq!(one_time["status"], "active");
    let one_time_created_at = one_time["created_at"].as_i64().unwrap();
    let one_time_expires_at = one_time["expires_at"].as_i64().unwrap();
    assert_eq!(one_time_expires_at, one_time_created_at + 3_600);
    let persisted = store.get("", one_time_id).await.unwrap().unwrap();
    assert_eq!(persisted.credential.owner, "bootstrap-job");
    assert_eq!(persisted.credential.created_at, one_time_created_at);
    assert_eq!(persisted.credential.expires_at, one_time_expires_at);
    assert_eq!(
        persisted.credential.verifier_version,
        agent_auth_http::credential::VerifierVersion::HmacSha256V1
    );
    let one_time_secret = one_time_token.split_once('.').unwrap().1;
    assert_ne!(persisted.credential.verifier, one_time_secret);
    assert!(!serde_json::to_string(&persisted)
        .unwrap()
        .contains(one_time_secret));
    assert_eq!(
        dcr_register(&router, Some(one_time_token)).await.status(),
        StatusCode::CREATED
    );
    assert_eq!(
        dcr_register(&router, Some(one_time_token)).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let retiring = create_iat(
        &router,
        "bootstrap-rotation-old",
        &["dcr:register"],
        false,
        30,
    )
    .await;
    let rollback_candidate = create_iat(
        &router,
        "bootstrap-rotation-rollback",
        &["dcr:register"],
        false,
        30,
    )
    .await;
    let rollback_token = rollback_candidate["token"].as_str().unwrap();
    assert_eq!(retiring["owner"], "bootstrap-rotation-old");
    assert_eq!(rollback_candidate["owner"], "bootstrap-rotation-rollback");
    assert!(retiring["created_at"].as_i64().unwrap() < retiring["expires_at"].as_i64().unwrap());
    assert!(
        rollback_candidate["created_at"].as_i64().unwrap()
            < rollback_candidate["expires_at"].as_i64().unwrap()
    );
    assert_eq!(
        dcr_register(&router, Some(retiring["token"].as_str().unwrap()))
            .await
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        dcr_register(&router, Some(rollback_token)).await.status(),
        StatusCode::CREATED
    );
    let rollback_id = rollback_candidate["token_id"].as_str().unwrap();
    let (status, _) = admin_post(
        &router,
        &format!("/admin/initial-access-tokens/{rollback_id}/revoke"),
        json!({
            "credential_id": rollback_id,
            "expected_version": rollback_candidate["version"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        dcr_register(&router, Some(rollback_token)).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        dcr_register(&router, Some(retiring["token"].as_str().unwrap()))
            .await
            .status(),
        StatusCode::CREATED
    );

    let replacement = create_iat(
        &router,
        "bootstrap-rotation-new",
        &["dcr:register"],
        false,
        30,
    )
    .await;
    assert_eq!(replacement["owner"], "bootstrap-rotation-new");
    assert!(
        replacement["created_at"].as_i64().unwrap() < replacement["expires_at"].as_i64().unwrap()
    );
    let retiring_token = retiring["token"].as_str().unwrap();
    let replacement_token = replacement["token"].as_str().unwrap();
    assert_eq!(
        dcr_register(&router, Some(retiring_token)).await.status(),
        StatusCode::CREATED
    );
    assert_eq!(
        dcr_register(&router, Some(replacement_token))
            .await
            .status(),
        StatusCode::CREATED
    );
    let retiring_id = retiring["token_id"].as_str().unwrap();
    let (status, _) = admin_post(
        &router,
        &format!("/admin/initial-access-tokens/{retiring_id}/revoke"),
        json!({
            "credential_id": retiring_id,
            "expected_version": retiring["version"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        dcr_register(&router, Some(retiring_token)).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        dcr_register(&router, Some(replacement_token))
            .await
            .status(),
        StatusCode::CREATED
    );

    let wrong_scope = create_iat(&router, "wrong-scope", &["inventory:read"], false, 30).await;
    assert_eq!(
        dcr_register(&router, wrong_scope["token"].as_str())
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let limited = create_iat(&router, "limited", &["dcr:register"], false, 1).await;
    let limited_token = limited["token"].as_str().unwrap();
    assert_eq!(
        dcr_register(&router, Some(limited_token)).await.status(),
        StatusCode::CREATED
    );
    assert_eq!(
        dcr_register(&router, Some(limited_token)).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );

    let revoked = create_iat(&router, "revoked", &["dcr:register"], false, 30).await;
    let revoked_token = revoked["token"].as_str().unwrap().to_string();
    let token_id = revoked["token_id"].as_str().unwrap();
    let (status, revoked_view) = admin_post(
        &router,
        &format!("/admin/initial-access-tokens/{token_id}/revoke"),
        json!({"credential_id": token_id, "expected_version": revoked["version"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(revoked_view["version"], 2);
    let (retry_status, retry_view) = admin_post(
        &router,
        &format!("/admin/initial-access-tokens/{token_id}/revoke"),
        json!({"credential_id": token_id, "expected_version": revoked_view["version"]}),
    )
    .await;
    assert_eq!(retry_status, StatusCode::OK);
    assert_eq!(
        retry_view["version"], revoked_view["version"],
        "idempotent revoke must return the stored version without a phantom increment"
    );
    assert_eq!(
        dcr_register(&router, Some(&revoked_token)).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let now = agent_auth_http::current_unix_secs();
    let expired_id = "iat_expired";
    let expired_secret = "expired-secret";
    store
        .put_new(
            "",
            agent_auth_http::credential::InitialAccessTokenRecord {
                token_id: expired_id.to_string(),
                credential: agent_auth_http::credential::new_credential_record(
                    &server_secret,
                    agent_auth_http::credential::CredentialKind::InitialAccessToken,
                    "",
                    expired_id.to_string(),
                    "expired".to_string(),
                    expired_secret,
                    now - 100,
                    now - 1,
                    "test".to_string(),
                    None,
                ),
                scopes: vec!["dcr:register".to_string()],
                rate_limit_per_minute: 30,
                one_time: false,
                used_at: None,
                version: 1,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        dcr_register(&router, Some(&format!("{expired_id}.{expired_secret}")))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let response = router
        .oneshot(
            Request::builder()
                .uri("/admin/initial-access-tokens")
                .header("host", HOST)
                .header("authorization", ADMIN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let raw = String::from_utf8(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(!raw.contains("verifier"));
    assert!(!raw.contains(one_time_token.split_once('.').unwrap().1));
    assert!(!raw.contains(revoked_token.split_once('.').unwrap().1));
    let audit = audit.snapshot().join("\n");
    assert!(audit.contains(&format!(
        "token_id={one_time_id} owner=bootstrap-job one_time=true"
    )));
    assert!(audit.contains("ADMIN_IAT_REVOKE"));
    assert!(!audit.contains(one_time_token));
    assert!(!audit.contains(&revoked_token));
    assert!(!audit.contains("verifier"));
}

#[tokio::test]
async fn rate_limit_store_is_available_for_iat_security_gate() {
    let state = AppState::dev(HOST);
    let decision = state
        .rate_limit
        .as_ref()
        .unwrap()
        .try_consume("iat:test", 1_000, 1.0, 1.0 / 60.0, 1.0)
        .await
        .unwrap();
    assert!(decision.allowed);
}
