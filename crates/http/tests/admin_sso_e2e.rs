//! HTTP integration coverage for tenant Admin OIDC SSO and action-level RBAC.

use agent_auth_http::ports::{
    AdminAuthStore, AdminIdentityField, AdminOidcConfig, AdminSessionRecord, ClientStore,
    CredentialChangeOwner, PasswordStore, PlatformJwk, ScimGroupChange, ScimGroupCreateInput,
    ScimGroupMutation, ScimGroupsStore, ScimUserInput, Signer, TenantRole, UpstreamTokenSet,
    UserStatus, UsersStore,
};
use agent_auth_http::{
    build_router,
    security_event::{
        SecurityActor, SecurityEventCategory, SecurityEventOutcome, SecurityEventStore,
        SecuritySubject,
    },
    AppState,
};
use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use tower::ServiceExt;

const HOST: &str = "localhost";
const ADMIN_TOKEN: &str = "dev-admin-token-not-for-prod";
const ISSUER: &str = "https://admin-idp.example.com";
const CLIENT_ID: &str = "agent-auth-admin";
const SECRET_REF: &str = "agent-auth/admin-oidc/default";
const USER_EMAIL: &str = "admin@example.com";

struct TestResponse {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Value,
}

async fn request(
    router: &axum::Router,
    method: Method,
    host: &str,
    path: &str,
    bearer: Option<&str>,
    cookie: Option<&str>,
    body: Option<Value>,
) -> TestResponse {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", host);
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    let response = router
        .clone()
        .oneshot(
            builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(body.map_or_else(Body::empty, |value| {
                    Body::from(serde_json::to_vec(&value).unwrap())
                }))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    TestResponse {
        status,
        headers,
        body,
    }
}

fn cookie_value(response: &TestResponse, name: &str) -> Option<String> {
    response
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|line| {
            line.strip_prefix(&format!("{name}="))
                .map(|rest| rest.split(';').next().unwrap_or("").to_string())
        })
}

fn location(response: &TestResponse) -> String {
    response
        .headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn query_param(url: &str, name: &str) -> String {
    url.split(['?', '&'])
        .find_map(|part| part.strip_prefix(&format!("{name}=")))
        .unwrap_or("")
        .to_string()
}

fn query_values(url: &str, name: &str) -> Vec<String> {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .filter(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .collect()
}

async fn mint_id_token(claims: Value) -> (String, PlatformJwk) {
    let signer = agent_auth_http::adapters::memory::MemorySigner::from_seed([91u8; 32]);
    let jwk = signer.public_rsa_jwks().await.unwrap().remove(0);
    let header = json!({"alg": "RS256", "typ": "JWT", "kid": jwk.kid});
    let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let input = format!("{encoded_header}.{encoded_claims}");
    let (_, signature) = signer.sign_rs256(input.as_bytes()).await.unwrap();
    (
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)),
        PlatformJwk {
            kid: Some(jwk.kid),
            kty: Some("RSA".into()),
            n: jwk.n,
            e: jwk.e,
            alg: Some("RS256".into()),
            ..Default::default()
        },
    )
}

async fn provision_role(state: &AppState, role: TenantRole) -> String {
    provision_role_in(
        state,
        "",
        "scim-admin-user",
        "directory-admin-user",
        USER_EMAIL,
        "admin-group",
        "directory-admins",
        role,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn provision_role_in(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    external_id: &str,
    email: &str,
    group_id: &str,
    group_external_id: &str,
    role: TenantRole,
) -> String {
    let user_id = user_id.to_string();
    state
        .users
        .create_scim(
            tenant,
            ScimUserInput {
                user_id: user_id.clone(),
                external_id: external_id.into(),
                user_name: email.into(),
                display_name: Some("Admin User".into()),
                active: true,
                now: agent_auth_http::current_unix_secs(),
            },
        )
        .await
        .unwrap();
    state
        .scim_groups
        .create(
            tenant,
            ScimGroupCreateInput {
                group_id: group_id.into(),
                external_id: group_external_id.into(),
                display_name: "Directory Admins".into(),
                members: vec![user_id.clone()],
                now: agent_auth_http::current_unix_secs(),
            },
        )
        .await
        .unwrap();
    state
        .scim_groups
        .set_role_mapping(
            tenant,
            group_external_id,
            Some(role),
            agent_auth_http::current_unix_secs(),
        )
        .await
        .unwrap();
    user_id
}

async fn configure(router: &axum::Router, state: &AppState) -> TestResponse {
    state
        .secret_resolver_seed(SECRET_REF, "not-a-real-secret")
        .await;
    request(
        router,
        Method::PUT,
        HOST,
        "/admin/oidc",
        Some(ADMIN_TOKEN),
        None,
        Some(json!({
            "issuer": ISSUER,
            "client_id": CLIENT_ID,
            "client_secret_ref": SECRET_REF,
            "authorization_endpoint": format!("{ISSUER}/authorize"),
            "token_endpoint": format!("{ISSUER}/token"),
            "jwks_uri": format!("{ISSUER}/jwks"),
            "redirect_uri": "https://localhost/admin/sso/callback",
            "scopes": ["openid", "email"],
            "strong_acr_values": ["urn:example:admin:mfa"],
            "identity_claim": "email",
            "identity_field": "user_name",
            "expected_revision": 0
        })),
    )
    .await
}

async fn setup(role: TenantRole) -> (axum::Router, AppState, String) {
    let state = AppState::dev(HOST);
    let user_id = provision_role(&state, role).await;
    let (router, _) = build_router(state.clone());
    let configured = configure(&router, &state).await;
    assert_eq!(configured.status, StatusCode::OK);
    assert_eq!(configured.body["revision"], 1);
    (router, state, user_id)
}

fn saas_state() -> AppState {
    let mut state = AppState::dev(HOST);
    state.form = agent_auth_discovery::Form::Saas {
        zone: "example.com".into(),
        control_host: "control.example.com".into(),
    };
    state.saas_tenants = std::sync::Arc::new(vec!["t1".to_string(), "t2".to_string()]);
    state.tenant_partitioning = true;
    state
}

async fn provision_saas_admin(
    state: &AppState,
    tenant: &str,
    role: TenantRole,
) -> (String, String, String) {
    let user_id = format!("scim-{tenant}-admin");
    let email = format!("admin-{tenant}@example.com");
    let client_id = format!("agent-auth-admin-{tenant}");
    let secret_ref = format!("agent-auth/admin-oidc/{tenant}");
    provision_role_in(
        state,
        tenant,
        &user_id,
        &format!("directory-{tenant}-admin"),
        &email,
        &format!("{tenant}-admin-group"),
        &format!("directory-{tenant}-admins"),
        role,
    )
    .await;
    state
        .secret_resolver_seed(&secret_ref, &format!("{tenant}-client-secret"))
        .await;
    let now = agent_auth_http::current_unix_secs();
    assert!(matches!(
        state
            .admin_auth
            .put_config(
                AdminOidcConfig {
                    tenant_id: tenant.into(),
                    binding_id: format!("{tenant}-binding"),
                    issuer: ISSUER.into(),
                    client_id: client_id.clone(),
                    client_secret_ref: secret_ref.clone(),
                    authorization_endpoint: format!("{ISSUER}/authorize?tenant={tenant}"),
                    token_endpoint: format!("{ISSUER}/token"),
                    jwks_uri: format!("{ISSUER}/jwks"),
                    redirect_uri: format!("https://{tenant}.example.com/admin/sso/callback"),
                    scopes: vec!["openid".into(), "email".into()],
                    strong_acr_values: vec!["urn:example:admin:mfa".into()],
                    identity_claim: "email".into(),
                    identity_field: AdminIdentityField::UserName,
                    revision: 1,
                    updated_at: now,
                },
                0,
            )
            .await
            .unwrap(),
        agent_auth_http::ports::AdminOidcConfigPutOutcome::Stored(_)
    ));
    (user_id, email, client_id)
}

async fn start_flow(router: &axum::Router) -> (String, String, String) {
    start_flow_at(router, "/admin/sso/start").await
}

async fn start_flow_at(router: &axum::Router, path: &str) -> (String, String, String) {
    start_flow_on(router, HOST, path).await
}

async fn start_flow_on(router: &axum::Router, host: &str, path: &str) -> (String, String, String) {
    let response = request(router, Method::GET, host, path, None, None, None).await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    let location = location(&response);
    assert!(location.starts_with(ISSUER));
    (
        query_param(&location, "state"),
        query_param(&location, "nonce"),
        cookie_value(&response, "__Host-agent_auth_admin_oidc_flow").unwrap(),
    )
}

async fn complete_login(
    router: &axum::Router,
    state: &AppState,
    code: &str,
    extra_claims: Value,
) -> TestResponse {
    let (flow_state, nonce, flow_cookie) = start_flow(router).await;
    seed_login(state, code, &nonce, extra_claims).await;
    let flow_cookie_header = format!("__Host-agent_auth_admin_oidc_flow={flow_cookie}");
    request(
        router,
        Method::GET,
        HOST,
        &format!("/admin/sso/callback?code={code}&state={flow_state}"),
        None,
        Some(&flow_cookie_header),
        None,
    )
    .await
}

async fn login_session_cookie(router: &axum::Router, state: &AppState, code: &str) -> String {
    let callback = complete_login(router, state, code, json!({})).await;
    assert_eq!(callback.status, StatusCode::SEE_OTHER);
    format!(
        "__Host-agent_auth_admin_session={}",
        cookie_value(&callback, "__Host-agent_auth_admin_session").unwrap()
    )
}

async fn assert_session_status(router: &axum::Router, cookie: &str, expected: StatusCode) {
    let response = request(
        router,
        Method::GET,
        HOST,
        "/admin/session",
        None,
        Some(cookie),
        None,
    )
    .await;
    assert_eq!(response.status, expected);
}

async fn seed_login(
    state: &AppState,
    code: &str,
    nonce: &str,
    extra_claims: Value,
) -> (String, String) {
    seed_login_for(
        state,
        code,
        nonce,
        ISSUER,
        CLIENT_ID,
        USER_EMAIL,
        extra_claims,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn seed_login_for(
    state: &AppState,
    code: &str,
    nonce: &str,
    issuer: &str,
    client_id: &str,
    email: &str,
    extra_claims: Value,
) -> (String, String) {
    let now = agent_auth_http::current_unix_secs();
    let mut claims = json!({
        "iss": issuer,
        "sub": "upstream-admin-subject",
        "aud": client_id,
        "exp": now + 300,
        "iat": now,
        "auth_time": now,
        "nonce": nonce,
        "acr": "urn:example:admin:mfa",
        "email": email,
        "email_verified": true,
        "role": "owner"
    });
    claims
        .as_object_mut()
        .unwrap()
        .extend(extra_claims.as_object().cloned().unwrap_or_default());
    let (id_token, jwk) = mint_id_token(claims).await;
    let access_token = format!("upstream-access-token-{code}");
    state
        .jwks_fetcher_set(format!("{issuer}/jwks"), vec![jwk])
        .await;
    state
        .upstream_exchanger_seed(
            code,
            UpstreamTokenSet {
                id_token: id_token.clone(),
                access_token: Some(access_token.clone()),
            },
        )
        .await;
    (id_token, access_token)
}

async fn oidc_rejection_count(state: &AppState, tenant_id: &str) -> usize {
    state
        .security_events
        .list_by_tenant(tenant_id, 0, i64::MAX, 1_000)
        .await
        .unwrap()
        .iter()
        .filter(|stored| {
            stored.event.action == "authentication.admin_oidc"
                && stored.event.category == SecurityEventCategory::Authentication
                && stored.event.outcome != SecurityEventOutcome::Success
        })
        .count()
}

#[tokio::test]
async fn oidc_state_is_bound_to_the_browser_that_started_the_flow() {
    let (router, state, _) = setup(TenantRole::Owner).await;
    let updated = request(
        &router,
        Method::PUT,
        HOST,
        "/admin/oidc",
        Some(ADMIN_TOKEN),
        None,
        Some(json!({
            "issuer": ISSUER,
            "client_id": CLIENT_ID,
            "client_secret_ref": SECRET_REF,
            "authorization_endpoint": format!("{ISSUER}/authorize?policy=mfa"),
            "token_endpoint": format!("{ISSUER}/token"),
            "jwks_uri": format!("{ISSUER}/jwks"),
            "redirect_uri": "https://localhost/admin/sso/callback",
            "scopes": ["openid", "email"],
            "strong_acr_values": ["urn:example:admin:mfa"],
            "identity_claim": "email",
            "identity_field": "user_name",
            "expected_revision": 1
        })),
    )
    .await;
    assert_eq!(updated.status, StatusCode::OK);

    let started = request(
        &router,
        Method::GET,
        HOST,
        "/admin/sso/start",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(started.status, StatusCode::SEE_OTHER);
    assert_eq!(
        started.headers.get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let authorization_url = location(&started);
    for (name, expected) in [
        ("policy", "mfa"),
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", "https://localhost/admin/sso/callback"),
        ("scope", "openid email"),
        ("code_challenge_method", "S256"),
        ("prompt", "login"),
    ] {
        assert_eq!(
            query_values(&authorization_url, name),
            vec![expected.to_string()],
            "{name} must be preserved exactly once"
        );
    }
    for name in ["state", "nonce", "code_challenge"] {
        let values = query_values(&authorization_url, name);
        assert_eq!(values.len(), 1, "{name} must be single-valued");
        assert!(!values[0].is_empty(), "{name} must not be empty");
    }
    let flow_state = query_values(&authorization_url, "state").remove(0);
    let nonce = query_values(&authorization_url, "nonce").remove(0);
    let code_challenge = query_values(&authorization_url, "code_challenge").remove(0);
    let flow_cookie = cookie_value(&started, "__Host-agent_auth_admin_oidc_flow").unwrap();
    let set_cookie = started
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("__Host-agent_auth_admin_oidc_flow="))
        .unwrap();
    for attribute in [
        "Path=/",
        "Secure",
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=600",
    ] {
        assert!(set_cookie.contains(attribute), "missing cookie {attribute}");
    }
    assert!(
        !set_cookie.to_ascii_lowercase().contains("domain="),
        "__Host- flow cookie must remain host-only"
    );
    let flows = state.admin_auth_flows().await;
    assert_eq!(flows.len(), 1);
    let flow = &flows[0];
    let now = agent_auth_http::current_unix_secs();
    assert!((599..=600).contains(&(flow.expires_at - now)));
    assert_ne!(flow.state_hash, flow_state);
    assert!(!flow.state_hash.contains(&flow_state));
    assert!(!flow.state_hash.contains(&flow_cookie));
    assert_eq!(
        agent_auth_client::s256_challenge(&flow.code_verifier),
        code_challenge
    );

    seed_login(&state, "browser-bound-code", &nonce, json!({})).await;
    let callback_path = format!("/admin/sso/callback?code=browser-bound-code&state={flow_state}");

    let missing_cookie =
        request(&router, Method::GET, HOST, &callback_path, None, None, None).await;
    assert_eq!(missing_cookie.status, StatusCode::BAD_REQUEST);

    let wrong_cookie = request(
        &router,
        Method::GET,
        HOST,
        &callback_path,
        None,
        Some("__Host-agent_auth_admin_oidc_flow=wrong-browser"),
        None,
    )
    .await;
    assert_eq!(wrong_cookie.status, StatusCode::BAD_REQUEST);

    let browser_cookie = format!("__Host-agent_auth_admin_oidc_flow={flow_cookie}");
    let accepted = request(
        &router,
        Method::GET,
        HOST,
        &callback_path,
        None,
        Some(&browser_cookie),
        None,
    )
    .await;
    assert_eq!(accepted.status, StatusCode::SEE_OTHER);
    assert!(cookie_value(&accepted, "__Host-agent_auth_admin_session").is_some());
    assert_eq!(
        cookie_value(&accepted, "__Host-agent_auth_admin_oidc_flow").as_deref(),
        Some("")
    );
    let exchanges = state.upstream_exchanger_requests().await;
    assert_eq!(exchanges.len(), 1);
    assert_eq!(exchanges[0].token_endpoint, format!("{ISSUER}/token"));
    assert_eq!(exchanges[0].client_id, CLIENT_ID);
    assert_eq!(
        exchanges[0].code_sha256,
        agent_auth_client::s256_challenge("browser-bound-code")
    );
    assert_eq!(exchanges[0].code_challenge, code_challenge);
    assert_eq!(
        exchanges[0].redirect_uri,
        "https://localhost/admin/sso/callback"
    );

    let replay = request(
        &router,
        Method::GET,
        HOST,
        &callback_path,
        None,
        Some(&browser_cookie),
        None,
    )
    .await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        state.upstream_exchanger_requests().await.len(),
        1,
        "a consumed flow must not reach token exchange twice"
    );
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    assert!(events.iter().any(|stored| {
        stored.event.action == "authentication.admin_oidc"
            && stored.event.category == SecurityEventCategory::Authentication
            && stored.event.outcome == SecurityEventOutcome::Success
    }));
}

#[tokio::test]
async fn oidc_callback_security_failures_are_audited_without_upstream_material() {
    let (router, state, user_id) = setup(TenantRole::Owner).await;

    let (upstream_error_state, _, upstream_error_cookie) = start_flow(&router).await;
    let upstream_error_path =
        format!("/admin/sso/callback?error=access_denied&state={upstream_error_state}");
    let upstream_error = request(
        &router,
        Method::GET,
        HOST,
        &upstream_error_path,
        None,
        Some(&format!(
            "__Host-agent_auth_admin_oidc_flow={upstream_error_cookie}"
        )),
        None,
    )
    .await;
    assert_eq!(upstream_error.status, StatusCode::BAD_REQUEST);
    assert_eq!(oidc_rejection_count(&state, "default").await, 1);
    let replayed_upstream_error = request(
        &router,
        Method::GET,
        HOST,
        &upstream_error_path,
        None,
        Some(&format!(
            "__Host-agent_auth_admin_oidc_flow={upstream_error_cookie}"
        )),
        None,
    )
    .await;
    assert_eq!(replayed_upstream_error.status, StatusCode::BAD_REQUEST);
    assert_eq!(oidc_rejection_count(&state, "default").await, 1);

    let (rejected_state, _, rejected_cookie) = start_flow(&router).await;
    let rejected = request(
        &router,
        Method::GET,
        HOST,
        &format!("/admin/sso/callback?code=rejected-code&state={rejected_state}"),
        None,
        Some(&format!(
            "__Host-agent_auth_admin_oidc_flow={rejected_cookie}"
        )),
        None,
    )
    .await;
    assert_eq!(rejected.status, StatusCode::BAD_REQUEST);
    assert_eq!(oidc_rejection_count(&state, "default").await, 2);

    let (missing_key_state, missing_key_nonce, missing_key_cookie) = start_flow(&router).await;
    let (missing_key_token, _) = mint_id_token(json!({
        "iss": ISSUER,
        "sub": "missing-key-subject",
        "aud": CLIENT_ID,
        "exp": agent_auth_http::current_unix_secs() + 300,
        "nonce": missing_key_nonce,
        "email": USER_EMAIL,
        "email_verified": true
    }))
    .await;
    state
        .upstream_exchanger_seed(
            "missing-key-code",
            UpstreamTokenSet {
                id_token: missing_key_token,
                access_token: None,
            },
        )
        .await;
    let missing_key = request(
        &router,
        Method::GET,
        HOST,
        &format!("/admin/sso/callback?code=missing-key-code&state={missing_key_state}"),
        None,
        Some(&format!(
            "__Host-agent_auth_admin_oidc_flow={missing_key_cookie}"
        )),
        None,
    )
    .await;
    assert_eq!(missing_key.status, StatusCode::BAD_REQUEST);
    assert_eq!(oidc_rejection_count(&state, "default").await, 3);

    let (bad_signature_state, bad_signature_nonce, bad_signature_cookie) =
        start_flow(&router).await;
    let (mut bad_signature_token, jwk) = mint_id_token(json!({
        "iss": ISSUER,
        "sub": "bad-signature-subject",
        "aud": CLIENT_ID,
        "exp": agent_auth_http::current_unix_secs() + 300,
        "nonce": bad_signature_nonce,
        "email": USER_EMAIL,
        "email_verified": true
    }))
    .await;
    let replacement = if bad_signature_token.ends_with('A') {
        'B'
    } else {
        'A'
    };
    bad_signature_token.pop();
    bad_signature_token.push(replacement);
    state
        .jwks_fetcher_set(format!("{ISSUER}/jwks"), vec![jwk])
        .await;
    state
        .upstream_exchanger_seed(
            "bad-signature-code",
            UpstreamTokenSet {
                id_token: bad_signature_token,
                access_token: None,
            },
        )
        .await;
    let bad_signature = request(
        &router,
        Method::GET,
        HOST,
        &format!("/admin/sso/callback?code=bad-signature-code&state={bad_signature_state}"),
        None,
        Some(&format!(
            "__Host-agent_auth_admin_oidc_flow={bad_signature_cookie}"
        )),
        None,
    )
    .await;
    assert_eq!(bad_signature.status, StatusCode::BAD_REQUEST);
    assert_eq!(oidc_rejection_count(&state, "default").await, 4);

    let (bad_claims_state, _, bad_claims_cookie) = start_flow(&router).await;
    seed_login(
        &state,
        "bad-claims-code",
        "nonce-from-another-flow",
        json!({}),
    )
    .await;
    let bad_claims = request(
        &router,
        Method::GET,
        HOST,
        &format!("/admin/sso/callback?code=bad-claims-code&state={bad_claims_state}"),
        None,
        Some(&format!(
            "__Host-agent_auth_admin_oidc_flow={bad_claims_cookie}"
        )),
        None,
    )
    .await;
    assert_eq!(bad_claims.status, StatusCode::BAD_REQUEST);
    assert_eq!(oidc_rejection_count(&state, "default").await, 5);

    let unverified_email = complete_login(
        &router,
        &state,
        "unverified-email-code",
        json!({"email_verified": false}),
    )
    .await;
    assert_eq!(unverified_email.status, StatusCode::BAD_REQUEST);
    assert_eq!(oidc_rejection_count(&state, "default").await, 6);

    let (wrong_issuer_state, wrong_issuer_nonce, wrong_issuer_cookie) = start_flow(&router).await;
    let (wrong_issuer_id_token, wrong_issuer_access_token) = seed_login(
        &state,
        "wrong-issuer-code",
        &wrong_issuer_nonce,
        json!({"iss": "https://attacker.example.com"}),
    )
    .await;
    let wrong_issuer = request(
        &router,
        Method::GET,
        HOST,
        &format!("/admin/sso/callback?code=wrong-issuer-code&state={wrong_issuer_state}"),
        None,
        Some(&format!(
            "__Host-agent_auth_admin_oidc_flow={wrong_issuer_cookie}"
        )),
        None,
    )
    .await;
    assert_eq!(wrong_issuer.status, StatusCode::BAD_REQUEST);
    assert!(cookie_value(&wrong_issuer, "__Host-agent_auth_admin_session").is_none());

    for (code, claims) in [
        (
            "wrong-audience-code",
            json!({"aud": "another-admin-client"}),
        ),
        (
            "expired-id-token-code",
            json!({"exp": agent_auth_http::current_unix_secs() - 61}),
        ),
    ] {
        let rejected = complete_login(&router, &state, code, claims).await;
        assert_eq!(rejected.status, StatusCode::BAD_REQUEST);
        assert!(cookie_value(&rejected, "__Host-agent_auth_admin_session").is_none());
    }

    let unknown = complete_login(
        &router,
        &state,
        "unknown-user-code",
        json!({"email": "unknown@example.com"}),
    )
    .await;
    assert_eq!(unknown.status, StatusCode::FORBIDDEN);
    assert!(cookie_value(&unknown, "__Host-agent_auth_admin_session").is_none());

    state
        .users
        .set_status(
            "",
            &user_id,
            UserStatus::Disabled,
            agent_auth_http::current_unix_secs(),
        )
        .await
        .unwrap();
    let disabled = complete_login(&router, &state, "disabled-user-code", json!({})).await;
    assert_eq!(disabled.status, StatusCode::FORBIDDEN);
    assert!(cookie_value(&disabled, "__Host-agent_auth_admin_session").is_none());
    state
        .users
        .set_status(
            "",
            &user_id,
            UserStatus::Active,
            agent_auth_http::current_unix_secs(),
        )
        .await
        .unwrap();

    let pending_epoch = match state
        .users
        .begin_credential_change(
            "",
            &user_id,
            0,
            "admin-oidc-pending",
            agent_auth_http::current_unix_secs(),
        )
        .await
        .unwrap()
    {
        agent_auth_http::ports::CredentialChangeStart::Started { epoch } => epoch,
        other => panic!("unexpected credential-change outcome: {other:?}"),
    };
    let pending = complete_login(&router, &state, "pending-user-code", json!({})).await;
    assert_eq!(pending.status, StatusCode::FORBIDDEN);
    assert!(cookie_value(&pending, "__Host-agent_auth_admin_session").is_none());
    assert!(state
        .users
        .complete_credential_change(
            "",
            &user_id,
            CredentialChangeOwner {
                epoch: pending_epoch,
                operation_id: "admin-oidc-pending",
            },
            agent_auth_http::current_unix_secs(),
        )
        .await
        .unwrap());

    state
        .scim_groups
        .set_role_mapping(
            "",
            "directory-admins",
            None,
            agent_auth_http::current_unix_secs(),
        )
        .await
        .unwrap();
    let unmapped = complete_login(&router, &state, "unmapped-group-code", json!({})).await;
    assert_eq!(unmapped.status, StatusCode::FORBIDDEN);
    assert!(cookie_value(&unmapped, "__Host-agent_auth_admin_session").is_none());
    state
        .scim_groups
        .set_role_mapping(
            "",
            "directory-admins",
            Some(TenantRole::Owner),
            agent_auth_http::current_unix_secs(),
        )
        .await
        .unwrap();

    let (stale_state, stale_nonce, stale_cookie) = start_flow(&router).await;
    seed_login(&state, "stale-config-code", &stale_nonce, json!({})).await;
    let stale_verifier = state.admin_auth_flows().await[0].code_verifier.clone();
    let current = state
        .admin_auth
        .get_config("default")
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        state
            .admin_auth
            .put_config(
                AdminOidcConfig {
                    binding_id: "changed-config-binding".into(),
                    revision: current.revision + 1,
                    updated_at: agent_auth_http::current_unix_secs(),
                    ..current
                },
                1,
            )
            .await
            .unwrap(),
        agent_auth_http::ports::AdminOidcConfigPutOutcome::Stored(_)
    ));
    let stale_config = request(
        &router,
        Method::GET,
        HOST,
        &format!("/admin/sso/callback?code=stale-config-code&state={stale_state}"),
        None,
        Some(&format!("__Host-agent_auth_admin_oidc_flow={stale_cookie}")),
        None,
    )
    .await;
    assert_eq!(stale_config.status, StatusCode::BAD_REQUEST);
    assert!(cookie_value(&stale_config, "__Host-agent_auth_admin_session").is_none());

    assert_eq!(oidc_rejection_count(&state, "default").await, 14);
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    let failures = events
        .iter()
        .filter(|stored| {
            stored.event.action == "authentication.admin_oidc"
                && stored.event.category == SecurityEventCategory::Authentication
                && stored.event.outcome == SecurityEventOutcome::Denied
        })
        .collect::<Vec<_>>();
    assert_eq!(failures.len(), 14);
    let serialized = serde_json::to_string(&failures).unwrap();
    for forbidden in [
        "rejected-code",
        "missing-key-code",
        "bad-signature-code",
        "bad-claims-code",
        "unverified-email-code",
        "wrong-issuer-code",
        "wrong-audience-code",
        "expired-id-token-code",
        "unknown-user-code",
        "disabled-user-code",
        "pending-user-code",
        "unmapped-group-code",
        "stale-config-code",
        "not-a-real-secret",
        SECRET_REF,
        &wrong_issuer_id_token,
        &wrong_issuer_access_token,
        &stale_verifier,
    ] {
        assert!(
            !serialized.contains(forbidden),
            "security events must not contain upstream code or secret material"
        );
    }
}

#[tokio::test]
async fn oidc_start_rejections_after_tenant_resolution_are_audited_once() {
    let (router, state, _) = setup(TenantRole::Owner).await;

    let invalid_max_age = request(
        &router,
        Method::GET,
        HOST,
        "/admin/sso/start?max_age=-1",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(invalid_max_age.status, StatusCode::BAD_REQUEST);
    assert_eq!(oidc_rejection_count(&state, "default").await, 1);

    let unsupported_assurance = request(
        &router,
        Method::GET,
        HOST,
        "/admin/sso/start?acr_values=urn%3Aexample%3Aunsupported",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(unsupported_assurance.status, StatusCode::BAD_REQUEST);
    assert_eq!(oidc_rejection_count(&state, "default").await, 2);

    state.admin_auth.delete_config("default", 1).await.unwrap();
    let missing_config = request(
        &router,
        Method::GET,
        HOST,
        "/admin/sso/start",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(missing_config.status, StatusCode::NOT_FOUND);
    assert_eq!(oidc_rejection_count(&state, "default").await, 3);
}

#[tokio::test]
async fn oidc_callback_tolerates_bounded_upstream_auth_time_clock_skew() {
    let (router, state, _) = setup(TenantRole::Owner).await;
    let start_path = format!(
        "/admin/sso/start?acr_values={}&max_age=300",
        agent_auth_authn::assurance::STRONG_ACR.replace(':', "%3A")
    );
    let now = agent_auth_http::current_unix_secs();
    let (flow_state, nonce, flow_cookie) = start_flow_at(&router, &start_path).await;
    seed_login(
        &state,
        "clock-skew-code",
        &nonce,
        json!({"auth_time": now + 60}),
    )
    .await;
    let callback = request(
        &router,
        Method::GET,
        HOST,
        &format!("/admin/sso/callback?code=clock-skew-code&state={flow_state}"),
        None,
        Some(&format!("__Host-agent_auth_admin_oidc_flow={flow_cookie}")),
        None,
    )
    .await;

    assert_eq!(callback.status, StatusCode::SEE_OTHER);
    let raw_session = cookie_value(&callback, "__Host-agent_auth_admin_session").unwrap();
    let stored = state
        .admin_auth
        .get_session(
            &session_hash(&state, &raw_session),
            agent_auth_http::current_unix_secs(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.auth_time, stored.created_at,
        "bounded future skew must not extend the stored freshness window"
    );

    let (flow_state, nonce, flow_cookie) = start_flow_at(&router, &start_path).await;
    seed_login(
        &state,
        "excessive-clock-skew-code",
        &nonce,
        json!({"auth_time": now + 600}),
    )
    .await;
    let excessive = request(
        &router,
        Method::GET,
        HOST,
        &format!("/admin/sso/callback?code=excessive-clock-skew-code&state={flow_state}"),
        None,
        Some(&format!("__Host-agent_auth_admin_oidc_flow={flow_cookie}")),
        None,
    )
    .await;
    assert_eq!(excessive.status, StatusCode::FORBIDDEN);
    assert_eq!(excessive.body["error"], "unmet_authentication_requirements");
    assert!(cookie_value(&excessive, "__Host-agent_auth_admin_session").is_none());
}

#[tokio::test]
async fn oidc_session_is_attributable_and_auditor_write_is_denied_and_audited() {
    let (router, state, user_id) = setup(TenantRole::Auditor).await;
    let local_user = request(
        &router,
        Method::POST,
        HOST,
        "/admin/users",
        Some(ADMIN_TOKEN),
        None,
        Some(json!({
            "email": "auditor-target@example.com",
            "initial_password": "Initial-password-123!"
        })),
    )
    .await;
    assert_eq!(local_user.status, StatusCode::CREATED);
    let local_user_id = local_user.body["user_id"].as_str().unwrap().to_string();
    let client = request(
        &router,
        Method::POST,
        HOST,
        "/admin/clients",
        Some(ADMIN_TOKEN),
        None,
        Some(json!({
            "client_id": "auditor-target-client",
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "client_secret_basic"
        })),
    )
    .await;
    assert_eq!(client.status, StatusCode::CREATED);
    let client_id = client.body["client_id"].as_str().unwrap().to_string();
    let user_before = state
        .users
        .get_by_id("", &local_user_id)
        .await
        .unwrap()
        .unwrap();
    let password_before = state.passwords.get("", &local_user_id).await.unwrap();
    let client_before = state.clients.get("", &client_id).await.unwrap().unwrap();

    let callback = complete_login(&router, &state, "auditor-code", json!({})).await;
    assert_eq!(callback.status, StatusCode::SEE_OTHER);
    assert_eq!(location(&callback), "https://localhost/admin");
    let session = cookie_value(&callback, "__Host-agent_auth_admin_session").unwrap();
    let cookie = format!("__Host-agent_auth_admin_session={session}");

    let status = request(
        &router,
        Method::GET,
        HOST,
        "/admin/session",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status.status, StatusCode::OK);
    assert_eq!(status.body["role"], "auditor");
    assert_eq!(status.body["auth_type"], "oidc_session");
    assert!(status.body["actor"].as_str().unwrap().contains(&user_id));

    let malformed_authorization = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/admin/session")
                .header("host", HOST)
                .header(header::AUTHORIZATION, "Basic invalid")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        malformed_authorization.status(),
        StatusCode::UNAUTHORIZED,
        "an explicit malformed Authorization header must not fall through to the session cookie"
    );

    let read = request(
        &router,
        Method::GET,
        HOST,
        "/admin/overview",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(read.status, StatusCode::OK);

    let config_read = request(
        &router,
        Method::GET,
        HOST,
        "/admin/oidc",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(config_read.status, StatusCode::OK);

    let denied_password_reset = request(
        &router,
        Method::POST,
        HOST,
        &format!("/admin/users/{local_user_id}/reset-password"),
        None,
        Some(&cookie),
        Some(json!({"temporary_password": "Replacement-password-456!"})),
    )
    .await;
    assert_eq!(denied_password_reset.status, StatusCode::FORBIDDEN);

    let denied_client_update = request(
        &router,
        Method::PATCH,
        HOST,
        &format!("/admin/clients/{client_id}"),
        None,
        Some(&cookie),
        Some(json!({
            "redirect_uris": ["https://attacker.example.com/callback"]
        })),
    )
    .await;
    assert_eq!(denied_client_update.status, StatusCode::FORBIDDEN);

    let denied_key_rotation = request(
        &router,
        Method::POST,
        HOST,
        &format!("/admin/clients/{client_id}/credentials/client-secret/rotate"),
        None,
        Some(&cookie),
        Some(json!({
            "rotation_request_id": "auditor-denied-rotation",
            "expires_in_seconds": 3600,
            "overlap_seconds": 60,
            "expected_version": client_before.client_secret_credentials.version
        })),
    )
    .await;
    assert_eq!(denied_key_rotation.status, StatusCode::FORBIDDEN);

    assert_eq!(
        state
            .users
            .get_by_id("", &local_user_id)
            .await
            .unwrap()
            .unwrap(),
        user_before
    );
    let password_after = state
        .passwords
        .get("", &local_user_id)
        .await
        .unwrap()
        .unwrap();
    let password_before = password_before.unwrap();
    assert_eq!(password_after.user_id, password_before.user_id);
    assert_eq!(
        password_after.password_hash.expose(),
        password_before.password_hash.expose()
    );
    assert_eq!(password_after.must_change, password_before.must_change);
    assert_eq!(
        password_after.revocation_pending,
        password_before.revocation_pending
    );
    assert_eq!(
        password_after.credential_change_id,
        password_before.credential_change_id
    );
    assert_eq!(password_after.version, password_before.version);
    assert_eq!(password_after.updated_at, password_before.updated_at);
    assert_eq!(
        state.clients.get("", &client_id).await.unwrap().unwrap(),
        client_before
    );

    let audit = state.credential_audit.snapshot().join("\n");
    let denied_line = format!(
        "ADMIN_AUTHORIZATION tenant=default actor={user_id} role=auditor action=tenant.write result=denied"
    );
    assert_eq!(
        audit.lines().filter(|line| *line == denied_line).count(),
        3,
        "password reset, client modification, and credential rotation must each be denied and audited"
    );
    assert!(
        !audit.contains("role=owner action=tenant.write"),
        "the untrusted upstream role claim must never grant management authority"
    );
}

#[tokio::test]
async fn oidc_session_identity_reaches_resource_specific_audit_events() {
    let (router, state, user_id) = setup(TenantRole::Admin).await;
    let created = request(
        &router,
        Method::POST,
        HOST,
        "/admin/clients",
        Some(ADMIN_TOKEN),
        None,
        Some(json!({
            "client_id": "attributed-client",
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "client_secret_basic"
        })),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let client_id = created.body["client_id"].as_str().unwrap();
    let credential_version = created.body["client_secret_credentials"]["version"]
        .as_u64()
        .unwrap();

    let callback = complete_login(&router, &state, "audit-code", json!({})).await;
    let session = cookie_value(&callback, "__Host-agent_auth_admin_session").unwrap();
    let cookie = format!("__Host-agent_auth_admin_session={session}");
    let rotated = request(
        &router,
        Method::POST,
        HOST,
        &format!("/admin/clients/{client_id}/credentials/client-secret/rotate"),
        None,
        Some(&cookie),
        Some(json!({
            "rotation_request_id": "admin-sso-attribution",
            "expires_in_seconds": 3600,
            "overlap_seconds": 60,
            "expected_version": credential_version
        })),
    )
    .await;
    assert_eq!(rotated.status, StatusCode::OK);

    let audit = state.credential_audit.snapshot().join("\n");
    assert!(audit.contains(&format!(
        "ADMIN_CREDENTIAL_ROTATE actor=admin-user:{user_id} tenant="
    )));
    assert!(!audit.contains("ADMIN_CREDENTIAL_ROTATE actor=none"));
}

#[tokio::test]
async fn logout_deletes_session_and_clears_cookie() {
    let (router, state, _) = setup(TenantRole::Admin).await;
    let callback = complete_login(&router, &state, "logout-code", json!({})).await;
    let session = cookie_value(&callback, "__Host-agent_auth_admin_session").unwrap();
    let cookie = format!("__Host-agent_auth_admin_session={session}");

    assert!(state.admin_auth_fail_next_delete_session());
    let failed_logout = request(
        &router,
        Method::POST,
        HOST,
        "/admin/logout",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(failed_logout.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        failed_logout.headers.get(header::SET_COOKIE).is_none(),
        "a failed persistent delete must not clear the browser cookie"
    );
    let still_active = request(
        &router,
        Method::GET,
        HOST,
        "/admin/session",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(still_active.status, StatusCode::OK);

    let logout = request(
        &router,
        Method::POST,
        HOST,
        "/admin/logout",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);
    let clear = logout
        .headers
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(clear.contains("Max-Age=0"));

    let after = request(
        &router,
        Method::GET,
        HOST,
        "/admin/session",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn every_admin_session_authority_change_fails_closed_independently() {
    {
        let (router, state, _) = setup(TenantRole::Admin).await;
        let cookie = login_session_cookie(&router, &state, "config-change-code").await;
        assert_session_status(&router, &cookie, StatusCode::OK).await;
        let current = state
            .admin_auth
            .get_config("default")
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            state
                .admin_auth
                .put_config(
                    AdminOidcConfig {
                        binding_id: "replacement-binding".into(),
                        revision: 2,
                        updated_at: agent_auth_http::current_unix_secs(),
                        ..current
                    },
                    1,
                )
                .await
                .unwrap(),
            agent_auth_http::ports::AdminOidcConfigPutOutcome::Stored(_)
        ));
        assert_session_status(&router, &cookie, StatusCode::UNAUTHORIZED).await;
    }

    {
        let (router, state, _) = setup(TenantRole::Admin).await;
        let cookie = login_session_cookie(&router, &state, "config-delete-code").await;
        assert_session_status(&router, &cookie, StatusCode::OK).await;
        assert_eq!(
            state.admin_auth.delete_config("default", 1).await.unwrap(),
            agent_auth_http::ports::AdminOidcConfigDeleteOutcome::Deleted
        );
        assert_session_status(&router, &cookie, StatusCode::UNAUTHORIZED).await;
    }

    {
        let (router, state, user_id) = setup(TenantRole::Admin).await;
        let cookie = login_session_cookie(&router, &state, "disabled-user-session-code").await;
        assert_session_status(&router, &cookie, StatusCode::OK).await;
        assert!(state
            .users
            .set_status(
                "",
                &user_id,
                UserStatus::Disabled,
                agent_auth_http::current_unix_secs(),
            )
            .await
            .unwrap());
        assert_session_status(&router, &cookie, StatusCode::UNAUTHORIZED).await;
    }

    {
        let (router, state, user_id) = setup(TenantRole::Admin).await;
        let cookie = login_session_cookie(&router, &state, "credential-epoch-code").await;
        assert_session_status(&router, &cookie, StatusCode::OK).await;
        let epoch = match state
            .users
            .begin_credential_change(
                "",
                &user_id,
                0,
                "credential-epoch-only",
                agent_auth_http::current_unix_secs(),
            )
            .await
            .unwrap()
        {
            agent_auth_http::ports::CredentialChangeStart::Started { epoch } => epoch,
            other => panic!("unexpected credential-change outcome: {other:?}"),
        };
        assert!(state
            .users
            .complete_credential_change(
                "",
                &user_id,
                CredentialChangeOwner {
                    epoch,
                    operation_id: "credential-epoch-only",
                },
                agent_auth_http::current_unix_secs(),
            )
            .await
            .unwrap());
        let current = state.users.get_by_id("", &user_id).await.unwrap().unwrap();
        assert_eq!(current.credential_epoch, epoch);
        assert!(!current.revocation_pending);
        assert_session_status(&router, &cookie, StatusCode::UNAUTHORIZED).await;
    }

    {
        let (router, state, user_id) = setup(TenantRole::Admin).await;
        let epoch = match state
            .users
            .begin_credential_change(
                "",
                &user_id,
                0,
                "revocation-pending-only",
                agent_auth_http::current_unix_secs(),
            )
            .await
            .unwrap()
        {
            agent_auth_http::ports::CredentialChangeStart::Started { epoch } => epoch,
            other => panic!("unexpected credential-change outcome: {other:?}"),
        };
        let config = state
            .admin_auth
            .get_config("default")
            .await
            .unwrap()
            .unwrap();
        let raw = state.region.issue_id("revocation-pending-session");
        let now = agent_auth_http::current_unix_secs();
        state
            .admin_auth
            .create_session(AdminSessionRecord {
                session_hash: session_hash(&state, &raw),
                tenant_id: "default".into(),
                user_id: user_id.clone(),
                upstream_subject: "pending-subject".into(),
                role: TenantRole::Admin,
                credential_epoch: epoch,
                config_revision: config.revision,
                config_binding_id: config.binding_id,
                acr: Some(agent_auth_authn::assurance::STRONG_ACR.into()),
                auth_time: now,
                created_at: now,
                expires_at: now + 300,
            })
            .await
            .unwrap();
        let cookie = format!("__Host-agent_auth_admin_session={raw}");
        assert_session_status(&router, &cookie, StatusCode::UNAUTHORIZED).await;
        assert!(state
            .users
            .complete_credential_change(
                "",
                &user_id,
                CredentialChangeOwner {
                    epoch,
                    operation_id: "revocation-pending-only",
                },
                agent_auth_http::current_unix_secs(),
            )
            .await
            .unwrap());
        assert_session_status(&router, &cookie, StatusCode::OK).await;
    }

    {
        let (router, state, user_id) = setup(TenantRole::Admin).await;
        let cookie = login_session_cookie(&router, &state, "membership-removal-code").await;
        assert_session_status(&router, &cookie, StatusCode::OK).await;
        state
            .scim_groups
            .mutate(
                "",
                "admin-group",
                ScimGroupMutation::Patch {
                    changes: vec![ScimGroupChange::RemoveMembers(vec![user_id])],
                    now: agent_auth_http::current_unix_secs(),
                },
            )
            .await
            .unwrap();
        assert_session_status(&router, &cookie, StatusCode::UNAUTHORIZED).await;
    }

    {
        let (router, state, _) = setup(TenantRole::Admin).await;
        let cookie = login_session_cookie(&router, &state, "mapping-removal-code").await;
        assert_session_status(&router, &cookie, StatusCode::OK).await;
        state
            .scim_groups
            .set_role_mapping(
                "",
                "directory-admins",
                None,
                agent_auth_http::current_unix_secs(),
            )
            .await
            .unwrap();
        assert_session_status(&router, &cookie, StatusCode::UNAUTHORIZED).await;
    }

    {
        let (router, state, _) = setup(TenantRole::Admin).await;
        let cookie = login_session_cookie(&router, &state, "role-change-code").await;
        assert_session_status(&router, &cookie, StatusCode::OK).await;
        state
            .scim_groups
            .set_role_mapping(
                "",
                "directory-admins",
                Some(TenantRole::Owner),
                agent_auth_http::current_unix_secs(),
            )
            .await
            .unwrap();
        assert_session_status(&router, &cookie, StatusCode::UNAUTHORIZED).await;
    }
}

#[tokio::test]
async fn owner_can_delete_the_exact_config_revision_and_invalidate_sessions() {
    let (router, state, _) = setup(TenantRole::Owner).await;
    let callback = complete_login(&router, &state, "delete-config-code", json!({})).await;
    let session = cookie_value(&callback, "__Host-agent_auth_admin_session").unwrap();
    let cookie = format!("__Host-agent_auth_admin_session={session}");

    let deleted = request(
        &router,
        Method::DELETE,
        HOST,
        "/admin/oidc?expected_revision=1",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);

    let invalidated = request(
        &router,
        Method::GET,
        HOST,
        "/admin/session",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(invalidated.status, StatusCode::UNAUTHORIZED);
    assert!(state
        .admin_auth
        .get_config("default")
        .await
        .unwrap()
        .is_none());
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    for action in ["secret.admin_oidc.configure", "secret.admin_oidc.delete"] {
        let event = events
            .iter()
            .find(|stored| stored.event.action == action)
            .unwrap_or_else(|| panic!("missing {action} security event"));
        assert_eq!(event.event.category, SecurityEventCategory::KeySecret);
        assert_eq!(event.event.outcome, SecurityEventOutcome::Success);
        assert_eq!(event.event.subject, SecuritySubject::tenant("default"));
        assert!(
            !serde_json::to_string(event).unwrap().contains(SECRET_REF),
            "secret reference names must not enter the event envelope"
        );
    }

    let stale_delete = request(
        &router,
        Method::DELETE,
        HOST,
        "/admin/oidc?expected_revision=1",
        Some(ADMIN_TOKEN),
        None,
        None,
    )
    .await;
    assert_eq!(stale_delete.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn low_assurance_owner_cannot_mutate_access_config_before_rfc9470_step_up() {
    let (router, state, user_id) = setup(TenantRole::Owner).await;
    let baseline = complete_login(
        &router,
        &state,
        "baseline-owner-code",
        json!({
            "acr": "urn:example:unknown:mfa",
            "amr": ["pwd", "mfa", "otp"]
        }),
    )
    .await;
    assert_eq!(baseline.status, StatusCode::SEE_OTHER);
    let session = cookie_value(&baseline, "__Host-agent_auth_admin_session").unwrap();
    let cookie = format!("__Host-agent_auth_admin_session={session}");
    let original = state
        .admin_auth
        .get_config("default")
        .await
        .unwrap()
        .unwrap();

    let denied_put = request(
        &router,
        Method::PUT,
        HOST,
        "/admin/oidc",
        None,
        Some(&cookie),
        Some(json!({
            "issuer": ISSUER,
            "client_id": CLIENT_ID,
            "client_secret_ref": SECRET_REF,
            "authorization_endpoint": format!("{ISSUER}/authorize"),
            "token_endpoint": format!("{ISSUER}/token"),
            "jwks_uri": format!("{ISSUER}/jwks"),
            "redirect_uri": "https://localhost/admin/sso/callback",
            "scopes": ["openid", "email"],
            "strong_acr_values": ["urn:example:admin:mfa"],
            "identity_claim": "email",
            "identity_field": "user_name",
            "expected_revision": 1
        })),
    )
    .await;
    assert_eq!(denied_put.status, StatusCode::UNAUTHORIZED);
    let challenge = denied_put
        .headers
        .get(header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .unwrap();
    assert!(challenge.contains("error=\"insufficient_user_authentication\""));
    assert!(challenge.contains(&format!(
        "acr_values=\"{}\"",
        agent_auth_authn::assurance::STRONG_ACR
    )));
    assert!(challenge.contains("max_age=\"300\""));
    assert_eq!(
        state
            .admin_auth
            .get_config("default")
            .await
            .unwrap()
            .unwrap(),
        original,
        "the rejected PUT must not change the Admin OIDC configuration"
    );

    let denied_delete = request(
        &router,
        Method::DELETE,
        HOST,
        "/admin/oidc?expected_revision=1",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(denied_delete.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        state
            .admin_auth
            .get_config("default")
            .await
            .unwrap()
            .unwrap(),
        original,
        "the rejected DELETE must not remove the Admin OIDC configuration"
    );
    assert!(state
        .credential_audit
        .snapshot()
        .join("\n")
        .contains("action=access.manage result=step_up_required"));
    assert!(state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 500)
        .await
        .unwrap()
        .iter()
        .any(|stored| {
            stored.event.category == SecurityEventCategory::StepUp
                && stored.event.outcome == SecurityEventOutcome::Denied
                && stored.event.action == "admin.authorization.access.manage"
        }));

    let start_path = format!(
        "/admin/sso/start?acr_values={}&max_age=300",
        agent_auth_authn::assurance::STRONG_ACR.replace(':', "%3A")
    );
    let failed_start = request(&router, Method::GET, HOST, &start_path, None, None, None).await;
    assert_eq!(failed_start.status, StatusCode::SEE_OTHER);
    let failed_location = location(&failed_start);
    assert!(failed_location.contains("acr_values=urn%3Aexample%3Aadmin%3Amfa"));
    assert!(failed_location.contains("max_age=300"));
    let failed_state = query_param(&failed_location, "state");
    let failed_nonce = query_param(&failed_location, "nonce");
    let failed_flow_cookie =
        cookie_value(&failed_start, "__Host-agent_auth_admin_oidc_flow").unwrap();
    seed_login(
        &state,
        "unmapped-step-up-code",
        &failed_nonce,
        json!({"acr": "urn:example:unknown:mfa"}),
    )
    .await;
    let failed_callback = request(
        &router,
        Method::GET,
        HOST,
        &format!("/admin/sso/callback?code=unmapped-step-up-code&state={failed_state}"),
        None,
        Some(&format!(
            "__Host-agent_auth_admin_oidc_flow={failed_flow_cookie}"
        )),
        None,
    )
    .await;
    assert_eq!(failed_callback.status, StatusCode::FORBIDDEN);
    assert_eq!(
        failed_callback.body["error"],
        "unmet_authentication_requirements"
    );
    assert!(cookie_value(&failed_callback, "__Host-agent_auth_admin_session").is_none());

    let successful_start = request(&router, Method::GET, HOST, &start_path, None, None, None).await;
    let successful_location = location(&successful_start);
    let successful_state = query_param(&successful_location, "state");
    let successful_nonce = query_param(&successful_location, "nonce");
    let successful_flow_cookie =
        cookie_value(&successful_start, "__Host-agent_auth_admin_oidc_flow").unwrap();
    seed_login(&state, "mapped-step-up-code", &successful_nonce, json!({})).await;
    let successful_callback = request(
        &router,
        Method::GET,
        HOST,
        &format!("/admin/sso/callback?code=mapped-step-up-code&state={successful_state}"),
        None,
        Some(&format!(
            "__Host-agent_auth_admin_oidc_flow={successful_flow_cookie}"
        )),
        None,
    )
    .await;
    assert_eq!(successful_callback.status, StatusCode::SEE_OTHER);
    let step_up_events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 500)
        .await
        .unwrap();
    assert!(step_up_events.iter().any(|stored| {
        stored.event.category == SecurityEventCategory::StepUp
            && stored.event.outcome == SecurityEventOutcome::Denied
            && stored.event.action == "admin.step_up"
            && stored.event.subject == SecuritySubject::user("upstream-admin-subject")
    }));
    assert!(step_up_events.iter().any(|stored| {
        stored.event.category == SecurityEventCategory::StepUp
            && stored.event.outcome == SecurityEventOutcome::Success
            && stored.event.action == "admin.step_up"
            && stored.event.actor == agent_auth_http::security_event::SecurityActor::user(&user_id)
    }));
    let elevated_session =
        cookie_value(&successful_callback, "__Host-agent_auth_admin_session").unwrap();
    let deleted = request(
        &router,
        Method::DELETE,
        HOST,
        "/admin/oidc?expected_revision=1",
        None,
        Some(&format!(
            "__Host-agent_auth_admin_session={elevated_session}"
        )),
        None,
    )
    .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn recreated_revision_cannot_resurrect_old_sessions_or_flows() {
    let (router, state, _) = setup(TenantRole::Owner).await;
    let original_binding = state
        .admin_auth
        .get_config("default")
        .await
        .unwrap()
        .unwrap()
        .binding_id;

    let (stale_state, stale_nonce, stale_flow_cookie) = start_flow(&router).await;
    seed_login(&state, "stale-flow-code", &stale_nonce, json!({})).await;

    let callback = complete_login(&router, &state, "stale-session-code", json!({})).await;
    assert_eq!(callback.status, StatusCode::SEE_OTHER);
    let stale_session = cookie_value(&callback, "__Host-agent_auth_admin_session").unwrap();
    let stale_session_cookie = format!("__Host-agent_auth_admin_session={stale_session}");

    let deleted = request(
        &router,
        Method::DELETE,
        HOST,
        "/admin/oidc?expected_revision=1",
        None,
        Some(&stale_session_cookie),
        None,
    )
    .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);

    let recreated = configure(&router, &state).await;
    assert_eq!(recreated.status, StatusCode::OK);
    assert_eq!(recreated.body["revision"], 1);
    let recreated_binding = state
        .admin_auth
        .get_config("default")
        .await
        .unwrap()
        .unwrap()
        .binding_id;
    assert_ne!(recreated_binding, original_binding);

    let stale_session_response = request(
        &router,
        Method::GET,
        HOST,
        "/admin/session",
        None,
        Some(&stale_session_cookie),
        None,
    )
    .await;
    assert_eq!(stale_session_response.status, StatusCode::UNAUTHORIZED);

    let stale_flow_cookie = format!("__Host-agent_auth_admin_oidc_flow={stale_flow_cookie}");
    let stale_flow_response = request(
        &router,
        Method::GET,
        HOST,
        &format!("/admin/sso/callback?code=stale-flow-code&state={stale_state}"),
        None,
        Some(&stale_flow_cookie),
        None,
    )
    .await;
    assert_eq!(stale_flow_response.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn saas_tenant_origins_complete_independent_oidc_sessions() {
    let state = saas_state();
    let (t1_user, t1_email, t1_client) =
        provision_saas_admin(&state, "t1", TenantRole::Owner).await;
    let (t2_user, t2_email, t2_client) =
        provision_saas_admin(&state, "t2", TenantRole::Auditor).await;
    let (router, _) = build_router(state.clone());

    let control = request(
        &router,
        Method::GET,
        "control.example.com",
        "/admin/sso/start",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(control.status, StatusCode::BAD_REQUEST);

    let (cross_state, _, cross_cookie) =
        start_flow_on(&router, "t1.example.com", "/admin/sso/start").await;
    let crossed = request(
        &router,
        Method::GET,
        "t2.example.com",
        &format!("/admin/sso/callback?state={cross_state}"),
        None,
        Some(&format!("__Host-agent_auth_admin_oidc_flow={cross_cookie}")),
        None,
    )
    .await;
    assert_eq!(crossed.status, StatusCode::BAD_REQUEST);

    let mut sessions = Vec::new();
    for (tenant, user_id, email, client_id, expected_role) in [
        ("t1", t1_user, t1_email, t1_client, "owner"),
        ("t2", t2_user, t2_email, t2_client, "auditor"),
    ] {
        let host = format!("{tenant}.example.com");
        let code = format!("{tenant}-saas-admin-code");
        let (flow_state, nonce, flow_cookie) =
            start_flow_on(&router, &host, "/admin/sso/start").await;
        let authorization_url = state
            .admin_auth_flows()
            .await
            .iter()
            .find(|flow| flow.tenant_id == tenant)
            .cloned()
            .expect("tenant flow persisted");
        assert_eq!(authorization_url.config_revision, 1);
        seed_login_for(&state, &code, &nonce, ISSUER, &client_id, &email, json!({})).await;
        let callback = request(
            &router,
            Method::GET,
            &host,
            &format!("/admin/sso/callback?code={code}&state={flow_state}"),
            None,
            Some(&format!("__Host-agent_auth_admin_oidc_flow={flow_cookie}")),
            None,
        )
        .await;
        assert_eq!(callback.status, StatusCode::SEE_OTHER);
        assert_eq!(location(&callback), format!("https://{host}/admin"));
        let raw_session = cookie_value(&callback, "__Host-agent_auth_admin_session").unwrap();
        let cookie = format!("__Host-agent_auth_admin_session={raw_session}");
        let session = request(
            &router,
            Method::GET,
            &host,
            "/admin/session",
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(session.status, StatusCode::OK);
        assert_eq!(session.body["tenant_id"], tenant);
        assert_eq!(session.body["role"], expected_role);
        assert!(session.body["actor"]
            .as_str()
            .is_some_and(|actor| actor.contains(&user_id)));

        let other_host = if tenant == "t1" {
            "t2.example.com"
        } else {
            "t1.example.com"
        };
        let crossed_session = request(
            &router,
            Method::GET,
            other_host,
            "/admin/session",
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(crossed_session.status, StatusCode::UNAUTHORIZED);
        sessions.push((tenant.to_string(), code, client_id, host));
    }

    let exchanges = state.upstream_exchanger_requests().await;
    for (tenant, code, client_id, host) in sessions {
        let exchange = exchanges
            .iter()
            .find(|request| request.code_sha256 == agent_auth_client::s256_challenge(code.as_str()))
            .expect("tenant callback reached token exchange");
        assert_eq!(exchange.client_id, client_id);
        assert_eq!(exchange.token_endpoint, format!("{ISSUER}/token"));
        assert_eq!(
            exchange.redirect_uri,
            format!("https://{host}/admin/sso/callback")
        );
        let config = state.admin_auth.get_config(&tenant).await.unwrap().unwrap();
        assert_eq!(
            config.client_secret_ref,
            format!("agent-auth/admin-oidc/{tenant}")
        );
        assert_eq!(config.client_id, client_id);
        assert_eq!(config.redirect_uri, exchange.redirect_uri);
    }
}

#[tokio::test]
async fn oidc_flow_replayed_on_another_tenant_emits_boundary_denial() {
    let mut state = AppState::dev(HOST);
    state.form = agent_auth_discovery::Form::Saas {
        zone: "example.com".into(),
        control_host: "control.example.com".into(),
    };
    state.saas_tenants = std::sync::Arc::new(vec!["t1".to_string(), "t2".to_string()]);
    state.tenant_partitioning = true;
    let now = agent_auth_http::current_unix_secs();
    assert!(matches!(
        state
            .admin_auth
            .put_config(
                AdminOidcConfig {
                    tenant_id: "t1".into(),
                    binding_id: "t1-binding".into(),
                    issuer: ISSUER.into(),
                    client_id: CLIENT_ID.into(),
                    client_secret_ref: "agent-auth/admin-oidc/t1".into(),
                    authorization_endpoint: format!("{ISSUER}/authorize"),
                    token_endpoint: format!("{ISSUER}/token"),
                    jwks_uri: format!("{ISSUER}/jwks"),
                    redirect_uri: "https://t1.example.com/admin/sso/callback".into(),
                    scopes: vec!["openid".into(), "email".into()],
                    strong_acr_values: vec![],
                    identity_claim: "email".into(),
                    identity_field: agent_auth_http::ports::AdminIdentityField::UserName,
                    revision: 1,
                    updated_at: now,
                },
                0,
            )
            .await
            .unwrap(),
        agent_auth_http::ports::AdminOidcConfigPutOutcome::Stored(_)
    ));
    let (router, _) = build_router(state.clone());
    let started = request(
        &router,
        Method::GET,
        "t1.example.com",
        "/admin/sso/start",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(started.status, StatusCode::SEE_OTHER);
    let flow_state = query_param(&location(&started), "state");
    let flow_cookie = cookie_value(&started, "__Host-agent_auth_admin_oidc_flow").unwrap();

    let replayed = request(
        &router,
        Method::GET,
        "t2.example.com",
        &format!("/admin/sso/callback?state={flow_state}"),
        None,
        Some(&format!("__Host-agent_auth_admin_oidc_flow={flow_cookie}")),
        None,
    )
    .await;
    assert_eq!(replayed.status, StatusCode::BAD_REQUEST);

    let events = state
        .security_events
        .list_by_tenant("t2", 0, i64::MAX, 100)
        .await
        .unwrap();
    let boundary = events
        .iter()
        .find(|stored| stored.event.action == "tenant.access_denied")
        .expect("cross-tenant Admin OIDC callback must emit a boundary denial");
    assert_eq!(
        boundary.event.category,
        SecurityEventCategory::TenantBoundary
    );
    assert_eq!(boundary.event.outcome, SecurityEventOutcome::Denied);
    assert_eq!(boundary.event.actor, SecurityActor::system("admin-oidc"));
    assert_eq!(boundary.event.subject, SecuritySubject::tenant("t1"));
    let authentication_failures = events
        .iter()
        .filter(|stored| {
            stored.event.action == "authentication.admin_oidc"
                && stored.event.category == SecurityEventCategory::Authentication
                && stored.event.outcome == SecurityEventOutcome::Denied
        })
        .count();
    assert_eq!(authentication_failures, 1);
}

#[tokio::test]
async fn expired_and_cross_tenant_sessions_fail_closed() {
    let state = saas_state();
    let (user_id, _, _) = provision_saas_admin(&state, "t1", TenantRole::Owner).await;
    let user = state
        .users
        .get_by_id("t1", &user_id)
        .await
        .unwrap()
        .unwrap();
    let config = state.admin_auth.get_config("t1").await.unwrap().unwrap();
    let now = agent_auth_http::current_unix_secs();
    let valid_raw = state.region.issue_id("valid-admin-session");
    state
        .admin_auth
        .create_session(AdminSessionRecord {
            session_hash: session_hash(&state, &valid_raw),
            tenant_id: "t1".into(),
            user_id: user_id.clone(),
            upstream_subject: "sub1".into(),
            role: TenantRole::Owner,
            credential_epoch: user.credential_epoch,
            config_revision: config.revision,
            config_binding_id: config.binding_id.clone(),
            acr: Some(agent_auth_authn::assurance::STRONG_ACR.into()),
            auth_time: now,
            created_at: now,
            expires_at: now + 300,
        })
        .await
        .unwrap();
    let (router, _) = build_router(state.clone());
    let valid_cookie = format!("__Host-agent_auth_admin_session={valid_raw}");
    let valid = request(
        &router,
        Method::GET,
        "t1.example.com",
        "/admin/session",
        None,
        Some(&valid_cookie),
        None,
    )
    .await;
    assert_eq!(valid.status, StatusCode::OK);

    let raw = state.region.issue_id("expired-admin-session");
    state
        .admin_auth
        .create_session(AdminSessionRecord {
            session_hash: session_hash(&state, &raw),
            tenant_id: "t1".into(),
            user_id: user_id.clone(),
            upstream_subject: "sub1".into(),
            role: TenantRole::Owner,
            credential_epoch: user.credential_epoch,
            config_revision: config.revision,
            config_binding_id: config.binding_id.clone(),
            acr: Some(agent_auth_authn::assurance::STRONG_ACR.into()),
            auth_time: now,
            created_at: now - 1,
            expires_at: now,
        })
        .await
        .unwrap();
    let cookie = format!("__Host-agent_auth_admin_session={raw}");
    let expired = request(
        &router,
        Method::GET,
        "t1.example.com",
        "/admin/session",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(expired.status, StatusCode::UNAUTHORIZED);

    let cross_raw = state.region.issue_id("cross-tenant-admin-session");
    state
        .admin_auth
        .create_session(AdminSessionRecord {
            session_hash: session_hash(&state, &cross_raw),
            tenant_id: "t1".into(),
            user_id: user_id.clone(),
            upstream_subject: "sub1".into(),
            role: TenantRole::Owner,
            credential_epoch: user.credential_epoch,
            config_revision: config.revision,
            config_binding_id: config.binding_id,
            acr: Some(agent_auth_authn::assurance::STRONG_ACR.into()),
            auth_time: now,
            created_at: now,
            expires_at: now + 300,
        })
        .await
        .unwrap();
    let cross_cookie = format!("__Host-agent_auth_admin_session={cross_raw}");
    let owning_control = request(
        &router,
        Method::GET,
        "t1.example.com",
        "/admin/session",
        None,
        Some(&cross_cookie),
        None,
    )
    .await;
    assert_eq!(owning_control.status, StatusCode::OK);
    let cross = request(
        &router,
        Method::GET,
        "t2.example.com",
        "/admin/session",
        None,
        Some(&cross_cookie),
        None,
    )
    .await;
    assert_eq!(cross.status, StatusCode::UNAUTHORIZED);
    let boundary_events = state
        .security_events
        .list_by_tenant("t2", 0, i64::MAX, 100)
        .await
        .unwrap();
    let boundary = boundary_events
        .iter()
        .find(|stored| stored.event.action == "tenant.access_denied")
        .expect("cross-tenant Admin session use must emit a boundary denial");
    assert_eq!(
        boundary.event.category,
        SecurityEventCategory::TenantBoundary
    );
    assert_eq!(boundary.event.outcome, SecurityEventOutcome::Denied);
    assert_eq!(boundary.event.actor, SecurityActor::user(&user_id));
    assert_eq!(boundary.event.subject, SecuritySubject::tenant("t1"));

    let cross_tenant_logout = request(
        &router,
        Method::POST,
        "t2.example.com",
        "/admin/logout",
        None,
        Some(&cross_cookie),
        None,
    )
    .await;
    assert_eq!(cross_tenant_logout.status, StatusCode::NO_CONTENT);
    assert!(state
        .admin_auth
        .get_session(&session_hash(&state, &cross_raw), now)
        .await
        .unwrap()
        .is_some());

    let owning_tenant_logout = request(
        &router,
        Method::POST,
        "t1.example.com",
        "/admin/logout",
        None,
        Some(&cross_cookie),
        None,
    )
    .await;
    assert_eq!(owning_tenant_logout.status, StatusCode::NO_CONTENT);
    assert!(state
        .admin_auth
        .get_session(&session_hash(&state, &cross_raw), now)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn invalid_upstream_claims_and_config_retries_fail_closed() {
    let (router, state, _) = setup(TenantRole::Owner).await;
    let duplicate = configure(&router, &state).await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT);

    let bad_redirect = request(
        &router,
        Method::PUT,
        HOST,
        "/admin/oidc",
        Some(ADMIN_TOKEN),
        None,
        Some(json!({
            "issuer": ISSUER,
            "client_id": CLIENT_ID,
            "client_secret_ref": SECRET_REF,
            "authorization_endpoint": format!("{ISSUER}/authorize"),
            "token_endpoint": format!("{ISSUER}/token"),
            "jwks_uri": format!("{ISSUER}/jwks"),
            "redirect_uri": "https://attacker.example.com/callback",
            "scopes": ["openid"],
            "identity_claim": "email",
            "identity_field": "user_name",
            "expected_revision": 1
        })),
    )
    .await;
    assert_eq!(bad_redirect.status, StatusCode::BAD_REQUEST);

    let wrong_secret_domain = request(
        &router,
        Method::PUT,
        HOST,
        "/admin/oidc",
        Some(ADMIN_TOKEN),
        None,
        Some(json!({
            "issuer": ISSUER,
            "client_id": CLIENT_ID,
            "client_secret_ref": "agent-auth/admin-oidc/another-tenant",
            "authorization_endpoint": format!("{ISSUER}/authorize"),
            "token_endpoint": format!("{ISSUER}/token"),
            "jwks_uri": format!("{ISSUER}/jwks"),
            "redirect_uri": "https://localhost/admin/sso/callback",
            "scopes": ["openid"],
            "identity_claim": "email",
            "identity_field": "user_name",
            "expected_revision": 1
        })),
    )
    .await;
    assert_eq!(wrong_secret_domain.status, StatusCode::BAD_REQUEST);

    let unverified_user_name_claim = request(
        &router,
        Method::PUT,
        HOST,
        "/admin/oidc",
        Some(ADMIN_TOKEN),
        None,
        Some(json!({
            "issuer": ISSUER,
            "client_id": CLIENT_ID,
            "client_secret_ref": SECRET_REF,
            "authorization_endpoint": format!("{ISSUER}/authorize"),
            "token_endpoint": format!("{ISSUER}/token"),
            "jwks_uri": format!("{ISSUER}/jwks"),
            "redirect_uri": "https://localhost/admin/sso/callback",
            "scopes": ["openid"],
            "identity_claim": "preferred_username",
            "identity_field": "user_name",
            "expected_revision": 1
        })),
    )
    .await;
    assert_eq!(unverified_user_name_claim.status, StatusCode::BAD_REQUEST);

    let callback = complete_login(
        &router,
        &state,
        "bad-claims-code",
        json!({"email_verified": false}),
    )
    .await;
    assert_eq!(callback.status, StatusCode::BAD_REQUEST);
    assert!(cookie_value(&callback, "__Host-agent_auth_admin_session").is_none());
}

#[tokio::test]
async fn fixed_role_matrix_is_enforced_per_action() {
    let (router, state, user_id) = setup(TenantRole::Member).await;
    let user = state.users.get_by_id("", &user_id).await.unwrap().unwrap();
    let config = state
        .admin_auth
        .get_config("default")
        .await
        .unwrap()
        .unwrap();
    state
        .scim_groups
        .create(
            "",
            ScimGroupCreateInput {
                group_id: "managed-access-group".into(),
                external_id: "managed-access-group".into(),
                display_name: "Managed Access Group".into(),
                members: Vec::new(),
                now: agent_auth_http::current_unix_secs(),
            },
        )
        .await
        .unwrap();
    let cases = [
        (
            TenantRole::Member,
            StatusCode::FORBIDDEN,
            StatusCode::FORBIDDEN,
            StatusCode::FORBIDDEN,
        ),
        (
            TenantRole::Auditor,
            StatusCode::OK,
            StatusCode::FORBIDDEN,
            StatusCode::FORBIDDEN,
        ),
        (
            TenantRole::Admin,
            StatusCode::OK,
            StatusCode::OK,
            StatusCode::FORBIDDEN,
        ),
        (
            TenantRole::Owner,
            StatusCode::OK,
            StatusCode::OK,
            StatusCode::OK,
        ),
    ];
    for (index, (role, read_status, write_status, access_status)) in cases.into_iter().enumerate() {
        state
            .scim_groups
            .set_role_mapping(
                "",
                "directory-admins",
                Some(role),
                agent_auth_http::current_unix_secs(),
            )
            .await
            .unwrap();
        let raw = state
            .region
            .issue_id(format!("role-matrix-session-{index}"));
        let now = agent_auth_http::current_unix_secs();
        state
            .admin_auth
            .create_session(AdminSessionRecord {
                session_hash: session_hash(&state, &raw),
                tenant_id: "default".into(),
                user_id: user_id.clone(),
                upstream_subject: format!("subject-{index}"),
                role,
                credential_epoch: user.credential_epoch,
                config_revision: config.revision,
                config_binding_id: config.binding_id.clone(),
                acr: Some(agent_auth_authn::assurance::STRONG_ACR.into()),
                auth_time: now,
                created_at: now,
                expires_at: now + 300,
            })
            .await
            .unwrap();
        let cookie = format!("__Host-agent_auth_admin_session={raw}");

        let session = request(
            &router,
            Method::GET,
            HOST,
            "/admin/session",
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(session.status, StatusCode::OK, "{role:?} session policy");

        let read = request(
            &router,
            Method::GET,
            HOST,
            "/admin/overview",
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(read.status, read_status, "{role:?} read policy");

        let created = request(
            &router,
            Method::POST,
            HOST,
            "/admin/clients",
            Some(ADMIN_TOKEN),
            None,
            Some(json!({
                "client_id": format!("role-matrix-client-{index}"),
                "redirect_uris": [format!("https://client-{index}.example.com/callback")],
                "token_endpoint_auth_method": "none"
            })),
        )
        .await;
        assert_eq!(created.status, StatusCode::CREATED);
        let client_id = created.body["client_id"].as_str().unwrap().to_string();
        let write = request(
            &router,
            Method::DELETE,
            HOST,
            &format!("/admin/clients/{client_id}"),
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(write.status, write_status, "{role:?} write policy");
        if write_status == StatusCode::FORBIDDEN {
            assert!(
                state.clients.get("", &client_id).await.unwrap().is_some(),
                "denied tenant write must not delete the client"
            );
            let cleanup = request(
                &router,
                Method::DELETE,
                HOST,
                &format!("/admin/clients/{client_id}"),
                Some(ADMIN_TOKEN),
                None,
                None,
            )
            .await;
            assert_eq!(cleanup.status, StatusCode::OK);
        } else {
            assert!(state.clients.get("", &client_id).await.unwrap().is_none());
        }

        state
            .scim_groups
            .set_role_mapping(
                "",
                "managed-access-group",
                None,
                agent_auth_http::current_unix_secs(),
            )
            .await
            .unwrap();
        let access = request(
            &router,
            Method::PUT,
            HOST,
            "/admin/scim/group-role-mappings/managed-access-group",
            None,
            Some(&cookie),
            Some(json!({"role": "member"})),
        )
        .await;
        assert_eq!(access.status, access_status, "{role:?} access policy");

        let role_name = match role {
            TenantRole::Owner => "owner",
            TenantRole::Admin => "admin",
            TenantRole::Auditor => "auditor",
            TenantRole::Member => "member",
        };
        let audit = state.credential_audit.snapshot().join("\n");
        for (action, result) in [
            ("session.read", "allowed"),
            (
                "tenant.read",
                if read_status == StatusCode::OK {
                    "allowed"
                } else {
                    "denied"
                },
            ),
            (
                "tenant.write",
                if write_status == StatusCode::OK {
                    "allowed"
                } else {
                    "denied"
                },
            ),
            (
                "access.manage",
                if access_status == StatusCode::OK {
                    "allowed"
                } else {
                    "denied"
                },
            ),
        ] {
            assert!(
                audit.contains(&format!(
                    "ADMIN_AUTHORIZATION tenant=default actor={user_id} role={role_name} action={action} result={result}"
                )),
                "missing {role_name}/{action}/{result} authorization audit"
            );
        }
    }
}

fn session_hash(state: &AppState, raw: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&state.server_secret).expect("HMAC accepts any key length");
    mac.update(b"admin-session:");
    mac.update(raw.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}
