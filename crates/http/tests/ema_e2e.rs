use agent_auth_ema::{
    derive_enterprise_user_id, derive_replay_key, EmaPolicy, PolicyConfig, ResourcePolicyConfig,
    SigningAlgorithm,
};
use agent_auth_http::ema_flow::TenantEmaPolicy;
use agent_auth_http::ports::{
    ClientRecord, ClientStore, JtiStore, PlatformJwk, ReplayStore, Signer, UserStatus, UsersStore,
};
use agent_auth_http::state::UsersStoreImpl;
use agent_auth_http::{build_router, AppState, Phase, SubjectType};
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use p256::ecdsa::{
    signature::{Signer as _, Verifier as _},
    Signature, SigningKey, VerifyingKey,
};
use rand::{rngs::StdRng, SeedableRng};
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::signature::SignatureEncoding;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use sha2::Sha256;
use tower::ServiceExt;

const HOST: &str = "localhost";
const CLIENT_ID: &str = "ema-client";
const CLIENT_SECRET: &str = "ema-client-secret";
const IDP_ISSUER: &str = "https://login.example.com/acme/v2.0";
const IDP_TENANT: &str = "acme";
const JWKS_URI: &str = "https://login.example.com/acme/discovery/keys";
const ATTACKER_JWKS_URI: &str = "https://attacker.example/jwks";
const RESOURCE: &str = "https://mcp.example.com";

fn policy() -> EmaPolicy {
    policy_with_algorithms(vec![SigningAlgorithm::Es256, SigningAlgorithm::Rs256])
}

fn policy_with_algorithms(allowed_algorithms: Vec<SigningAlgorithm>) -> EmaPolicy {
    EmaPolicy::try_from(PolicyConfig {
        policy_id: "entra-acme".into(),
        trusted_issuer: IDP_ISSUER.into(),
        issuer_tenant: Some(IDP_TENANT.into()),
        jwks_uri: JWKS_URI.into(),
        allowed_algorithms,
        authenticated_client_id: CLIENT_ID.into(),
        assertion_client_id: "enterprise-mcp-client".into(),
        resources: vec![ResourcePolicyConfig {
            resource: RESOURCE.into(),
            scopes: vec!["mcp:read".into(), "mcp:write".into()],
        }],
        allow_legacy_missing_resource: false,
        max_assertion_lifetime_secs: 300,
        allowed_clock_skew_secs: 30,
    })
    .unwrap()
}

fn valid_claims(now: i64, jti: &str) -> serde_json::Value {
    serde_json::json!({
        "iss": IDP_ISSUER,
        "tenant": IDP_TENANT,
        "sub": "enterprise-user-1",
        "aud": format!("https://{HOST}"),
        "client_id": "enterprise-mcp-client",
        "exp": now + 300,
        "iat": now,
        "nbf": now - 1,
        "jti": jti,
        "scope": "mcp:read mcp:write",
        "resource": RESOURCE,
    })
}

fn default_id_jag_header() -> serde_json::Value {
    serde_json::json!({
        "alg": "ES256",
        "typ": "oauth-id-jag+jwt",
        "kid": "idp-key-1"
    })
}

fn sign_id_jag(header: serde_json::Value, claims: serde_json::Value) -> (String, PlatformJwk) {
    sign_id_jag_with_seed(23, header, claims)
}

fn sign_id_jag_with_seed(
    seed: u8,
    header: serde_json::Value,
    claims: serde_json::Value,
) -> (String, PlatformJwk) {
    let signing_key = SigningKey::from_bytes(&[seed; 32].into()).unwrap();
    let point = signing_key.verifying_key().to_encoded_point(false);
    let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    (
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ),
        PlatformJwk {
            kid: Some("idp-key-1".into()),
            kty: Some("EC".into()),
            n: String::new(),
            e: String::new(),
            crv: Some("P-256".into()),
            x: Some(URL_SAFE_NO_PAD.encode(point.x().unwrap())),
            y: Some(URL_SAFE_NO_PAD.encode(point.y().unwrap())),
            alg: Some("ES256".into()),
        },
    )
}

fn id_jag(now: i64) -> (String, PlatformJwk) {
    sign_id_jag(
        serde_json::json!({
            "alg": "ES256",
            "typ": "oauth-id-jag+jwt",
            "kid": "idp-key-1",
        }),
        valid_claims(now, "id-jag-1"),
    )
}

fn rs256_id_jag(now: i64) -> (String, PlatformJwk) {
    let private_key = RsaPrivateKey::new(&mut StdRng::seed_from_u64(43), 2048).unwrap();
    let public_key = private_key.to_public_key();
    let header = serde_json::json!({
        "alg": "RS256",
        "typ": "oauth-id-jag+jwt",
        "kid": "idp-rsa-key-1",
    });
    let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let encoded_claims =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&valid_claims(now, "id-jag-rs256")).unwrap());
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signing_key = RsaSigningKey::<Sha256>::new(private_key);
    let signature = rsa::signature::Signer::sign(&signing_key, signing_input.as_bytes());
    (
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ),
        PlatformJwk {
            kid: Some("idp-rsa-key-1".into()),
            kty: Some("RSA".into()),
            n: URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
            e: URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
            alg: Some("RS256".into()),
            ..Default::default()
        },
    )
}

fn standard_form(assertion: &str) -> Vec<(String, String)> {
    [
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", assertion),
        ("resource", RESOURCE),
        ("scope", "mcp:read"),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_string(), value.to_string()))
    .collect()
}

struct EmaResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: serde_json::Value,
}

async fn post_ema(
    router: &axum::Router,
    form: Vec<(String, String)>,
    authorization: Option<&str>,
    dpop: Option<&str>,
) -> EmaResponse {
    post_ema_host(router, HOST, form, authorization, dpop).await
}

async fn post_ema_host(
    router: &axum::Router,
    host: &str,
    form: Vec<(String, String)>,
    authorization: Option<&str>,
    dpop: Option<&str>,
) -> EmaResponse {
    let mut request = Request::builder()
        .method("POST")
        .uri("/token")
        .header("host", host)
        .header("content-type", "application/x-www-form-urlencoded");
    if let Some(authorization) = authorization {
        request = request.header("authorization", authorization);
    }
    if let Some(dpop) = dpop {
        request = request.header("dpop", dpop);
    }
    let response = router
        .clone()
        .oneshot(
            request
                .body(Body::from(serde_urlencoded::to_string(form).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    EmaResponse {
        status,
        headers,
        body: serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
    }
}

fn basic(client_id: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
}

fn verify_access_token_signature(
    token: &str,
    jwk: &agent_auth_infra_core::EcJwk,
) -> serde_json::Value {
    let parts: Vec<_> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "at+jwt");
    assert_eq!(header["kid"], jwk.kid);
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend(URL_SAFE_NO_PAD.decode(&jwk.x).unwrap());
    sec1.extend(URL_SAFE_NO_PAD.decode(&jwk.y).unwrap());
    let verifying_key = VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
    verifying_key
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap()
}

fn dpop_key(seed: u8) -> (SigningKey, serde_json::Value, String) {
    let key = SigningKey::from_bytes(&[seed; 32].into()).unwrap();
    let point = key.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
    let jwk = serde_json::json!({"kty":"EC","crv":"P-256","x":x,"y":y});
    let jkt = URL_SAFE_NO_PAD.encode(agent_auth_infra_core::jwks::ec_thumbprint("P-256", &x, &y));
    (key, jwk, jkt)
}

fn dpop_proof(key: &SigningKey, jwk: &serde_json::Value, jti: &str, now: i64) -> String {
    let header = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":jwk});
    let claims = serde_json::json!({
        "htu": format!("https://{HOST}/token"),
        "htm": "POST",
        "iat": now,
        "jti": jti
    });
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let input = format!("{header}.{claims}");
    let signature: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

async fn configured_state() -> (AppState, String) {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    state.ema_enabled = true;
    state.ema_policies = std::sync::Arc::new(vec![TenantEmaPolicy {
        agent_auth_tenant: String::new(),
        policy: policy(),
    }]);
    ClientStore::put(
        state.clients.as_ref(),
        "",
        ClientRecord {
            client_id: CLIENT_ID.into(),
            token_endpoint_auth_method: "client_secret_basic".into(),
            client_secret: Some(CLIENT_SECRET.into()),
            client_type: Some("confidential".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (assertion, jwk) = id_jag(agent_auth_http::current_unix_secs());
    state.jwks_fetcher_set(JWKS_URI, vec![jwk]).await;
    (state, assertion)
}

#[tokio::test]
async fn valid_id_jag_issues_one_resource_access_token_and_jits_enterprise_user() {
    let (state, assertion) = configured_state().await;
    let inspect = state.clone();
    let (router, _) = build_router(state);
    let form = serde_urlencoded::to_string([
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", assertion.as_str()),
        ("resource", RESOURCE),
        ("scope", "mcp:read"),
    ])
    .unwrap();
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .header(
                    "authorization",
                    format!(
                        "Basic {}",
                        STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
                    ),
                )
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["cache-control"],
        "no-store",
        "EMA token responses must not be cached"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let token: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(token["resource"], RESOURCE);
    assert_eq!(token["scope"], "mcp:read");
    assert!(token["access_token"].is_string());
    assert!(token.get("refresh_token").is_none());
    assert!(token.get("id_token").is_none());
    let access_token = token["access_token"].as_str().unwrap();
    let signing_jwk = inspect.signer.public_jwks().await.unwrap().remove(0);
    let claims = verify_access_token_signature(access_token, &signing_jwk);
    assert_eq!(claims["iss"], format!("https://{HOST}"));
    assert_eq!(claims["aud"], serde_json::json!([RESOURCE]));
    assert_eq!(claims["client_id"], CLIENT_ID);
    assert_eq!(claims["scope"], "mcp:read");
    assert!(claims["sub"].as_str().is_some_and(|sub| !sub.is_empty()));
    assert_eq!(claims["https://a-auth.com/c"]["sub_type"], "user");
    assert_eq!(claims["https://a-auth.com/c"]["auth_grant"], "id-jag");
    assert!(claims.get("cnf").is_none());

    let user_id = derive_enterprise_user_id(
        &inspect.server_secret,
        "",
        IDP_ISSUER,
        Some(IDP_TENANT),
        "enterprise-user-1",
    );
    let user = inspect
        .users
        .get_by_id("", &user_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.user_id, user_id);
    assert!(user.email.is_empty());
    assert_eq!(user.status, UserStatus::Active);
    assert!(!user.revocation_pending);
    assert!(user.scim_external_id.is_none());
    assert!(user.scim_user_name.is_none());
    assert!(user.scim_display_name.is_none());
    let jti = claims["jti"].as_str().unwrap();
    let mapping = inspect
        .jti_store
        .as_ref()
        .unwrap()
        .get("default", jti)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mapping.user_id, user_id);
}

#[tokio::test]
async fn ema_access_token_contract_preserves_subject_profile_and_expiry_bound() {
    for (subject_type, profile) in [
        (SubjectType::Public, "public"),
        (SubjectType::Pairwise, "pairwise"),
    ] {
        let (mut state, assertion) = configured_state().await;
        state.subject_type = subject_type;
        let inspect = state.clone();
        let (router, _) = build_router(state);
        let response = post_ema(
            &router,
            standard_form(&assertion),
            Some(&basic(CLIENT_ID, CLIENT_SECRET)),
            None,
        )
        .await;

        assert_eq!(
            response.status,
            StatusCode::OK,
            "{profile}: {}",
            response.body
        );
        assert_eq!(response.headers["cache-control"], "no-store");
        let mut response_keys: Vec<_> = response
            .body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        response_keys.sort_unstable();
        assert_eq!(
            response_keys,
            [
                "access_token",
                "expires_in",
                "resource",
                "scope",
                "token_type"
            ],
            "{profile}: EMA v1 must return only one access-token contract"
        );
        assert_eq!(response.body["token_type"], "Bearer");
        assert_eq!(response.body["expires_in"], 900);
        assert_eq!(response.body["resource"], RESOURCE);
        assert_eq!(response.body["scope"], "mcp:read");

        let signing_jwk = inspect.signer.public_jwks().await.unwrap().remove(0);
        let claims = verify_access_token_signature(
            response.body["access_token"].as_str().unwrap(),
            &signing_jwk,
        );
        assert_eq!(claims["iss"], format!("https://{HOST}"));
        assert_eq!(claims["aud"], serde_json::json!([RESOURCE]));
        assert_eq!(claims["client_id"], CLIENT_ID);
        assert_eq!(claims["scope"], "mcp:read");
        assert_eq!(claims["https://a-auth.com/c"]["sub_type"], "user");
        assert_eq!(claims["https://a-auth.com/c"]["auth_grant"], "id-jag");
        assert!(claims.get("cnf").is_none());
        let issued_at = claims["iat"].as_i64().unwrap();
        let expires_at = claims["exp"].as_i64().unwrap();
        assert_eq!(
            expires_at - issued_at,
            response.body["expires_in"].as_i64().unwrap(),
            "{profile}: offline residual validity must be bounded by the advertised exp"
        );

        let user_id = derive_enterprise_user_id(
            &inspect.server_secret,
            "",
            IDP_ISSUER,
            Some(IDP_TENANT),
            "enterprise-user-1",
        );
        let expected_sub = match subject_type {
            SubjectType::Public => user_id.clone(),
            SubjectType::Pairwise => {
                agent_auth_token::pairwise_sub(&inspect.server_secret, &user_id, RESOURCE)
            }
        };
        assert_eq!(claims["sub"], expected_sub, "{profile}");

        let jti = claims["jti"].as_str().unwrap();
        let mapping = inspect
            .jti_store
            .as_ref()
            .unwrap()
            .get("default", jti)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(mapping.user_id, user_id, "{profile}");
        assert_eq!(mapping.expires_at, expires_at, "{profile}");
    }
}

#[tokio::test]
async fn assertion_email_claim_never_links_or_populates_enterprise_user() {
    let (state, _) = configured_state().await;
    let now = agent_auth_http::current_unix_secs();
    let local_user_id = "user:local-email-owner";
    let local_user_before = state
        .users
        .create_or_get_by_email("", "victim@example.com", local_user_id, now)
        .await
        .unwrap();
    let enterprise_user_id = derive_enterprise_user_id(
        &state.server_secret,
        "",
        IDP_ISSUER,
        Some(IDP_TENANT),
        "enterprise-user-1",
    );
    let inspect = state.clone();
    let (router, _) = build_router(state);
    let signing_jwk = inspect.signer.public_jwks().await.unwrap().remove(0);

    for (jti, email) in [
        ("id-jag-email-1", "victim@example.com"),
        ("id-jag-email-2", "other@example.com"),
    ] {
        let mut claims = valid_claims(now, jti);
        claims["email"] = serde_json::json!(email);
        let (assertion, _) = sign_id_jag(default_id_jag_header(), claims);
        let response = post_ema(
            &router,
            standard_form(&assertion),
            Some(&basic(CLIENT_ID, CLIENT_SECRET)),
            None,
        )
        .await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "{email}: {}",
            response.body
        );
        let access_claims = verify_access_token_signature(
            response.body["access_token"].as_str().unwrap(),
            &signing_jwk,
        );
        let mapping = inspect
            .jti_store
            .as_ref()
            .unwrap()
            .get("default", access_claims["jti"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(mapping.user_id, enterprise_user_id);
    }

    let enterprise_user = inspect
        .users
        .get_by_id("", &enterprise_user_id)
        .await
        .unwrap()
        .unwrap();
    assert!(enterprise_user.email.is_empty());
    assert_eq!(enterprise_user.status, UserStatus::Active);
    let local_user = inspect
        .users
        .get_by_email("", "victim@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(local_user, local_user_before);
    assert_eq!(local_user.user_id, local_user_id);
    assert_ne!(local_user.user_id, enterprise_user.user_id);
}

#[tokio::test]
async fn valid_rs256_id_jag_is_verified_by_the_http_flow() {
    let now = agent_auth_http::current_unix_secs();
    let (assertion, jwk) = rs256_id_jag(now);
    let (state, _) = configured_state().await;
    state.jwks_fetcher_set(JWKS_URI, vec![jwk]).await;
    let (router, _) = build_router(state);

    let response = post_ema(
        &router,
        standard_form(&assertion),
        Some(&basic(CLIENT_ID, CLIENT_SECRET)),
        None,
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    assert!(response.body["access_token"].is_string());
}

#[tokio::test]
async fn malformed_ema_form_uses_oauth_error_and_no_store() {
    let (state, assertion) = configured_state().await;
    let (router, _) = build_router(state);
    let mut form = standard_form(&assertion);
    form.push((
        "grant_type".into(),
        "urn:ietf:params:oauth:grant-type:jwt-bearer".into(),
    ));

    let response = post_ema(&router, form, Some(&basic(CLIENT_ID, CLIENT_SECRET)), None).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.headers["cache-control"], "no-store");
    assert_eq!(response.body["error"], "invalid_request");
}

#[tokio::test]
async fn ema_with_invalid_content_type_still_uses_oauth_error_and_no_store() {
    let (state, assertion) = configured_state().await;
    let (router, _) = build_router(state);
    let body = serde_urlencoded::to_string(standard_form(&assertion)).unwrap();
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"],
        "invalid_request"
    );
}

#[tokio::test]
async fn malformed_non_ema_form_uses_oauth_error_and_no_store() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state);
    let response = post_ema(
        &router,
        vec![
            ("grant_type".into(), "authorization_code".into()),
            ("grant_type".into(), "authorization_code".into()),
        ],
        None,
        None,
    )
    .await;

    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.headers["cache-control"], "no-store");
    assert_eq!(response.headers["pragma"], "no-cache");
    assert_eq!(response.body["error"], "invalid_request");
}

#[tokio::test]
async fn non_ema_with_invalid_content_type_uses_oauth_error_and_no_store() {
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state);
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/json")
                .body(Body::from("grant_type=authorization_code"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"],
        "invalid_request"
    );
}

#[tokio::test]
async fn replayed_id_jag_is_rejected_after_the_first_success() {
    let (state, assertion) = configured_state().await;
    let (router, _) = build_router(state);
    let basic = format!(
        "Basic {}",
        STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
    );

    for expected in [StatusCode::OK, StatusCode::BAD_REQUEST] {
        let form = serde_urlencoded::to_string([
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion.as_str()),
            ("resource", RESOURCE),
            ("scope", "mcp:read"),
        ])
        .unwrap();
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header("host", HOST)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("authorization", &basic)
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert_eq!(response.headers()["cache-control"], "no-store");
        if expected == StatusCode::BAD_REQUEST {
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(error["error"], "invalid_grant");
        }
    }
}

#[tokio::test]
async fn unknown_kid_refreshes_the_fixed_policy_jwks_once() {
    let (state, assertion) = configured_state().await;
    let (_, good_key) = id_jag(agent_auth_http::current_unix_secs());
    let mut stale_key = good_key.clone();
    stale_key.kid = Some("stale-key".into());
    state.jwks_fetcher_set(JWKS_URI, vec![stale_key]).await;
    state.jwks_fetcher_set_fresh(JWKS_URI, vec![good_key]).await;
    let inspect = state.clone();
    let (router, _) = build_router(state);
    let form = serde_urlencoded::to_string([
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", assertion.as_str()),
        ("resource", RESOURCE),
        ("scope", "mcp:read"),
    ])
    .unwrap();
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .header(
                    "authorization",
                    format!(
                        "Basic {}",
                        STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
                    ),
                )
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(inspect.jwks_fetcher_calls(JWKS_URI).await, Some(1));
    assert_eq!(inspect.jwks_fetcher_fresh_calls(JWKS_URI).await, Some(1));
    assert_eq!(inspect.jwks_fetcher_calls(ATTACKER_JWKS_URI).await, Some(0));
    assert_eq!(
        inspect.jwks_fetcher_fresh_calls(ATTACKER_JWKS_URI).await,
        Some(0)
    );
}

#[tokio::test]
async fn invalid_scope_neither_consumes_assertion_nor_creates_user() {
    let (state, _) = configured_state().await;
    let now = agent_auth_http::current_unix_secs();
    let mut claims = valid_claims(now, "scope-boundary");
    claims["scope"] = serde_json::json!("mcp:read");
    let (assertion, jwk) = sign_id_jag(default_id_jag_header(), claims);
    state.jwks_fetcher_set(JWKS_URI, vec![jwk]).await;
    let inspect = state.clone();
    let (router, _) = build_router(state);
    let user_id = derive_enterprise_user_id(
        &inspect.server_secret,
        "",
        IDP_ISSUER,
        Some(IDP_TENANT),
        "enterprise-user-1",
    );

    for (scope, expected, expected_error) in [
        ("", StatusCode::BAD_REQUEST, Some("invalid_scope")),
        (
            "mcp:read mcp:read",
            StatusCode::BAD_REQUEST,
            Some("invalid_scope"),
        ),
        ("mcp:write", StatusCode::BAD_REQUEST, Some("invalid_scope")),
        ("mcp:admin", StatusCode::BAD_REQUEST, Some("invalid_scope")),
        ("mcp:read", StatusCode::OK, None),
    ] {
        let form = serde_urlencoded::to_string([
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion.as_str()),
            ("resource", RESOURCE),
            ("scope", scope),
        ])
        .unwrap();
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header("host", HOST)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header(
                        "authorization",
                        format!(
                            "Basic {}",
                            STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
                        ),
                    )
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{scope:?}");
        if let Some(expected_error) = expected_error {
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(error["error"], expected_error);
            assert!(
                inspect
                    .users
                    .get_by_id("", &user_id)
                    .await
                    .unwrap()
                    .is_none(),
                "invalid pre-replay request must not JIT a user"
            );
        }
    }
}

#[tokio::test]
async fn preconsumed_assertion_is_rejected_before_jit() {
    let (state, assertion) = configured_state().await;
    let now = agent_auth_http::current_unix_secs();
    let user_id = derive_enterprise_user_id(
        &state.server_secret,
        "",
        IDP_ISSUER,
        Some(IDP_TENANT),
        "enterprise-user-1",
    );
    let replay_key = derive_replay_key(
        &state.server_secret,
        "",
        IDP_ISSUER,
        Some(IDP_TENANT),
        "id-jag-1",
    );
    assert!(state
        .replay_store
        .as_ref()
        .unwrap()
        .check_and_set("", &replay_key, now + 330)
        .await
        .unwrap());
    assert!(state.users.get_by_id("", &user_id).await.unwrap().is_none());

    let inspect = state.clone();
    let (router, _) = build_router(state);
    let response = post_ema(
        &router,
        standard_form(&assertion),
        Some(&basic(CLIENT_ID, CLIENT_SECRET)),
        None,
    )
    .await;

    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.body["error"], "invalid_grant");
    assert!(response.body.get("access_token").is_none());
    assert!(
        inspect
            .users
            .get_by_id("", &user_id)
            .await
            .unwrap()
            .is_none(),
        "a replay rejection must happen before enterprise-user JIT"
    );
}

#[tokio::test]
async fn post_jit_identity_reread_failure_leaves_assertion_consumed_without_token() {
    let (state, assertion) = configured_state().await;
    match state.users.as_ref() {
        UsersStoreImpl::Memory(users) => users.fail_get_by_id_after(1),
        #[cfg(feature = "aws")]
        UsersStoreImpl::Dynamo(_) => panic!("dev state must use the memory users store"),
    }
    let user_id = derive_enterprise_user_id(
        &state.server_secret,
        "",
        IDP_ISSUER,
        Some(IDP_TENANT),
        "enterprise-user-1",
    );
    let inspect = state.clone();
    let (router, _) = build_router(state);
    let authorization = basic(CLIENT_ID, CLIENT_SECRET);

    let failed = post_ema(
        &router,
        standard_form(&assertion),
        Some(&authorization),
        None,
    )
    .await;
    assert_eq!(failed.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(failed.body["error"], "temporarily_unavailable");
    assert!(failed.body.get("access_token").is_none());
    assert!(
        inspect
            .users
            .get_by_id("", &user_id)
            .await
            .unwrap()
            .is_some(),
        "JIT must complete only after replay consumption and before the issuance reread"
    );

    let retry = post_ema(
        &router,
        standard_form(&assertion),
        Some(&authorization),
        None,
    )
    .await;
    assert_eq!(retry.status, StatusCode::BAD_REQUEST);
    assert_eq!(retry.body["error"], "invalid_grant");
    assert!(retry.body.get("access_token").is_none());
}

#[tokio::test]
async fn concurrent_replay_allows_exactly_one_success() {
    let (state, assertion) = configured_state().await;
    let (router, _) = build_router(state);
    let form = serde_urlencoded::to_string([
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", assertion.as_str()),
        ("resource", RESOURCE),
        ("scope", "mcp:read"),
    ])
    .unwrap();
    let basic = format!(
        "Basic {}",
        STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
    );
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/token")
            .header("host", HOST)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("authorization", &basic)
            .body(Body::from(form.clone()))
            .unwrap()
    };

    let (first, second) = tokio::join!(
        router.clone().oneshot(request()),
        router.clone().oneshot(request())
    );
    let mut responses = vec![first.unwrap(), second.unwrap()];
    responses.sort_by_key(|response| response.status());

    assert_eq!(responses[0].status(), StatusCode::OK);
    assert_eq!(responses[1].status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(responses.pop().unwrap().into_body(), usize::MAX)
        .await
        .unwrap();
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["error"], "invalid_grant");
}

#[tokio::test]
async fn disabled_enterprise_user_is_rejected_before_replay_consumption() {
    let (state, assertion) = configured_state().await;
    let now = agent_auth_http::current_unix_secs();
    let user_id = derive_enterprise_user_id(
        &state.server_secret,
        "",
        IDP_ISSUER,
        Some(IDP_TENANT),
        "enterprise-user-1",
    );
    state
        .users
        .create_or_get_by_id("", &user_id, now)
        .await
        .unwrap();
    state
        .users
        .set_status("", &user_id, UserStatus::Disabled, now)
        .await
        .unwrap();
    let inspect = state.clone();
    let (router, _) = build_router(state);

    for expected in [StatusCode::BAD_REQUEST, StatusCode::OK] {
        let form = serde_urlencoded::to_string([
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion.as_str()),
            ("resource", RESOURCE),
            ("scope", "mcp:read"),
        ])
        .unwrap();
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header("host", HOST)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header(
                        "authorization",
                        format!(
                            "Basic {}",
                            STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
                        ),
                    )
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        if expected == StatusCode::BAD_REQUEST {
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(error["error"], "invalid_grant");
            inspect
                .users
                .set_status("", &user_id, UserStatus::Active, now + 1)
                .await
                .unwrap();
        }
    }
}

#[tokio::test]
async fn post_consume_and_final_identity_lifecycle_changes_fail_closed() {
    for (successful_reads, status) in [(0, UserStatus::Disabled), (1, UserStatus::Tombstoned)] {
        let (state, assertion) = configured_state().await;
        let now = agent_auth_http::current_unix_secs();
        let user_id = derive_enterprise_user_id(
            &state.server_secret,
            "",
            IDP_ISSUER,
            Some(IDP_TENANT),
            "enterprise-user-1",
        );
        state
            .users
            .create_or_get_by_id("", &user_id, now)
            .await
            .unwrap();
        match state.users.as_ref() {
            UsersStoreImpl::Memory(users) => {
                users
                    .transition_status_after_get_by_id(successful_reads, status)
                    .await;
            }
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(_) => panic!("dev state must use the memory users store"),
        }
        let inspect = state.clone();
        let (router, _) = build_router(state);

        let response = post_ema(
            &router,
            standard_form(&assertion),
            Some(&basic(CLIENT_ID, CLIENT_SECRET)),
            None,
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{status:?}");
        assert_eq!(response.body["error"], "invalid_grant");
        assert!(response.body.get("access_token").is_none());
        assert_eq!(
            inspect
                .users
                .get_by_id("", &user_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            status
        );

        let replay_key = derive_replay_key(
            &inspect.server_secret,
            "",
            IDP_ISSUER,
            Some(IDP_TENANT),
            "id-jag-1",
        );
        assert!(
            !inspect
                .replay_store
                .as_ref()
                .unwrap()
                .check_and_set("", &replay_key, now + 330)
                .await
                .unwrap(),
            "{status:?} transition must fail only after replay consumption"
        );
    }
}

#[tokio::test]
async fn ema_requires_the_registered_confidential_client_credentials() {
    let good_basic = basic(CLIENT_ID, CLIENT_SECRET);

    let (state, assertion) = configured_state().await;
    let (router, _) = build_router(state);
    let missing = post_ema(&router, standard_form(&assertion), None, None).await;
    assert_eq!(missing.status, StatusCode::UNAUTHORIZED);
    assert_eq!(missing.body["error"], "invalid_client");
    assert_eq!(missing.headers["cache-control"], "no-store");

    let (state, assertion) = configured_state().await;
    let (router, _) = build_router(state);
    let wrong = post_ema(
        &router,
        standard_form(&assertion),
        Some(&basic(CLIENT_ID, "wrong-secret")),
        None,
    )
    .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.body["error"], "invalid_client");
    assert_eq!(wrong.headers["www-authenticate"], "Basic realm=\"token\"");

    let (state, assertion) = configured_state().await;
    ClientStore::put(
        state.clients.as_ref(),
        "",
        ClientRecord {
            client_id: "public-ema-client".into(),
            token_endpoint_auth_method: "none".into(),
            client_type: Some("public".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (router, _) = build_router(state);
    let mut public_form = standard_form(&assertion);
    public_form.push(("client_id".into(), "public-ema-client".into()));
    let public = post_ema(&router, public_form, None, None).await;
    assert_eq!(public.status, StatusCode::UNAUTHORIZED);
    assert_eq!(public.body["error"], "invalid_client");

    let (state, assertion) = configured_state().await;
    let mut malformed_confidential = ClientStore::get(state.clients.as_ref(), "", CLIENT_ID)
        .await
        .unwrap()
        .unwrap();
    malformed_confidential.token_endpoint_auth_method = "none".into();
    malformed_confidential.client_type = Some("confidential".into());
    ClientStore::put(state.clients.as_ref(), "", malformed_confidential)
        .await
        .unwrap();
    let inspect = state.clone();
    let (router, _) = build_router(state);
    let mut malformed_form = standard_form(&assertion);
    malformed_form.push(("client_id".into(), CLIENT_ID.into()));
    let malformed = post_ema(&router, malformed_form, None, None).await;
    assert_eq!(malformed.status, StatusCode::UNAUTHORIZED);
    assert_eq!(malformed.body["error"], "invalid_client");
    let persisted = ClientStore::get(inspect.clients.as_ref(), "", CLIENT_ID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        persisted.client_secret.as_deref(),
        Some(CLIENT_SECRET),
        "malformed confidential+none records must fail before lazy secret migration"
    );
    assert!(persisted.client_secret_credentials.current.is_none());

    let (state, assertion) = configured_state().await;
    ClientStore::put(
        state.clients.as_ref(),
        "",
        ClientRecord {
            client_id: "other-client".into(),
            token_endpoint_auth_method: "client_secret_basic".into(),
            client_secret: Some("other-secret".into()),
            client_type: Some("confidential".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (router, _) = build_router(state);
    let cross_client = post_ema(
        &router,
        standard_form(&assertion),
        Some(&basic("other-client", "other-secret")),
        None,
    )
    .await;
    assert_eq!(cross_client.status, StatusCode::BAD_REQUEST);
    assert_eq!(cross_client.body["error"], "invalid_grant");
    assert_eq!(cross_client.headers["cache-control"], "no-store");

    // C13.2:ID-JAG 只属于 authorization-grant `assertion` 槽；EMA dispatch 不读取
    // client_assertion 或 RFC 8693 subject/actor token 槽，也不得因此消费 assertion jti。
    let (state, assertion) = configured_state().await;
    let (router, _) = build_router(state);

    let client_assertion_only = post_ema(
        &router,
        vec![
            (
                "grant_type".into(),
                "urn:ietf:params:oauth:grant-type:jwt-bearer".into(),
            ),
            (
                "client_assertion_type".into(),
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
            ),
            ("client_assertion".into(), assertion.clone()),
            ("resource".into(), RESOURCE.into()),
            ("scope".into(), "mcp:read".into()),
        ],
        Some(&good_basic),
        None,
    )
    .await;
    assert_eq!(client_assertion_only.status, StatusCode::UNAUTHORIZED);
    assert_eq!(client_assertion_only.body["error"], "invalid_client");
    assert!(client_assertion_only.body.get("access_token").is_none());
    assert_eq!(client_assertion_only.headers["cache-control"], "no-store");

    for token_slot in ["subject_token", "actor_token"] {
        let misplaced = post_ema(
            &router,
            vec![
                (
                    "grant_type".into(),
                    "urn:ietf:params:oauth:grant-type:jwt-bearer".into(),
                ),
                (token_slot.into(), assertion.clone()),
                (
                    format!("{token_slot}_type"),
                    "urn:ietf:params:oauth:token-type:access_token".into(),
                ),
                ("resource".into(), RESOURCE.into()),
                ("scope".into(), "mcp:read".into()),
            ],
            Some(&good_basic),
            None,
        )
        .await;
        assert_eq!(misplaced.status, StatusCode::BAD_REQUEST, "{token_slot}");
        assert_eq!(misplaced.body["error"], "invalid_request", "{token_slot}");
        assert_eq!(
            misplaced.body["error_description"], "assertion is required",
            "{token_slot}:JWT bearer grant 必须由独立 EMA dispatch 读取 assertion"
        );
        assert!(misplaced.body.get("access_token").is_none(), "{token_slot}");
        assert_eq!(
            misplaced.headers["cache-control"], "no-store",
            "{token_slot}"
        );
    }

    // 上述错误槽位请求不得消费 ID-JAG；同一 assertion 放回正确槽后必须仍可成功。
    let valid = post_ema(&router, standard_form(&assertion), Some(&good_basic), None).await;
    assert_eq!(valid.status, StatusCode::OK);
    assert!(valid.body["access_token"].is_string());
}

#[tokio::test]
async fn claim_policy_and_signature_failures_are_rejected_without_key_refresh() {
    let now = agent_auth_http::current_unix_secs();
    let default_header = || {
        serde_json::json!({
            "alg": "ES256",
            "typ": "oauth-id-jag+jwt",
            "kid": "idp-key-1",
        })
    };
    let mut cases = Vec::new();

    let mut wrong_issuer = valid_claims(now, "wrong-issuer");
    wrong_issuer["iss"] = serde_json::json!("https://attacker.example.com");
    cases.push(("wrong issuer", default_header(), wrong_issuer));

    let mut missing_issuer = valid_claims(now, "missing-issuer");
    missing_issuer.as_object_mut().unwrap().remove("iss");
    cases.push(("missing issuer", default_header(), missing_issuer));

    let mut wrong_tenant = valid_claims(now, "wrong-tenant");
    wrong_tenant["tenant"] = serde_json::json!("other-tenant");
    cases.push(("wrong issuer tenant", default_header(), wrong_tenant));

    let mut missing_tenant = valid_claims(now, "missing-tenant");
    missing_tenant.as_object_mut().unwrap().remove("tenant");
    cases.push(("missing issuer tenant", default_header(), missing_tenant));

    let mut wrong_audience = valid_claims(now, "wrong-audience");
    wrong_audience["aud"] = serde_json::json!("https://other-auth.example.com");
    cases.push(("wrong audience", default_header(), wrong_audience));

    let mut missing_audience = valid_claims(now, "missing-audience");
    missing_audience.as_object_mut().unwrap().remove("aud");
    cases.push(("missing audience", default_header(), missing_audience));

    let mut wrong_client = valid_claims(now, "wrong-client");
    wrong_client["client_id"] = serde_json::json!("another-enterprise-client");
    cases.push(("wrong assertion client", default_header(), wrong_client));

    let mut missing_client = valid_claims(now, "missing-client");
    missing_client.as_object_mut().unwrap().remove("client_id");
    cases.push(("missing assertion client", default_header(), missing_client));

    let mut wrong_resource = valid_claims(now, "wrong-resource");
    wrong_resource["resource"] = serde_json::json!("https://other-mcp.example.com");
    cases.push(("wrong assertion resource", default_header(), wrong_resource));

    let mut expired = valid_claims(now, "expired");
    expired["iat"] = serde_json::json!(now - 400);
    expired["nbf"] = serde_json::json!(now - 400);
    expired["exp"] = serde_json::json!(now - 100);
    cases.push(("expired", default_header(), expired));

    let mut future = valid_claims(now, "future");
    future["iat"] = serde_json::json!(now + 120);
    future["nbf"] = serde_json::json!(now + 120);
    future["exp"] = serde_json::json!(now + 300);
    cases.push(("future iat/nbf", default_header(), future));

    let mut missing_subject = valid_claims(now, "missing-subject");
    missing_subject.as_object_mut().unwrap().remove("sub");
    cases.push(("missing subject", default_header(), missing_subject));

    let mut missing_expiry = valid_claims(now, "missing-expiry");
    missing_expiry.as_object_mut().unwrap().remove("exp");
    cases.push(("missing expiry", default_header(), missing_expiry));

    let mut missing_issued_at = valid_claims(now, "missing-issued-at");
    missing_issued_at.as_object_mut().unwrap().remove("iat");
    cases.push(("missing issued-at", default_header(), missing_issued_at));

    let mut missing_jti = valid_claims(now, "missing-jti");
    missing_jti.as_object_mut().unwrap().remove("jti");
    cases.push(("missing JWT ID", default_header(), missing_jti));

    let mut missing_scope = valid_claims(now, "missing-scope");
    missing_scope.as_object_mut().unwrap().remove("scope");
    cases.push(("missing scope", default_header(), missing_scope));

    cases.push((
        "wrong type",
        serde_json::json!({"alg":"ES256","typ":"JWT","kid":"idp-key-1"}),
        valid_claims(now, "wrong-type"),
    ));
    cases.push((
        "wrong algorithm",
        serde_json::json!({
            "alg":"RS256",
            "typ":"oauth-id-jag+jwt",
            "kid":"idp-key-1"
        }),
        valid_claims(now, "wrong-algorithm"),
    ));

    for (label, header, claims) in cases {
        let (assertion, jwk) = sign_id_jag(header, claims);
        let (state, _) = configured_state().await;
        state.jwks_fetcher_set(JWKS_URI, vec![jwk]).await;
        let inspect = state.clone();
        let (router, _) = build_router(state);
        let response = post_ema(
            &router,
            standard_form(&assertion),
            Some(&basic(CLIENT_ID, CLIENT_SECRET)),
            None,
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{label}");
        assert_eq!(response.body["error"], "invalid_grant", "{label}");
        assert_eq!(response.headers["cache-control"], "no-store", "{label}");
        assert_eq!(
            inspect.jwks_fetcher_fresh_calls(JWKS_URI).await,
            Some(0),
            "{label} must not trigger unknown-kid refresh"
        );
    }

    let (valid, jwk) = id_jag(now);
    let mut parts: Vec<_> = valid.split('.').map(str::to_string).collect();
    parts[2] = URL_SAFE_NO_PAD.encode([0u8; 64]);
    let bad_signature = parts.join(".");
    let (state, _) = configured_state().await;
    state.jwks_fetcher_set(JWKS_URI, vec![jwk]).await;
    let inspect = state.clone();
    let (router, _) = build_router(state);
    let response = post_ema(
        &router,
        standard_form(&bad_signature),
        Some(&basic(CLIENT_ID, CLIENT_SECRET)),
        None,
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.body["error"], "invalid_grant");
    assert_eq!(inspect.jwks_fetcher_fresh_calls(JWKS_URI).await, Some(0));

    let (mut state, assertion) = configured_state().await;
    state.ema_policies = std::sync::Arc::new(vec![TenantEmaPolicy {
        agent_auth_tenant: String::new(),
        policy: policy_with_algorithms(vec![SigningAlgorithm::Rs256]),
    }]);
    let (router, _) = build_router(state);
    let response = post_ema(
        &router,
        standard_form(&assertion),
        Some(&basic(CLIENT_ID, CLIENT_SECRET)),
        None,
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.body["error"], "invalid_grant");
    assert!(response.body.get("access_token").is_none());
}

#[tokio::test]
async fn key_selection_accepts_one_compatible_no_kid_key_and_rejects_ambiguity() {
    let now = agent_auth_http::current_unix_secs();
    let mut claims_without_nbf = valid_claims(now, "no-kid");
    claims_without_nbf.as_object_mut().unwrap().remove("nbf");
    let (without_kid, jwk) = sign_id_jag(
        serde_json::json!({
            "alg":"ES256",
            "typ":"oauth-id-jag+jwt"
        }),
        claims_without_nbf,
    );
    let (state, _) = configured_state().await;
    let (_, incompatible_rsa_jwk) = rs256_id_jag(now);
    state
        .jwks_fetcher_set(JWKS_URI, vec![jwk.clone(), incompatible_rsa_jwk])
        .await;
    let (router, _) = build_router(state);
    let accepted = post_ema(
        &router,
        standard_form(&without_kid),
        Some(&basic(CLIENT_ID, CLIENT_SECRET)),
        None,
    )
    .await;
    assert_eq!(accepted.status, StatusCode::OK);

    let (assertion, jwk) = id_jag(now);
    let (state, _) = configured_state().await;
    state
        .jwks_fetcher_set(JWKS_URI, vec![jwk.clone(), jwk])
        .await;
    let inspect = state.clone();
    let (router, _) = build_router(state);
    let rejected = post_ema(
        &router,
        standard_form(&assertion),
        Some(&basic(CLIENT_ID, CLIENT_SECRET)),
        None,
    )
    .await;
    assert_eq!(rejected.status, StatusCode::BAD_REQUEST);
    assert_eq!(rejected.body["error"], "invalid_grant");
    assert_eq!(inspect.jwks_fetcher_fresh_calls(JWKS_URI).await, Some(0));
}

#[tokio::test]
async fn assertion_headers_and_claims_cannot_select_the_trust_anchor() {
    let now = agent_auth_http::current_unix_secs();
    let mut claims = valid_claims(now, "attacker-trust-anchor");
    claims["jwks_uri"] = serde_json::json!(ATTACKER_JWKS_URI);
    claims["jku"] = serde_json::json!(ATTACKER_JWKS_URI);
    let (assertion, attacker_jwk) = sign_id_jag_with_seed(
        29,
        serde_json::json!({
            "alg": "ES256",
            "typ": "oauth-id-jag+jwt",
            "kid": "idp-key-1",
            "jku": ATTACKER_JWKS_URI,
            "x5u": ATTACKER_JWKS_URI,
        }),
        claims,
    );
    let (state, _) = configured_state().await;
    state
        .jwks_fetcher_set(ATTACKER_JWKS_URI, vec![attacker_jwk])
        .await;
    let inspect = state.clone();
    let (router, _) = build_router(state);

    let response = post_ema(
        &router,
        standard_form(&assertion),
        Some(&basic(CLIENT_ID, CLIENT_SECRET)),
        None,
    )
    .await;

    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.body["error"], "invalid_grant");
    assert!(response.body.get("access_token").is_none());
    assert_eq!(inspect.jwks_fetcher_calls(JWKS_URI).await, Some(1));
    assert_eq!(inspect.jwks_fetcher_fresh_calls(JWKS_URI).await, Some(0));
    assert_eq!(inspect.jwks_fetcher_calls(ATTACKER_JWKS_URI).await, Some(0));
    assert_eq!(
        inspect.jwks_fetcher_fresh_calls(ATTACKER_JWKS_URI).await,
        Some(0)
    );
}

#[tokio::test]
async fn invalid_target_and_request_rar_do_not_consume_the_assertion() {
    let (state, assertion) = configured_state().await;
    let (router, _) = build_router(state);
    let auth = basic(CLIENT_ID, CLIENT_SECRET);

    let mut missing_resource = standard_form(&assertion);
    missing_resource.retain(|(name, _)| name != "resource");
    let response = post_ema(&router, missing_resource, Some(&auth), None).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.body["error"], "invalid_target");

    for resource in ["not-a-uri", "https://other-mcp.example.com"] {
        let mut invalid_resource = standard_form(&assertion);
        invalid_resource
            .iter_mut()
            .find(|(name, _)| name == "resource")
            .unwrap()
            .1 = resource.into();
        let response = post_ema(&router, invalid_resource, Some(&auth), None).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{resource}");
        assert_eq!(response.body["error"], "invalid_target", "{resource}");
    }

    let mut rar = standard_form(&assertion);
    rar.push((
        "authorization_details".into(),
        r#"[{"type":"account_information"}]"#.into(),
    ));
    let response = post_ema(&router, rar, Some(&auth), None).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.body["error"], "invalid_authorization_details");

    let valid = post_ema(&router, standard_form(&assertion), Some(&auth), None).await;
    assert_eq!(valid.status, StatusCode::OK);
}

#[tokio::test]
async fn strict_missing_assertion_resource_does_not_consume_the_jti() {
    let now = agent_auth_http::current_unix_secs();
    let jti = "strict-missing-assertion-resource";
    let mut missing_resource_claims = valid_claims(now, jti);
    missing_resource_claims
        .as_object_mut()
        .unwrap()
        .remove("resource");
    let (missing_resource, jwk) = sign_id_jag(default_id_jag_header(), missing_resource_claims);
    let (state, _) = configured_state().await;
    state.jwks_fetcher_set(JWKS_URI, vec![jwk]).await;
    let (router, _) = build_router(state);
    let auth = basic(CLIENT_ID, CLIENT_SECRET);

    let rejected = post_ema(&router, standard_form(&missing_resource), Some(&auth), None).await;
    assert_eq!(rejected.status, StatusCode::BAD_REQUEST);
    assert_eq!(rejected.body["error"], "invalid_grant");
    assert!(rejected.body.get("access_token").is_none());

    let (valid, _) = sign_id_jag(default_id_jag_header(), valid_claims(now, jti));
    let accepted = post_ema(&router, standard_form(&valid), Some(&auth), None).await;
    assert_eq!(accepted.status, StatusCode::OK);
    assert!(accepted.body["access_token"].is_string());
}

#[tokio::test]
async fn assertion_rar_actor_and_missing_dpop_binding_fail_closed() {
    let now = agent_auth_http::current_unix_secs();
    for (label, mut claims) in [
        ("non-empty RAR", valid_claims(now, "assertion-rar")),
        (
            "malformed RAR",
            valid_claims(now, "assertion-malformed-rar"),
        ),
        ("actor", valid_claims(now, "assertion-actor")),
        ("cnf", valid_claims(now, "assertion-cnf")),
    ] {
        match label {
            "non-empty RAR" => {
                claims["authorization_details"] =
                    serde_json::json!([{"type":"account_information"}]);
            }
            "malformed RAR" => claims["authorization_details"] = serde_json::json!([{}]),
            "actor" => claims["act"] = serde_json::json!({"sub":"delegating-agent"}),
            "cnf" => claims["cnf"] = serde_json::json!({"jkt":"required-thumbprint"}),
            _ => unreachable!(),
        }
        let (assertion, jwk) = sign_id_jag(
            serde_json::json!({
                "alg":"ES256",
                "typ":"oauth-id-jag+jwt",
                "kid":"idp-key-1"
            }),
            claims,
        );
        let (state, _) = configured_state().await;
        state.jwks_fetcher_set(JWKS_URI, vec![jwk]).await;
        let (router, _) = build_router(state);
        let response = post_ema(
            &router,
            standard_form(&assertion),
            Some(&basic(CLIENT_ID, CLIENT_SECRET)),
            None,
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{label}");
        assert_eq!(response.body["error"], "invalid_grant", "{label}");
        assert!(response.body.get("access_token").is_none(), "{label}");
    }

    let (proof_key, proof_jwk, _) = dpop_key(77);
    let mismatched_proof = dpop_proof(&proof_key, &proof_jwk, "ema-wrong-binding", now);
    let mut claims = valid_claims(now, "assertion-cnf-mismatch");
    claims["cnf"] = serde_json::json!({"jkt":"required-thumbprint"});
    let (assertion, jwk) = sign_id_jag(default_id_jag_header(), claims);
    let (state, _) = configured_state().await;
    state.jwks_fetcher_set(JWKS_URI, vec![jwk]).await;
    let (router, _) = build_router(state);
    let response = post_ema(
        &router,
        standard_form(&assertion),
        Some(&basic(CLIENT_ID, CLIENT_SECRET)),
        Some(&mismatched_proof),
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.body["error"], "invalid_grant");
    assert!(response.body.get("access_token").is_none());
}

#[tokio::test]
async fn dpop_is_bound_from_assertion_to_the_issued_access_token() {
    let now = agent_auth_http::current_unix_secs();

    // Assertion 不带 cnf 时，合法 proof 应把 access token 绑定到 proof key。
    let (proof_key, dpop_jwk, dpop_jkt) = dpop_key(41);
    let proof = dpop_proof(&proof_key, &dpop_jwk, "ema-dpop-1", now);
    let (assertion, jwk) = sign_id_jag(
        serde_json::json!({
            "alg":"ES256",
            "typ":"oauth-id-jag+jwt",
            "kid":"idp-key-1"
        }),
        valid_claims(now, "proof-derived-binding"),
    );
    let (state, _) = configured_state().await;
    state.jwks_fetcher_set(JWKS_URI, vec![jwk]).await;
    let inspect = state.clone();
    let (router, _) = build_router(state);
    let response = post_ema(
        &router,
        standard_form(&assertion),
        Some(&basic(CLIENT_ID, CLIENT_SECRET)),
        Some(&proof),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body["token_type"], "DPoP");
    let signing_jwk = inspect.signer.public_jwks().await.unwrap().remove(0);
    let access_claims = verify_access_token_signature(
        response.body["access_token"].as_str().unwrap(),
        &signing_jwk,
    );
    assert_eq!(access_claims["cnf"]["jkt"], dpop_jkt);

    // Assertion 已带 cnf 时，匹配 proof 应逐值保留 assertion binding。
    let (assertion_key, assertion_jwk, assertion_jkt) = dpop_key(42);
    let assertion_proof = dpop_proof(
        &assertion_key,
        &assertion_jwk,
        "ema-dpop-assertion-bound",
        now,
    );
    let mut assertion_claims = valid_claims(now, "assertion-derived-binding");
    assertion_claims["cnf"] = serde_json::json!({"jkt":assertion_jkt});
    let (bound_assertion, bound_jwk) = sign_id_jag(
        serde_json::json!({
            "alg":"ES256",
            "typ":"oauth-id-jag+jwt",
            "kid":"idp-key-1"
        }),
        assertion_claims,
    );
    let (state, _) = configured_state().await;
    state.jwks_fetcher_set(JWKS_URI, vec![bound_jwk]).await;
    let inspect = state.clone();
    let (router, _) = build_router(state);
    let bound = post_ema(
        &router,
        standard_form(&bound_assertion),
        Some(&basic(CLIENT_ID, CLIENT_SECRET)),
        Some(&assertion_proof),
    )
    .await;
    assert_eq!(bound.status, StatusCode::OK);
    assert_eq!(bound.body["token_type"], "DPoP");
    let signing_jwk = inspect.signer.public_jwks().await.unwrap().remove(0);
    let bound_claims =
        verify_access_token_signature(bound.body["access_token"].as_str().unwrap(), &signing_jwk);
    assert_eq!(bound_claims["cnf"]["jkt"], assertion_jkt);

    // Assertion 与请求都没有 sender constraint 时，EMA 保持 Bearer 且不得编造 cnf。
    let (state, bearer_assertion) = configured_state().await;
    let inspect = state.clone();
    let (router, _) = build_router(state);
    let bearer = post_ema(
        &router,
        standard_form(&bearer_assertion),
        Some(&basic(CLIENT_ID, CLIENT_SECRET)),
        None,
    )
    .await;
    assert_eq!(bearer.status, StatusCode::OK);
    assert_eq!(bearer.body["token_type"], "Bearer");
    let signing_jwk = inspect.signer.public_jwks().await.unwrap().remove(0);
    let bearer_claims =
        verify_access_token_signature(bearer.body["access_token"].as_str().unwrap(), &signing_jwk);
    assert!(
        bearer_claims.get("cnf").is_none(),
        "proof-free EMA issuance must not invent cnf"
    );

    let (state, assertion) = configured_state().await;
    let (router, _) = build_router(state);
    let malformed = post_ema(
        &router,
        standard_form(&assertion),
        Some(&basic(CLIENT_ID, CLIENT_SECRET)),
        Some("not-a-jwt"),
    )
    .await;
    assert_eq!(malformed.status, StatusCode::BAD_REQUEST);
    assert_eq!(malformed.body["error"], "invalid_dpop_proof");
    assert!(
        malformed.body.get("access_token").is_none(),
        "invalid DPoP proof must not leak an access token"
    );
    assert!(
        malformed.body.get("refresh_token").is_none(),
        "invalid DPoP proof must not leak a refresh token"
    );
    assert!(
        malformed.body.get("token_type").is_none(),
        "invalid DPoP proof must not downgrade to a Bearer token response"
    );
}

#[tokio::test]
async fn enterprise_identity_conflicts_and_tombstones_are_rejected_pre_replay() {
    for status in [UserStatus::Active, UserStatus::Tombstoned] {
        let (state, assertion) = configured_state().await;
        let now = agent_auth_http::current_unix_secs();
        let user_id = derive_enterprise_user_id(
            &state.server_secret,
            "",
            IDP_ISSUER,
            Some(IDP_TENANT),
            "enterprise-user-1",
        );
        state
            .users
            .create_or_get_by_email("", "conflict@example.com", &user_id, now)
            .await
            .unwrap();
        if status == UserStatus::Tombstoned {
            state
                .users
                .set_status("", &user_id, UserStatus::Tombstoned, now + 1)
                .await
                .unwrap();
        }
        let (rejected_router, _) = build_router(state.clone());
        let rejected = post_ema(
            &rejected_router,
            standard_form(&assertion),
            Some(&basic(CLIENT_ID, CLIENT_SECRET)),
            None,
        )
        .await;
        assert_eq!(rejected.status, StatusCode::BAD_REQUEST);
        assert_eq!(rejected.body["error"], "invalid_grant");

        let mut repaired = state;
        repaired.users = std::sync::Arc::new(UsersStoreImpl::Memory(
            agent_auth_http::adapters::memory::MemoryUsersStore::default(),
        ));
        let (repaired_router, _) = build_router(repaired);
        let accepted = post_ema(
            &repaired_router,
            standard_form(&assertion),
            Some(&basic(CLIENT_ID, CLIENT_SECRET)),
            None,
        )
        .await;
        assert_eq!(
            accepted.status,
            StatusCode::OK,
            "{status:?} identity rejection must not consume replay state"
        );
    }
}

#[tokio::test]
async fn post_replay_signer_failure_is_retryable_but_keeps_the_assertion_consumed() {
    let (mut state, assertion) = configured_state().await;
    let signer = agent_auth_http::adapters::memory::MemorySigner::from_seed([55u8; 32]);
    signer.fail_next_es256(true);
    let signer = std::sync::Arc::new(agent_auth_http::state::SignerImpl::Memory(signer));
    state.signer = signer.clone();
    state.tenant_keys = std::sync::Arc::new(
        agent_auth_http::tenant_keys::TenantKeyService::shared(signer),
    );
    let (router, _) = build_router(state);
    let auth = basic(CLIENT_ID, CLIENT_SECRET);

    let failed = post_ema(&router, standard_form(&assertion), Some(&auth), None).await;
    assert_eq!(failed.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(failed.body["error"], "temporarily_unavailable");
    assert_eq!(failed.headers["retry-after"], "1");
    assert_eq!(failed.headers["cache-control"], "no-store");

    let retry = post_ema(&router, standard_form(&assertion), Some(&auth), None).await;
    assert_eq!(retry.status, StatusCode::BAD_REQUEST);
    assert_eq!(retry.body["error"], "invalid_grant");
}

#[tokio::test]
async fn post_replay_permanent_signer_failure_is_server_error_without_sensitive_material() {
    let (mut state, assertion) = configured_state().await;
    let signer = agent_auth_http::adapters::memory::MemorySigner::from_seed([56u8; 32]);
    signer.fail_next_es256(false);
    let signer = std::sync::Arc::new(agent_auth_http::state::SignerImpl::Memory(signer));
    state.signer = signer.clone();
    state.tenant_keys = std::sync::Arc::new(
        agent_auth_http::tenant_keys::TenantKeyService::shared(signer),
    );
    let (router, _) = build_router(state);
    let auth = basic(CLIENT_ID, CLIENT_SECRET);

    let failed = post_ema(&router, standard_form(&assertion), Some(&auth), None).await;
    assert_eq!(failed.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(failed.body["error"], "server_error");
    assert_eq!(failed.body["error_description"], "token signing failed");
    assert_eq!(failed.headers["cache-control"], "no-store");
    assert!(failed.headers.get("retry-after").is_none());
    let response_body = failed.body.to_string();
    for sensitive in [&assertion, IDP_ISSUER, "enterprise-user-1", "access_token"] {
        assert!(
            !response_body.contains(sensitive),
            "permanent failure response exposed sensitive EMA material"
        );
    }

    let retry = post_ema(&router, standard_form(&assertion), Some(&auth), None).await;
    assert_eq!(retry.status, StatusCode::BAD_REQUEST);
    assert_eq!(retry.body["error"], "invalid_grant");
}

#[tokio::test]
async fn replay_and_enterprise_identity_are_partitioned_by_agent_auth_tenant() {
    let now = agent_auth_http::current_unix_secs();
    let mut state = AppState::dev(HOST);
    state.form = agent_auth_discovery::Form::Saas {
        zone: "auth.example.com".into(),
        control_host: "c.auth.example.com".into(),
    };
    state.tenant_partitioning = true;
    state.saas_tenants = std::sync::Arc::new(vec!["t1".into(), "t2".into()]);
    state.phase = Phase::P2;
    state.ema_enabled = true;
    state.ema_policies = std::sync::Arc::new(
        ["t1", "t2"]
            .into_iter()
            .map(|tenant| TenantEmaPolicy {
                agent_auth_tenant: tenant.into(),
                policy: policy(),
            })
            .collect(),
    );
    for tenant in ["t1", "t2"] {
        ClientStore::put(
            state.clients.as_ref(),
            tenant,
            ClientRecord {
                client_id: CLIENT_ID.into(),
                token_endpoint_auth_method: "client_secret_basic".into(),
                client_secret: Some(CLIENT_SECRET.into()),
                client_type: Some("confidential".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }

    let mut t1_claims = valid_claims(now, "same-jti-across-tenants");
    t1_claims["aud"] = serde_json::json!("https://t1.auth.example.com");
    let (t1_assertion, jwk) = sign_id_jag(
        serde_json::json!({
            "alg":"ES256",
            "typ":"oauth-id-jag+jwt",
            "kid":"idp-key-1"
        }),
        t1_claims,
    );
    let mut t2_claims = valid_claims(now, "same-jti-across-tenants");
    t2_claims["aud"] = serde_json::json!("https://t2.auth.example.com");
    let (t2_assertion, _) = sign_id_jag(
        serde_json::json!({
            "alg":"ES256",
            "typ":"oauth-id-jag+jwt",
            "kid":"idp-key-1"
        }),
        t2_claims,
    );
    state.jwks_fetcher_set(JWKS_URI, vec![jwk]).await;
    let inspect = state.clone();
    let (router, _) = build_router(state);
    let auth = basic(CLIENT_ID, CLIENT_SECRET);
    let signing_jwk = inspect.signer.public_jwks().await.unwrap().remove(0);

    for (tenant, host, assertion) in [
        ("t1", "t1.auth.example.com", t1_assertion),
        ("t2", "t2.auth.example.com", t2_assertion),
    ] {
        let response =
            post_ema_host(&router, host, standard_form(&assertion), Some(&auth), None).await;
        assert_eq!(response.status, StatusCode::OK, "{host}: {}", response.body);
        let claims = verify_access_token_signature(
            response.body["access_token"].as_str().unwrap(),
            &signing_jwk,
        );
        assert_eq!(claims["iss"], format!("https://{host}"));
        assert_eq!(claims["aud"], serde_json::json!([RESOURCE]));
        assert_eq!(claims["client_id"], CLIENT_ID);
        assert_eq!(claims["scope"], "mcp:read");
        let user_id = derive_enterprise_user_id(
            &inspect.server_secret,
            tenant,
            IDP_ISSUER,
            Some(IDP_TENANT),
            "enterprise-user-1",
        );
        assert_eq!(
            claims["sub"],
            agent_auth_token::pairwise_sub(&inspect.server_secret, &user_id, RESOURCE)
        );
    }

    let t1_user = derive_enterprise_user_id(
        &inspect.server_secret,
        "t1",
        IDP_ISSUER,
        Some(IDP_TENANT),
        "enterprise-user-1",
    );
    let t2_user = derive_enterprise_user_id(
        &inspect.server_secret,
        "t2",
        IDP_ISSUER,
        Some(IDP_TENANT),
        "enterprise-user-1",
    );
    assert_ne!(t1_user, t2_user);
    assert!(inspect
        .users
        .get_by_id("t1", &t1_user)
        .await
        .unwrap()
        .is_some());
    assert!(inspect
        .users
        .get_by_id("t2", &t2_user)
        .await
        .unwrap()
        .is_some());
}
