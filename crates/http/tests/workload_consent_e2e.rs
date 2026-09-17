//! Production HTTP authorization -> consent -> code -> workload exchange.
//! Fixtures configure identities and a platform JWKS only: Grants, refresh
//! families, authorization codes and JTI authority are created by HTTP handlers.

use agent_auth_http::adapters::memory::MemoryJwksFetcher;
use agent_auth_http::ports::{PlatformJwk, WorkloadTrustStore};
use agent_auth_http::state::JwksFetcherImpl;
use agent_auth_http::{build_router, AppState, Phase};
use agent_auth_workload::{TrustBinding, TrustMechanism};
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

const HOST: &str = "localhost";
const RESOURCE: &str = "https://covedb.example";
const CLIENT: &str = "coveai";
const REDIRECT: &str = "http://127.0.0.1/callback";
const VERIFIER: &str = "0123456789012345678901234567890123456789abc";
const PLATFORM: &str = "https://platform.example";
const JWKS: &str = "https://platform.example/jwks";
const TE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";
const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

fn form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter().copied())
        .finish()
}

async fn request(
    router: &axum::Router,
    method: &str,
    path: &str,
    cookie: &str,
    content_type: &str,
    body: String,
) -> (StatusCode, HeaderMap, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("host", HOST)
                .header("cookie", cookie)
                .header("content-type", content_type)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value =
        serde_json::from_slice(&bytes).unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes)));
    (status, headers, value)
}

fn cookie(headers: &HeaderMap, name: &str) -> String {
    headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&format!("{name}=")))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

async fn login_session(router: &axum::Router) -> String {
    let (status, headers, body) = request(
        router,
        "POST",
        "/login/magic-link",
        "",
        "application/json",
        json!({"email":"alice@example.com", "authorize_query":""}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let nonce = cookie(&headers, "__Host-agent_auth_login_nonce");
    let link = url::Url::parse(body["dev_link"].as_str().unwrap()).unwrap();
    let (status, headers, body) = request(
        router,
        "GET",
        &format!("{}?{}", link.path(), link.query().unwrap()),
        &nonce,
        "",
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    cookie(&headers, "__Host-agent_auth_session")
}

struct Fixture {
    router: axum::Router,
    state: AppState,
    session: String,
    key: rsa::RsaPrivateKey,
}

impl Fixture {
    async fn new() -> Self {
        let mut state = AppState::dev(HOST);
        state.phase = Phase::P2;
        state.seed_dev_client(CLIENT, REDIRECT, None).await;
        state.seed_dev_user("alice@example.com").await;
        for actor in ["analysis-runtime", "ops-runtime"] {
            state.seed_workload_client(actor).await;
            state
                .workload_trust
                .put(
                    "",
                    actor.into(),
                    TrustBinding {
                        tenant_id: "default".into(),
                        mechanism: TrustMechanism::Oidc {
                            platform_issuer: PLATFORM.into(),
                            jwks_uri: JWKS.into(),
                            subject_pattern: actor.into(),
                        },
                        mapped_client_id: actor.into(),
                    },
                )
                .await
                .unwrap();
        }
        state
            .seed_rs_introspect_client("covedb-rs", "rs-secret", &[RESOURCE])
            .await;
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let public = key.to_public_key();
        let fetcher = MemoryJwksFetcher::default();
        fetcher
            .set(
                JWKS,
                vec![PlatformJwk {
                    kid: Some("platform-key".into()),
                    kty: Some("RSA".into()),
                    n: B64.encode(public.n().to_bytes_be()),
                    e: B64.encode(public.e().to_bytes_be()),
                    alg: Some("RS256".into()),
                    ..Default::default()
                }],
            )
            .await;
        state.jwks_fetcher = Arc::new(JwksFetcherImpl::Memory(fetcher));
        let (router, _) = build_router(state.clone());
        let session = login_session(&router).await;
        Self {
            router,
            state,
            session,
            key,
        }
    }

    fn actor(&self, actor: &str) -> String {
        let now = agent_auth_http::current_unix_secs();
        let header =
            B64.encode(json!({"alg":"RS256", "typ":"JWT", "kid":"platform-key"}).to_string());
        let payload = B64.encode(json!({"iss":PLATFORM,"sub":actor,"aud":format!("https://{HOST}"),"iat":now,"exp":now+300}).to_string());
        let input = format!("{header}.{payload}");
        let signature = SigningKey::<sha2::Sha256>::new(self.key.clone()).sign(input.as_bytes());
        format!("{input}.{}", B64.encode(signature.to_bytes()))
    }

    fn query(&self, actor: Option<&str>, resource: &str) -> String {
        let mut query = form(&[
            ("response_type", "code"),
            ("client_id", CLIENT),
            ("redirect_uri", REDIRECT),
            (
                "code_challenge",
                &agent_auth_client::s256_challenge(VERIFIER),
            ),
            ("code_challenge_method", "S256"),
            ("scope", "openid db:read"),
            ("resource", resource),
        ]);
        if let Some(actor) = actor {
            query.push('&');
            query.push_str(&form(&[("workload_actor", actor)]));
        }
        query
    }

    async fn consent(&self, query: &str) -> (String, Value) {
        let (status, headers, body) = request(
            &self.router,
            "GET",
            &format!("/authorize?{query}"),
            &self.session,
            "",
            String::new(),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
        let location = url::Url::parse(headers["location"].to_str().unwrap()).unwrap();
        assert_eq!(location.path(), "/consent");
        let query = location.query().unwrap().to_string();
        let (status, _, context) = request(
            &self.router,
            "GET",
            &format!("/consent/context?{query}"),
            &self.session,
            "",
            String::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{context}");
        (query, context)
    }

    async fn approve(&self, query: &str, context: &Value) -> (StatusCode, Value) {
        let (status, _, body) = request(
            &self.router,
            "POST",
            "/consent/decision",
            &self.session,
            "application/json",
            json!({"decision":"approve","csrf":context["csrf_token"],"authorize_query":query,"workload_actor":context["workload_actor"]})
                .to_string(),
        )
        .await;
        (status, body)
    }

    async fn authorize(&self, actor: Option<&str>) -> Value {
        let (query, context) = self.consent(&self.query(actor, RESOURCE)).await;
        assert_eq!(context["workload_actor"].as_str(), actor);
        let (status, decision) = self.approve(&query, &context).await;
        assert_eq!(status, StatusCode::OK, "{decision}");
        let redirect = url::Url::parse(decision["redirect"].as_str().unwrap()).unwrap();
        let code = redirect
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned();
        let (status, body) = self
            .token(&[
                ("grant_type", "authorization_code"),
                ("client_id", CLIENT),
                ("redirect_uri", REDIRECT),
                ("code", &code),
                ("code_verifier", VERIFIER),
                ("resource", RESOURCE),
            ])
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    async fn token(&self, fields: &[(&str, &str)]) -> (StatusCode, Value) {
        let (status, _, body) = request(
            &self.router,
            "POST",
            "/token",
            "",
            "application/x-www-form-urlencoded",
            form(fields),
        )
        .await;
        (status, body)
    }

    async fn exchange(&self, subject: &str, actor: &str, resource: &str) -> (StatusCode, Value) {
        self.token(&[
            ("grant_type", TE),
            ("subject_token", subject),
            ("subject_token_type", ACCESS),
            ("actor_token", &self.actor(actor)),
            ("actor_token_type", JWT_BEARER),
            ("resource", resource),
            ("scope", "db:read"),
        ])
        .await
    }

    async fn refresh(&self, token: &str) -> (StatusCode, Value) {
        self.token(&[
            ("grant_type", "refresh_token"),
            ("client_id", CLIENT),
            ("refresh_token", token),
            ("resource", RESOURCE),
        ])
        .await
    }
}

fn claims(token: &str) -> Value {
    serde_json::from_slice(&B64.decode(token.split('.').nth(1).unwrap()).unwrap()).unwrap()
}

async fn introspect(f: &Fixture, token: &str) -> Value {
    let response = f
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/introspect")
                .header("host", HOST)
                .header(
                    "authorization",
                    format!(
                        "Basic {}",
                        base64::engine::general_purpose::STANDARD.encode("covedb-rs:rs-secret")
                    ),
                )
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form(&[("token", token)])))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap()
}

async fn exchange_flow(advance_clock: bool) {
    let f = Fixture::new().await;
    let issued = f.authorize(Some("analysis-runtime")).await;
    let subject = issued["access_token"].as_str().unwrap();
    let initial_claims = claims(subject);
    let (status, delegated) = f.exchange(subject, "analysis-runtime", RESOURCE).await;
    assert_eq!(status, StatusCode::OK, "{delegated}");
    assert!(delegated.get("refresh_token").is_none());
    let token = delegated["access_token"].as_str().unwrap();
    let decoded = claims(token);
    assert_eq!(decoded["aud"], json!([RESOURCE]));
    assert_eq!(decoded["act"], json!({"sub":"analysis-runtime"}));
    assert_eq!(introspect(&f, token).await["active"], true);
    let (status, body) = f.exchange(subject, "ops-runtime", RESOURCE).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = f
        .exchange(subject, "analysis-runtime", "https://other.example")
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = f.exchange(token, "analysis-runtime", RESOURCE).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    if advance_clock {
        let clock_file = std::env::var("A_AUTH_TEST_CLOCK_FILE")
            .expect("run scripts/run_deferred_exchange_test.sh");
        std::fs::write(clock_file, "7201\n").unwrap();
        let now = agent_auth_http::current_unix_secs();
        assert!(now - initial_claims["iat"].as_i64().unwrap() >= 7200);
        assert!(now > initial_claims["exp"].as_i64().unwrap() + 60);
        let (status, body) = f.exchange(subject, "analysis-runtime", RESOURCE).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "expired original subject: {body}"
        );
    }
    let (status, refreshed) = f.refresh(issued["refresh_token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{refreshed}");
    assert_ne!(issued["refresh_token"], refreshed["refresh_token"]);
    let refreshed_subject = refreshed["access_token"].as_str().unwrap();
    let (status, delegated) = f
        .exchange(refreshed_subject, "analysis-runtime", RESOURCE)
        .await;
    assert_eq!(status, StatusCode::OK, "{delegated}");
    let delegated_token = delegated["access_token"].as_str().unwrap();
    assert_eq!(introspect(&f, delegated_token).await["active"], true);
    let session = if advance_clock {
        login_session(&f.router).await
    } else {
        f.session.clone()
    };
    let (status, _, grants) =
        request(&f.router, "GET", "/grants", &session, "", String::new()).await;
    assert_eq!(status, StatusCode::OK, "{grants}");
    let grant_id = grants[0]["grant_id"].as_str().unwrap();
    assert_eq!(grants[0]["actor_allowlist"], json!(["analysis-runtime"]));
    let (status, _, body) = request(
        &f.router,
        "DELETE",
        &format!("/grants/{grant_id}"),
        &session,
        "",
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = f
        .refresh(refreshed["refresh_token"].as_str().unwrap())
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "revoked refresh: {body}");
    let (status, body) = f
        .exchange(refreshed_subject, "analysis-runtime", RESOURCE)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "revoked exchange: {body}");
    assert_eq!(introspect(&f, delegated_token).await["active"], false);
}

#[tokio::test]
async fn workload_consent_exchange_refresh_and_revocation_use_only_http() {
    exchange_flow(false).await;
}

#[tokio::test]
#[ignore = "requires isolated process clock; scripts/run_deferred_exchange_test.sh"]
async fn workload_consent_deferred_exchange_after_two_hours() {
    exchange_flow(true).await;
}

#[tokio::test]
async fn workload_consent_rejects_invalid_requests_and_csrf_actor_substitution() {
    let f = Fixture::new().await;
    for query in [
        f.query(Some("missing-workload"), RESOURCE),
        f.query(Some(CLIENT), RESOURCE),
        f.query(Some("analysis-*"), RESOURCE),
        f.query(Some(""), RESOURCE),
        f.query(Some("analysis-runtime"), ""),
        format!(
            "{}&resource=https://other.example",
            f.query(Some("analysis-runtime"), RESOURCE)
        ),
        format!(
            "{}&workload_actor=ops-runtime",
            f.query(Some("analysis-runtime"), RESOURCE)
        ),
    ] {
        let (status, _, body) = request(
            &f.router,
            "GET",
            &format!("/authorize?{query}"),
            &f.session,
            "",
            String::new(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {body}");
        let (status, _, body) = request(
            &f.router,
            "GET",
            &format!("/consent/context?{query}"),
            &f.session,
            "",
            String::new(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "direct context {query}: {body}"
        );
    }
    let (query, context) = f
        .consent(&f.query(Some("analysis-runtime"), RESOURCE))
        .await;
    let changed = query.replace("analysis-runtime", "ops-runtime");
    let (status, body) = f.approve(&changed, &context).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "CSRF must bind actor: {body}"
    );
    // Retiring the workload between display and approval must invalidate consent.
    use agent_auth_http::ports::ClientStore;
    f.state
        .clients
        .delete("", "analysis-runtime")
        .await
        .unwrap();
    let (status, body) = f.approve(&query, &context).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "retired workload: {body}");
}

#[tokio::test]
async fn workload_consent_is_never_inferred_or_silently_approved() {
    let f = Fixture::new().await;
    let issued = f.authorize(None).await;
    let (status, body) = f
        .exchange(
            issued["access_token"].as_str().unwrap(),
            "analysis-runtime",
            RESOURCE,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "ordinary consent grants no workload: {body}"
    );
    let query = format!(
        "{}&prompt=none",
        f.query(Some("analysis-runtime"), RESOURCE)
    );
    let (status, headers, body) = request(
        &f.router,
        "GET",
        &format!("/authorize?{query}"),
        &f.session,
        "",
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert!(headers["location"]
        .to_str()
        .unwrap()
        .contains("error=consent_required"));
}

#[tokio::test]
async fn workload_consent_lifecycle_disable_and_reenable_cannot_restore_old_authority() {
    let f = Fixture::new().await;
    let issued = f.authorize(Some("analysis-runtime")).await;
    let subject = issued["access_token"].as_str().unwrap();
    for action in ["disable", "enable"] {
        let response = f
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/admin/users/user:alice@example.com/{action}"))
                    .header("host", HOST)
                    .header("authorization", "Bearer dev-admin-token-not-for-prod")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let (status, body) = f.refresh(issued["refresh_token"].as_str().unwrap()).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{action} old refresh: {body}"
        );
        let (status, body) = f.exchange(subject, "analysis-runtime", RESOURCE).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{action} old exchange: {body}"
        );
    }
}

#[tokio::test]
async fn workload_consent_grant_ref_does_not_replace_a_live_subject() {
    let f = Fixture::new().await;
    let issued = f.authorize(Some("analysis-runtime")).await;
    let (_, _, grants) = request(&f.router, "GET", "/grants", &f.session, "", String::new()).await;
    let grant_id = grants[0]["grant_id"].as_str().unwrap();
    let (status, _, reference) = request(
        &f.router,
        "POST",
        &format!("/grants/{grant_id}/refs"),
        &f.session,
        "application/json",
        json!({"bound_agent":"analysis-runtime"}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{reference}");
    let grant_ref = reference["grant_ref"].as_str().unwrap();
    let (status, body) = f
        .token(&[
            ("grant_type", TE),
            ("subject_token", grant_ref),
            (
                "subject_token_type",
                "urn:agent-auth:params:token-type:grant-ref",
            ),
            ("actor_token", &f.actor("analysis-runtime")),
            ("actor_token_type", JWT_BEARER),
            ("resource", RESOURCE),
        ])
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "standalone grant ref must fail: {body}"
    );
    let (status, body) = f
        .token(&[
            ("grant_type", TE),
            ("subject_token", issued["access_token"].as_str().unwrap()),
            ("subject_token_type", ACCESS),
            ("grant_ref", grant_ref),
            ("actor_token", &f.actor("analysis-runtime")),
            ("actor_token_type", JWT_BEARER),
            ("resource", RESOURCE),
        ])
        .await;
    assert_eq!(status, StatusCode::OK, "live subject plus selector: {body}");
}

#[tokio::test]
async fn workload_consent_requires_explicit_actor_acknowledgement_from_the_page() {
    let f = Fixture::new().await;
    let (query, context) = f
        .consent(&f.query(Some("analysis-runtime"), RESOURCE))
        .await;
    let (status, _, body) = request(
        &f.router,
        "POST",
        "/consent/decision",
        &f.session,
        "application/json",
        json!({"decision":"approve","csrf":context["csrf_token"],"authorize_query":query})
            .to_string(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an old page that cannot display actors must not approve: {body}"
    );
}

async fn admin_post(router: &axum::Router, path: &str, body: Value) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("host", HOST)
                .header("authorization", "Bearer dev-admin-token-not-for-prod")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body =
        serde_json::from_slice(&bytes).unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes)));
    (status, body)
}

#[tokio::test]
async fn workload_consent_admin_registered_actor_completes_first_exchange() {
    let f = Fixture::new().await;
    let (status, registered) = admin_post(
        &f.router,
        "/admin/clients",
        json!({"client_type":"workload","redirect_uris":[]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{registered}");
    assert_eq!(registered["client_type"], "workload");
    assert!(registered.get("client_secret").is_none());
    let actor = registered["client_id"].as_str().unwrap();
    let (status, body) = admin_post(
        &f.router,
        "/admin/workload-trust",
        json!({
            "binding_id":"http-registered-actor",
            "tenant_id":"default",
            "platform_issuer":PLATFORM,
            "jwks_uri":JWKS,
            "subject_pattern":actor,
            "mapped_client_id":actor
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let tokens = f.authorize(Some(actor)).await;
    let (status, delegated) = f
        .exchange(tokens["access_token"].as_str().unwrap(), actor, RESOURCE)
        .await;
    assert_eq!(status, StatusCode::OK, "{delegated}");
    let claims = claims(delegated["access_token"].as_str().unwrap());
    assert_eq!(claims["act"]["sub"], actor);
    let (status, body) = f
        .token(&[
            ("grant_type", "client_credentials"),
            ("client_assertion", &f.actor(actor)),
            ("client_assertion_type", JWT_BEARER),
            ("resource", RESOURCE),
        ])
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_target");

    let query = form(&[
        ("response_type", "code"),
        ("client_id", actor),
        ("redirect_uri", REDIRECT),
        (
            "code_challenge",
            &agent_auth_client::s256_challenge(VERIFIER),
        ),
        ("code_challenge_method", "S256"),
    ]);
    let (status, _, body) = request(
        &f.router,
        "GET",
        &format!("/authorize?{query}"),
        &f.session,
        "",
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn workload_registration_is_admin_only_and_rejects_mixed_client_profiles() {
    let f = Fixture::new().await;
    let valid = json!({"client_type":"workload","redirect_uris":[]});
    let (status, _, body) = request(
        &f.router,
        "POST",
        "/admin/clients",
        &f.session,
        "application/json",
        valid.to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    for patch in [
        json!({"client_type":"unknown"}),
        json!({"redirect_uris":[REDIRECT]}),
        json!({"token_endpoint_auth_method":"client_secret_basic"}),
        json!({"introspect_enabled":true}),
        json!({"post_logout_redirect_uris":[REDIRECT]}),
    ] {
        let mut body = valid.clone();
        body.as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        let (status, body) = admin_post(&f.router, "/admin/clients", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
    let mut earlier_phase = f.state.clone();
    earlier_phase.phase = Phase::P1;
    let (router, _) = build_router(earlier_phase);
    let (status, body) = admin_post(&router, "/admin/clients", valid).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let (status, _, registration) = request(
        &f.router,
        "POST",
        "/register",
        "",
        "application/json",
        json!({"client_type":"workload","application_type":"native","redirect_uris":[REDIRECT],"token_endpoint_auth_method":"none"})
            .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{registration}");
    let actor = registration["client_id"].as_str().unwrap();
    let (status, _, body) = request(
        &f.router,
        "GET",
        &format!("/authorize?{}", f.query(Some(actor), RESOURCE)),
        &f.session,
        "",
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}
