//! Issue #77 controlled acceptance: prepare -> per-payment strong consent ->
//! one-hop workload exchange -> execute -> query, all over production HTTP.
//!
//! Fixtures configure identities, strong authentication sessions, the
//! platform JWKS and the synthetic payment registry/channel only. Intents,
//! Grants, codes, tokens and attempts are created by HTTP handlers; nothing
//! patches a store to skip authorization.

use std::sync::Arc;

use agent_auth_http::adapters::memory::MemoryJwksFetcher;
use agent_auth_http::payment::adapter::SubmitFault;
use agent_auth_http::payment::registry::{FundingSource, Payee};
use agent_auth_http::payment::store::PaymentStore;
use agent_auth_http::payment::{ControlledParts, PaymentConfig, PaymentModule};
use agent_auth_http::ports::{PlatformJwk, SessionRecord, SessionStore, WorkloadTrustStore};
use agent_auth_http::state::{GrantStoreImpl, JwksFetcherImpl};
use agent_auth_http::{build_router, AppState, Phase};
use agent_auth_payment::{ChannelState, PaymentIntent, PaymentStatus};
use agent_auth_workload::{TrustBinding, TrustMechanism};
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use serde_json::{json, Value};
use tower::ServiceExt;

const HOST: &str = "localhost";
const PAYMENTS: &str = "https://payments.example";
const OTHER_RESOURCE: &str = "https://covedb.example";
const CLIENT: &str = "coveai";
const OTHER_CLIENT: &str = "other-app";
const REDIRECT: &str = "http://127.0.0.1/callback";
const VERIFIER: &str = "0123456789012345678901234567890123456789abc";
const PLATFORM: &str = "https://platform.example";
const JWKS: &str = "https://platform.example/jwks";
const ACTOR: &str = "pay-runtime";
const OTHER_ACTOR: &str = "other-runtime";
const ALICE: &str = "user:alice@example.com";
const BOB: &str = "user:bob@example.com";
const STRONG_ACR: &str = "urn:agent-auth:assurance:strong";
const TE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";
const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const PAYMENT_TYPE: &str = "agent_auth_payment_v1";

fn now() -> i64 {
    agent_auth_http::current_unix_secs()
}

fn form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter().copied())
        .finish()
}

fn claims(token: &str) -> Value {
    serde_json::from_slice(&B64.decode(token.split('.').nth(1).unwrap()).unwrap()).unwrap()
}

async fn send(router: &axum::Router, request: Request<Body>) -> (StatusCode, HeaderMap, Value) {
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value =
        serde_json::from_slice(&bytes).unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes)));
    (status, headers, value)
}

fn browser(method: &str, path: &str, cookie: &str, body: Option<Value>) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", HOST)
        .header("cookie", cookie);
    match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

fn api(method: &str, path: &str, bearer: Option<&str>, body: Option<Value>) -> Request<Body> {
    api_at(HOST, method, path, bearer, body)
}

fn api_at(
    host: &str,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", host);
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

fn config() -> PaymentConfig {
    PaymentConfig {
        resource: PAYMENTS.into(),
        currency: "USD".into(),
        currency_exponent: 2,
        max_amount_minor: 100_000,
        max_execute_window_secs: 3600,
    }
}

fn payment_details(intent_id: &str) -> Value {
    json!([{"type": PAYMENT_TYPE, "intent_id": intent_id}])
}

/// One `/authorize` request for the given client and parameters.
struct AuthzRequest<'a> {
    client: &'a str,
    scope: &'a str,
    resources: Vec<&'a str>,
    actor: Option<&'a str>,
    details: Option<Value>,
    extra: Vec<(&'a str, &'a str)>,
}

impl<'a> AuthzRequest<'a> {
    fn payment(intent_id: &str) -> AuthzRequest<'static> {
        AuthzRequest {
            client: CLIENT,
            scope: "payments:execute",
            resources: vec![PAYMENTS],
            actor: Some(ACTOR),
            details: Some(payment_details(intent_id)),
            extra: vec![],
        }
    }

    fn query(&self) -> String {
        let challenge = agent_auth_client::s256_challenge(VERIFIER);
        let mut pairs = vec![
            ("response_type", "code".to_string()),
            ("client_id", self.client.to_string()),
            ("redirect_uri", REDIRECT.to_string()),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256".to_string()),
            ("scope", self.scope.to_string()),
            ("state", "app-state".to_string()),
        ];
        for resource in &self.resources {
            pairs.push(("resource", resource.to_string()));
        }
        if let Some(actor) = self.actor {
            pairs.push(("workload_actor", actor.to_string()));
        }
        if let Some(details) = &self.details {
            pairs.push(("authorization_details", details.to_string()));
        }
        for (key, value) in &self.extra {
            pairs.push((*key, value.to_string()));
        }
        let borrowed: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
        form(&borrowed)
    }
}

/// A prepared, authorized intent and the credentials of each party.
struct Authorized {
    intent_id: String,
    /// The 3LO client's user token for the payment resource (no `act`).
    subject_token: String,
    /// The designated actor's delegated token.
    delegated: String,
}

struct Fixture {
    router: axum::Router,
    state: AppState,
    parts: ControlledParts,
    alice: String,
    bob: String,
    alice_prepare: String,
    bob_prepare: String,
    alice_sub: String,
    key: rsa::RsaPrivateKey,
}

async fn strong_session(state: &AppState, user_id: &str, auth_time: i64) -> String {
    let session_id = format!(
        "strong-{}-{}",
        user_id.replace([':', '@', '.'], "-"),
        auth_time
    );
    let issued = now();
    state
        .sessions
        .create(
            "",
            SessionRecord {
                session_id: session_id.clone(),
                user_id: user_id.to_string(),
                credential_epoch: 0,
                auth_time,
                created_at: auth_time,
                last_used_at: issued,
                device: "Passkey browser".into(),
                expires_at: issued + 3600,
                acr: Some(STRONG_ACR.to_string()),
                amr: vec!["webauthn".into(), "hwk".into()],
            },
        )
        .await
        .unwrap();
    format!("__Host-agent_auth_session={session_id}")
}

impl Fixture {
    async fn new() -> Self {
        Self::with_config(Some(config())).await
    }

    async fn with_config(payment: Option<PaymentConfig>) -> Self {
        let mut state = AppState::dev(HOST);
        state.phase = Phase::P2;
        state.seed_dev_client(CLIENT, REDIRECT, None).await;
        state.seed_dev_client(OTHER_CLIENT, REDIRECT, None).await;
        state.seed_dev_user("alice@example.com").await;
        state.seed_dev_user("bob@example.com").await;
        for actor in [ACTOR, OTHER_ACTOR] {
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
        let (module, parts) = PaymentModule::controlled(
            payment.clone().unwrap_or_else(config),
            b"controlled-callback-secret",
        )
        .unwrap();
        if payment.is_some() {
            state.payments = Some(Arc::new(module));
        }
        let (router, _) = build_router(state.clone());
        let alice = strong_session(&state, ALICE, now()).await;
        let bob = strong_session(&state, BOB, now()).await;
        let mut fixture = Self {
            router,
            state,
            parts,
            alice,
            bob,
            alice_prepare: String::new(),
            bob_prepare: String::new(),
            alice_sub: String::new(),
            key,
        };
        fixture.alice_prepare = fixture.prepare_token(&fixture.alice.clone(), CLIENT).await;
        fixture.bob_prepare = fixture.prepare_token(&fixture.bob.clone(), CLIENT).await;
        fixture.alice_sub = claims(&fixture.alice_prepare)["sub"]
            .as_str()
            .unwrap()
            .to_string();
        let bob_sub = claims(&fixture.bob_prepare)["sub"]
            .as_str()
            .unwrap()
            .to_string();
        for (id, owner, label) in [
            ("fs_alice", fixture.alice_sub.clone(), "Visa •••• 4242"),
            ("fs_bob", bob_sub, "Mastercard •••• 5555"),
        ] {
            fixture
                .parts
                .registry
                .put_funding_source(
                    "",
                    FundingSource {
                        funding_source_id: id.into(),
                        owner,
                        version: 1,
                        label: label.into(),
                        currency: "USD".into(),
                        active: true,
                    },
                )
                .await;
        }
        fixture.put_payee(1).await;
        fixture
    }

    async fn put_payee(&self, version: u64) {
        self.parts
            .registry
            .put_payee(
                "",
                Payee {
                    payee_id: "merchant_books".into(),
                    version,
                    name: "Example Books Ltd".into(),
                    active: true,
                },
            )
            .await;
    }

    fn module(&self) -> &PaymentModule {
        self.state.payments.as_deref().unwrap()
    }

    fn actor_assertion(&self, actor: &str) -> String {
        let issued = now();
        let header =
            B64.encode(json!({"alg":"RS256","typ":"JWT","kid":"platform-key"}).to_string());
        let payload = B64.encode(
            json!({"iss":PLATFORM,"sub":actor,"aud":format!("https://{HOST}"),"iat":issued,"exp":issued+300})
                .to_string(),
        );
        let input = format!("{header}.{payload}");
        let signature = SigningKey::<sha2::Sha256>::new(self.key.clone()).sign(input.as_bytes());
        format!("{input}.{}", B64.encode(signature.to_bytes()))
    }

    /// `/authorize` → `/consent` redirect → `/consent/context`.
    async fn consent(
        &self,
        session: &str,
        request: &AuthzRequest<'_>,
    ) -> Result<(String, Value), (StatusCode, HeaderMap, Value)> {
        let (status, headers, body) = send(
            &self.router,
            browser(
                "GET",
                &format!("/authorize?{}", request.query()),
                session,
                None,
            ),
        )
        .await;
        let location = headers
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|v| url::Url::parse(v).unwrap());
        let Some(location) =
            location.filter(|l| status == StatusCode::SEE_OTHER && l.path() == "/consent")
        else {
            return Err((status, headers, body));
        };
        let query = location.query().unwrap().to_string();
        let (status, headers, context) = send(
            &self.router,
            browser("GET", &format!("/consent/context?{query}"), session, None),
        )
        .await;
        if status != StatusCode::OK {
            return Err((status, headers, context));
        }
        Ok((query, context))
    }

    async fn decide(
        &self,
        session: &str,
        query: &str,
        context: &Value,
        digest: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut body = json!({
            "decision": "approve",
            "csrf": context["csrf_token"],
            "authorize_query": query,
            "workload_actor": context["workload_actor"],
        });
        if let Some(digest) = digest {
            body["payment_terms_digest"] = json!(digest);
        }
        let (status, _, body) = send(
            &self.router,
            browser("POST", "/consent/decision", session, Some(body)),
        )
        .await;
        (status, body)
    }

    async fn token(&self, fields: &[(&str, &str)]) -> (StatusCode, Value) {
        let (status, _, body) = send(
            &self.router,
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form(fields)))
                .unwrap(),
        )
        .await;
        (status, body)
    }

    async fn redeem(&self, client: &str, redirect: &Value, resource: &str) -> Value {
        let redirect = url::Url::parse(redirect["redirect"].as_str().unwrap()).unwrap();
        let code = redirect
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap_or_else(|| panic!("no code in {redirect}"))
            .1
            .into_owned();
        let (status, body) = self
            .token(&[
                ("grant_type", "authorization_code"),
                ("client_id", client),
                ("redirect_uri", REDIRECT),
                ("code", &code),
                ("code_verifier", VERIFIER),
                ("resource", resource),
            ])
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    /// Complete an authorization, acknowledging a payment digest when present.
    async fn authorize(&self, session: &str, request: &AuthzRequest<'_>) -> Value {
        let (query, context) = self
            .consent(session, request)
            .await
            .unwrap_or_else(|(status, _, body)| panic!("consent failed {status}: {body}"));
        let digest = context["payment"]["terms_digest"]
            .as_str()
            .map(String::from);
        let (status, decision) = self
            .decide(session, &query, &context, digest.as_deref())
            .await;
        assert_eq!(status, StatusCode::OK, "{decision}");
        self.redeem(request.client, &decision, request.resources[0])
            .await
    }

    async fn prepare_token(&self, session: &str, client: &str) -> String {
        let issued = self
            .authorize(
                session,
                &AuthzRequest {
                    client,
                    scope: "payments:prepare",
                    resources: vec![PAYMENTS],
                    actor: None,
                    details: None,
                    extra: vec![],
                },
            )
            .await;
        issued["access_token"].as_str().unwrap().to_string()
    }

    async fn exchange(&self, subject: &str, actor: &str) -> (StatusCode, Value) {
        self.token(&[
            ("grant_type", TE),
            ("subject_token", subject),
            ("subject_token_type", ACCESS),
            ("actor_token", &self.actor_assertion(actor)),
            ("actor_token_type", JWT_BEARER),
            ("resource", PAYMENTS),
            ("scope", "payments:execute"),
        ])
        .await
    }

    fn order(&self, order_id: &str, amount: &str, execute_before: i64) -> Value {
        json!({
            "order_id": order_id,
            "actor": ACTOR,
            "funding_source_id": "fs_alice",
            "payee_id": "merchant_books",
            "amount_minor": amount,
            "currency": "USD",
            "execute_before": execute_before,
        })
    }

    async fn prepare(&self, token: &str, body: Value) -> (StatusCode, Value) {
        let (status, _, body) = send(
            &self.router,
            api("POST", "/payments/intents", Some(token), Some(body)),
        )
        .await;
        (status, body)
    }

    async fn prepared(&self, order_id: &str) -> String {
        let (status, body) = self
            .prepare(
                &self.alice_prepare,
                self.order(order_id, "1999", now() + 600),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body["intent_id"].as_str().unwrap().to_string()
    }

    /// Prepare, approve with strong consent, redeem and exchange for the actor.
    async fn authorized(&self, order_id: &str) -> Authorized {
        let intent_id = self.prepared(order_id).await;
        self.authorize_intent(intent_id).await
    }

    async fn authorize_intent(&self, intent_id: String) -> Authorized {
        let issued = self
            .authorize(&self.alice, &AuthzRequest::payment(&intent_id))
            .await;
        let subject_token = issued["access_token"].as_str().unwrap().to_string();
        let (status, delegated) = self.exchange(&subject_token, ACTOR).await;
        assert_eq!(status, StatusCode::OK, "{delegated}");
        Authorized {
            intent_id,
            subject_token,
            delegated: delegated["access_token"].as_str().unwrap().to_string(),
        }
    }

    async fn execute(&self, token: &str, intent_id: &str) -> (StatusCode, Value) {
        let (status, _, body) = send(
            &self.router,
            api(
                "POST",
                &format!("/payments/intents/{intent_id}/execute"),
                Some(token),
                None,
            ),
        )
        .await;
        (status, body)
    }

    async fn get(&self, token: &str, intent_id: &str) -> (StatusCode, Value) {
        let (status, _, body) = send(
            &self.router,
            api(
                "GET",
                &format!("/payments/intents/{intent_id}"),
                Some(token),
                None,
            ),
        )
        .await;
        (status, body)
    }

    async fn reconcile(&self, token: &str, intent_id: &str) -> (StatusCode, Value) {
        let (status, _, body) = send(
            &self.router,
            api(
                "POST",
                &format!("/payments/intents/{intent_id}/reconcile"),
                Some(token),
                None,
            ),
        )
        .await;
        (status, body)
    }

    async fn callback(&self, body: &[u8], signature: &str) -> (StatusCode, Value) {
        let (status, _, body) = send(
            &self.router,
            Request::builder()
                .method("POST")
                .uri("/payments/channel/callback")
                .header("host", HOST)
                .header("content-type", "application/json")
                .header("x-payment-signature", signature)
                .body(Body::from(body.to_vec()))
                .unwrap(),
        )
        .await;
        (status, body)
    }

    async fn record(&self, intent_id: &str) -> PaymentIntent {
        self.parts.store.get("", intent_id).await.unwrap().unwrap()
    }

    async fn idempotency_key(&self, intent_id: &str) -> String {
        self.record(intent_id)
            .await
            .attempt
            .expect("attempt")
            .idempotency_key
    }

    async fn grant_ids(&self) -> Vec<String> {
        let (status, _, grants) =
            send(&self.router, browser("GET", "/grants", &self.alice, None)).await;
        assert_eq!(status, StatusCode::OK, "{grants}");
        grants
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g["grant_id"].as_str().unwrap().to_string())
            .collect()
    }

    async fn grant_of(&self, token: &str) -> String {
        claims(token)["https://a-auth.com/c"]["auth_grant"]
            .as_str()
            .unwrap()
            .to_string()
    }

    async fn revoke(&self, grant_id: &str) {
        let (status, _, body) = send(
            &self.router,
            browser("DELETE", &format!("/grants/{grant_id}"), &self.alice, None),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    }

    async fn channel_calls(&self) -> u64 {
        self.parts.adapter.submit_calls().await
    }
}

fn reconcile_internal<'a>(
    f: &'a Fixture,
    intent_id: &'a str,
) -> impl std::future::Future<Output = PaymentIntent> + 'a {
    async move {
        agent_auth_http::payment::recovery::reconcile_intent(f.module(), "", intent_id)
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn payment_prepare_consent_execute_and_query_use_only_http() {
    let f = Fixture::new().await;
    let (status, prepared) = f
        .prepare(&f.alice_prepare, f.order("order-1", "1999", now() + 600))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{prepared}");
    assert_eq!(prepared["status"], "PREPARED");
    assert_eq!(prepared["client_id"], CLIENT);
    assert_eq!(prepared["actor"], ACTOR);
    assert_eq!(prepared["funding_source"]["label"], "Visa •••• 4242");
    assert_eq!(prepared["payee"]["name"], "Example Books Ltd");
    let intent_id = prepared["intent_id"].as_str().unwrap().to_string();
    assert_eq!(
        prepared["authorization_details"],
        json!([{"type": PAYMENT_TYPE, "intent_id": intent_id, "locations": [PAYMENTS], "actions": ["execute"]}])
    );

    // The consent page shows the frozen terms exactly as prepared.
    let (query, context) = f
        .consent(&f.alice, &AuthzRequest::payment(&intent_id))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let view = &context["payment"];
    assert_eq!(view["intent_id"], intent_id);
    assert_eq!(view["terms_digest"], prepared["terms_digest"]);
    assert_eq!(view["amount_minor"], "1999");
    assert_eq!(view["currency"], "USD");
    assert_eq!(view["currency_exponent"], 2);
    assert_eq!(view["funding_source"], prepared["funding_source"]);
    assert_eq!(view["payee"], prepared["payee"]);
    assert_eq!(view["actor"], ACTOR);
    assert_eq!(view["execute_before"], prepared["execute_before"]);
    assert_eq!(context["workload_actor"], ACTOR);
    assert_eq!(context["authorization_details"][0]["type"], PAYMENT_TYPE);
    assert_eq!(
        context["authorization_details"][0]["terms_digest"],
        prepared["terms_digest"]
    );
    let (status, decision) = f
        .decide(&f.alice, &query, &context, view["terms_digest"].as_str())
        .await;
    assert_eq!(status, StatusCode::OK, "{decision}");
    let issued = f.redeem(CLIENT, &decision, PAYMENTS).await;
    let subject = issued["access_token"].as_str().unwrap();
    let subject_claims = claims(subject);
    assert_eq!(subject_claims["acr"], STRONG_ACR);
    assert_eq!(
        subject_claims["authorization_details"][0]["terms_digest"],
        prepared["terms_digest"]
    );

    // The designated workload performs the only delegation hop.
    let (status, delegated) = f.exchange(subject, ACTOR).await;
    assert_eq!(status, StatusCode::OK, "{delegated}");
    let delegated = delegated["access_token"].as_str().unwrap();
    let delegated_claims = claims(delegated);
    assert_eq!(delegated_claims["act"], json!({"sub": ACTOR}));
    assert_eq!(delegated_claims["aud"], json!([PAYMENTS]));
    assert_eq!(
        delegated_claims["authorization_details"],
        subject_claims["authorization_details"]
    );
    let (status, body) = f.exchange(subject, OTHER_ACTOR).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "undesignated actor: {body}");
    assert_eq!(
        f.channel_calls().await,
        0,
        "issuance never touches the channel"
    );

    let (status, executed) = f.execute(delegated, &intent_id).await;
    assert_eq!(status, StatusCode::OK, "{executed}");
    assert_eq!(executed["status"], "SUCCEEDED");
    let channel_txn = executed["attempt"]["channel_transaction_id"]
        .as_str()
        .unwrap()
        .to_string();
    let transactions = f.parts.adapter.transactions().await;
    assert_eq!(transactions.len(), 1);
    let txn = &transactions[0];
    assert_eq!(txn.channel_transaction_id, channel_txn);
    assert_eq!(txn.amount_minor, "1999");
    assert_eq!(txn.currency, "USD");
    assert_eq!(txn.payee_id, "merchant_books");
    assert_eq!(txn.funding_source_id, "fs_alice");
    assert_eq!(txn.reference, intent_id);
    assert_eq!(txn.idempotency_key, f.idempotency_key(&intent_id).await);

    // Both parties can query; neither query starts anything new.
    for token in [f.alice_prepare.as_str(), delegated] {
        let (status, body) = f.get(token, &intent_id).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "SUCCEEDED");
        assert_eq!(body["attempt"]["channel_transaction_id"], channel_txn);
        assert!(body["attempt"].get("idempotency_key").is_none());
    }
    let (status, again) = f.execute(delegated, &intent_id).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(
        again["attempt"]["attempt_id"],
        executed["attempt"]["attempt_id"]
    );
    assert_eq!(f.channel_calls().await, 1);
    assert_eq!(f.parts.adapter.transactions().await.len(), 1);
}

#[tokio::test]
async fn payment_consent_requires_fresh_strong_explicit_digest_acknowledgement() {
    let f = Fixture::new().await;
    let intent_id = f.prepared("order-consent").await;
    let request = AuthzRequest::payment(&intent_id);

    // A baseline (magic-link) session is sent to step-up before consent.
    let (status, headers, body) = send(
        &f.router,
        browser("GET", &format!("/authorize?{}", request.query()), "", None),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let location = headers["location"].to_str().unwrap();
    assert!(location.contains("/login?"), "{location}");
    assert!(
        location.contains("acr_values=urn%3Aagent-auth%3Aassurance%3Astrong"),
        "{location}"
    );

    // prompt=none can never approve a payment silently.
    let silent = AuthzRequest {
        extra: vec![("prompt", "none")],
        ..AuthzRequest::payment(&intent_id)
    };
    let (status, headers, body) = send(
        &f.router,
        browser(
            "GET",
            &format!("/authorize?{}", silent.query()),
            &f.alice,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let location = headers["location"].to_str().unwrap();
    assert!(location.starts_with(REDIRECT), "{location}");
    assert!(location.contains("error=consent_required"), "{location}");
    assert!(!location.contains("code="));

    let (query, context) = f
        .consent(&f.alice, &request)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let digest = context["payment"]["terms_digest"]
        .as_str()
        .unwrap()
        .to_string();
    // An older page that does not acknowledge the digest cannot approve.
    let (status, body) = f.decide(&f.alice, &query, &context, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "no digest: {body}");
    let (status, body) = f
        .decide(
            &f.alice,
            &query,
            &context,
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "wrong digest: {body}");
    // The CSRF token binds the full continuation, including the intent reference.
    let other = f.prepared("order-consent-other").await;
    let tampered = query.replace(&intent_id, &other);
    assert_ne!(tampered, query);
    let (status, body) = f.decide(&f.alice, &tampered, &context, Some(&digest)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "tampered query: {body}");
    // The page must echo the displayed actor.
    let (status, body) = send(
        &f.router,
        browser(
            "POST",
            "/consent/decision",
            &f.alice,
            Some(json!({"decision":"approve","csrf":context["csrf_token"],"authorize_query":query,"workload_actor":OTHER_ACTOR,"payment_terms_digest":digest})),
        ),
    )
    .await
    .then_status_body();
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "actor substitution: {body}"
    );
    // A registry change between display and approval invalidates the consent.
    f.put_payee(2).await;
    let (status, body) = f.decide(&f.alice, &query, &context, Some(&digest)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "registry changed: {body}");
    f.put_payee(1).await;
    let (status, decision) = f.decide(&f.alice, &query, &context, Some(&digest)).await;
    assert_eq!(status, StatusCode::OK, "{decision}");
    // The same continuation cannot be approved twice.
    let (status, body) = f.decide(&f.alice, &query, &context, Some(&digest)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "replayed approval: {body}");
    assert_eq!(f.channel_calls().await, 0);
}

trait StatusBody {
    fn then_status_body(self) -> (StatusCode, Value);
}

impl StatusBody for (StatusCode, HeaderMap, Value) {
    fn then_status_body(self) -> (StatusCode, Value) {
        (self.0, self.2)
    }
}

#[tokio::test]
async fn payment_consent_rejects_strong_authentication_that_is_stale_at_approval() {
    let f = Fixture::new().await;
    let intent_id = f.prepared("order-stale").await;
    // Fresh enough when the request starts, older than 300 s when approved.
    let session = strong_session(&f.state, ALICE, now() - 298).await;
    let (query, context) = f
        .consent(&session, &AuthzRequest::payment(&intent_id))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let digest = context["payment"]["terms_digest"].as_str().unwrap();
    let (status, body) = f.decide(&session, &query, &context, Some(digest)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body.to_string()
            .contains("unmet_authentication_requirements"),
        "{body}"
    );
}

#[tokio::test]
async fn payment_authorization_rejects_mismatched_or_tampered_requests() {
    let f = Fixture::new().await;
    let intent_id = f.prepared("order-reject").await;
    let cancelled = f.prepared("order-cancelled").await;
    let (status, body) = send(
        &f.router,
        api(
            "POST",
            &format!("/payments/intents/{cancelled}/cancel"),
            Some(&f.alice_prepare),
            None,
        ),
    )
    .await
    .then_status_body();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "CANCELLED");
    let reference = payment_details(&intent_id)[0].clone();
    let generic = json!({"type": "agent_auth_rar_v1", "locations": [PAYMENTS]});
    let cases: Vec<(&str, AuthzRequest)> = vec![
        (
            "other client",
            AuthzRequest {
                client: OTHER_CLIENT,
                ..AuthzRequest::payment(&intent_id)
            },
        ),
        (
            "other actor",
            AuthzRequest {
                actor: Some(OTHER_ACTOR),
                ..AuthzRequest::payment(&intent_id)
            },
        ),
        (
            "no actor",
            AuthzRequest {
                actor: None,
                ..AuthzRequest::payment(&intent_id)
            },
        ),
        (
            "other resource",
            AuthzRequest {
                resources: vec![OTHER_RESOURCE],
                ..AuthzRequest::payment(&intent_id)
            },
        ),
        (
            "extra resource",
            AuthzRequest {
                resources: vec![PAYMENTS, OTHER_RESOURCE],
                ..AuthzRequest::payment(&intent_id)
            },
        ),
        (
            "mixed generic entry",
            AuthzRequest {
                details: Some(json!([reference, generic])),
                ..AuthzRequest::payment(&intent_id)
            },
        ),
        (
            "two payment entries",
            AuthzRequest {
                details: Some(json!([reference, payment_details(&cancelled)[0]])),
                ..AuthzRequest::payment(&intent_id)
            },
        ),
        (
            "client-supplied amount",
            AuthzRequest {
                details: Some(
                    json!([{"type": PAYMENT_TYPE, "intent_id": intent_id, "amount_minor": "1"}]),
                ),
                ..AuthzRequest::payment(&intent_id)
            },
        ),
        (
            "client-supplied terms",
            AuthzRequest {
                details: Some(json!([{"type": PAYMENT_TYPE, "intent_id": intent_id, "terms": {}}])),
                ..AuthzRequest::payment(&intent_id)
            },
        ),
        (
            "wrong locations",
            AuthzRequest {
                details: Some(
                    json!([{"type": PAYMENT_TYPE, "intent_id": intent_id, "locations": [OTHER_RESOURCE]}]),
                ),
                ..AuthzRequest::payment(&intent_id)
            },
        ),
        (
            "transfer action",
            AuthzRequest {
                details: Some(
                    json!([{"type": PAYMENT_TYPE, "intent_id": intent_id, "actions": ["transfer"]}]),
                ),
                ..AuthzRequest::payment(&intent_id)
            },
        ),
        (
            "unknown version",
            AuthzRequest {
                details: Some(json!([{"type": "agent_auth_payment_v2", "intent_id": intent_id}])),
                ..AuthzRequest::payment(&intent_id)
            },
        ),
        ("unknown intent", AuthzRequest::payment("pi_does_not_exist")),
        ("cancelled intent", AuthzRequest::payment(&cancelled)),
    ];
    for (name, request) in cases {
        let (status, _, body) = send(
            &f.router,
            browser(
                "GET",
                &format!("/authorize?{}", request.query()),
                &f.alice,
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}: {body}");
        // Driving consent directly cannot display or approve the request
        // either. An unknown RAR type keeps the generic behavior: the context
        // displays no details and the decision fails closed.
        let (status, _, body) = send(
            &f.router,
            browser(
                "GET",
                &format!("/consent/context?{}", request.query()),
                &f.alice,
                None,
            ),
        )
        .await;
        match status {
            StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN => {}
            StatusCode::OK => {
                assert!(body.get("payment").is_none(), "{name}: {body}");
                assert!(
                    body.get("authorization_details").is_none(),
                    "{name}: {body}"
                );
                let (status, decision) = f.decide(&f.alice, &request.query(), &body, None).await;
                assert!(
                    status.is_client_error(),
                    "{name} decision: {status} {decision}"
                );
            }
            other => panic!("{name} direct context: {other} {body}"),
        }
    }
    // Another user cannot approve (or even view) this payer's intent.
    match f.consent(&f.bob, &AuthzRequest::payment(&intent_id)).await {
        Err((status, _, body)) => assert_eq!(status, StatusCode::FORBIDDEN, "{body}"),
        Ok((_, context)) => panic!("other payer saw consent context: {context}"),
    }
    assert_eq!(f.channel_calls().await, 0);
}

#[tokio::test]
async fn payment_profile_is_unavailable_until_the_payment_resource_is_configured() {
    let f = Fixture::with_config(None).await;
    let (status, body) = f
        .prepare(&f.alice_prepare, f.order("order-off", "1999", now() + 600))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, _, body) = send(
        &f.router,
        browser(
            "GET",
            &format!("/authorize?{}", AuthzRequest::payment("pi_any").query()),
            &f.alice,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn payment_prepare_derives_identity_and_enforces_terms() {
    let f = Fixture::new().await;
    let deadline = now() + 600;
    let base = f.order("order-prepare", "1999", deadline);
    let mut cases: Vec<(&str, Value, StatusCode)> = Vec::new();
    for (field, value) in [
        ("payer", json!("attacker")),
        ("tenant", json!("other")),
        ("client_id", json!(OTHER_CLIENT)),
        ("payee_name", json!("Totally Legit")),
        ("fee_minor", json!("10")),
    ] {
        let mut body = base.clone();
        body[field] = value;
        cases.push(("identity or unknown field", body, StatusCode::BAD_REQUEST));
    }
    for (amount, name) in [
        (json!(19.99), "float amount"),
        (json!(1999), "numeric amount"),
        (json!("0"), "zero amount"),
        (json!("01999"), "leading zero"),
        (json!("19.99"), "decimal string"),
        (json!("100001"), "over the ceiling"),
    ] {
        let mut body = base.clone();
        body["amount_minor"] = amount;
        cases.push((name, body, StatusCode::BAD_REQUEST));
    }
    let mut body = base.clone();
    body["currency"] = json!("EUR");
    cases.push(("other currency", body, StatusCode::BAD_REQUEST));
    for execute_before in [now() - 1, now() + 3601] {
        let mut body = base.clone();
        body["execute_before"] = json!(execute_before);
        cases.push(("deadline window", body, StatusCode::BAD_REQUEST));
    }
    let mut body = base.clone();
    body["actor"] = json!(CLIENT);
    cases.push(("actor is not a workload", body, StatusCode::BAD_REQUEST));
    let mut body = base.clone();
    body["funding_source_id"] = json!("fs_bob");
    cases.push((
        "another payer's funding source",
        body,
        StatusCode::FORBIDDEN,
    ));
    let mut body = base.clone();
    body["payee_id"] = json!("merchant_unknown");
    cases.push(("unknown payee", body, StatusCode::BAD_REQUEST));
    for (name, body, expected) in cases {
        let (status, response) = f.prepare(&f.alice_prepare, body).await;
        assert_eq!(status, expected, "{name}: {response}");
    }
    // A token without payments:prepare, or a delegated token, cannot prepare.
    let authorized = f.authorized("order-scope").await;
    for token in [&authorized.subject_token, &authorized.delegated] {
        let (status, body) = f.prepare(token, base.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }
    let (status, body) = f.prepare("not-a-token", base.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // Idempotent per order; a different payment for the same order conflicts,
    // whichever client, actor or amount is changed.
    let (status, first) = f.prepare(&f.alice_prepare, base.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    let (status, again) = f.prepare(&f.alice_prepare, base.clone()).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["intent_id"], first["intent_id"]);
    let mut changed = base.clone();
    changed["amount_minor"] = json!("2000");
    let (status, body) = f.prepare(&f.alice_prepare, changed).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let mut changed = base.clone();
    changed["actor"] = json!(OTHER_ACTOR);
    let (status, body) = f.prepare(&f.alice_prepare, changed).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let other_client_token = f.prepare_token(&f.alice, OTHER_CLIENT).await;
    let (status, body) = f.prepare(&other_client_token, base.clone()).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "other client, same order: {body}"
    );
    let mut bob_order = base.clone();
    bob_order["funding_source_id"] = json!("fs_bob");
    let (status, body) = f.prepare(&f.bob_prepare, bob_order).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "other payer, same order: {body}"
    );
}

#[tokio::test]
async fn payment_execute_rejections_never_call_the_channel() {
    let f = Fixture::new().await;
    let a = f.authorized("order-a").await;

    // An intent for another actor, and one for another payer.
    let (status, other) = f
        .prepare(
            &f.alice_prepare,
            json!({"order_id":"order-b","actor":OTHER_ACTOR,"funding_source_id":"fs_alice","payee_id":"merchant_books","amount_minor":"1999","currency":"USD","execute_before":now()+600}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{other}");
    let other_issued = f
        .authorize(
            &f.alice,
            &AuthzRequest {
                actor: Some(OTHER_ACTOR),
                ..AuthzRequest::payment(other["intent_id"].as_str().unwrap())
            },
        )
        .await;
    let (status, other_actor_token) = f
        .exchange(other_issued["access_token"].as_str().unwrap(), OTHER_ACTOR)
        .await;
    assert_eq!(status, StatusCode::OK, "{other_actor_token}");
    let (status, bob_intent) = f
        .prepare(
            &f.bob_prepare,
            json!({"order_id":"order-bob","actor":ACTOR,"funding_source_id":"fs_bob","payee_id":"merchant_books","amount_minor":"1999","currency":"USD","execute_before":now()+600}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{bob_intent}");
    let bob_issued = f
        .authorize(
            &f.bob,
            &AuthzRequest::payment(bob_intent["intent_id"].as_str().unwrap()),
        )
        .await;
    let (status, bob_delegated) = f
        .exchange(bob_issued["access_token"].as_str().unwrap(), ACTOR)
        .await;
    assert_eq!(status, StatusCode::OK, "{bob_delegated}");

    // Tokens that carry no payment authorization, or a permissive generic one.
    let no_rar = f
        .authorize(
            &f.alice,
            &AuthzRequest {
                details: None,
                ..AuthzRequest::payment(&a.intent_id)
            },
        )
        .await;
    let (status, no_rar_delegated) = f
        .exchange(no_rar["access_token"].as_str().unwrap(), ACTOR)
        .await;
    assert_eq!(status, StatusCode::OK, "{no_rar_delegated}");
    let loose = f
        .authorize(
            &f.alice,
            &AuthzRequest {
                details: Some(json!([{"type": "agent_auth_rar_v1", "locations": [PAYMENTS]}])),
                ..AuthzRequest::payment(&a.intent_id)
            },
        )
        .await;
    let (status, loose_delegated) = f
        .exchange(loose["access_token"].as_str().unwrap(), ACTOR)
        .await;
    assert_eq!(status, StatusCode::OK, "{loose_delegated}");
    let other_audience = f
        .authorize(
            &f.alice,
            &AuthzRequest {
                scope: "db:read",
                resources: vec![OTHER_RESOURCE],
                actor: None,
                details: None,
                ..AuthzRequest::payment(&a.intent_id)
            },
        )
        .await;

    let cases: Vec<(&str, String, StatusCode)> = vec![
        (
            "3LO subject token without act",
            a.subject_token.clone(),
            StatusCode::FORBIDDEN,
        ),
        (
            "payer prepare token",
            f.alice_prepare.clone(),
            StatusCode::FORBIDDEN,
        ),
        (
            "other designated actor",
            other_actor_token["access_token"].as_str().unwrap().into(),
            StatusCode::FORBIDDEN,
        ),
        (
            "other payer",
            bob_delegated["access_token"].as_str().unwrap().into(),
            StatusCode::FORBIDDEN,
        ),
        (
            "missing payment RAR",
            no_rar_delegated["access_token"].as_str().unwrap().into(),
            StatusCode::FORBIDDEN,
        ),
        (
            "permissive generic RAR",
            loose_delegated["access_token"].as_str().unwrap().into(),
            StatusCode::FORBIDDEN,
        ),
        (
            "other audience",
            other_audience["access_token"].as_str().unwrap().into(),
            StatusCode::UNAUTHORIZED,
        ),
        ("garbage", "not-a-token".into(), StatusCode::UNAUTHORIZED),
    ];
    for (name, token, expected) in cases {
        let (status, body) = f.execute(&token, &a.intent_id).await;
        assert_eq!(status, expected, "{name}: {body}");
    }
    let (status, _, body) = send(
        &f.router,
        api(
            "POST",
            &format!("/payments/intents/{}/execute", a.intent_id),
            None,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no token: {body}");
    // A token issued for one issuer host is not active on another.
    let (status, _, body) = send(
        &f.router,
        api_at(
            "127.0.0.1",
            "POST",
            &format!("/payments/intents/{}/execute", a.intent_id),
            Some(&a.delegated),
            None,
        ),
    )
    .await;
    assert!(
        status.is_client_error(),
        "other issuer host: {status} {body}"
    );
    // A second delegation hop is refused by the authorization server.
    let (status, body) = f.exchange(&a.delegated, ACTOR).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "second hop: {body}");

    assert_eq!(
        f.channel_calls().await,
        0,
        "no rejected request reached the channel"
    );
    assert_eq!(f.record(&a.intent_id).await.status, PaymentStatus::Prepared);
    let (status, body) = f.execute(&a.delegated, &a.intent_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "SUCCEEDED");
    assert_eq!(f.channel_calls().await, 1);
}

#[tokio::test]
async fn payment_revocation_disablement_expiry_and_unavailable_checks_block_new_acceptance() {
    let f = Fixture::new().await;

    let revoked = f.authorized("order-revoked").await;
    f.revoke(&f.grant_of(&revoked.subject_token).await).await;
    let (status, body) = f.execute(&revoked.delegated, &revoked.intent_id).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "revoked Grant: {body}");

    let unavailable = f.authorized("order-unavailable").await;
    // Refutable only when the `aws` feature adds the DynamoDB variant.
    #[allow(irrefutable_let_patterns)]
    let GrantStoreImpl::Memory(grants) = &*f.state.grants
    else {
        unreachable!("dev state uses memory Grants")
    };
    grants.fail_next_get_permanent();
    let (status, body) = f
        .execute(&unavailable.delegated, &unavailable.intent_id)
        .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "online check unavailable: {body}"
    );
    f.parts.registry.fail_next_lookup();
    let (status, body) = f
        .execute(&unavailable.delegated, &unavailable.intent_id)
        .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "registry unavailable: {body}"
    );
    f.parts.store.fail_next_get();
    let (status, body) = f
        .execute(&unavailable.delegated, &unavailable.intent_id)
        .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "payment store unavailable: {body}"
    );

    // A funding-source version change after consent blocks acceptance.
    let stale_source = f.authorized("order-stale-source").await;
    f.parts
        .registry
        .put_funding_source(
            "",
            FundingSource {
                funding_source_id: "fs_alice".into(),
                owner: f.alice_sub.clone(),
                version: 2,
                label: "Visa •••• 4242".into(),
                currency: "USD".into(),
                active: true,
            },
        )
        .await;
    let (status, body) = f
        .execute(&stale_source.delegated, &stale_source.intent_id)
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "funding source changed: {body}"
    );
    assert_eq!(f.channel_calls().await, 0);

    // Expiry of the first-acceptance deadline.
    f.parts
        .registry
        .put_funding_source(
            "",
            FundingSource {
                funding_source_id: "fs_alice".into(),
                owner: f.alice_sub.clone(),
                version: 3,
                label: "Visa •••• 4242".into(),
                currency: "USD".into(),
                active: true,
            },
        )
        .await;
    let deadline = now() + 2;
    let (status, short) = f
        .prepare(
            &f.alice_prepare,
            f.order("order-expiring", "1999", deadline),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{short}");
    let expiring = f
        .authorize_intent(short["intent_id"].as_str().unwrap().to_string())
        .await;
    while now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let (status, body) = f.execute(&expiring.delegated, &expiring.intent_id).await;
    assert_eq!(status, StatusCode::CONFLICT, "expired intent: {body}");
    let (status, body) = f.get(&f.alice_prepare, &expiring.intent_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "EXPIRED");
    // A new confirmation is required; the never-accepted order may get a new intent.
    let (status, renewed) = f
        .prepare(
            &f.alice_prepare,
            f.order("order-expiring", "1999", now() + 600),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{renewed}");
    assert_ne!(renewed["intent_id"], short["intent_id"]);
    let (status, body) = send(
        &f.router,
        browser(
            "GET",
            &format!(
                "/authorize?{}",
                AuthzRequest::payment(&expiring.intent_id).query()
            ),
            &f.alice,
            None,
        ),
    )
    .await
    .then_status_body();
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "re-consent to an expired intent: {body}"
    );

    // Disabling the user makes the delegated authority inactive.
    let disabled = f.authorized("order-disabled").await;
    let (status, _, body) = send(
        &f.router,
        Request::builder()
            .method("POST")
            .uri(format!("/admin/users/{ALICE}/disable"))
            .header("host", HOST)
            .header("authorization", "Bearer dev-admin-token-not-for-prod")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = f.execute(&disabled.delegated, &disabled.intent_id).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "disabled user: {body}");

    assert_eq!(
        f.channel_calls().await,
        0,
        "no new acceptance reached the channel"
    );
    for intent in [&revoked, &unavailable, &stale_source, &disabled] {
        assert!(f.record(&intent.intent_id).await.attempt.is_none());
    }
}

#[tokio::test]
async fn payment_concurrent_revocation_after_the_online_check_is_an_accepted_boundary() {
    let f = Fixture::new().await;
    let a = f.authorized("order-race").await;
    let grant_id = f.grant_of(&a.subject_token).await;
    let pause = f.parts.store.pause_next_accept();
    let router = f.router.clone();
    let token = a.delegated.clone();
    let intent_id = a.intent_id.clone();
    let execution = tokio::spawn(async move {
        send(
            &router,
            api(
                "POST",
                &format!("/payments/intents/{intent_id}/execute"),
                Some(&token),
                None,
            ),
        )
        .await
    });
    pause.reached.notified().await;
    // The authoritative check already returned active; revoke before the write.
    f.revoke(&grant_id).await;
    pause.release.notify_one();
    let (status, _, body) = execution.await.unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "SUCCEEDED");
    let record = f.record(&a.intent_id).await;
    let attempt = record.attempt.as_ref().unwrap();
    assert!(attempt.authorization.checked_at <= attempt.accepted_at);
    assert_eq!(attempt.authorization.grant_id, grant_id);
    // The revoked authority cannot be used again, but the accepted attempt is
    // still recoverable without any user token.
    let (status, body) = f.execute(&a.delegated, &a.intent_id).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let reconciled = reconcile_internal(&f, &a.intent_id).await;
    assert_eq!(reconciled.status, PaymentStatus::Succeeded);
    assert_eq!(f.parts.adapter.transactions().await.len(), 1);
}

#[tokio::test]
async fn payment_concurrent_and_repeated_execution_share_one_attempt() {
    let f = Fixture::new().await;
    let a = f.authorized("order-concurrent").await;
    let mut handles = Vec::new();
    for _ in 0..8 {
        let router = f.router.clone();
        let token = a.delegated.clone();
        let intent_id = a.intent_id.clone();
        handles.push(tokio::spawn(async move {
            send(
                &router,
                api(
                    "POST",
                    &format!("/payments/intents/{intent_id}/execute"),
                    Some(&token),
                    None,
                ),
            )
            .await
        }));
    }
    let mut attempts = std::collections::BTreeSet::new();
    for handle in handles {
        let (status, _, body) = handle.await.unwrap();
        assert_eq!(status, StatusCode::OK, "{body}");
        attempts.insert(body["attempt"]["attempt_id"].as_str().unwrap().to_string());
    }
    assert_eq!(attempts.len(), 1, "all executions share one attempt");
    assert_eq!(f.channel_calls().await, 1);
    assert_eq!(f.parts.adapter.transactions().await.len(), 1);
    let key = f.idempotency_key(&a.intent_id).await;

    // A fresh exchange from the same consent returns the same record.
    let (status, again) = f.exchange(&a.subject_token, ACTOR).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    let (status, body) = f
        .execute(again["access_token"].as_str().unwrap(), &a.intent_id)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(attempts.contains(body["attempt"]["attempt_id"].as_str().unwrap()));
    // A second consent for an executed intent is refused.
    let (status, _, body) = send(
        &f.router,
        browser(
            "GET",
            &format!("/authorize?{}", AuthzRequest::payment(&a.intent_id).query()),
            &f.alice,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "re-consent: {body}");
    // Re-preparing the same order returns or refuses, never a parallel intent.
    let record = f.record(&a.intent_id).await;
    let mut same = f.order("order-concurrent", "1999", record.terms.execute_before);
    same["actor"] = json!(ACTOR);
    let (status, body) = f.prepare(&f.alice_prepare, same).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["intent_id"], a.intent_id);
    let (status, body) = f
        .prepare(
            &f.alice_prepare,
            f.order("order-concurrent", "1999", now() + 900),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(f.channel_calls().await, 1);
    assert_eq!(f.idempotency_key(&a.intent_id).await, key);
}

#[tokio::test]
async fn payment_recovery_reuses_the_persisted_attempt_after_faults() {
    let f = Fixture::new().await;

    // 1. The acceptance write commits but its response is lost.
    let lost = f.authorized("order-lost-accept").await;
    f.parts.store.lose_next_accept_response();
    let (status, body) = f.execute(&lost.delegated, &lost.intent_id).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(f.channel_calls().await, 0);
    let key = f.idempotency_key(&lost.intent_id).await;
    let (status, body) = f.execute(&lost.delegated, &lost.intent_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["status"], "ACCEPTED",
        "a retry returns the attempt, it does not submit"
    );
    assert_eq!(f.channel_calls().await, 0);
    let (status, body) = f.reconcile(&lost.delegated, &lost.intent_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "SUCCEEDED");
    assert_eq!(f.idempotency_key(&lost.intent_id).await, key);

    // 2. The process stops after acceptance, before the channel call.
    let crashed = f.authorized("order-crash").await;
    let pause = f.parts.store.pause_after_next_accept();
    let router = f.router.clone();
    let token = crashed.delegated.clone();
    let intent_id = crashed.intent_id.clone();
    let execution = tokio::spawn(async move {
        send(
            &router,
            api(
                "POST",
                &format!("/payments/intents/{intent_id}/execute"),
                Some(&token),
                None,
            ),
        )
        .await
    });
    pause.reached.notified().await;
    execution.abort();
    assert!(execution.await.unwrap_err().is_cancelled());
    let calls = f.channel_calls().await;
    let record = f.record(&crashed.intent_id).await;
    assert_eq!(record.status, PaymentStatus::Accepted);
    let crash_key = record.attempt.unwrap().idempotency_key;
    let recovered = reconcile_internal(&f, &crashed.intent_id).await;
    assert_eq!(recovered.status, PaymentStatus::Succeeded);
    assert_eq!(f.channel_calls().await, calls + 1);
    assert_eq!(recovered.attempt.unwrap().idempotency_key, crash_key);

    // 3. The channel charges but the response is lost.
    let lost_response = f.authorized("order-lost-response").await;
    f.parts
        .adapter
        .push_submit_fault(SubmitFault::LoseResponseAfterProcessing)
        .await;
    let (status, body) = f
        .execute(&lost_response.delegated, &lost_response.intent_id)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "UNKNOWN");
    let recovered = reconcile_internal(&f, &lost_response.intent_id).await;
    assert_eq!(recovered.status, PaymentStatus::Succeeded);

    // 4. Timeout before processing, then a temporarily unreachable channel,
    //    while the Grant is revoked: unknown never becomes failed.
    let timeout = f.authorized("order-timeout").await;
    f.parts
        .adapter
        .push_submit_fault(SubmitFault::TimeoutBeforeProcessing)
        .await;
    let (status, body) = f.execute(&timeout.delegated, &timeout.intent_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "UNKNOWN");
    f.revoke(&f.grant_of(&timeout.subject_token).await).await;
    f.parts.adapter.fail_next_queries(2).await;
    for _ in 0..2 {
        assert_eq!(
            reconcile_internal(&f, &timeout.intent_id).await.status,
            PaymentStatus::Unknown
        );
    }
    let timeout_key = f.idempotency_key(&timeout.intent_id).await;
    let recovered = reconcile_internal(&f, &timeout.intent_id).await;
    assert_eq!(recovered.status, PaymentStatus::Succeeded);
    assert_eq!(recovered.attempt.unwrap().idempotency_key, timeout_key);

    // 5. A temporary 5xx is unknown too, and is recovered with the same key.
    let server_error = f.authorized("order-5xx").await;
    f.parts
        .adapter
        .push_submit_fault(SubmitFault::ServerErrorBeforeProcessing)
        .await;
    let (_, body) = f
        .execute(&server_error.delegated, &server_error.intent_id)
        .await;
    assert_eq!(body["status"], "UNKNOWN");
    let (status, body) = f.reconcile(&f.alice_prepare, &server_error.intent_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "SUCCEEDED");

    // Every intent produced exactly one channel transaction with its own key.
    let transactions = f.parts.adapter.transactions().await;
    assert_eq!(transactions.len(), 5);
    let keys: std::collections::BTreeSet<_> = transactions
        .iter()
        .map(|t| t.idempotency_key.clone())
        .collect();
    assert_eq!(keys.len(), 5);
    assert!(keys.contains(&key) && keys.contains(&crash_key) && keys.contains(&timeout_key));
}

#[tokio::test]
async fn payment_recovery_outside_the_idempotency_window_waits_for_review() {
    let f = Fixture::new().await;
    f.parts.adapter.set_idempotency_retention_secs(0);
    let a = f.authorized("order-window").await;
    let pause = f.parts.store.pause_after_next_accept();
    let router = f.router.clone();
    let token = a.delegated.clone();
    let intent_id = a.intent_id.clone();
    let execution = tokio::spawn(async move {
        send(
            &router,
            api(
                "POST",
                &format!("/payments/intents/{intent_id}/execute"),
                Some(&token),
                None,
            ),
        )
        .await
    });
    pause.reached.notified().await;
    execution.abort();
    let _ = execution.await;
    let key = f.idempotency_key(&a.intent_id).await;
    let reviewed = reconcile_internal(&f, &a.intent_id).await;
    assert_eq!(
        reviewed.status,
        PaymentStatus::Accepted,
        "not converted to failed"
    );
    let attempt = reviewed.attempt.unwrap();
    assert!(attempt.needs_review);
    assert_eq!(attempt.idempotency_key, key, "no new key");
    assert_eq!(
        f.channel_calls().await,
        0,
        "no resubmission outside the window"
    );
    let (_, body) = f.get(&f.alice_prepare, &a.intent_id).await;
    assert_eq!(body["attempt"]["needs_review"], true);
}

#[tokio::test]
async fn payment_callbacks_are_authenticated_matched_and_monotonic() {
    let f = Fixture::new().await;
    f.parts
        .adapter
        .set_initial_state(ChannelState::Pending)
        .await;
    let a = f.authorized("order-callback").await;
    let (status, body) = f.execute(&a.delegated, &a.intent_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "PENDING");
    let key = f.idempotency_key(&a.intent_id).await;
    let (pending_body, pending_signature) = f
        .parts
        .adapter
        .callback_for(&key, "evt_pending")
        .await
        .unwrap();
    // Forged callbacks are rejected and change nothing.
    let (status, body) = f.callback(&pending_body, "v1=forged").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let mut forged: Value = serde_json::from_slice(&pending_body).unwrap();
    forged["state"] = json!("succeeded");
    let forged = serde_json::to_vec(&forged).unwrap();
    let (status, body) = f.callback(&forged, &pending_signature).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "re-used signature: {body}"
    );
    assert_eq!(f.record(&a.intent_id).await.status, PaymentStatus::Pending);

    assert!(f.parts.adapter.settle(&key, ChannelState::Succeeded).await);
    let (success_body, success_signature) = f
        .parts
        .adapter
        .callback_for(&key, "evt_success")
        .await
        .unwrap();
    let (status, body) = f.callback(&success_body, &success_signature).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "SUCCEEDED");
    let evidence = f.record(&a.intent_id).await.attempt.unwrap().evidence.len();
    // Duplicate delivery is idempotent.
    let (status, body) = f.callback(&success_body, &success_signature).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        f.record(&a.intent_id).await.attempt.unwrap().evidence.len(),
        evidence
    );
    // An older pending callback arriving late cannot reopen the result.
    let (status, body) = f.callback(&pending_body, &pending_signature).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "SUCCEEDED");
    // Contradicting authentic evidence is retained for review, never applied.
    let mut contradicting: Value = serde_json::from_slice(&success_body).unwrap();
    contradicting["state"] = json!("declined");
    contradicting["event_id"] = json!("evt_contradiction");
    let contradicting = serde_json::to_vec(&contradicting).unwrap();
    let signature = f.parts.adapter.sign(&contradicting);
    let (status, body) = f.callback(&contradicting, &signature).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "SUCCEEDED");
    let mut wrong_amount: Value = serde_json::from_slice(&success_body).unwrap();
    wrong_amount["amount_minor"] = json!("1");
    wrong_amount["event_id"] = json!("evt_amount");
    let wrong_amount = serde_json::to_vec(&wrong_amount).unwrap();
    let signature = f.parts.adapter.sign(&wrong_amount);
    let (status, body) = f.callback(&wrong_amount, &signature).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let record = f.record(&a.intent_id).await;
    assert_eq!(record.status, PaymentStatus::Succeeded);
    let attempt = record.attempt.unwrap();
    assert!(attempt.needs_review);
    let dispositions: Vec<_> = attempt
        .evidence
        .iter()
        .map(|e| e.disposition.as_str())
        .collect();
    assert!(dispositions.contains(&"stale"), "{dispositions:?}");
    assert!(dispositions.contains(&"conflict"), "{dispositions:?}");
    assert!(dispositions.contains(&"mismatch"), "{dispositions:?}");
    // A callback for a different attempt key is not applied to this intent.
    let mut other_key: Value = serde_json::from_slice(&success_body).unwrap();
    other_key["idempotency_key"] = json!("pk_other");
    let other_key = serde_json::to_vec(&other_key).unwrap();
    let signature = f.parts.adapter.sign(&other_key);
    let (status, body) = f.callback(&other_key, &signature).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // A definitive decline is the only path to FAILED.
    f.parts
        .adapter
        .set_initial_state(ChannelState::Declined)
        .await;
    let declined = f.authorized("order-declined").await;
    let (status, body) = f.execute(&declined.delegated, &declined.intent_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "FAILED");
    assert_eq!(f.channel_calls().await, 2);
}

#[tokio::test]
async fn payment_audit_links_grant_intent_attempt_and_channel_without_secrets() {
    let f = Fixture::new().await;
    let a = f.authorized("order-audit").await;
    let (status, body) = f.execute(&a.delegated, &a.intent_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let grant_id = f.grant_of(&a.subject_token).await;
    assert!(f.grant_ids().await.contains(&grant_id));
    let record = f.record(&a.intent_id).await;
    let attempt = record.attempt.as_ref().unwrap();
    assert_eq!(attempt.authorization.grant_id, grant_id);
    assert_eq!(attempt.authorization.actor, ACTOR);
    assert_eq!(attempt.authorization.client_id, CLIENT);
    assert_eq!(attempt.authorization.acr, STRONG_ACR);
    assert_eq!(attempt.terms_digest, record.terms_digest);
    let jti = claims(&a.delegated)["jti"].as_str().unwrap().to_string();
    assert_eq!(attempt.authorization.token_jti_sha256.len(), 43);
    assert_ne!(attempt.authorization.token_jti_sha256, jti);
    let transactions = f.parts.adapter.transactions().await;
    assert_eq!(
        attempt.channel_transaction_id.as_deref(),
        Some(transactions[0].channel_transaction_id.as_str())
    );
    let history: Vec<_> = record.history.iter().map(|h| (h.from, h.to)).collect();
    assert_eq!(
        history,
        vec![
            (PaymentStatus::Prepared, PaymentStatus::Accepted),
            (PaymentStatus::Accepted, PaymentStatus::Succeeded),
        ]
    );
    let serialized = serde_json::to_string(&record).unwrap();
    for secret in [&a.delegated, &a.subject_token, &f.alice_prepare, &jti] {
        assert!(
            !serialized.contains(secret.as_str()),
            "record leaks token material"
        );
    }
    assert!(!serialized.contains("4242424242424242"));
    assert!(!body.to_string().contains(&attempt.idempotency_key));
}
