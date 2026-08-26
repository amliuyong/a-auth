//! 进程内 e2e:上游 OIDC 联邦登录往返(spec 003 §4,C9.5b)。
//!
//! 全链在进程内(无外部 mock-IdP HTTP server):用一枚**测试上游 signer**(MemorySigner)铸 RS256
//! id_token + 把其 JWKS 注入 MemoryJwksFetcher、把 token 预置进 MemoryUpstreamTokenExchanger、secret
//! 预置进 MemorySecretResolver。驱动:
//!   `/authorize?idp_hint` → 302 上游(state 存 flow)→ 模拟上游回调 `/federation/callback?code=&state=`
//!   → 建本地会话(Set-Cookie)→ 303 续跑回 `/authorize`(带原下游 query,F1)。
//! 并验各 fail-closed:功能关 callback 404、bad state 400、nonce 不符 400、上游 error 透传回下游。

use agent_auth_client::s256_challenge;
use agent_auth_http::federation_attributes::{
    FederationAttributeMappingsStore, MappingChange, MappingChangeOutcome, MappingMode, MappingSpec,
};
use agent_auth_http::ports::{
    CodeStore, FederationConfigStore, FederationFlowState, FederationFlowStore, LeaseAcquire,
    PlatformJwk, PutAttrOutcome, SessionStore, Signer, UpstreamTokenSet, UsersStore,
};
use agent_auth_http::security_event::{
    SecurityActor, SecurityEventCategory, SecurityEventOutcome, SecurityEventStore, SecuritySubject,
};
use agent_auth_http::state::FederationAttributeMappingsStoreImpl;
use agent_auth_http::{build_router, AppState};
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use std::sync::Arc;
use tower::ServiceExt;

const HOST: &str = "localhost";
const UPSTREAM_ISS: &str = "https://idp.example.com";
const UP_CLIENT: &str = "as-rp-client";
const IDP: &str = "okta";
const SECRET_REF: &str = "secretsmanager:fed/okta";
// 下游 client(本 AS 的 client)——已在 dev seed(用现成 dev client）。
const DS_CLIENT: &str = "test-client";
const DS_REDIRECT: &str = "https://app.example.com/cb";
const RS: &str = "https://rs.example.com/api";
const VERIFIER: &str = "0123456789012345678901234567890123456789abc";

// 用一枚独立 signer 扮"上游 IdP"铸 RS256 id_token(header 带 kid),并返回其 JWKS(供注入 fetcher)。
async fn mint_upstream_id_token(claims: serde_json::Value) -> (String, PlatformJwk) {
    // 独立种子(区别于 AS 自己的 signer)。
    let up = agent_auth_http::adapters::memory::MemorySigner::from_seed([42u8; 32]);
    let rsa_jwks = up.public_rsa_jwks().await.unwrap();
    let jwk = rsa_jwks.first().unwrap().clone();
    let kid = jwk.kid.clone();
    let header = serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": kid });
    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let p_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{h_b64}.{p_b64}");
    let (_kid, sig) = up.sign_rs256(signing_input.as_bytes()).await.unwrap();
    let s_b64 = URL_SAFE_NO_PAD.encode(sig);
    let jwt = format!("{signing_input}.{s_b64}");
    let platform_jwk = PlatformJwk {
        kid: Some(jwk.kid),
        kty: Some("RSA".into()),
        n: jwk.n,
        e: jwk.e,
        alg: Some("RS256".into()),
        ..Default::default()
    };
    (jwt, platform_jwk)
}

async fn federation_state() -> AppState {
    let mut state = AppState::dev(HOST);
    state.federation_enabled = true;
    // 下游 client(供 F1 续跑发码;用 dev seed helper)。
    state.seed_dev_client(DS_CLIENT, DS_REDIRECT, None).await;
    // 登记上游 IdP config(复合键 default+okta)。
    state
        .federation_config
        .put(agent_auth_authn::federation::FederationConfig {
            tenant_id: "default".into(),
            upstream_idp_id: IDP.into(),
            protocol: agent_auth_authn::federation::UpstreamProtocol::Oidc,
            upstream_issuer: UPSTREAM_ISS.into(),
            strong_acr_values: vec!["urn:mace:incommon:iap:silver".into()],
            oidc: Some(agent_auth_authn::federation::OidcRpParams {
                client_id: UP_CLIENT.into(),
                client_secret_ref: SECRET_REF.into(),
                authorization_endpoint: format!("{UPSTREAM_ISS}/authorize"),
                token_endpoint: format!("{UPSTREAM_ISS}/token"),
                jwks_uri: format!("{UPSTREAM_ISS}/jwks"),
                scopes: vec!["openid".into()],
            }),
        })
        .await
        .unwrap();
    // secret 预置(引用名→明文)。
    state
        .secret_resolver_seed(SECRET_REF, "PLACEHOLDER-upstream-secret")
        .await;
    state
}

// 装配一个开了联邦、seed 了 config 的 AppState;返回 (router, state)。
async fn app_with_federation() -> (axum::Router, AppState) {
    let state = federation_state().await;
    let (router, _) = build_router(state.clone());
    (router, state)
}

async fn configure_federated_department_mapping(router: &axum::Router, state: &AppState) {
    let mut response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/admin/attribute-namespaces")
                .header("host", HOST)
                .header("authorization", "Bearer dev-admin-token-not-for-prod")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "canonical_namespace": RS,
                        "exact_audiences": [RS],
                        "expected_revision": 0,
                        "operation_id": "op-federation-rs"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let mut registration: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    for _ in 0..8 {
        let Some(revision) = registration["operation"]["revision"].as_u64() else {
            break;
        };
        response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/attribute-namespaces/advance")
                    .header("host", HOST)
                    .header("authorization", "Bearer dev-admin-token-not-for-prod")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "canonical_namespace": RS,
                            "operation_id": "op-federation-rs",
                            "expected_operation_revision": revision
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        registration = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
    }
    assert!(registration["operation"].is_null());

    let created = state
        .federation_attribute_mappings
        .change(
            "default",
            IDP,
            UPSTREAM_ISS,
            MappingChange::Create {
                mapping_id: "fm_department".to_string(),
                expected_registry_revision: 0,
                spec: MappingSpec {
                    source_claim: "department".to_string(),
                    target_namespace: RS.to_string(),
                    target_key: "department".to_string(),
                    mode: MappingMode::CopyString,
                },
            },
        )
        .await
        .unwrap();
    assert!(matches!(created, MappingChangeOutcome::Applied(_)));
}

// 取某 cookie 值。
fn set_cookie_val(resp: &axum::http::Response<Body>, name: &str) -> Option<String> {
    for hv in resp.headers().get_all(axum::http::header::SET_COOKIE) {
        let s = hv.to_str().ok()?;
        if let Some(rest) = s.strip_prefix(&format!("{name}=")) {
            return Some(rest.split(';').next().unwrap_or("").to_string());
        }
    }
    None
}

fn location(resp: &axum::http::Response<Body>) -> String {
    resp.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn query_param(url: &str, key: &str) -> Option<String> {
    url.split('?')
        .nth(1)?
        .split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")).map(|v| v.to_string()))
}

/// 解出 JWT payload 的某 claim(测试辅助;不验签,只读)。
fn jwt_claim(jwt: &str, key: &str) -> serde_json::Value {
    let payload = jwt.split('.').nth(1).expect("jwt payload");
    let bytes = URL_SAFE_NO_PAD.decode(payload).expect("b64");
    let c: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    c.get(key).cloned().unwrap_or(serde_json::Value::Null)
}

async fn approve_federated_callback(
    router: &axum::Router,
    callback: axum::http::Response<Body>,
) -> String {
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    let session = set_cookie_val(&callback, "__Host-agent_auth_session").expect("session cookie");
    let continuation = location(&callback);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&continuation)
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let consent_location = location(&response);
    assert!(
        consent_location.contains("/consent?"),
        "fresh federated session must continue to consent, got {consent_location}"
    );
    let consent_query = consent_location
        .split_once('?')
        .map(|(_, query)| query.to_string())
        .expect("consent query");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/consent/context?{consent_query}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let csrf = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["csrf_token"]
        .as_str()
        .expect("csrf token")
        .to_string();

    let decision = serde_json::json!({
        "decision": "approve",
        "csrf": csrf,
        "authorize_query": consent_query,
    });
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/consent/decision")
                .header("host", HOST)
                .header("content-type", "application/json")
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::from(serde_json::to_vec(&decision).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let redirect = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["redirect"]
        .as_str()
        .expect("redirect")
        .to_string();
    query_param(&redirect, "code").expect("authorization code")
}

async fn assert_code_auth_time(state: &AppState, code: &str, expected_auth_time: i64) {
    let now = agent_auth_http::current_unix_secs();
    let acquired = state
        .codes
        .acquire_lease("", code, "federation-test", now, now + 30)
        .await
        .unwrap();
    let LeaseAcquire::Acquired(record) = acquired else {
        panic!("new authorization code must be available, got {acquired:?}");
    };
    assert_eq!(
        record.auth_time, expected_auth_time,
        "authorization code must preserve the normalized authentication event"
    );
    state
        .codes
        .release_lease("", code, "federation-test", now)
        .await
        .unwrap();
}

async fn exchange_code_for_tokens(router: &axum::Router, code: &str) -> serde_json::Value {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&code_verifier={VERIFIER}\
                     &redirect_uri={DS_REDIRECT}&client_id={DS_CLIENT}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn peek_federation_flow(state: &AppState, flow_state: &str) -> FederationFlowState {
    let flow = state
        .federation_flow
        .consume(flow_state)
        .await
        .unwrap()
        .expect("federation flow");
    state.federation_flow.put(flow.clone()).await.unwrap();
    flow
}

async fn start_federation_request(
    router: &axum::Router,
    challenge: &str,
    downstream_state: &str,
    acr_values: Option<&str>,
) -> String {
    let acr_query = acr_values
        .map(|value| format!("&acr_values={value}"))
        .unwrap_or_default();
    let authz = format!(
        "/authorize?response_type=code&client_id={DS_CLIENT}&redirect_uri={DS_REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&state={downstream_state}\
         &idp_hint={IDP}{acr_query}"
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(authz)
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "idp_hint must redirect to the upstream IdP"
    );
    let upstream_location = location(&response);
    assert!(
        upstream_location.starts_with(&format!("{UPSTREAM_ISS}/authorize")),
        "must redirect to upstream authorize: {upstream_location}"
    );
    query_param(&upstream_location, "state").expect("upstream state")
}

// 驱动 /authorize?idp_hint → 拿到上游重定向里的 state(flow key)。
async fn start_federation(router: &axum::Router) -> String {
    start_federation_with_challenge(router, "abc").await
}

// 同上,但用指定 code_challenge(端到端到 /token 的测试须用真实 PKCE 派生的 challenge)。
async fn start_federation_with_challenge(router: &axum::Router, challenge: &str) -> String {
    start_federation_request(router, challenge, "downstream-state", None).await
}

async fn complete_strong_federation_with_auth_time(
    router: &axum::Router,
    state: &AppState,
    downstream_state: &str,
    code: &str,
    subject: &str,
    auth_time: i64,
) -> axum::http::Response<Body> {
    let flow_state = start_federation_request(
        router,
        &s256_challenge(VERIFIER),
        downstream_state,
        Some("urn%3Aagent-auth%3Aassurance%3Astrong"),
    )
    .await;
    let flow = peek_federation_flow(state, &flow_state).await;
    let now = agent_auth_http::current_unix_secs();
    let (id_token, jwk) = mint_upstream_id_token(serde_json::json!({
        "iss": UPSTREAM_ISS,
        "sub": subject,
        "aud": UP_CLIENT,
        "exp": now + 300,
        "iat": now,
        "nonce": flow.nonce,
        "acr": "urn:mace:incommon:iap:silver",
        "amr": ["webauthn", "hwk"],
        "auth_time": auth_time
    }))
    .await;
    state
        .jwks_fetcher_set(format!("{UPSTREAM_ISS}/jwks"), vec![jwk])
        .await;
    state
        .upstream_exchanger_seed(
            code,
            UpstreamTokenSet {
                id_token,
                access_token: None,
            },
        )
        .await;

    router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/federation/callback?code={code}&state={flow_state}"
                ))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn federation_max_age_zero_is_forwarded_without_continuation_loop() {
    let (router, state) = app_with_federation().await;
    let authz = format!(
        "/authorize?response_type=code&client_id={DS_CLIENT}&redirect_uri={DS_REDIRECT}\
         &code_challenge=abc&code_challenge_method=S256&scope=openid&state=max-age-zero\
         &max_age=0&idp_hint={IDP}"
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(authz)
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let upstream_location = location(&response);
    assert!(upstream_location.contains("max_age=0"));
    assert!(upstream_location.contains("prompt=login"));
    let flow_state = upstream_location
        .split(&['?', '&'][..])
        .find_map(|part| part.strip_prefix("state="))
        .expect("upstream state");
    let flow = agent_auth_http::ports::FederationFlowStore::consume(
        state.federation_flow.as_ref(),
        flow_state,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(flow.required_max_age_secs, Some(0));
    assert!(
        !flow.original_authz_request.contains("max_age=0"),
        "the callback continuation must not force another reauthentication loop"
    );
}

// 快乐路径:idp_hint → 上游 → callback → 建会话 + 续跑回下游 authorize。
#[tokio::test]
async fn federation_happy_path_end_to_end() {
    let (router, state) = app_with_federation().await;
    let flow_state = start_federation(&router).await;

    // 铸一枚合法上游 id_token(nonce 须 == flow 里存的;从 state 直接读 flow 拿 nonce)。
    let flow = peek_federation_flow(&state, &flow_state).await;
    let now = agent_auth_http::current_unix_secs();
    let (id_token, jwk) = mint_upstream_id_token(serde_json::json!({
        "iss": UPSTREAM_ISS, "sub": "upstream-user-1", "aud": UP_CLIENT,
        "exp": now + 300, "iat": now, "nonce": flow.nonce,
        "acr": "mfa", "amr": ["pwd", "otp"], "auth_time": now
    }))
    .await;
    // 注入上游 JWKS + 预置 code→token。
    state
        .jwks_fetcher_set(format!("{UPSTREAM_ISS}/jwks"), vec![jwk])
        .await;
    state
        .upstream_exchanger_seed(
            "upstream-code-1",
            UpstreamTokenSet {
                id_token,
                access_token: None,
            },
        )
        .await;

    // callback。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/federation/callback?code=upstream-code-1&state={flow_state}"
                ))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "callback 成功应 303 续跑"
    );
    // 建了本地会话 cookie。
    assert!(
        set_cookie_val(&resp, "__Host-agent_auth_session").is_some(),
        "callback 应建本地会话 cookie"
    );
    // 续跑回下游 authorize(带原 client_id + downstream state)。
    let loc = location(&resp);
    assert!(loc.contains("/authorize?"), "应续跑回 /authorize: {loc}");
    assert!(
        loc.contains(&format!("client_id={DS_CLIENT}")),
        "带原下游 client_id"
    );
    assert!(
        loc.contains("state=downstream-state"),
        "带原下游 state(F1 续跑)"
    );
    let (users, _) = state
        .users
        .list(
            "",
            10,
            None,
            None,
            agent_auth_http::ports::UserListStatusFilter::All,
        )
        .await
        .unwrap();
    let federated = users
        .iter()
        .find(|user| user.user_id.starts_with("user:fed:"))
        .expect("联邦 callback 应 JIT 创建 canonical user");
    assert!(
        federated.last_login_at.is_some(),
        "联邦登录成功建立会话后应记录最后登录时间"
    );
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    assert!(events.iter().any(|stored| {
        let event = serde_json::to_value(&stored.event).unwrap();
        stored.event.category == SecurityEventCategory::Authentication
            && stored.event.action == "authentication.federation"
            && stored.event.outcome == SecurityEventOutcome::Success
            && event["actor"]["kind"] == "user"
            && event["actor"]["id"] == federated.user_id
            && event["subject"]["id"] == federated.user_id
    }));
}

#[tokio::test]
async fn federation_callback_reconciles_attributes_before_creating_session() {
    let (router, state) = app_with_federation().await;
    configure_federated_department_mapping(&router, &state).await;
    let flow_state = start_federation(&router).await;
    let flow = peek_federation_flow(&state, &flow_state).await;
    let now = agent_auth_http::current_unix_secs();
    let (id_token, jwk) = mint_upstream_id_token(serde_json::json!({
        "iss": UPSTREAM_ISS,
        "sub": "mapped-user",
        "aud": UP_CLIENT,
        "exp": now + 300,
        "iat": now,
        "nonce": flow.nonce,
        "department": "treasury"
    }))
    .await;
    let raw_id_token = id_token.clone();
    state
        .jwks_fetcher_set(format!("{UPSTREAM_ISS}/jwks"), vec![jwk])
        .await;
    state
        .upstream_exchanger_seed(
            "mapped-user-code",
            UpstreamTokenSet {
                id_token,
                access_token: None,
            },
        )
        .await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/federation/callback?code=mapped-user-code&state={flow_state}"
                ))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(set_cookie_val(&response, "__Host-agent_auth_session").is_some());

    let (users, _) = state
        .users
        .list(
            "",
            10,
            None,
            None,
            agent_auth_http::ports::UserListStatusFilter::All,
        )
        .await
        .unwrap();
    let user = users
        .iter()
        .find(|user| user.user_id.starts_with("user:fed:"))
        .unwrap();
    assert_eq!(user.attributes[RS].kv["department"], "treasury");
    let owner = &user.attributes[RS].federation_owners["department"];
    assert_eq!(owner.upstream_idp_id, IDP);
    assert_eq!(owner.upstream_issuer, UPSTREAM_ISS);
    assert_eq!(owner.mapping_id, "fm_department");
    assert_eq!(owner.mapping_revision, 1);

    let detail_response = router
        .oneshot(
            Request::builder()
                .uri(format!("/admin/users/{}", user.user_id))
                .header("host", HOST)
                .header("authorization", "Bearer dev-admin-token-not-for-prod")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(detail_response.status(), StatusCode::OK);
    let detail: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(detail_response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        detail["attributes"][RS]["federation_owners"]["department"],
        serde_json::json!({
            "upstream_idp_id": IDP,
            "mapping_id": "fm_department",
            "mapping_revision": 1,
            "state": "active"
        })
    );
    assert!(!detail.to_string().contains(UPSTREAM_ISS));

    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    let reconciliation = events
        .iter()
        .find(|stored| {
            stored.event.action == "federation.attribute_reconciliation"
                && stored.event.outcome == SecurityEventOutcome::Success
        })
        .expect("successful reconciliation must emit a security event");
    let event = serde_json::to_value(&reconciliation.event).unwrap();
    assert_eq!(event["actor"]["kind"], "system");
    assert_eq!(event["actor"]["id"], "federation-reconciler");
    assert_eq!(event["subject"]["kind"], "user");
    assert_eq!(event["subject"]["id"], user.user_id);
    assert_eq!(event["correlation"]["upstream_idp_id"], IDP);
    assert_eq!(event["correlation"]["mapping_id"], "fm_department");
    assert_eq!(event["correlation"]["mapping_revision"], 1);
    assert_eq!(event["correlation"]["target_namespace"], RS);
    assert_eq!(event["correlation"]["target_key"], "department");
    assert!(event["correlation"]["operation_id"]
        .as_str()
        .is_some_and(|value| value.starts_with("far_")));
    assert!(event["correlation"]["old_value_summary"]
        .as_str()
        .is_some_and(|value| value.starts_with("fav_")));
    assert!(event["correlation"]["new_value_summary"]
        .as_str()
        .is_some_and(|value| value.starts_with("fav_")));
    assert_ne!(
        event["correlation"]["old_value_summary"],
        event["correlation"]["new_value_summary"]
    );
    let serialized = event.to_string();
    assert!(!serialized.contains("treasury"));
    assert!(!serialized.contains(&raw_id_token));
}

#[tokio::test]
async fn federation_callback_mapping_store_failure_creates_no_session() {
    let mut state = federation_state().await;
    state.federation_attribute_mappings = Arc::new(FederationAttributeMappingsStoreImpl::Disabled);
    let (router, _) = build_router(state.clone());
    let flow_state = start_federation(&router).await;
    let flow = peek_federation_flow(&state, &flow_state).await;
    let user_id = agent_auth_authn::federation::federated_user_id(
        &state.server_secret,
        &flow.tenant_id,
        UPSTREAM_ISS,
        "store-failure-user",
    );
    let now = agent_auth_http::current_unix_secs();
    let (id_token, jwk) = mint_upstream_id_token(serde_json::json!({
        "iss": UPSTREAM_ISS,
        "sub": "store-failure-user",
        "aud": UP_CLIENT,
        "exp": now + 300,
        "iat": now,
        "nonce": flow.nonce,
        "department": "must-not-be-logged"
    }))
    .await;
    state
        .jwks_fetcher_set(format!("{UPSTREAM_ISS}/jwks"), vec![jwk])
        .await;
    state
        .upstream_exchanger_seed(
            "mapping-store-failure-code",
            UpstreamTokenSet {
                id_token,
                access_token: None,
            },
        )
        .await;

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/federation/callback?code=mapping-store-failure-code&state={flow_state}"
                ))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(set_cookie_val(&response, "__Host-agent_auth_session").is_none());
    assert!(state
        .sessions
        .list_by_user("", &user_id, now)
        .await
        .unwrap()
        .is_empty());
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    assert!(events.iter().any(|stored| {
        stored.event.action == "federation.attribute_reconciliation"
            && stored.event.outcome == SecurityEventOutcome::Failure
            && stored.event.subject.id() == user_id
    }));
    assert!(!serde_json::to_string(&events)
        .unwrap()
        .contains("must-not-be-logged"));
}

#[tokio::test]
async fn federation_callback_attribute_size_overflow_creates_no_session_or_partial_values() {
    let (router, state) = app_with_federation().await;
    configure_federated_department_mapping(&router, &state).await;
    let flow_state = start_federation(&router).await;
    let flow = peek_federation_flow(&state, &flow_state).await;
    let user_id = agent_auth_authn::federation::federated_user_id(
        &state.server_secret,
        &flow.tenant_id,
        UPSTREAM_ISS,
        "oversized-mapped-user",
    );
    let now = agent_auth_http::current_unix_secs();
    state
        .users
        .create_or_get_by_id("", &user_id, now)
        .await
        .unwrap();
    let mut existing = std::collections::BTreeMap::new();
    existing.insert("blob".to_string(), "x".repeat(3900));
    assert!(matches!(
        state
            .users
            .put_attributes("", &user_id, RS, existing, 0)
            .await
            .unwrap(),
        PutAttrOutcome::Ok { revision: 1 }
    ));

    let (id_token, jwk) = mint_upstream_id_token(serde_json::json!({
        "iss": UPSTREAM_ISS,
        "sub": "oversized-mapped-user",
        "aud": UP_CLIENT,
        "exp": now + 300,
        "iat": now,
        "nonce": flow.nonce,
        "department": "treasury"
    }))
    .await;
    state
        .jwks_fetcher_set(format!("{UPSTREAM_ISS}/jwks"), vec![jwk])
        .await;
    state
        .upstream_exchanger_seed(
            "oversized-mapping-code",
            UpstreamTokenSet {
                id_token,
                access_token: None,
            },
        )
        .await;

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/federation/callback?code=oversized-mapping-code&state={flow_state}"
                ))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(set_cookie_val(&response, "__Host-agent_auth_session").is_none());
    assert!(state
        .sessions
        .list_by_user("", &user_id, now)
        .await
        .unwrap()
        .is_empty());
    let user = state.users.get_by_id("", &user_id).await.unwrap().unwrap();
    assert_eq!(user.attributes_generation, 1);
    assert_eq!(user.attributes[RS].kv["blob"].len(), 3900);
    assert!(!user.attributes[RS].kv.contains_key("department"));
    assert!(!user.attributes[RS]
        .federation_owners
        .contains_key("department"));
}

#[tokio::test]
async fn federation_verified_disabled_user_is_the_denial_subject() {
    let (router, state) = app_with_federation().await;
    let flow_state = start_federation(&router).await;
    let flow = peek_federation_flow(&state, &flow_state).await;
    let now = agent_auth_http::current_unix_secs();
    let upstream_sub = "disabled-upstream-user";
    let user_id = agent_auth_authn::federation::federated_user_id(
        &state.server_secret,
        &flow.tenant_id,
        UPSTREAM_ISS,
        upstream_sub,
    );
    state
        .users
        .create_or_get_by_id("", &user_id, now)
        .await
        .unwrap();
    assert!(state
        .users
        .set_status(
            "",
            &user_id,
            agent_auth_http::ports::UserStatus::Disabled,
            now,
        )
        .await
        .unwrap());
    let (id_token, jwk) = mint_upstream_id_token(serde_json::json!({
        "iss": UPSTREAM_ISS, "sub": upstream_sub, "aud": UP_CLIENT,
        "exp": now + 300, "iat": now, "nonce": flow.nonce,
        "auth_time": now
    }))
    .await;
    state
        .jwks_fetcher_set(format!("{UPSTREAM_ISS}/jwks"), vec![jwk])
        .await;
    state
        .upstream_exchanger_seed(
            "disabled-user-code",
            UpstreamTokenSet {
                id_token,
                access_token: None,
            },
        )
        .await;

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/federation/callback?code=disabled-user-code&state={flow_state}"
                ))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(set_cookie_val(&response, "__Host-agent_auth_session").is_none());
    assert!(
        state
            .sessions
            .list_by_user("", &user_id, now)
            .await
            .unwrap()
            .is_empty(),
        "disabled federation user must not receive a session"
    );
    assert_eq!(
        state
            .users
            .get_by_id("", &user_id)
            .await
            .unwrap()
            .unwrap()
            .last_login_at,
        None,
        "disabled federation callback 未建立会话,不得记录最后登录时间"
    );

    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    let denied = events
        .iter()
        .find(|stored| {
            stored.event.action == "authentication.federation"
                && stored.event.outcome == SecurityEventOutcome::Denied
        })
        .expect("verified federation denial must remain auditable");
    let event = serde_json::to_value(&denied.event).unwrap();
    assert_eq!(event["actor"]["kind"], "system");
    assert_eq!(event["actor"]["id"], "anonymous");
    assert_eq!(event["subject"]["kind"], "user");
    assert_eq!(event["subject"]["id"], user_id);
}

// C12.4 端到端:显式信任的上游 acr 映射为 canonical strong，amr 仅保留作观测证据。
// 全链:idp_hint → 上游(带 acr/amr 的 id_token)→ callback 建会话 → 续跑 /authorize(带会话)
//       → consent approve 发 code → /token 兑换 → 断言下游 access token + id_token 的 acr/amr == 上游值。
// (复用进程内自控上游,不依赖 Cognito——Cognito 默认不发标准 acr/amr。)
#[tokio::test]
async fn federation_acr_amr_propagates_to_downstream_token() {
    let (router, state) = app_with_federation().await;
    // 真实 PKCE 对(端到端到 /token 须用真 verifier/challenge)。
    let challenge = s256_challenge(VERIFIER);
    let flow_state = start_federation_with_challenge(&router, &challenge).await;

    // 取 flow.nonce 铸合法上游 id_token(带 acr/amr)。
    let flow = peek_federation_flow(&state, &flow_state).await;
    let now = agent_auth_http::current_unix_secs();
    let (id_token, jwk) = mint_upstream_id_token(serde_json::json!({
        "iss": UPSTREAM_ISS, "sub": "upstream-user-2", "aud": UP_CLIENT,
        "exp": now + 300, "iat": now, "nonce": flow.nonce,
        // `acr` 在配置 allowlist 中；amr 自身不参与提权。
        "acr": "urn:mace:incommon:iap:silver", "amr": ["pwd", "otp"]
    }))
    .await;
    state
        .jwks_fetcher_set(format!("{UPSTREAM_ISS}/jwks"), vec![jwk])
        .await;
    state
        .upstream_exchanger_seed(
            "upstream-code-2",
            UpstreamTokenSet {
                id_token,
                access_token: None,
            },
        )
        .await;

    // callback → 建会话 + 续跑回 /authorize。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/federation/callback?code=upstream-code-2&state={flow_state}"
                ))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let code = approve_federated_callback(&router, resp).await;
    let tok = exchange_code_for_tokens(&router, &code).await;

    // **核心断言**:下游 token 使用 canonical strong；id_token 仍保留上游 amr。
    let id_token = tok["id_token"].as_str().expect("应返回 id_token");
    // 评审 codex Low:先断言这是**本 AS 签发的下游 id_token**(iss=本 AS、aud=下游 client),
    // 而非意外把上游 id_token(iss=UPSTREAM_ISS、aud=UP_CLIENT)原样转发——否则 acr/amr 值相同也会"通过"。
    assert_eq!(
        jwt_claim(id_token, "iss"),
        serde_json::json!(format!("https://{HOST}")),
        "下游 id_token iss MUST=本 AS(非上游原样转发)"
    );
    assert_eq!(
        jwt_claim(id_token, "aud"),
        serde_json::json!(DS_CLIENT),
        "下游 id_token aud MUST=下游 client(非上游 UP_CLIENT)"
    );
    assert_eq!(
        jwt_claim(id_token, "acr"),
        serde_json::json!(agent_auth_authn::assurance::STRONG_ACR),
        "id_token.acr MUST be the mapped internal class"
    );
    assert_eq!(
        jwt_claim(id_token, "amr"),
        serde_json::json!(["pwd", "otp"]),
        "id_token.amr MUST == 上游透传值"
    );
    let access = tok["access_token"].as_str().expect("access_token");
    assert_eq!(
        jwt_claim(access, "acr"),
        serde_json::json!(agent_auth_authn::assurance::STRONG_ACR),
        "access_token carries the mapped class for RFC 9470-aware resources"
    );
    assert_eq!(
        jwt_claim(access, "amr"),
        serde_json::Value::Null,
        "access_token 当前 profile 不载 amr(本部署选择,非标准强制;RFC 9068 允许)"
    );
}

#[tokio::test]
async fn federation_strong_request_fails_closed_when_upstream_acr_is_unmapped() {
    let (router, state) = app_with_federation().await;
    let authz = format!(
        "/authorize?response_type=code&client_id={DS_CLIENT}&redirect_uri={DS_REDIRECT}\
         &code_challenge=abc&code_challenge_method=S256&scope=openid&state=strong-state\
         &acr_values=urn%3Aagent-auth%3Aassurance%3Astrong&idp_hint={IDP}"
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(authz)
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let upstream_location = location(&response);
    assert!(
        upstream_location.contains("acr_values=urn%3Amace%3Aincommon%3Aiap%3Asilver"),
        "configured upstream strong ACR must be requested: {upstream_location}"
    );
    assert!(
        upstream_location.contains("max_age=300"),
        "effective strong freshness must be forwarded upstream: {upstream_location}"
    );
    assert!(
        upstream_location.contains("prompt=login"),
        "step-up must explicitly request upstream reauthentication: {upstream_location}"
    );
    let flow_state = upstream_location
        .split(&['?', '&'][..])
        .find_map(|part| part.strip_prefix("state="))
        .unwrap()
        .to_string();
    let flow = peek_federation_flow(&state, &flow_state).await;
    let now = agent_auth_http::current_unix_secs();
    let (id_token, jwk) = mint_upstream_id_token(serde_json::json!({
        "iss": UPSTREAM_ISS,
        "sub": "unmapped-upstream-user",
        "aud": UP_CLIENT,
        "exp": now + 300,
        "iat": now,
        "nonce": flow.nonce,
        "acr": "urn:unknown:mfa",
        "amr": ["pwd", "mfa", "otp"],
        "auth_time": now
    }))
    .await;
    state
        .jwks_fetcher_set(format!("{UPSTREAM_ISS}/jwks"), vec![jwk])
        .await;
    state
        .upstream_exchanger_seed(
            "upstream-code-unmapped",
            UpstreamTokenSet {
                id_token,
                access_token: None,
            },
        )
        .await;

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/federation/callback?code=upstream-code-unmapped&state={flow_state}"
                ))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let downstream_location = location(&response);
    assert!(downstream_location.starts_with(DS_REDIRECT));
    assert!(downstream_location.contains("error=unmet_authentication_requirements"));
    assert!(downstream_location.contains("state=strong-state"));
    assert!(
        set_cookie_val(&response, "__Host-agent_auth_session").is_none(),
        "unmapped upstream evidence must not create a lower-assurance session"
    );
}

#[tokio::test]
async fn federation_strong_request_requires_fresh_upstream_auth_time() {
    let (router, state) = app_with_federation().await;
    let authz = format!(
        "/authorize?response_type=code&client_id={DS_CLIENT}&redirect_uri={DS_REDIRECT}\
         &code_challenge=abc&code_challenge_method=S256&scope=openid&state=fresh-state\
         &acr_values=urn%3Aagent-auth%3Aassurance%3Astrong&idp_hint={IDP}"
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(authz)
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let upstream_location = location(&response);
    let flow_state = upstream_location
        .split(&['?', '&'][..])
        .find_map(|part| part.strip_prefix("state="))
        .expect("upstream state")
        .to_string();
    let flow = peek_federation_flow(&state, &flow_state).await;
    let now = agent_auth_http::current_unix_secs();
    let (id_token, jwk) = mint_upstream_id_token(serde_json::json!({
        "iss": UPSTREAM_ISS,
        "sub": "missing-auth-time",
        "aud": UP_CLIENT,
        "exp": now + 300,
        "iat": now,
        "nonce": flow.nonce,
        "acr": "urn:mace:incommon:iap:silver",
        "amr": ["webauthn", "hwk"]
    }))
    .await;
    state
        .jwks_fetcher_set(format!("{UPSTREAM_ISS}/jwks"), vec![jwk])
        .await;
    state
        .upstream_exchanger_seed(
            "upstream-code-no-auth-time",
            UpstreamTokenSet {
                id_token,
                access_token: None,
            },
        )
        .await;

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/federation/callback?code=upstream-code-no-auth-time&state={flow_state}"
                ))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let downstream_location = location(&response);
    assert!(downstream_location.starts_with(DS_REDIRECT));
    assert!(downstream_location.contains("error=unmet_authentication_requirements"));
    assert!(downstream_location.contains("state=fresh-state"));
    assert!(
        set_cookie_val(&response, "__Host-agent_auth_session").is_none(),
        "missing upstream auth_time must not create a strong session"
    );
}

#[tokio::test]
async fn federation_strong_request_normalizes_only_bounded_upstream_clock_skew() {
    let (router, state) = app_with_federation().await;
    state
        .seed_dev_client(DS_CLIENT, DS_REDIRECT, Some(RS))
        .await;
    state
        .seed_rs_introspect_client("rs-introspect", "introspect-secret", &[RS])
        .await;
    let now = agent_auth_http::current_unix_secs();
    let response = complete_strong_federation_with_auth_time(
        &router,
        &state,
        "bounded-skew-state",
        "upstream-code-bounded-skew",
        "bounded-clock-skew",
        now + 60,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let session_id = set_cookie_val(&response, "__Host-agent_auth_session")
        .expect("bounded upstream clock skew must create a strong session");
    let session = state.sessions.get("", &session_id).await.unwrap().unwrap();
    let normalized_auth_time = session.expires_at - 3600;
    assert_eq!(
        session.auth_time, normalized_auth_time,
        "bounded future auth_time must be clamped to the exact callback time"
    );
    assert_ne!(
        normalized_auth_time,
        now + 60,
        "the future upstream value must not be stored unchanged"
    );

    let code = approve_federated_callback(&router, response).await;
    assert_code_auth_time(&state, &code, normalized_auth_time).await;
    let tokens = exchange_code_for_tokens(&router, &code).await;
    let access_token = tokens["access_token"].as_str().expect("access token");
    let id_token = tokens["id_token"].as_str().expect("ID token");
    assert_eq!(
        jwt_claim(access_token, "auth_time"),
        serde_json::json!(normalized_auth_time)
    );
    assert_eq!(
        jwt_claim(id_token, "auth_time"),
        serde_json::json!(normalized_auth_time)
    );

    let refresh_token = tokens["refresh_token"].as_str().expect("refresh token");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={refresh_token}&client_id={DS_CLIENT}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let refreshed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let refreshed_access = refreshed["access_token"]
        .as_str()
        .expect("refreshed access token");
    assert_eq!(
        jwt_claim(refreshed_access, "auth_time"),
        serde_json::json!(normalized_auth_time)
    );

    let basic = base64::engine::general_purpose::STANDARD.encode("rs-introspect:introspect-secret");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/introspect")
                .header("host", HOST)
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "token={refreshed_access}&client_id=rs-introspect"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let introspection: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(introspection["active"], true);
    assert_eq!(
        introspection["auth_time"],
        serde_json::json!(normalized_auth_time)
    );

    let response = complete_strong_federation_with_auth_time(
        &router,
        &state,
        "excessive-skew-state",
        "upstream-code-excessive-skew",
        "excessive-clock-skew",
        now + 600,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let downstream_location = location(&response);
    assert!(downstream_location.starts_with(DS_REDIRECT));
    assert!(downstream_location.contains("error=unmet_authentication_requirements"));
    assert!(downstream_location.contains("state=excessive-skew-state"));
    assert!(
        set_cookie_val(&response, "__Host-agent_auth_session").is_none(),
        "excessive upstream clock skew must not create a session"
    );
}

// 功能关:callback 404(不暴露不完整登录面,F10)。
#[tokio::test]
async fn callback_404_when_federation_disabled() {
    let state = AppState::dev(HOST); // federation_enabled=false 默认
    let (router, _) = build_router(state);
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/federation/callback?code=x&state=y")
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "联邦关时 callback 应 404"
    );
}

// bad state(未 stash / 已消费)→ 400。
#[tokio::test]
async fn callback_bad_state_rejected() {
    let (router, state) = app_with_federation().await;
    let missing = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/federation/callback?code=x")
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST, "缺 state 应 400");
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/federation/callback?code=x&state=never-stashed")
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "未知 state 应 400");
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    let denied = events
        .iter()
        .filter(|stored| {
            stored.event.action == "authentication.federation"
                && stored.event.outcome == SecurityEventOutcome::Denied
        })
        .collect::<Vec<_>>();
    assert_eq!(denied.len(), 2);
    assert!(denied.iter().all(|stored| {
        serde_json::to_value(&stored.event).unwrap()["actor"]["kind"] == "system"
            && stored.event.subject == SecuritySubject::unknown("anonymous")
    }));
    assert!(
        denied
            .iter()
            .all(|stored| !serde_json::to_string(&stored.event)
                .unwrap()
                .contains("never-stashed")),
        "untrusted callback state must not enter the event envelope"
    );
}

// nonce 不符(id_token.nonce != flow.nonce)→ 400(防 id_token 重放)。
#[tokio::test]
async fn callback_nonce_mismatch_rejected() {
    let (router, state) = app_with_federation().await;
    let flow_state = start_federation(&router).await;
    let now = agent_auth_http::current_unix_secs();
    // 用**错误 nonce** 铸 id_token。
    let (id_token, jwk) = mint_upstream_id_token(serde_json::json!({
        "iss": UPSTREAM_ISS, "sub": "u", "aud": UP_CLIENT,
        "exp": now + 300, "nonce": "attacker-nonce"
    }))
    .await;
    state
        .jwks_fetcher_set(format!("{UPSTREAM_ISS}/jwks"), vec![jwk])
        .await;
    state
        .upstream_exchanger_seed(
            "c2",
            UpstreamTokenSet {
                id_token,
                access_token: None,
            },
        )
        .await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri(format!("/federation/callback?code=c2&state={flow_state}"))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "nonce 不符应 400(防重放)"
    );
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    let denied = events
        .iter()
        .find(|stored| {
            stored.event.action == "authentication.federation"
                && stored.event.outcome == SecurityEventOutcome::Denied
        })
        .expect("rejected federation authentication must remain auditable");
    assert_eq!(denied.event.category, SecurityEventCategory::Authentication);
    assert_eq!(
        serde_json::to_value(&denied.event).unwrap()["actor"]["kind"],
        "system"
    );
    assert_eq!(denied.event.subject, SecuritySubject::unknown("anonymous"));
}

#[tokio::test]
async fn callback_unregistered_issuer_emits_trust_boundary_denial() {
    let (router, state) = app_with_federation().await;
    let flow_state = start_federation(&router).await;
    let flow = peek_federation_flow(&state, &flow_state).await;
    let unregistered_issuer = "https://unregistered-idp.example.com";
    let now = agent_auth_http::current_unix_secs();
    let (id_token, jwk) = mint_upstream_id_token(serde_json::json!({
        "iss": unregistered_issuer,
        "sub": "attacker-subject",
        "aud": UP_CLIENT,
        "exp": now + 300,
        "iat": now,
        "nonce": flow.nonce
    }))
    .await;
    state
        .jwks_fetcher_set(format!("{UPSTREAM_ISS}/jwks"), vec![jwk])
        .await;
    state
        .upstream_exchanger_seed(
            "wrong-issuer-code",
            UpstreamTokenSet {
                id_token,
                access_token: None,
            },
        )
        .await;

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/federation/callback?code=wrong-issuer-code&state={flow_state}"
                ))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    let boundary = events
        .iter()
        .find(|stored| stored.event.category == SecurityEventCategory::TenantBoundary)
        .expect("a verified token from an unregistered issuer must emit a trust boundary denial");
    assert_eq!(boundary.event.outcome, SecurityEventOutcome::Denied);
    assert_eq!(boundary.event.actor, SecurityActor::system("federation"));
    assert_eq!(
        boundary.event.subject,
        SecuritySubject::issuer(unregistered_issuer)
    );
}

#[tokio::test]
async fn callback_on_another_tenant_host_emits_boundary_denial() {
    let mut state = AppState::dev("example.com");
    state.form = agent_auth_discovery::Form::Saas {
        zone: "example.com".into(),
        control_host: "control.example.com".into(),
    };
    state.saas_tenants = std::sync::Arc::new(vec!["t1".to_string(), "t2".to_string()]);
    state.tenant_partitioning = true;
    state.federation_enabled = true;
    state
        .federation_config
        .put(agent_auth_authn::federation::FederationConfig {
            tenant_id: "t1".into(),
            upstream_idp_id: IDP.into(),
            protocol: agent_auth_authn::federation::UpstreamProtocol::Oidc,
            upstream_issuer: UPSTREAM_ISS.into(),
            strong_acr_values: vec![],
            oidc: Some(agent_auth_authn::federation::OidcRpParams {
                client_id: UP_CLIENT.into(),
                client_secret_ref: SECRET_REF.into(),
                authorization_endpoint: format!("{UPSTREAM_ISS}/authorize"),
                token_endpoint: format!("{UPSTREAM_ISS}/token"),
                jwks_uri: format!("{UPSTREAM_ISS}/jwks"),
                scopes: vec!["openid".into()],
            }),
        })
        .await
        .unwrap();
    let mut start_headers = HeaderMap::new();
    start_headers.insert("host", "t1.example.com".parse().unwrap());
    let started = agent_auth_http::federation_flow::start(
        &state,
        &start_headers,
        IDP,
        "client_id=test-client&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb",
        None,
        false,
    )
    .await
    .expect("configured tenant must start federation");
    let flow_state = query_param(&location(&started), "state").unwrap();
    let (router, _) = build_router(state.clone());

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/federation/callback?state={flow_state}"))
                .header("host", "t2.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let events = state
        .security_events
        .list_by_tenant("t2", 0, i64::MAX, 100)
        .await
        .unwrap();
    let boundary = events
        .iter()
        .find(|stored| stored.event.action == "tenant.access_denied")
        .expect("cross-tenant federation callback must emit a boundary denial");
    assert_eq!(
        boundary.event.category,
        SecurityEventCategory::TenantBoundary
    );
    assert_eq!(boundary.event.actor, SecurityActor::system("federation"));
    assert_eq!(boundary.event.subject, SecuritySubject::tenant("t1"));
}

// 上游 error 透传:callback 带 ?error= → 回跳原下游 redirect_uri 带 error(F5)。
#[tokio::test]
async fn callback_upstream_error_passed_through_to_downstream() {
    let (router, _) = app_with_federation().await;
    let flow_state = start_federation(&router).await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/federation/callback?error=access_denied&state={flow_state}"
                ))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = location(&resp);
    assert!(
        loc.starts_with(DS_REDIRECT),
        "透传回下游 redirect_uri: {loc}"
    );
    assert!(loc.contains("error=access_denied"), "透传上游 error");
    assert!(loc.contains("state=downstream-state"), "带回下游 state");
}
