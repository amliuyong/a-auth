//! HTTP acceptance coverage for RFC 9470 assurance and step-up (C12.4).

use agent_auth_authn::assurance::{BASELINE_ACR, STRONG_ACR};
use agent_auth_client::s256_challenge;
use agent_auth_http::ports::{AuthzSessionStore, GrantStore, SessionRecord, SessionStore};
use agent_auth_http::{build_router, AppState, Phase};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use tower::ServiceExt;

const HOST: &str = "localhost";
const CLIENT: &str = "assurance-client";
const REDIRECT: &str = "https://client.example.com/callback";
const RESOURCE: &str = "https://api.example.com";
const USER: &str = "user:assurance@example.com";
const VERIFIER: &str = "0123456789012345678901234567890123456789abc";

fn location(response: &axum::response::Response) -> &str {
    response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
}

async fn app_with_session(acr: &str, amr: Vec<String>) -> (axum::Router, AppState, String, i64) {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    state.passkey_enabled = true;
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    state.seed_dev_user("assurance@example.com").await;
    let session_id = format!("session-{}", acr.rsplit(':').next().unwrap_or("unknown"));
    let now = agent_auth_http::current_unix_secs();
    state
        .sessions
        .create(
            "",
            SessionRecord {
                session_id: session_id.clone(),
                user_id: USER.to_string(),
                credential_epoch: 0,
                auth_time: now,
                created_at: now,
                last_used_at: now,
                device: "Test browser".into(),
                expires_at: now + 3600,
                acr: Some(acr.to_string()),
                amr,
            },
        )
        .await
        .unwrap();
    let observable_state = state.clone();
    let (router, _) = build_router(state);
    (router, observable_state, session_id, now)
}

fn authorize_uri(acr_values: &str) -> String {
    let challenge = s256_challenge(VERIFIER);
    format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid\
         &state=assurance-state&acr_values={acr_values}"
    )
}

async fn authorize(router: &axum::Router, uri: &str, session_id: &str) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn acr_values_requires_step_up_and_canonical_strong_session_satisfies_it() {
    let (baseline_router, _, baseline_session, _) =
        app_with_session(BASELINE_ACR, vec!["pwd".to_string()]).await;
    let requested = STRONG_ACR.replace(':', "%3A");
    let uri = authorize_uri(&requested);

    let baseline = authorize(&baseline_router, &uri, &baseline_session).await;
    assert_eq!(baseline.status(), StatusCode::SEE_OTHER);
    assert!(
        location(&baseline).starts_with("https://localhost/login?"),
        "a baseline session must be sent to step-up, got {}",
        location(&baseline)
    );
    assert!(
        location(&baseline).contains("acr_values=urn%3Aagent-auth%3Aassurance%3Astrong"),
        "the required assurance must survive the browser continuation"
    );
    assert!(!location(&baseline).contains("code="));

    let (strong_router, _, strong_session, _) =
        app_with_session(STRONG_ACR, vec!["webauthn".to_string(), "hwk".to_string()]).await;
    let strong = authorize(&strong_router, &uri, &strong_session).await;
    assert_eq!(strong.status(), StatusCode::SEE_OTHER);
    assert!(
        location(&strong).starts_with("https://localhost/consent?"),
        "a canonical strong session must satisfy strong assurance, got {}",
        location(&strong)
    );
}

#[tokio::test]
async fn baseline_acr_cannot_be_elevated_by_passkey_shaped_amr() {
    let (router, _, session, _) = app_with_session(
        BASELINE_ACR,
        vec!["webauthn".to_string(), "hwk".to_string()],
    )
    .await;
    let requested = STRONG_ACR.replace(':', "%3A");
    let response = authorize(&router, &authorize_uri(&requested), &session).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        location(&response).starts_with("https://localhost/login?"),
        "observational AMR must not override a mapped baseline ACR"
    );
    assert!(!location(&response).contains("code="));
}

#[tokio::test]
async fn unsupported_acr_values_fails_at_the_authorization_boundary() {
    let (router, _, session, _) = app_with_session(BASELINE_ACR, vec!["pwd".to_string()]).await;
    let response = authorize(&router, &authorize_uri("unknown-acr"), &session).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(location(&response).starts_with(REDIRECT));
    assert!(location(&response).contains("error=unmet_authentication_requirements"));
    assert!(location(&response).contains("state=assurance-state"));
    assert!(!location(&response).contains("code="));
}

#[tokio::test]
async fn login_placeholder_cannot_issue_code_for_high_risk_rar() {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    state.seed_dev_user("assurance@example.com").await;
    let (router, _) = build_router(state);
    let challenge = s256_challenge(VERIFIER);
    let rar = serde_urlencoded::to_string([(
        "authorization_details",
        r#"[{"type":"agent_auth_rar_v1","actions":["transfer"]}]"#,
    )])
    .unwrap();
    let uri = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid\
         &state=placeholder-state&login_user=user%3Aassurance%40example.com&{rar}"
    );
    let response = router
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(location(&response).starts_with(REDIRECT));
    assert!(location(&response).contains("error=unmet_authentication_requirements"));
    assert!(location(&response).contains("state=placeholder-state"));
    assert!(!location(&response).contains("code="));
}

#[tokio::test]
async fn high_risk_rar_is_gated_again_at_consent_before_code_issuance() {
    let (router, state, session, _) = app_with_session(BASELINE_ACR, vec!["pwd".to_string()]).await;
    let rar = r#"[{"type":"agent_auth_rar_v1","actions":["transfer"]}]"#;
    let encoded_rar = serde_urlencoded::to_string([("authorization_details", rar)]).unwrap();
    let authorize_query = format!(
        "{}&{encoded_rar}",
        authorize_uri(&BASELINE_ACR.replace(':', "%3A")).trim_start_matches("/authorize?")
    );

    let response = authorize(&router, &format!("/authorize?{authorize_query}"), &session).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(location(&response).starts_with("https://localhost/login?"));
    assert!(location(&response).contains("acr_values=urn%3Aagent-auth%3Aassurance%3Astrong"));
    assert!(!location(&response).contains("code="));
    let authz_session_id =
        query_param(location(&response), "authz_session_id").expect("authorization session id");
    let authorize_query = format!("{authorize_query}&authz_session_id={authz_session_id}");

    // A browser-controlled authorize_query must not bypass the earlier gate.
    let context = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/consent/context?{authorize_query}"))
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(context.status(), StatusCode::OK);
    let body = axum::body::to_bytes(context.into_body(), usize::MAX)
        .await
        .unwrap();
    let csrf = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["csrf_token"]
        .as_str()
        .unwrap()
        .to_string();

    let decision = serde_json::json!({
        "decision": "approve",
        "csrf": csrf,
        "authorize_query": authorize_query,
    });
    let response = router
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
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], b"unmet_authentication_requirements");
    let authz_session = state
        .authz_sessions
        .get("", &authz_session_id)
        .await
        .unwrap()
        .expect("authorization session");
    assert_eq!(
        authz_session.state,
        agent_auth_authn::authz_session::AuthzState::PendingUserAuthentication.as_str(),
        "failed step-up must not claim that an authorization code was issued"
    );
}

#[tokio::test]
async fn strong_step_up_completes_high_risk_rar_without_pre_step_up_grant() {
    let (router, state, baseline_session, _) =
        app_with_session(BASELINE_ACR, vec!["pwd".to_string()]).await;
    state
        .seed_dev_client(CLIENT, REDIRECT, Some(RESOURCE))
        .await;
    let now = agent_auth_http::current_unix_secs();
    let strong_session = "session-strong-rar".to_string();
    state
        .sessions
        .create(
            "",
            SessionRecord {
                session_id: strong_session.clone(),
                user_id: USER.to_string(),
                credential_epoch: 0,
                auth_time: now,
                created_at: now,
                last_used_at: now,
                device: "Step-up browser".into(),
                expires_at: now + 3600,
                acr: Some(STRONG_ACR.to_string()),
                amr: vec!["webauthn".to_string(), "hwk".to_string()],
            },
        )
        .await
        .unwrap();

    let rar = r#"[{"type":"agent_auth_rar_v1","actions":["transfer"]}]"#;
    let encoded_rar = serde_urlencoded::to_string([("authorization_details", rar)]).unwrap();
    let authorize_query = format!(
        "{}&resource={RESOURCE}&{encoded_rar}",
        authorize_uri(&BASELINE_ACR.replace(':', "%3A")).trim_start_matches("/authorize?")
    );

    let baseline = authorize(
        &router,
        &format!("/authorize?{authorize_query}"),
        &baseline_session,
    )
    .await;
    assert_eq!(baseline.status(), StatusCode::SEE_OTHER);
    assert!(location(&baseline).starts_with("https://localhost/login?"));
    assert!(location(&baseline).contains("acr_values=urn%3Aagent-auth%3Aassurance%3Astrong"));
    assert!(!location(&baseline).contains("code="));
    assert!(
        state
            .grants
            .list_by_user("", USER)
            .await
            .unwrap()
            .is_empty(),
        "the low-assurance request must not create a Grant before step-up"
    );

    let authz_session_id =
        query_param(location(&baseline), "authz_session_id").expect("authorization session id");
    let pending = state
        .authz_sessions
        .get("", &authz_session_id)
        .await
        .unwrap()
        .expect("authorization session");
    assert_eq!(
        pending.state,
        agent_auth_authn::authz_session::AuthzState::PendingUserAuthentication.as_str(),
        "the low-assurance request must not reach an authorization-code state"
    );
    let resumed_query = format!("{authorize_query}&authz_session_id={authz_session_id}");
    let resumed = authorize(
        &router,
        &format!("/authorize?{resumed_query}"),
        &strong_session,
    )
    .await;
    assert_eq!(resumed.status(), StatusCode::SEE_OTHER);
    assert!(location(&resumed).starts_with("https://localhost/consent?"));
    let consent_query = location(&resumed)
        .split_once('?')
        .expect("consent query")
        .1
        .to_string();

    let context = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/consent/context?{consent_query}"))
                .header("host", HOST)
                .header(
                    "cookie",
                    format!("__Host-agent_auth_session={strong_session}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(context.status(), StatusCode::OK);
    let body = axum::body::to_bytes(context.into_body(), usize::MAX)
        .await
        .unwrap();
    let csrf = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["csrf_token"]
        .as_str()
        .unwrap()
        .to_string();
    let decision = serde_json::json!({
        "decision": "approve",
        "csrf": csrf,
        "authorize_query": consent_query,
    });
    let consent = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/consent/decision")
                .header("host", HOST)
                .header("content-type", "application/json")
                .header(
                    "cookie",
                    format!("__Host-agent_auth_session={strong_session}"),
                )
                .body(Body::from(serde_json::to_vec(&decision).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(consent.status(), StatusCode::OK);
    let body = axum::body::to_bytes(consent.into_body(), usize::MAX)
        .await
        .unwrap();
    let redirect = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["redirect"]
        .as_str()
        .unwrap()
        .to_string();
    let code = query_param(&redirect, "code").expect("authorization code after strong step-up");

    let token = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&code_verifier={VERIFIER}\
                     &redirect_uri={REDIRECT}&client_id={CLIENT}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let token_status = token.status();
    let body = axum::body::to_bytes(token.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        token_status,
        StatusCode::OK,
        "token exchange failed: {}",
        String::from_utf8_lossy(&body)
    );
    let token: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let claims = jwt_claims(token["access_token"].as_str().unwrap());
    assert_eq!(claims["acr"], STRONG_ACR);
    assert_eq!(claims["authorization_details"][0]["actions"][0], "transfer");

    let grants = state.grants.list_by_user("", USER).await.unwrap();
    assert_eq!(grants.len(), 1);
    assert!(
        grants[0].per_resource.iter().any(|resource| {
            resource
                .authorization_details
                .iter()
                .any(|detail| detail["actions"][0] == "transfer")
        }),
        "Grant did not preserve transfer RAR: {:#?}",
        grants[0]
    );
}

fn jwt_claims(jwt: &str) -> serde_json::Value {
    let payload = jwt.split('.').nth(1).expect("JWT payload");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

fn query_param(url: &str, key: &str) -> Option<String> {
    url.split_once('?')?.1.split('&').find_map(|part| {
        let (name, value) = part.split_once('=')?;
        (name == key).then(|| value.to_string())
    })
}

#[tokio::test]
async fn access_and_refresh_tokens_preserve_the_authentication_event() {
    let (router, _, session, auth_time) =
        app_with_session(STRONG_ACR, vec!["webauthn".to_string(), "hwk".to_string()]).await;
    let requested = STRONG_ACR.replace(':', "%3A");
    let response = authorize(&router, &authorize_uri(&requested), &session).await;
    let consent_query = location(&response)
        .split_once('?')
        .expect("consent query")
        .1
        .to_string();

    let context = router
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
    assert_eq!(context.status(), StatusCode::OK);
    let body = axum::body::to_bytes(context.into_body(), usize::MAX)
        .await
        .unwrap();
    let csrf = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["csrf_token"]
        .as_str()
        .unwrap()
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
        .unwrap()
        .to_string();
    let code = query_param(&redirect, "code").expect("authorization code");

    let token = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&code_verifier={VERIFIER}\
                     &redirect_uri={REDIRECT}&client_id={CLIENT}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(token.status(), StatusCode::OK);
    let body = axum::body::to_bytes(token.into_body(), usize::MAX)
        .await
        .unwrap();
    let token: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let first_claims = jwt_claims(token["access_token"].as_str().unwrap());
    assert_eq!(first_claims["acr"], STRONG_ACR);
    assert_eq!(first_claims["auth_time"], auth_time);

    let refresh = token["refresh_token"].as_str().expect("refresh token");
    let refreshed = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={refresh}&client_id={CLIENT}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refreshed.status(), StatusCode::OK);
    let body = axum::body::to_bytes(refreshed.into_body(), usize::MAX)
        .await
        .unwrap();
    let refreshed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let refreshed_claims = jwt_claims(refreshed["access_token"].as_str().unwrap());
    assert_eq!(refreshed_claims["acr"], STRONG_ACR);
    assert_eq!(refreshed_claims["auth_time"], auth_time);
}
