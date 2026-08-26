use agent_auth_http::{
    build_router,
    ports::{AuthzSessionRecord, AuthzSessionStore, SessionRecord, SessionStore},
    AppState,
};
use axum::{
    body::Body,
    http::{header, Request, Response, StatusCode},
};
use tower::ServiceExt;

const ZONE: &str = "aws.example.com";
const CONTROL: &str = "c.aws.example.com";
const T1_HOST: &str = "t1.aws.example.com";
const T2_HOST: &str = "t2.aws.example.com";
const SESSION_COOKIE: &str = "__Host-agent_auth_session";

fn cookie_value(response: &Response<Body>, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .find_map(|value| {
            let value = value.to_str().ok()?;
            value
                .strip_prefix(&format!("{name}="))
                .map(|rest| rest.split(';').next().unwrap_or_default().to_string())
        })
}

async fn login(router: &axum::Router, host: &str, email: &str, user_agent: &str) -> String {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login/magic-link")
                .header("host", host)
                .header(header::USER_AGENT, user_agent)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "email": email,
                        "authorize_query": "",
                        "next": "",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let nonce = cookie_value(&response, "__Host-agent_auth_login_nonce").unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let link = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["dev_link"]
        .as_str()
        .unwrap()
        .to_string();
    let path_and_query = link.split_once("/login/callback").unwrap().1;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/login/callback{path_and_query}"))
                .header("host", host)
                .header(header::USER_AGENT, user_agent)
                .header(
                    header::COOKIE,
                    format!("__Host-agent_auth_login_nonce={nonce}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    cookie_value(&response, SESSION_COOKIE).unwrap()
}

async fn request(
    router: &axum::Router,
    method: &str,
    host: &str,
    path: &str,
    session: &str,
) -> Response<Body> {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("host", host)
                .header(header::COOKIE, format!("{SESSION_COOKIE}={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn list(router: &axum::Router, host: &str, session: &str) -> (StatusCode, serde_json::Value) {
    let response = request(router, "GET", host, "/account/sessions", session).await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
    )
}

async fn app() -> (axum::Router, AppState) {
    let mut state = AppState::dev("unused.example.com");
    state.form = agent_auth_discovery::Form::Saas {
        zone: ZONE.to_string(),
        control_host: CONTROL.to_string(),
    };
    state.saas_tenants = std::sync::Arc::new(vec!["t1".to_string(), "t2".to_string()]);
    state.tenant_partitioning = true;
    state
        .seed_dev_user_in_tenant("t1", "alice@example.com")
        .await;
    state
        .seed_dev_user_in_tenant("t1", "mallory@example.com")
        .await;
    state
        .seed_dev_user_in_tenant("t2", "alice@example.com")
        .await;
    let observable = state.clone();
    let (router, _) = build_router(state);
    (router, observable)
}

#[tokio::test]
async fn list_revoke_and_keep_current_are_private_idempotent_and_audited() {
    let (router, state) = app().await;
    let chrome = login(
        &router,
        T1_HOST,
        "alice@example.com",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
    )
    .await;
    let safari = "test-safari-session-cookie".to_string();
    let firefox = "test-firefox-session-cookie".to_string();
    let now = agent_auth_http::current_unix_secs();
    for (session_id, device) in [
        (&safari, "Safari on iPhone"),
        (&firefox, "Firefox on Windows"),
    ] {
        state
            .sessions
            .create(
                "t1",
                SessionRecord {
                    session_id: session_id.clone(),
                    user_id: "user:alice@example.com".to_string(),
                    credential_epoch: 0,
                    auth_time: now,
                    created_at: now,
                    last_used_at: now,
                    device: device.to_string(),
                    expires_at: now + 3_600,
                    acr: None,
                    amr: vec!["pwd".to_string()],
                },
            )
            .await
            .unwrap();
    }
    let mallory = login(
        &router,
        T1_HOST,
        "mallory@example.com",
        "Mozilla/5.0 (Android 15) AppleWebKit/537.36 Chrome/126.0 Mobile Safari/537.36",
    )
    .await;
    let t2_alice = login(
        &router,
        T2_HOST,
        "alice@example.com",
        "Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1",
    )
    .await;
    state
        .authz_sessions
        .create(
            "t1",
            AuthzSessionRecord {
                session_id: "oauth-authorization-session".to_string(),
                client_id: "oauth-client".to_string(),
                user_id: Some("user:alice@example.com".to_string()),
                state: "pending_consent".to_string(),
                session_token_hash: "not-a-login-cookie".to_string(),
                sequence: 0,
                last_error: None,
                expires_at: now + 3_600,
            },
        )
        .await
        .unwrap();

    let (status, sessions) = list(&router, T1_HOST, &chrome).await;
    assert_eq!(status, StatusCode::OK);
    let sessions = sessions.as_array().unwrap();
    assert_eq!(sessions.len(), 3);
    assert_eq!(
        sessions
            .iter()
            .filter(|session| session["current"] == true)
            .count(),
        1
    );
    assert!(sessions
        .iter()
        .any(|session| session["device"] == "Chrome on Linux"));
    assert!(sessions
        .iter()
        .any(|session| session["device"] == "Safari on iPhone"));
    assert!(sessions
        .iter()
        .any(|session| session["device"] == "Firefox on Windows"));
    assert!(sessions.iter().all(|session| {
        session["id"].as_str().is_some_and(|id| {
            (60..=512).contains(&id.len())
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        }) && session["created_at"].as_i64().is_some()
            && session["last_used_at"].as_i64().is_some()
            && session["expires_at"].as_i64().is_some()
    }));
    let encoded = serde_json::to_string(sessions).unwrap();
    assert!(
        !encoded.contains("oauth-authorization-session"),
        "the account surface must not mix OAuth AuthzSession records into login sessions"
    );
    for raw_cookie in [&chrome, &safari, &firefox] {
        assert!(
            !encoded.contains(raw_cookie),
            "session listing must not expose an active cookie credential"
        );
    }

    let safari_handle = sessions
        .iter()
        .find(|session| session["device"] == "Safari on iPhone")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Another user and another tenant receive the same idempotent response but
    // cannot resolve or delete the target session.
    for (host, attacker) in [(T1_HOST, &mallory), (T2_HOST, &t2_alice)] {
        let response = request(
            &router,
            "DELETE",
            host,
            &format!("/account/sessions/{safari_handle}"),
            attacker,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(list(&router, T1_HOST, &safari).await.0, StatusCode::OK);
    }

    // Authenticated callers cannot turn a modified or oversized ciphertext into
    // a deletion primitive.
    let mut tampered = safari_handle.clone().into_bytes();
    tampered[0] = if tampered[0] == b'A' { b'B' } else { b'A' };
    for invalid_handle in [String::from_utf8(tampered).unwrap(), "A".repeat(513)] {
        let response = request(
            &router,
            "DELETE",
            T1_HOST,
            &format!("/account/sessions/{invalid_handle}"),
            &chrome,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(list(&router, T1_HOST, &safari).await.0, StatusCode::OK);
    }

    // Concurrent retries are idempotent: one conditional delete wins, the other
    // observes an already-absent target, and both return the same external result.
    let path = format!("/account/sessions/{safari_handle}");
    let (first, second) = tokio::join!(
        request(&router, "DELETE", T1_HOST, &path, &chrome),
        request(&router, "DELETE", T1_HOST, &path, &chrome),
    );
    assert_eq!(first.status(), StatusCode::NO_CONTENT);
    assert_eq!(second.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        request(&router, "DELETE", T1_HOST, &path, &chrome)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        list(&router, T1_HOST, &safari).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(list(&router, T1_HOST, &chrome).await.0, StatusCode::OK);

    // Revoke all remaining sessions except the authenticated current session.
    assert_eq!(
        request(&router, "DELETE", T1_HOST, "/account/sessions", &chrome)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        request(&router, "DELETE", T1_HOST, "/account/sessions", &chrome)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        list(&router, T1_HOST, &firefox).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, retained) = list(&router, T1_HOST, &chrome).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(retained.as_array().unwrap().len(), 1);
    assert_eq!(retained[0]["current"], true);

    let audit = state.credential_audit.snapshot().join("\n");
    assert!(
        audit.contains("USER_SESSION_OPERATION action=list tenant=t1 actor=user:alice@example.com")
    );
    assert!(audit.contains("USER_SESSION_OPERATION action=revoke tenant=t1"));
    assert!(audit.contains("result=success affected=1"));
    assert!(audit.contains(
        "USER_SESSION_OPERATION action=revoke_others tenant=t1 actor=user:alice@example.com target=all_other result=success"
    ));
    for raw_cookie in [&chrome, &safari, &firefox, &mallory, &t2_alice] {
        assert!(
            !audit.contains(raw_cookie),
            "audit must not contain cookie credentials"
        );
    }
}

#[tokio::test]
async fn revoking_current_session_clears_cookie_and_rejects_next_request() {
    let (router, _) = app().await;
    let session = login(
        &router,
        T1_HOST,
        "alice@example.com",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Version/17.5 Safari/605.1.15",
    )
    .await;
    let (_, sessions) = list(&router, T1_HOST, &session).await;
    let current_handle = sessions[0]["id"].as_str().unwrap();

    let response = request(
        &router,
        "DELETE",
        T1_HOST,
        &format!("/account/sessions/{current_handle}"),
        &session,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let cleared = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(cleared.starts_with("__Host-agent_auth_session=;"));
    assert!(cleared.contains("Max-Age=0"));
    assert_eq!(
        list(&router, T1_HOST, &session).await.0,
        StatusCode::UNAUTHORIZED
    );
}
