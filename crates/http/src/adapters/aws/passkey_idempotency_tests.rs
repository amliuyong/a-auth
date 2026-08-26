use super::{
    DynamoPasskeyChallengeStore, DynamoPasskeyStore, DynamoSessionStore, DynamoUsersStore,
};
use crate::ports::{PasskeyRegistrationOutcome, PasskeyStore, SessionRecord, SessionStore};
use crate::state::PasskeyChallengeStoreImpl;
use crate::{build_router, AppState};
use agent_auth_authn::passkey::PasskeyCredential;
use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

fn test_client(address: std::net::SocketAddr) -> aws_sdk_dynamodb::Client {
    let config = aws_sdk_dynamodb::Config::builder()
        .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
        .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
        .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
        .endpoint_url(format!("http://{address}"))
        .retry_config(aws_sdk_dynamodb::config::retry::RetryConfig::standard().with_max_attempts(1))
        .build();
    aws_sdk_dynamodb::Client::from_conf(config)
}

async fn serve(app: Router) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (address, server)
}

async fn always_failing_dynamo() -> impl IntoResponse {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [
            (header::CONTENT_TYPE, "application/x-amz-json-1.0"),
            (
                header::HeaderName::from_static("x-amzn-errortype"),
                "InternalServerError",
            ),
        ],
        r#"{"__type":"com.amazonaws.dynamodb.v20120810#InternalServerError","message":"unavailable"}"#,
    )
}

#[tokio::test]
async fn passkey_registration_audits_challenge_store_failures() {
    let (address, server) = serve(Router::new().route("/", post(always_failing_dynamo))).await;
    let mut state = AppState::dev("localhost");
    state.passkey_enabled = true;
    state.seed_dev_user("audit-failure@example.com").await;
    state.passkey_challenges = Arc::new(PasskeyChallengeStoreImpl::Dynamo(
        DynamoPasskeyChallengeStore::new(test_client(address), "challenge-table"),
    ));
    let now = crate::current_unix_secs();
    state
        .sessions
        .create(
            "",
            SessionRecord {
                session_id: "audit-failure-session".to_string(),
                user_id: "user:audit-failure@example.com".to_string(),
                credential_epoch: 0,
                auth_time: now,
                created_at: now,
                last_used_at: now,
                device: "Test".to_string(),
                expires_at: now + 3_600,
                acr: None,
                amr: vec!["email".to_string()],
            },
        )
        .await
        .unwrap();
    let audit = state.credential_audit.clone();
    let (router, _) = build_router(state);
    let begin_response = router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/passkey/register/begin")
                .header("host", "localhost")
                .header("cookie", "__Host-agent_auth_session=audit-failure-session")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(begin_response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        audit
            .snapshot()
            .iter()
            .filter(|event| event.contains("action=register tenant= actor=user:audit-failure@example.com kind=passkey target=new result=failed"))
            .count(),
        1
    );

    let finish_response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/passkey/register/finish")
                .header("host", "localhost")
                .header("cookie", "__Host-agent_auth_session=audit-failure-session")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "challenge": "challenge",
                        "client_data_json": "ignored",
                        "attestation_object": "ignored"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    server.abort();

    assert_eq!(finish_response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        audit
            .snapshot()
            .iter()
            .filter(|event| event.contains("action=register tenant= actor=user:audit-failure@example.com kind=passkey target=new result=failed"))
            .count(),
        2
    );
}

#[derive(Clone, Default)]
struct RegistrationFake {
    transactions: Arc<Mutex<Vec<Value>>>,
}

async fn registration_dynamo(
    State(fake): State<RegistrationFake>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let target = headers
        .get("x-amz-target")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if target.ends_with(".GetItem") {
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
            "{}",
        )
            .into_response();
    }
    let request: Value = serde_json::from_slice(&body).expect("transaction request");
    let attempt = {
        let mut transactions = fake.transactions.lock().unwrap();
        transactions.push(request);
        transactions.len()
    };
    if attempt == 1 {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            [
                (header::CONTENT_TYPE, "application/x-amz-json-1.0"),
                (
                    header::HeaderName::from_static("x-amzn-errortype"),
                    "InternalServerError",
                ),
            ],
            r#"{"__type":"com.amazonaws.dynamodb.v20120810#InternalServerError","message":"response lost after commit"}"#,
        )
            .into_response()
    } else {
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
            "{}",
        )
            .into_response()
    }
}

#[tokio::test]
async fn passkey_registration_replays_an_ambiguous_commit_with_the_same_token() {
    let fake = RegistrationFake::default();
    let (address, server) = serve(
        Router::new()
            .route("/", post(registration_dynamo))
            .with_state(fake.clone()),
    )
    .await;
    let db = test_client(address);
    let users = DynamoUsersStore::new(db.clone(), "users-table");
    let sessions = DynamoSessionStore::new(db.clone(), "sessions-table");
    let passkeys = DynamoPasskeyStore::new(db, "passkeys-table");
    let now = 1_700_000_000;
    let session = SessionRecord {
        session_id: "session".to_string(),
        user_id: "user:test@example.com".to_string(),
        credential_epoch: 0,
        auth_time: now,
        created_at: now,
        last_used_at: now,
        device: "Test".to_string(),
        expires_at: now + 3_600,
        acr: None,
        amr: vec!["email".to_string()],
    };
    let outcome = passkeys
        .put_new_authorized(
            &users,
            &sessions,
            "",
            &session,
            PasskeyCredential {
                credential_id: "credential".to_string(),
                user_id: session.user_id.clone(),
                rp_id: "localhost".to_string(),
                public_key_sec1: vec![4; 65],
                sign_count: 0,
                name: "Passkey".to_string(),
                created_at: now,
            },
            now,
        )
        .await
        .unwrap();
    server.abort();

    assert_eq!(outcome, PasskeyRegistrationOutcome::Created);
    let transactions = fake.transactions.lock().unwrap();
    assert_eq!(transactions.len(), 2);
    assert_eq!(transactions[0], transactions[1]);
    assert_eq!(
        transactions[0]["ClientRequestToken"]
            .as_str()
            .unwrap()
            .len(),
        36
    );
}

#[derive(Clone)]
struct RenameFake {
    before: PasskeyCredential,
    after: PasskeyCredential,
    get_count: Arc<Mutex<usize>>,
    put_count: Arc<Mutex<usize>>,
}

async fn rename_dynamo(
    State(fake): State<RenameFake>,
    headers: HeaderMap,
    _body: Bytes,
) -> impl IntoResponse {
    let target = headers
        .get("x-amz-target")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if target.ends_with(".GetItem") {
        let credential = {
            let mut count = fake.get_count.lock().unwrap();
            *count += 1;
            if *count == 1 {
                &fake.before
            } else {
                &fake.after
            }
        };
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
            json!({
                "Item": {
                    "cred_json": { "S": serde_json::to_string(credential).unwrap() }
                }
            })
            .to_string(),
        )
            .into_response();
    }
    *fake.put_count.lock().unwrap() += 1;
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [
            (header::CONTENT_TYPE, "application/x-amz-json-1.0"),
            (
                header::HeaderName::from_static("x-amzn-errortype"),
                "InternalServerError",
            ),
        ],
        r#"{"__type":"com.amazonaws.dynamodb.v20120810#InternalServerError","message":"response lost after commit"}"#,
    )
        .into_response()
}

#[tokio::test]
async fn passkey_rename_reconciles_a_committed_lost_response() {
    let before = PasskeyCredential {
        credential_id: "credential".to_string(),
        user_id: "user:test@example.com".to_string(),
        rp_id: "localhost".to_string(),
        public_key_sec1: vec![4; 65],
        sign_count: 0,
        name: "Before".to_string(),
        created_at: 1_700_000_000,
    };
    let mut after = before.clone();
    after.name = "After".to_string();
    let fake = RenameFake {
        before,
        after,
        get_count: Arc::new(Mutex::new(0)),
        put_count: Arc::new(Mutex::new(0)),
    };
    let (address, server) = serve(
        Router::new()
            .route("/", post(rename_dynamo))
            .with_state(fake.clone()),
    )
    .await;
    let passkeys = DynamoPasskeyStore::new(test_client(address), "passkeys-table");
    let renamed = passkeys
        .rename_owned("", "user:test@example.com", "credential", "After")
        .await
        .unwrap();
    server.abort();

    assert!(renamed);
    assert_eq!(*fake.get_count.lock().unwrap(), 2);
    assert_eq!(*fake.put_count.lock().unwrap(), 1);
}
