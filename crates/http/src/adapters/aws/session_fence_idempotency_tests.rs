use super::DynamoSessionStore;
use crate::ports::SessionStore;
use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct FakeDynamo {
    committed: Arc<Mutex<bool>>,
    tokens: Arc<Mutex<Vec<String>>>,
}

async fn dynamo(
    State(fake): State<FakeDynamo>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let target = headers
        .get("x-amz-target")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let request: Value = serde_json::from_slice(&body).expect("DynamoDB request is JSON");

    if target.ends_with(".TransactWriteItems") {
        let token = request["ClientRequestToken"]
            .as_str()
            .expect("transaction has an idempotency token")
            .to_string();
        let fence_id = request["TransactItems"][0]["Update"]["ExpressionAttributeValues"][":fence"]
            ["S"]
            .as_str()
            .expect("generation update has a fence id");
        assert_eq!(fence_id, token);
        fake.tokens.lock().expect("token lock").push(token);
        *fake.committed.lock().expect("commit lock") = true;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [
                (header::CONTENT_TYPE, "application/x-amz-json-1.0"),
                (
                    header::HeaderName::from_static("x-amzn-errortype"),
                    "InternalServerError",
                ),
            ],
            r#"{"__type":"com.amazonaws.dynamodb.v20120810#InternalServerError","message":"response lost after commit"}"#.to_string(),
        )
            .into_response();
    }

    let key = request["Key"]["session_id"]["S"]
        .as_str()
        .expect("GetItem session key");
    let committed = *fake.committed.lock().expect("commit lock");
    let item = if key.contains("__login_session_generation__") {
        if committed {
            let token = fake
                .tokens
                .lock()
                .expect("token lock")
                .first()
                .cloned()
                .expect("committed transaction token");
            Some(json!({
                "session_id": { "S": key },
                "generation": { "N": "1" },
                "credential_session_fence_id": { "S": token }
            }))
        } else {
            None
        }
    } else if committed {
        None
    } else {
        Some(json!({
            "session_id": { "S": key },
            "user_id": { "S": "user:test@example.com" },
            "session_generation": { "N": "0" },
            "credential_epoch": { "N": "0" },
            "auth_time": { "N": "1700000000" },
            "created_at": { "N": "1700000000" },
            "last_used_at": { "N": "1700000000" },
            "expires_at": { "N": "1700003600" }
        }))
    };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
        item.map_or_else(|| json!({}), |item| json!({ "Item": item }))
            .to_string(),
    )
        .into_response()
}

#[tokio::test]
async fn credential_session_fence_reconciles_a_committed_lost_response() {
    let fake = FakeDynamo::default();
    let app = Router::new()
        .route("/", post(dynamo))
        .with_state(fake.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let config = aws_sdk_dynamodb::Config::builder()
        .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
        .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
        .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
        .endpoint_url(format!("http://{address}"))
        .retry_config(aws_sdk_dynamodb::config::retry::RetryConfig::standard().with_max_attempts(1))
        .build();
    let sessions = DynamoSessionStore::new(
        aws_sdk_dynamodb::Client::from_conf(config),
        "sessions-table",
    );

    assert!(sessions
        .revoke_all_by_actor("", "user:test@example.com", "actor-session")
        .await
        .unwrap());
    server.abort();

    let tokens = fake.tokens.lock().unwrap();
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0].len(), 36);
    assert_eq!(tokens[0], tokens[1]);
}
