use super::{DynamoRecoveryStore, DynamoUsersStore};
use crate::ports::{RecoveryCodeEntry, RecoveryRecord};
use axum::{
    body::Bytes,
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use serde_json::Value;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct FakeDynamo {
    requests: Arc<Mutex<Vec<Value>>>,
}

async fn transact_write(State(fake): State<FakeDynamo>, body: Bytes) -> impl IntoResponse {
    let request: Value = serde_json::from_slice(&body).expect("DynamoDB request is JSON");
    let attempt = {
        let mut requests = fake.requests.lock().expect("request lock");
        requests.push(request);
        requests.len()
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
async fn recovery_rotation_replays_an_ambiguous_commit_with_the_same_token() {
    let fake = FakeDynamo::default();
    let app = Router::new()
        .route("/", post(transact_write))
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
    let db = aws_sdk_dynamodb::Client::from_conf(config);
    let users = DynamoUsersStore::new(db.clone(), "users-table");
    let recovery = DynamoRecoveryStore::new(db, "recovery-table");
    let committed = recovery
        .commit_rotation(
            &users,
            "t1",
            RecoveryRecord {
                user_lookup: "lookup".to_string(),
                user_id: "user:test@example.com".to_string(),
                activation_id: "recovery".to_string(),
                code_hashes: vec![RecoveryCodeEntry {
                    hash_b64: "hmac-only".to_string(),
                    consumed: false,
                }],
                attempt_count: 0,
                locked_until: 0,
            },
            "test@example.com",
            crate::ports::CredentialChangeOwner {
                epoch: 1,
                operation_id: "recovery-operation",
            },
            1_700_000_000,
        )
        .await
        .unwrap();
    server.abort();

    assert!(committed);
    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], requests[1]);
    let token = requests[0]["ClientRequestToken"].as_str().unwrap();
    assert_eq!(token.len(), 36);
    let items = requests[0]["TransactItems"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    let user_update = items
        .iter()
        .find(|item| item["Update"]["TableName"] == "users-table")
        .unwrap();
    assert!(user_update["Update"]["ConditionExpression"]
        .as_str()
        .unwrap()
        .contains("email = :expected_email"));
    assert_eq!(
        user_update["Update"]["ExpressionAttributeValues"][":expected_email"]["S"],
        "t1\u{1f}test@example.com"
    );
    let recovery_put = items
        .iter()
        .find(|item| item["Put"]["TableName"] == "recovery-table")
        .unwrap();
    assert_eq!(
        recovery_put["Put"]["Item"]["code_hashes"]["L"][0]["S"],
        "hmac-only"
    );
    assert_eq!(
        recovery_put["Put"]["Item"]["consumed"]["L"][0]["BOOL"],
        false
    );
    assert_eq!(
        recovery_put["Put"]["Item"]["user_lookup"]["S"],
        "t1\u{1f}lookup"
    );
    let mut fields: Vec<&str> = recovery_put["Put"]["Item"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "activation_id",
            "attempt_count",
            "code_hashes",
            "consumed",
            "locked_until",
            "user_id",
            "user_lookup",
            "version",
        ]
    );
}
