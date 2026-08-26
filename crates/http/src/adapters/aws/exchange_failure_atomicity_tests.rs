use super::{DynamoAuthzSessionStore, DynamoCodeStore};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct FakeDynamo {
    requests: Arc<Mutex<Vec<(String, Value)>>>,
    cancel_transaction: Arc<AtomicBool>,
    authority_read_now: Arc<AtomicI64>,
}

async fn dynamo(
    State(fake): State<FakeDynamo>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let target = headers
        .get("x-amz-target")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let request: Value = serde_json::from_slice(&body).expect("DynamoDB request is JSON");
    fake.requests
        .lock()
        .expect("request lock")
        .push((target.clone(), request));

    if target.ends_with(".GetItem") {
        fake.authority_read_now.store(1_000, Ordering::SeqCst);
        return (
            StatusCode::OK,
            [("content-type", "application/x-amz-json-1.0")],
            json!({
                "Item": {
                    "session_id": { "S": "t1\u{1f}session-1" },
                    "client_id": { "S": "t1\u{1f}client-1" },
                    "state": { "S": "code_issued_awaiting_exchange" },
                    "session_token_hash": { "S": "hash" },
                    "sequence": { "N": "7" },
                    "expires_at": { "N": "1700001800" }
                }
            })
            .to_string(),
        )
            .into_response();
    }
    if fake.cancel_transaction.load(Ordering::SeqCst) {
        return (
            StatusCode::BAD_REQUEST,
            [
                ("content-type", "application/x-amz-json-1.0"),
                ("x-amzn-errortype", "TransactionCanceledException"),
            ],
            json!({
                "__type": "com.amazonaws.dynamodb.v20120810#TransactionCanceledException",
                "CancellationReasons": [
                    { "Code": "ConditionalCheckFailed", "Message": "lease changed" },
                    { "Code": "None" }
                ],
                "message": "transaction canceled"
            })
            .to_string(),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        [("content-type", "application/x-amz-json-1.0")],
        "{}".to_string(),
    )
        .into_response()
}

pub(super) async fn assert_exchange_failure_condition_cancel_is_retryable() {
    let fake = FakeDynamo::default();
    fake.cancel_transaction.store(true, Ordering::SeqCst);
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
    let db = aws_sdk_dynamodb::Client::from_conf(config);
    let codes = DynamoCodeStore::new(
        db.clone(),
        "codes-table",
        "clients-table",
        "authority-refs-table",
        "client-authority-refs-v1:test",
    );
    let sessions = DynamoAuthzSessionStore::new(db, "sessions-table");

    let error = codes
        .finalize_exchange_failure_with_clock(
            &sessions,
            "t1",
            "code-1",
            "client-1",
            1_700_000_100,
            1_700_000_000,
            "owner-1",
            Some("session-1"),
            r#"{"error":"invalid_grant","at":"token_endpoint","ts":1700000000}"#.to_string(),
            || 1_700_000_000,
        )
        .await
        .unwrap_err();
    server.abort();

    assert!(matches!(error, crate::ports::StoreError::Transient(_)));
    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].1["TransactItems"].as_array().unwrap().len(), 3);
}

pub(super) async fn assert_exchange_failure_uses_one_transaction_for_code_and_session() {
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
    let db = aws_sdk_dynamodb::Client::from_conf(config);
    let codes = DynamoCodeStore::new(
        db.clone(),
        "codes-table",
        "clients-table",
        "authority-refs-table",
        "client-authority-refs-v1:test",
    );
    let sessions = DynamoAuthzSessionStore::new(db, "sessions-table");
    let last_error =
        r#"{"error":"invalid_grant","at":"token_endpoint","ts":1700000000}"#.to_string();

    let transitioned = codes
        .finalize_exchange_failure_with_clock(
            &sessions,
            "t1",
            "code-1",
            "client-1",
            1_700_000_100,
            1_700_000_000,
            "owner-1",
            Some("session-1"),
            last_error.clone(),
            || 1_700_000_000,
        )
        .await
        .unwrap()
        .expect("transitioned authorization session");
    server.abort();

    assert_eq!(transitioned.state, "exchange_failed");
    assert_eq!(transitioned.sequence, 8);
    assert_eq!(
        transitioned.last_error.as_deref(),
        Some(last_error.as_str())
    );

    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].0.ends_with(".GetItem"));
    assert!(requests[1].0.ends_with(".TransactWriteItems"));
    let transaction = &requests[1].1;
    let items = transaction["TransactItems"].as_array().unwrap();
    assert_eq!(items.len(), 3);

    let code_update = &items[0]["Update"];
    assert_eq!(code_update["TableName"], "codes-table");
    assert_eq!(code_update["Key"]["code"]["S"], "t1\u{1f}code-1");
    assert_eq!(
        code_update["ExpressionAttributeValues"][":owner"]["S"],
        "owner-1"
    );
    assert!(code_update["ConditionExpression"]
        .as_str()
        .unwrap()
        .contains("#owner = :owner"));
    assert!(code_update["ConditionExpression"]
        .as_str()
        .unwrap()
        .contains("authz_session_id = :session_id"));
    assert!(code_update["ConditionExpression"]
        .as_str()
        .unwrap()
        .contains("expires_at > :now"));
    assert_eq!(
        code_update["ExpressionAttributeValues"][":session_id"]["S"],
        "session-1"
    );
    assert_eq!(
        code_update["ExpressionAttributeValues"][":client_id"]["S"],
        "t1\u{1f}client-1"
    );
    assert_eq!(
        code_update["ExpressionAttributeValues"][":expires_at"]["N"],
        "1700000100"
    );
    assert_eq!(
        code_update["ExpressionAttributeValues"][":now"]["N"],
        "1700000000"
    );
    assert!(code_update["UpdateExpression"]
        .as_str()
        .unwrap()
        .contains("#consumed = :true"));

    let session_update = &items[1]["Update"];
    assert!(session_update["ConditionExpression"]
        .as_str()
        .unwrap()
        .contains("expires_at > :now"));
    assert_eq!(
        session_update["ExpressionAttributeValues"][":now"]["N"],
        "1700000000"
    );

    let reference_delete = &items[2]["Delete"];
    assert_eq!(reference_delete["TableName"], "authority-refs-table");
    assert_eq!(
        reference_delete["Key"]["client_key"]["S"],
        "client#00000002t100000008client-1"
    );
    assert!(reference_delete["Key"]["reference_key"]["S"]
        .as_str()
        .unwrap()
        .starts_with("c#00000000001700000100#"));

    let session_update = &items[1]["Update"];
    assert_eq!(session_update["TableName"], "sessions-table");
    assert_eq!(
        session_update["Key"]["session_id"]["S"],
        "t1\u{1f}session-1"
    );
    assert_eq!(
        session_update["ExpressionAttributeValues"][":expected_state"]["S"],
        "code_issued_awaiting_exchange"
    );
    assert_eq!(
        session_update["ExpressionAttributeValues"][":expected_sequence"]["N"],
        "7"
    );
    assert_eq!(
        session_update["ExpressionAttributeValues"][":next_sequence"]["N"],
        "8"
    );
    assert_eq!(
        session_update["ExpressionAttributeValues"][":last_error"]["S"],
        last_error
    );
}

#[tokio::test]
async fn exchange_failure_resamples_expiry_after_session_authority_read() {
    assert_exchange_failure_resamples_expiry_after_session_authority_read().await;
}

pub(super) async fn assert_exchange_failure_resamples_expiry_after_session_authority_read() {
    let fake = FakeDynamo::default();
    fake.authority_read_now.store(999, Ordering::SeqCst);
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
    let db = aws_sdk_dynamodb::Client::from_conf(config);
    let codes = DynamoCodeStore::new(
        db.clone(),
        "codes-table",
        "clients-table",
        "authority-refs-table",
        "client-authority-refs-v1:test",
    );
    let sessions = DynamoAuthzSessionStore::new(db, "sessions-table");

    codes
        .finalize_exchange_failure_with_clock(
            &sessions,
            "t1",
            "code-1",
            "client-1",
            1_100,
            999,
            "owner-1",
            Some("session-1"),
            r#"{"error":"invalid_grant","at":"token_endpoint","ts":999}"#.to_string(),
            || fake.authority_read_now.load(Ordering::SeqCst),
        )
        .await
        .expect("exchange failure transaction");
    server.abort();

    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    let items = requests[1].1["TransactItems"].as_array().unwrap();
    assert_eq!(
        items[0]["Update"]["ExpressionAttributeValues"][":now"]["N"], "1000",
        "the code expiry fence must use time sampled after the session read"
    );
    assert_eq!(
        items[1]["Update"]["ExpressionAttributeValues"][":now"]["N"], "1000",
        "the session expiry fence must use the same post-read commit time"
    );
}
