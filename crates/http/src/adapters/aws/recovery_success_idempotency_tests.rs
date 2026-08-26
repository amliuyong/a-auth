use super::{
    DynamoNotifier, DynamoPasswordStore, DynamoRecoveryStore, DynamoSessionStore, DynamoUsersStore,
};
use crate::ports::{
    Notifier, RecoveryConsumeRequest, RecoveryStore, RecoverySuccessResult, SessionRecord,
};
use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use base64::Engine as _;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct FakeDynamo {
    committed_result: Arc<Mutex<Option<Value>>>,
    transactions: Arc<Mutex<Vec<Value>>>,
    transaction_tokens: Arc<Mutex<Vec<String>>>,
    result_reads: Arc<Mutex<usize>>,
    recovery_notifications: Arc<Mutex<Vec<String>>>,
}

fn internal_error(message: &'static str) -> axum::response::Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [
            (header::CONTENT_TYPE, "application/x-amz-json-1.0"),
            (
                header::HeaderName::from_static("x-amzn-errortype"),
                "InternalServerError",
            ),
        ],
        format!(
            r#"{{"__type":"com.amazonaws.dynamodb.v20120810#InternalServerError","message":"{message}"}}"#
        ),
    )
        .into_response()
}

fn conditional_check_failed() -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        [
            (header::CONTENT_TYPE, "application/x-amz-json-1.0"),
            (
                header::HeaderName::from_static("x-amzn-errortype"),
                "ConditionalCheckFailedException",
            ),
        ],
        r#"{"__type":"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException","message":"duplicate"}"#,
    )
        .into_response()
}

async fn dynamo(
    State(fake): State<FakeDynamo>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let target = headers
        .get("x-amz-target")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let request: Value = serde_json::from_slice(&body).expect("DynamoDB request is JSON");

    if target.ends_with(".TransactWriteItems") {
        let token = request["ClientRequestToken"]
            .as_str()
            .expect("transaction idempotency token")
            .to_string();
        fake.transaction_tokens
            .lock()
            .expect("transaction token lock")
            .push(token);
        fake.transactions
            .lock()
            .expect("transaction lock")
            .push(request.clone());
        let result = request["TransactItems"]
            .as_array()
            .expect("transaction items")
            .iter()
            .find_map(|item| {
                (item["Put"]["Item"]["kind"]["S"] == "recovery_success_result")
                    .then(|| item["Put"]["Item"].clone())
            })
            .expect("atomic transaction contains recovery success result");
        *fake.committed_result.lock().expect("result lock") = Some(result);
        return internal_error("response lost after commit");
    }

    if target.ends_with(".PutItem") {
        let message_id = request["Item"]["message_id"]["S"]
            .as_str()
            .expect("notification message id")
            .to_string();
        let mut notifications = fake
            .recovery_notifications
            .lock()
            .expect("notification lock");
        if notifications.contains(&message_id) {
            return conditional_check_failed();
        }
        notifications.push(message_id);
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
            "{}",
        )
            .into_response();
    }

    let table = request["TableName"].as_str().expect("GetItem table");
    let key = request["Key"]
        .as_object()
        .and_then(|key| key.values().next())
        .and_then(|value| value["S"].as_str())
        .expect("GetItem key");
    if table == "recovery-table" && key.contains("__recovery_success__:") {
        let read = {
            let mut reads = fake.result_reads.lock().expect("result read lock");
            *reads += 1;
            *reads
        };
        if read == 1 {
            return internal_error("reconciliation read lost");
        }
        let item = fake
            .committed_result
            .lock()
            .expect("result lock")
            .clone()
            .expect("committed result");
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
            json!({ "Item": item }).to_string(),
        )
            .into_response();
    }
    if table == "recovery-table" {
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
            json!({
                "Item": {
                    "user_lookup": { "S": key },
                    "user_id": { "S": "user:test@example.com" },
                    "activation_id": { "S": "recovery" },
                    "code_hashes": { "L": [{ "S": test_hash() }] },
                    "consumed": { "L": [{ "BOOL": false }] },
                    "attempt_count": { "N": "0" },
                    "locked_until": { "N": "0" },
                    "version": { "N": "0" }
                }
            })
            .to_string(),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
        "{}",
    )
        .into_response()
}

fn test_hash() -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32])
}

#[tokio::test]
async fn recovery_notification_uses_an_idempotent_dynamo_key() {
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
    let notifier = DynamoNotifier::new(aws_sdk_dynamodb::Client::from_conf(config), "messages");

    for _ in 0..2 {
        notifier
            .notify_recovery(
                "t1",
                "derived-notification-id",
                "test@example.com",
                1_700_000_000,
                Some("203.0.113.9"),
            )
            .await
            .unwrap();
    }
    server.abort();

    let notifications = fake.recovery_notifications.lock().unwrap();
    assert_eq!(notifications.len(), 1);
    assert!(notifications[0].starts_with("t1\u{1f}recovery#"));
}

#[tokio::test]
async fn committed_recovery_result_survives_lost_responses_and_failed_reconciliation() {
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
    let users = DynamoUsersStore::new(db.clone(), "users-table");
    let passwords = DynamoPasswordStore::new(db.clone(), "password-table");
    let sessions = DynamoSessionStore::new(db.clone(), "sessions-table");
    let recovery = DynamoRecoveryStore::new(db, "recovery-table");
    let now = 1_700_000_000;
    let tenant = "t1";
    let operation_key = "derived-operation-key";
    let session = SessionRecord {
        session_id: "recovered-session".to_string(),
        user_id: "user:test@example.com".to_string(),
        credential_epoch: 1,
        auth_time: now,
        created_at: now,
        last_used_at: now,
        device: "Test browser".to_string(),
        expires_at: now + 3_600,
        acr: None,
        amr: vec!["recovery_code".to_string()],
    };
    let result = RecoverySuccessResult {
        operation_key: operation_key.to_string(),
        user_lookup: "lookup".to_string(),
        user_id: session.user_id.clone(),
        presented_hash: test_hash(),
        credential_epoch: 1,
        session_id: session.session_id.clone(),
        created_at: now,
        expires_at: now + 60,
    };

    let first = recovery
        .verify_and_consume_at_epoch(
            &users,
            &passwords,
            &sessions,
            RecoveryConsumeRequest {
                tenant,
                user_lookup: "lookup",
                user_id: &session.user_id,
                expected_email: "test@example.com",
                expected_epoch: 0,
                presented_hash: &test_hash(),
                now,
            },
            session.clone(),
            result.clone(),
        )
        .await;
    assert!(
        first.is_err(),
        "the first HTTP attempt cannot prove its commit"
    );

    let recovered = recovery
        .get_success_result(tenant, operation_key)
        .await
        .unwrap()
        .expect("the next request recovers the committed result");
    server.abort();

    assert_eq!(recovered, result);
    let tokens = fake.transaction_tokens.lock().unwrap();
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0], tokens[1]);
    let transactions = fake.transactions.lock().unwrap();
    assert_eq!(transactions.len(), 2);
    assert_eq!(transactions[0], transactions[1]);
    let items = transactions[0]["TransactItems"].as_array().unwrap();
    assert_eq!(items.len(), 6);
    let user_update = items
        .iter()
        .find(|item| item["Update"]["TableName"] == "users-table")
        .unwrap();
    let user_condition = user_update["Update"]["ConditionExpression"]
        .as_str()
        .unwrap();
    assert!(user_condition.contains("email = :expected_email"));
    assert!(user_condition.contains("credential_epoch"));
    assert_eq!(
        user_update["Update"]["ExpressionAttributeValues"][":expected_email"]["S"],
        "t1\u{1f}test@example.com"
    );
    let recovery_puts: Vec<&Value> = items
        .iter()
        .filter(|item| item["Put"]["TableName"] == "recovery-table")
        .collect();
    assert_eq!(recovery_puts.len(), 2);
    let consumed_record = recovery_puts
        .iter()
        .find(|item| item["Put"]["Item"].get("kind").is_none())
        .unwrap();
    assert_eq!(
        consumed_record["Put"]["Item"]["consumed"]["L"][0]["BOOL"],
        true
    );
    assert_eq!(
        consumed_record["Put"]["Item"]["user_lookup"]["S"],
        "t1\u{1f}lookup"
    );
    let success_put = recovery_puts
        .iter()
        .find(|item| item["Put"]["Item"]["kind"]["S"] == "recovery_success_result")
        .unwrap();
    assert_eq!(
        success_put["Put"]["ConditionExpression"],
        "attribute_not_exists(user_lookup)"
    );
    assert_eq!(success_put["Put"]["Item"]["expires_at"]["N"], "1700000060");
    assert_eq!(
        success_put["Put"]["Item"]["user_lookup"]["S"],
        "t1\u{1f}__recovery_success__:derived-operation-key"
    );
    assert!(items
        .iter()
        .any(|item| item["ConditionCheck"]["TableName"] == "password-table"));
    assert!(items
        .iter()
        .any(|item| item["Update"]["TableName"] == "sessions-table"));
    assert!(items
        .iter()
        .any(|item| item["Put"]["TableName"] == "sessions-table"));
    let stored = fake.committed_result.lock().unwrap();
    let stored_json = stored.as_ref().unwrap().to_string();
    assert!(!stored_json.contains("raw-client-operation-id"));
    assert_eq!(stored.as_ref().unwrap()["expires_at"]["N"], "1700000060");
}
