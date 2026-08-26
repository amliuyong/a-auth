use super::super::DynamoPasswordStore;
use super::DynamoUsersStore;
use crate::ports::{
    CredentialChangeOwner, CredentialChangeStart, DisableStart, FencedPasswordMutation, UsersStore,
};
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
    operation_ids: Arc<Mutex<Vec<String>>>,
    requests: Arc<Mutex<Vec<Value>>>,
    targets: Arc<Mutex<Vec<String>>>,
}

#[derive(Clone, Default)]
struct FakeDisableDynamo {
    requests: Arc<Mutex<Vec<Value>>>,
}

#[derive(Clone, Default)]
struct FakeAdminStageDynamo {
    requests: Arc<Mutex<Vec<Value>>>,
    staged: Arc<Mutex<Option<(String, String, String)>>>,
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
    fake.targets
        .lock()
        .expect("target lock")
        .push(target.clone());
    if target.ends_with(".UpdateItem") {
        let request: Value = serde_json::from_slice(&body).expect("UpdateItem request is JSON");
        fake.requests
            .lock()
            .expect("request lock")
            .push(request.clone());
        let Some(operation_id) = request["ExpressionAttributeValues"][":operation"]["S"].as_str()
        else {
            return (
                StatusCode::BAD_REQUEST,
                [
                    (header::CONTENT_TYPE, "application/x-amz-json-1.0"),
                    (
                        header::HeaderName::from_static("x-amzn-errortype"),
                        "ConditionalCheckFailedException",
                    ),
                ],
                r#"{"__type":"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException","message":"legacy pending row has no operation marker"}"#.to_string(),
            )
                .into_response();
        };
        let operation_id = operation_id.to_string();
        let attempt = {
            let mut operation_ids = fake.operation_ids.lock().expect("operation lock");
            operation_ids.push(operation_id);
            operation_ids.len()
        };
        if attempt == 1 {
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
        return (
            StatusCode::BAD_REQUEST,
            [
                (header::CONTENT_TYPE, "application/x-amz-json-1.0"),
                (
                    header::HeaderName::from_static("x-amzn-errortype"),
                    "ConditionalCheckFailedException",
                ),
            ],
            r#"{"__type":"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException","message":"already committed"}"#.to_string(),
        )
            .into_response();
    }

    let operation_id = fake
        .operation_ids
        .lock()
        .expect("operation lock")
        .first()
        .cloned()
        .expect("UpdateItem ran before GetItem");
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
        json!({
            "Item": {
                "user_id": { "S": "user:test@example.com" },
                "credential_epoch": { "N": "1" },
                "revocation_pending": { "BOOL": true },
                "credential_change_id": { "S": operation_id }
            }
        })
        .to_string(),
    )
        .into_response()
}

async fn dynamo_disable(
    State(fake): State<FakeDisableDynamo>,
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
            json!({
                "Item": {
                    "user_id": { "S": "user:disable@example.com" },
                    "email": { "S": "disable@example.com" },
                    "created_at": { "N": "1" },
                    "updated_at": { "N": "2" },
                    "status": { "S": "active" },
                    "credential_epoch": { "N": "1" },
                    "revocation_pending": { "BOOL": true },
                    "credential_change_id": { "S": "stale-owner" }
                }
            })
            .to_string(),
        )
            .into_response();
    }
    if target.ends_with(".UpdateItem") {
        let request: Value = serde_json::from_slice(&body).expect("UpdateItem request is JSON");
        fake.requests.lock().expect("request lock").push(request);
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
            json!({
                "Attributes": {
                    "user_id": { "S": "user:disable@example.com" },
                    "email": { "S": "disable@example.com" },
                    "created_at": { "N": "1" },
                    "updated_at": { "N": "3" },
                    "status": { "S": "disabled" },
                    "credential_epoch": { "N": "2" },
                    "revocation_pending": { "BOOL": true }
                }
            })
            .to_string(),
        )
            .into_response();
    }
    (
        StatusCode::BAD_REQUEST,
        [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
        r#"{"message":"unexpected DynamoDB operation"}"#.to_string(),
    )
        .into_response()
}

async fn dynamo_admin_stage(
    State(fake): State<FakeAdminStageDynamo>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let target = headers
        .get("x-amz-target")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let request: Value = serde_json::from_slice(&body).expect("DynamoDB request is JSON");
    fake.requests
        .lock()
        .expect("request lock")
        .push(request.clone());
    if target.ends_with(".TransactWriteItems") {
        let password_values = &request["TransactItems"][1]["Update"]["ExpressionAttributeValues"];
        let operation_id = password_values[":operation"]["S"]
            .as_str()
            .expect("operation id")
            .to_string();
        let password_hash = password_values[":hash"]["S"]
            .as_str()
            .expect("password hash")
            .to_string();
        let version = password_values[":next"]["N"]
            .as_str()
            .expect("password version")
            .to_string();
        *fake.staged.lock().expect("staged lock") = Some((operation_id, password_hash, version));
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
    if target.ends_with(".GetItem") {
        let (operation_id, password_hash, version) = fake
            .staged
            .lock()
            .expect("staged lock")
            .clone()
            .expect("transaction ran before strong reads");
        let table = request["TableName"].as_str().unwrap_or_default();
        let item = if table == "users-table" {
            json!({
                "user_id": { "S": "user:stage@example.com" },
                "email": { "S": "stage@example.com" },
                "created_at": { "N": "1" },
                "updated_at": { "N": "2" },
                "status": { "S": "active" },
                "credential_epoch": { "N": "1" },
                "revocation_pending": { "BOOL": true },
                "credential_change_id": { "S": operation_id }
            })
        } else {
            json!({
                "user_id": { "S": "user:stage@example.com" },
                "password_hash": { "S": password_hash },
                "must_change": { "BOOL": true },
                "revocation_pending": { "BOOL": true },
                "credential_change_id": { "S": operation_id },
                "version": { "N": version },
                "updated_at": { "N": "2" }
            })
        };
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
            json!({ "Item": item }).to_string(),
        )
            .into_response();
    }
    (
        StatusCode::BAD_REQUEST,
        [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
        r#"{"message":"unexpected DynamoDB operation"}"#.to_string(),
    )
        .into_response()
}

#[tokio::test]
async fn credential_change_reconciles_an_sdk_retry_after_a_committed_lost_response() {
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
        .retry_config(aws_sdk_dynamodb::config::retry::RetryConfig::standard().with_max_attempts(2))
        .build();
    let users = DynamoUsersStore::new(aws_sdk_dynamodb::Client::from_conf(config), "users-table");
    let outcome = users
        .begin_credential_change(
            "",
            "user:test@example.com",
            0,
            "credential-operation",
            1_700_000_000,
        )
        .await
        .unwrap();
    server.abort();

    assert_eq!(outcome, CredentialChangeStart::Started { epoch: 1 });
    let operation_ids = fake.operation_ids.lock().unwrap();
    assert_eq!(operation_ids.len(), 2);
    assert_eq!(operation_ids[0], "credential-operation");
    assert_eq!(operation_ids[0], operation_ids[1]);
    let targets = fake.targets.lock().unwrap();
    assert_eq!(targets.len(), 3);
    assert!(targets[0].ends_with(".UpdateItem"));
    assert!(targets[1].ends_with(".UpdateItem"));
    assert!(targets[2].ends_with(".GetItem"));
}

#[tokio::test]
async fn admin_credential_change_reconciles_an_sdk_retry_after_a_committed_lost_response() {
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
        .retry_config(aws_sdk_dynamodb::config::retry::RetryConfig::standard().with_max_attempts(2))
        .build();
    let users = DynamoUsersStore::new(aws_sdk_dynamodb::Client::from_conf(config), "users-table");
    let outcome = users
        .begin_admin_credential_change(
            "",
            "user:test@example.com",
            0,
            "admin-credential-operation",
            1_700_000_000,
        )
        .await
        .unwrap();
    server.abort();

    assert_eq!(outcome, CredentialChangeStart::Started { epoch: 1 });
    let operation_ids = fake.operation_ids.lock().unwrap();
    assert_eq!(
        operation_ids.as_slice(),
        ["admin-credential-operation", "admin-credential-operation"]
    );
    let targets = fake.targets.lock().unwrap();
    assert_eq!(targets.len(), 3);
    assert!(targets[0].ends_with(".UpdateItem"));
    assert!(targets[1].ends_with(".UpdateItem"));
    assert!(targets[2].ends_with(".GetItem"));
    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0]["ConditionExpression"]
        .as_str()
        .unwrap()
        .contains("#status <> :tomb"));
}

#[tokio::test]
async fn expired_recovery_requires_and_removes_an_operation_marker() {
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
    let users = DynamoUsersStore::new(aws_sdk_dynamodb::Client::from_conf(config), "users-table");
    assert!(!users
        .recover_expired_credential_change(
            "",
            "user:test@example.com",
            1,
            1_700_000_000,
            1_700_000_001,
        )
        .await
        .unwrap());
    server.abort();

    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0]["ConditionExpression"]
        .as_str()
        .unwrap()
        .contains("attribute_exists(credential_change_id)"));
    assert!(requests[0]["ConditionExpression"]
        .as_str()
        .unwrap()
        .contains("#status <> :tomb"));
    assert!(requests[0]["UpdateExpression"]
        .as_str()
        .unwrap()
        .contains("REMOVE credential_change_id"));
}

#[tokio::test]
async fn disable_removes_a_prior_credential_operation_marker() {
    let fake = FakeDisableDynamo::default();
    let app = Router::new()
        .route("/", post(dynamo_disable))
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
    let users = DynamoUsersStore::new(aws_sdk_dynamodb::Client::from_conf(config), "users-table");
    let outcome = users
        .begin_disable("", "user:disable@example.com", 3)
        .await
        .unwrap();
    server.abort();

    assert!(matches!(
        outcome,
        DisableStart::Ready {
            epoch: 2,
            record
        } if record.status == crate::ports::UserStatus::Disabled
    ));
    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0]["UpdateExpression"]
        .as_str()
        .unwrap()
        .contains("REMOVE credential_change_id"));
}

#[tokio::test]
async fn admin_reset_stage_reconciles_a_committed_transaction_after_lost_responses() {
    let fake = FakeAdminStageDynamo::default();
    let app = Router::new()
        .route("/", post(dynamo_admin_stage))
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
    let client = aws_sdk_dynamodb::Client::from_conf(config);
    let users = DynamoUsersStore::new(client.clone(), "users-table");
    let passwords = DynamoPasswordStore::new(client, "passwords-table");
    let operation_id = "admin-stage-operation";
    let result = passwords
        .stage_admin_reset(
            &users,
            FencedPasswordMutation {
                tenant: "",
                user_id: "user:stage@example.com",
                password_hash: agent_auth_authn::password::hash_password(
                    "Admin stage replacement 123!",
                )
                .unwrap(),
                expected_version: None,
                credential_epoch: 1,
                updated_at: 2,
            },
            CredentialChangeOwner {
                epoch: 1,
                operation_id,
            },
        )
        .await
        .unwrap();
    server.abort();

    assert_eq!(result, Some(1));
    let requests = fake.requests.lock().unwrap();
    let transactions: Vec<_> = requests
        .iter()
        .filter(|request| request.get("TransactItems").is_some())
        .collect();
    assert_eq!(transactions.len(), 2);
    assert_eq!(
        transactions[0]["ClientRequestToken"],
        transactions[1]["ClientRequestToken"]
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request["TableName"] == "users-table")
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request["TableName"] == "passwords-table")
            .count(),
        1
    );
}
