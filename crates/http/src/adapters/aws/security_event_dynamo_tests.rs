use super::DynamoSecurityEventStore;
use crate::ports::StoreError;
use crate::security_event::{
    SecurityActor, SecurityEvent, SecurityEventCategory, SecurityEventCorrelation,
    SecurityEventDelivery, SecurityEventDeliveryStatus, SecurityEventOutcome, SecurityEventStore,
    SecuritySubject, SECURITY_EVENT_HOT_RETENTION_DAYS,
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
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct FakeDynamo {
    inserted: Arc<Mutex<HashSet<String>>>,
    items: Arc<Mutex<HashMap<String, Value>>>,
    requests: Arc<Mutex<Vec<Value>>>,
    envelope: Arc<Mutex<Option<String>>>,
    query_pages: Arc<Mutex<VecDeque<Value>>>,
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
    fake.requests.lock().unwrap().push(request.clone());

    if target.ends_with(".PutItem") {
        let event_id = request["Item"]["event_id"]["S"]
            .as_str()
            .expect("event id")
            .to_string();
        let inserted = fake.inserted.lock().unwrap().insert(event_id.clone());
        if inserted {
            fake.items
                .lock()
                .unwrap()
                .insert(event_id, request["Item"].clone());
            return (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
                "{}",
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
            r#"{"__type":"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException","message":"duplicate event"}"#,
        )
            .into_response();
    }

    if target.ends_with(".GetItem") {
        let event_id = request["Key"]["event_id"]["S"].as_str().expect("event id");
        let item = fake.items.lock().unwrap().get(event_id).cloned();
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
            item.map_or_else(|| json!({}), |item| json!({ "Item": item }))
                .to_string(),
        )
            .into_response();
    }

    if target.ends_with(".UpdateItem") {
        let event_id = request["Key"]["event_id"]["S"].as_str().expect("event id");
        let values = &request["ExpressionAttributeValues"];
        let mut items = fake.items.lock().unwrap();
        let item = items.get_mut(event_id).expect("updated item");
        let condition_matches = item["envelope"] == values[":envelope"]
            && item["source_delivery_attempts"] == values[":prior_source_attempts"]
            && item["source_delivery_history"] == values[":prior_source_history"]
            && item["delivery_status"] == values[":prior_delivery_status"];
        if !condition_matches {
            return (
                StatusCode::BAD_REQUEST,
                [
                    (header::CONTENT_TYPE, "application/x-amz-json-1.0"),
                    (
                        header::HeaderName::from_static("x-amzn-errortype"),
                        "ConditionalCheckFailedException",
                    ),
                ],
                r#"{"__type":"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException","message":"stale revision"}"#,
            )
                .into_response();
        }
        item["source_delivery_attempts"] = values[":source_attempts"].clone();
        item["source_delivery_history"] = values[":source_history"].clone();
        let suffix = values[":suffix"]["L"]
            .as_array()
            .expect("delivery history suffix")
            .clone();
        item["delivery_history"]["L"]
            .as_array_mut()
            .expect("delivery history")
            .extend(suffix);
        let attempts = item["delivery_attempts"]["N"]
            .as_str()
            .expect("delivery attempts")
            .parse::<u32>()
            .unwrap();
        let delta = values[":attempt_delta"]["N"]
            .as_str()
            .expect("attempt delta")
            .parse::<u32>()
            .unwrap();
        item["delivery_attempts"] = json!({ "N": attempts.saturating_add(delta).to_string() });
        if let Some(refresh_pending) = values.get(":refresh_pending") {
            item["delivery_status"] = refresh_pending.clone();
            item["last_delivery_at"] = values[":now"].clone();
        }
        drop(items);
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
            "{}",
        )
            .into_response();
    }

    assert!(target.ends_with(".Query"), "unexpected DynamoDB target");
    if let Some(page) = fake.query_pages.lock().unwrap().pop_front() {
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
            page.to_string(),
        )
            .into_response();
    }
    let envelope = fake
        .envelope
        .lock()
        .unwrap()
        .clone()
        .expect("query envelope");
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
        json!({
            "Items": [{
                "event_id": { "S": "event-1" },
                "tenant_id": { "S": "t1" },
                "occurred_at": { "N": "100" },
                "envelope": { "S": envelope },
                "delivery_status": { "S": "archived" },
                "delivery_attempts": { "N": "2" },
                "last_delivery_at": { "N": "110" },
                "archived_at": { "N": "110" },
                "archive_key": { "S": "security-events/tenant_id=t1/event-1.json" },
                "delivery_history": { "L": [
                    { "M": {
                        "status": { "S": "pending" },
                        "occurred_at": { "N": "100" }
                    }},
                    { "M": {
                        "status": { "S": "archived" },
                        "occurred_at": { "N": "110" }
                    }}
                ]}
            }, {
                "event_id": { "S": "corrupt-event" },
                "tenant_id": { "S": "t1" },
                "occurred_at": { "N": "99" },
                "envelope": { "S": "{not-json" },
                "delivery_status": { "S": "pending" },
                "delivery_attempts": { "N": "0" }
            }],
            "Count": 2,
            "ScannedCount": 2
        })
        .to_string(),
    )
        .into_response()
}

fn event() -> SecurityEvent {
    SecurityEvent::new_at(
        "event-1",
        100,
        "t1",
        SecurityActor::admin("admin-1"),
        Some(SecuritySubject::user("user:alice@example.com")),
        SecurityEventCategory::UserLifecycle,
        "user.disable",
        SecurityEventOutcome::Success,
        SecurityEventCorrelation::default(),
    )
    .unwrap()
}

#[tokio::test]
async fn security_event_dynamo_store_conditions_put_and_queries_tenant_time_index() {
    let fake = FakeDynamo::default();
    *fake.envelope.lock().unwrap() = Some(serde_json::to_string(&event()).unwrap());
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
    let store = DynamoSecurityEventStore::new(
        aws_sdk_dynamodb::Client::from_conf(config),
        "security-events-table",
    );

    let mut delivery = SecurityEventDelivery::pending(100);
    delivery.start_attempt(101);
    delivery.record(SecurityEventDeliveryStatus::Failed, 102);
    delivery.record(SecurityEventDeliveryStatus::Retrying, 103);
    delivery.start_attempt(104);
    assert!(store.put_with_delivery(&event(), &delivery).await.unwrap());
    assert!(!store.put(&event()).await.unwrap());
    assert_eq!(
        store.list_by_tenant("t1", 50, 150, 25).await.unwrap(),
        vec![crate::security_event::StoredSecurityEvent {
            event: event(),
            delivery: crate::security_event::SecurityEventDelivery {
                status: crate::security_event::SecurityEventDeliveryStatus::Archived,
                attempts: 2,
                last_attempt_at: Some(110),
                archived_at: Some(110),
                dead_lettered_at: None,
                archive_key: Some("security-events/tenant_id=t1/event-1.json".to_string()),
                history: vec![
                    crate::security_event::SecurityEventDeliveryAttempt {
                        status: crate::security_event::SecurityEventDeliveryStatus::Pending,
                        occurred_at: 100,
                    },
                    crate::security_event::SecurityEventDeliveryAttempt {
                        status: crate::security_event::SecurityEventDeliveryStatus::Archived,
                        occurred_at: 110,
                    },
                ],
            },
        }]
    );
    server.abort();

    let requests = fake.requests.lock().unwrap();
    let put = &requests[0];
    assert_eq!(put["ConditionExpression"], "attribute_not_exists(event_id)");
    assert_eq!(put["Item"]["tenant_id"]["S"], "t1");
    assert_eq!(put["Item"]["occurred_at"]["N"], "100");
    assert_eq!(
        put["Item"]["expires_at"]["N"],
        (100 + i64::from(SECURITY_EVENT_HOT_RETENTION_DAYS) * 86_400).to_string()
    );
    assert_eq!(put["Item"]["delivery_status"]["S"], "pending");
    assert_eq!(put["Item"]["delivery_attempts"]["N"], "2");
    assert_eq!(put["Item"]["source_delivery_attempts"]["N"], "2");
    assert_eq!(
        put["Item"]["source_delivery_history"],
        put["Item"]["delivery_history"]
    );
    assert_eq!(
        put["Item"]["delivery_history"]["L"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["M"]["status"]["S"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["pending", "pending", "failed", "retrying", "pending"]
    );

    let query = &requests[3];
    assert_eq!(query["IndexName"], "tenant_occurred_at-index");
    assert_eq!(
        query["KeyConditionExpression"],
        "tenant_id = :tenant AND occurred_at BETWEEN :from AND :through"
    );
    assert_eq!(query["ExpressionAttributeValues"][":tenant"]["S"], "t1");
    assert_eq!(query["ExpressionAttributeValues"][":from"]["N"], "50");
    assert_eq!(query["ExpressionAttributeValues"][":through"]["N"], "150");
    assert_eq!(query["Limit"], 25);
    assert_eq!(query["ScanIndexForward"], false);
}

#[tokio::test]
async fn archived_event_reopens_for_a_same_attempt_history_extension() {
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
    let store = DynamoSecurityEventStore::new(
        aws_sdk_dynamodb::Client::from_conf(config),
        "security-events-table",
    );

    let mut initial = SecurityEventDelivery::pending(100);
    initial.start_attempt(101);
    assert!(store.put_with_delivery(&event(), &initial).await.unwrap());
    {
        let mut items = fake.items.lock().unwrap();
        let item = items.get_mut("event-1").unwrap();
        item["delivery_status"] = json!({ "S": "archived" });
        item["last_delivery_at"] = json!({ "N": "110" });
        item["archived_at"] = json!({ "N": "110" });
        item["archive_key"] = json!({ "S": "security-events/tenant_id=t1/event-1.json" });
        item["delivery_history"]["L"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "M": {
                "status": { "S": "archived" },
                "occurred_at": { "N": "110" }
            }}));
    }
    let mut extended = initial;
    extended.record(SecurityEventDeliveryStatus::Failed, 201);
    assert!(!store.put_with_delivery(&event(), &extended).await.unwrap());
    server.abort();

    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    assert_eq!(
        requests[3]["UpdateExpression"],
        "SET source_delivery_attempts = :source_attempts, source_delivery_history = :source_history, delivery_status = :refresh_pending, last_delivery_at = :now, delivery_history = list_append(if_not_exists(delivery_history, :empty), :suffix) ADD delivery_attempts :attempt_delta"
    );
    assert_eq!(
        requests[3]["ConditionExpression"],
        "envelope = :envelope AND source_delivery_attempts = :prior_source_attempts AND source_delivery_history = :prior_source_history AND delivery_status = :prior_delivery_status"
    );
    assert_eq!(
        requests[3]["ExpressionAttributeValues"][":prior_delivery_status"]["S"],
        "archived"
    );
    assert_eq!(
        requests[3]["ExpressionAttributeValues"][":refresh_pending"]["S"],
        "archive_refresh_pending"
    );
    assert_eq!(
        requests[3]["ExpressionAttributeValues"][":attempt_delta"]["N"],
        "0"
    );
    assert_eq!(
        requests[3]["ExpressionAttributeValues"][":suffix"]["L"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["M"]["status"]["S"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["failed", "archive_refresh_pending"]
    );
}

#[tokio::test]
async fn duplicate_event_reconciles_new_history_and_rejects_divergence_at_the_same_attempt_count() {
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
    let store = DynamoSecurityEventStore::new(
        aws_sdk_dynamodb::Client::from_conf(config),
        "security-events-table",
    );

    let mut initial = SecurityEventDelivery::pending(100);
    initial.start_attempt(101);
    assert!(store.put_with_delivery(&event(), &initial).await.unwrap());

    let mut extended = initial.clone();
    extended.record(SecurityEventDeliveryStatus::Failed, 102);
    assert!(!store.put_with_delivery(&event(), &extended).await.unwrap());
    assert!(
        !store.put_with_delivery(&event(), &extended).await.unwrap(),
        "replaying a persisted same-attempt extension must converge without another update"
    );

    let mut divergent = initial;
    divergent.history[1].status = SecurityEventDeliveryStatus::Failed;
    let error = store
        .put_with_delivery(&event(), &divergent)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        StoreError::Permanent(message)
            if message == "security event duplicate has divergent delivery history"
    ));
    server.abort();

    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 8);
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.get("UpdateExpression").is_some())
            .count(),
        1
    );
    assert_eq!(
        requests[3]["ExpressionAttributeValues"][":attempt_delta"]["N"],
        "0"
    );
    assert_eq!(
        requests[3]["ConditionExpression"],
        "envelope = :envelope AND source_delivery_attempts = :prior_source_attempts AND source_delivery_history = :prior_source_history AND delivery_status = :prior_delivery_status"
    );
    assert_eq!(
        requests[3]["ExpressionAttributeValues"][":suffix"]["L"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["M"]["status"]["S"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["failed"]
    );
}

#[tokio::test]
async fn duplicate_event_id_with_a_different_envelope_is_permanent() {
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
    let store = DynamoSecurityEventStore::new(
        aws_sdk_dynamodb::Client::from_conf(config),
        "security-events-table",
    );
    let delivery = SecurityEventDelivery::pending(100);
    assert!(store.put_with_delivery(&event(), &delivery).await.unwrap());

    let mut conflicting = event();
    conflicting.action = "different.action".to_string();
    let error = store
        .put_with_delivery(&conflicting, &delivery)
        .await
        .unwrap_err();
    server.abort();

    assert!(matches!(
        error,
        StoreError::Permanent(message)
            if message == "security event id collision has a different envelope"
    ));
    assert_eq!(fake.requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn security_event_query_follows_pages_and_skips_invalid_rows_before_limit() {
    let fake = FakeDynamo::default();
    let envelope = serde_json::to_string(&event()).unwrap();
    fake.query_pages.lock().unwrap().extend([
        json!({
            "Items": [{
                "event_id": { "S": "corrupt-event" },
                "tenant_id": { "S": "t1" },
                "occurred_at": { "N": "101" },
                "envelope": { "S": "{not-json" },
                "delivery_status": { "S": "pending" },
                "delivery_attempts": { "N": "0" }
            }],
            "LastEvaluatedKey": {
                "event_id": { "S": "corrupt-event" },
                "tenant_id": { "S": "t1" },
                "occurred_at": { "N": "101" }
            }
        }),
        json!({
            "Items": [{
                "event_id": { "S": "event-1" },
                "tenant_id": { "S": "t1" },
                "occurred_at": { "N": "100" },
                "envelope": { "S": envelope },
                "delivery_status": { "S": "archived" },
                "delivery_attempts": { "N": "1" },
                "archived_at": { "N": "110" },
                "archive_key": { "S": "security-events/tenant_id=t1/event-1.json" },
                "delivery_history": { "L": [
                    { "M": {
                        "status": { "S": "pending" },
                        "occurred_at": { "N": "100" }
                    }},
                    { "M": {
                        "status": { "S": "archived" },
                        "occurred_at": { "N": "110" }
                    }}
                ]}
            }]
        }),
    ]);
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
    let store = DynamoSecurityEventStore::new(
        aws_sdk_dynamodb::Client::from_conf(config),
        "security-events-table",
    );

    let events = store.list_by_tenant("t1", 50, 150, 1).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event.event_id, "event-1");
    server.abort();

    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["Limit"], 1);
    assert_eq!(requests[1]["Limit"], 1);
    assert_eq!(
        requests[1]["ExclusiveStartKey"]["event_id"]["S"],
        "corrupt-event"
    );
}
