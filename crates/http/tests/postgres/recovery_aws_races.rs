//! Real loopback DynamoDB interleavings through the public recovery port.
//! Pause one already-completed read response, then regenerate/delete the set.

use super::recovery_contracts::record;
use agent_auth_http::{
    adapters::aws::DynamoRecoveryStore,
    ports::{RecoveryConsume, RecoveryStore},
};
use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap},
    response::IntoResponse,
    routing::post,
    Router,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::Notify;

#[derive(Clone)]
struct PausedRead {
    endpoint: String,
    client: reqwest::Client,
    first_read: Arc<AtomicBool>,
    captured: Arc<Notify>,
    release: Arc<Notify>,
}

async fn proxy(
    State(state): State<PausedRead>,
    mut headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let pause = headers
        .get("x-amz-target")
        .and_then(|header| header.to_str().ok())
        .is_some_and(|target| target.ends_with(".GetItem"))
        && !state.first_read.swap(true, Ordering::SeqCst);
    headers.remove(header::HOST);
    headers.remove(header::CONTENT_LENGTH);
    headers.remove(header::CONNECTION);
    let response = state
        .client
        .post(&state.endpoint)
        .headers(headers)
        .body(body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await.unwrap();
    if pause {
        state.captured.notify_one();
        state.release.notified().await;
    }
    (status, headers, body).into_response()
}

async fn stale_consumer_after_replacement(delete: bool, legacy: bool) {
    let (db, table) = super::aws_contract_database::table("user_lookup", vec![], vec![]).await;
    let direct = DynamoRecoveryStore::new(db.clone(), &table);
    let initial = record("lookup");
    direct.put("tenant", initial.clone()).await.unwrap();
    if legacy {
        db.update_item()
            .table_name(&table)
            .key(
                "user_lookup",
                aws_sdk_dynamodb::types::AttributeValue::S("tenant\u{1f}lookup".into()),
            )
            .update_expression("REMOVE code_set_generation")
            .send()
            .await
            .unwrap();
    }
    let state = PausedRead {
        endpoint: std::env::var("A_AUTH_TEST_DYNAMODB_ENDPOINT").unwrap(),
        client: reqwest::Client::new(),
        first_read: Arc::new(AtomicBool::new(false)),
        captured: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
    };
    let app = Router::new()
        .route("/", post(proxy))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let paused_db = aws_sdk_dynamodb::Client::from_conf(
        db.config().to_builder().endpoint_url(endpoint).build(),
    );
    let consumer = DynamoRecoveryStore::new(paused_db, &table);
    let hash = initial.code_hashes[0].hash_b64.clone();
    let consume = tokio::spawn(async move {
        consumer
            .verify_and_consume("tenant", "lookup", &hash, 100)
            .await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        state.captured.notified(),
    )
    .await
    .expect("consumer read must reach its interleaving point");
    let mut replacement = initial;
    replacement.activation_id = "replacement-code-set".into();
    replacement.code_hashes.remove(0);
    if delete {
        direct.delete_by_lookup("tenant", "lookup").await.unwrap();
    } else {
        direct.put("tenant", replacement.clone()).await.unwrap();
    }
    state.release.notify_one();
    let outcome = consume.await.unwrap().unwrap();
    server.abort();
    let stored = direct.get("tenant", "lookup").await.unwrap();
    db.delete_table().table_name(table).send().await.unwrap();
    if delete {
        assert_eq!(outcome, RecoveryConsume::NotFound);
        assert_eq!(
            stored, None,
            "a stale consumer must not resurrect a deleted set"
        );
    } else {
        assert_eq!(outcome, RecoveryConsume::Invalid);
        let stored = stored.unwrap();
        assert_eq!(stored.activation_id, replacement.activation_id);
        assert_eq!(stored.code_hashes, replacement.code_hashes);
        assert_eq!(stored.attempt_count, 1);
    }
}

#[tokio::test]
async fn aws_recovery_stale_consumer_cannot_restore_a_deleted_code_set() {
    for legacy in [false, true] {
        stale_consumer_after_replacement(true, legacy).await;
    }
}

#[tokio::test]
async fn aws_recovery_stale_consumer_cannot_adopt_a_regenerated_code_set() {
    for legacy in [false, true] {
        stale_consumer_after_replacement(false, legacy).await;
    }
}

#[tokio::test]
async fn aws_recovery_legacy_upgrade_and_exhausted_or_corrupt_fences_fail_closed() {
    use aws_sdk_dynamodb::types::AttributeValue;
    let (db, table) = super::aws_contract_database::table("user_lookup", vec![], vec![]).await;
    let store = DynamoRecoveryStore::new(db.clone(), &table);
    let initial = record("lookup");
    store.put("tenant", initial.clone()).await.unwrap();
    let key = AttributeValue::S("tenant\u{1f}lookup".into());
    db.update_item()
        .table_name(&table)
        .key("user_lookup", key.clone())
        .update_expression("REMOVE code_set_generation, #v")
        .expression_attribute_names("#v", "version")
        .send()
        .await
        .unwrap();
    assert_eq!(
        store
            .verify_and_consume("tenant", "lookup", &initial.code_hashes[0].hash_b64, 100)
            .await
            .unwrap(),
        RecoveryConsume::Valid
    );
    let baseline = store.get("tenant", "lookup").await.unwrap();
    db.update_item()
        .table_name(&table)
        .key("user_lookup", key.clone())
        .update_expression("SET #v = :v")
        .expression_attribute_names("#v", "version")
        .expression_attribute_values(":v", AttributeValue::N(u64::MAX.to_string()))
        .send()
        .await
        .unwrap();
    assert!(matches!(
        store
            .verify_and_consume("tenant", "lookup", &initial.code_hashes[1].hash_b64, 100)
            .await,
        Err(agent_auth_http::ports::StoreError::Permanent(_))
    ));
    assert_eq!(store.get("tenant", "lookup").await.unwrap(), baseline);
    for invalid in [
        AttributeValue::S("private-recovery-sentinel".into()),
        AttributeValue::N("0".into()),
    ] {
        db.update_item()
            .table_name(&table)
            .key("user_lookup", key.clone())
            .update_expression("SET code_set_generation = :g")
            .expression_attribute_values(":g", invalid)
            .send()
            .await
            .unwrap();
        for result in [
            store.get("tenant", "lookup").await.map(|_| ()),
            store
                .verify_and_consume("tenant", "lookup", &initial.code_hashes[1].hash_b64, 100)
                .await
                .map(|_| ()),
        ] {
            let error = result.expect_err("invalid generation must reject recovery authority");
            assert!(matches!(
                error,
                agent_auth_http::ports::StoreError::Permanent(_)
            ));
            assert!(!format!("{error:?}").contains("private-recovery-sentinel"));
        }
    }
    db.update_item()
        .table_name(&table)
        .key("user_lookup", key)
        .update_expression("SET #v = :v REMOVE code_set_generation")
        .expression_attribute_names("#v", "version")
        .expression_attribute_values(":v", AttributeValue::N("1".into()))
        .send()
        .await
        .unwrap();
    assert_eq!(store.get("tenant", "lookup").await.unwrap(), baseline);
    assert_eq!(
        store
            .verify_and_consume("tenant", "lookup", &initial.code_hashes[1].hash_b64, 100)
            .await
            .unwrap(),
        RecoveryConsume::Valid
    );
    db.delete_table().table_name(table).send().await.unwrap();
}
