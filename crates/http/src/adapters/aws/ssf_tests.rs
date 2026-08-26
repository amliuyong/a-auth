use super::*;
use crate::ssf::RISC_ACCOUNT_DISABLED_EVENT;

fn stream() -> SsfStream {
    SsfStream::new(
        "t1",
        "receiver-1",
        "https://receiver.example.net/events",
        "https://receiver.example.net",
        vec![RISC_ACCOUNT_DISABLED_EVENT.to_string()],
        100,
    )
    .unwrap()
}

fn delivery() -> SsfDelivery {
    SsfDelivery {
        tenant_id: "t1".to_string(),
        stream_id: "receiver-1".to_string(),
        stream_revision: 7,
        event_id: "evt-credential-change".to_string(),
        issuer: "https://t1.example.com".to_string(),
        endpoint: "https://receiver.example.net/events".to_string(),
        audience: "https://receiver.example.net".to_string(),
        event_uri: RISC_ACCOUNT_DISABLED_EVENT.to_string(),
        subject: serde_json::json!({
            "format": "iss_sub",
            "iss": "https://t1.example.com",
            "sub": "user:alice@example.com"
        }),
        payload: serde_json::json!({"event_timestamp": 101}),
        status: SsfDeliveryStatus::RetryWait,
        attempts: 2,
        cycle_attempts: 2,
        redrive_count: 1,
        attempt_history: vec![
            SsfDeliveryAttempt {
                attempted_at: 110,
                outcome: SsfDeliveryAttemptOutcome::Retryable,
                status_code: Some(503),
                error_class: Some("http_503".to_string()),
                set_sha256: Some("sha256:JW0E205eSsMIdR7QiFtyK3WGMFZ8U6cSXtn70Gjlw_Y".to_string()),
                signing_kid: Some("kid-1".to_string()),
            },
            SsfDeliveryAttempt {
                attempted_at: 140,
                outcome: SsfDeliveryAttemptOutcome::Retryable,
                status_code: None,
                error_class: Some("timeout".to_string()),
                set_sha256: Some("sha256:JW0E205eSsMIdR7QiFtyK3WGMFZ8U6cSXtn70Gjlw_Y".to_string()),
                signing_kid: Some("kid-1".to_string()),
            },
        ],
        event_occurred_at: 101,
        created_at: 105,
        updated_at: 140,
        cycle_started_at: 105,
        next_attempt_at: 260,
        expires_at: 40_000_000,
        compact_set: Some("header.payload.signature".to_string()),
        jti: Some("set_stable".to_string()),
        signing_kid: Some("kid-1".to_string()),
        issued_at: Some(110),
        lease_id: Some("lease-1".to_string()),
        lease_expires_at: Some(170),
    }
}

#[test]
fn stream_row_round_trip_preserves_tenant_scope_and_configuration() {
    let stream = stream();
    let item = DynamoSsfStore::stream_item(&stream);

    assert_eq!(item["tenant_id"].as_s().unwrap(), "t1");
    assert_eq!(item["record_key"].as_s().unwrap(), "stream#receiver-1");
    assert_eq!(
        DynamoSsfStore::stream_from_item(&item, "t1", Some("receiver-1")).unwrap(),
        stream
    );
    assert!(DynamoSsfStore::stream_from_item(&item, "t2", Some("receiver-1")).is_err());
}

#[test]
fn delivery_row_round_trip_keeps_internal_set_lease_and_due_fields() {
    let delivery = delivery();
    let item = DynamoSsfStore::delivery_item(&delivery).unwrap();

    assert_eq!(
        item["record_key"].as_s().unwrap(),
        "delivery#receiver-1#00000000000000000007#evt-credential-change"
    );
    assert_eq!(item["stream_partition"].as_s().unwrap(), "t1#receiver-1");
    assert_eq!(
        item["stream_created_at"].as_s().unwrap(),
        "00000000000000000105#00000000000000000007#evt-credential-change"
    );
    assert_eq!(item["due_partition"].as_s().unwrap(), DUE_PARTITION);
    assert_eq!(item["due_at"].as_n().unwrap(), "170");
    assert_eq!(
        item["compact_set"].as_s().unwrap(),
        "header.payload.signature"
    );
    assert_eq!(item["lease_id"].as_s().unwrap(), "lease-1");
    assert_eq!(
        DynamoSsfStore::delivery_from_item(&item, Some("t1"), Some("receiver-1")).unwrap(),
        delivery
    );
}

#[test]
fn terminal_delivery_is_removed_from_the_due_index() {
    let mut delivery = delivery();
    delivery.status = SsfDeliveryStatus::Terminal;
    delivery.lease_id = None;
    delivery.lease_expires_at = None;
    let item = DynamoSsfStore::delivery_item(&delivery).unwrap();

    assert!(!item.contains_key("due_partition"));
    assert!(!item.contains_key("due_at"));
}

#[test]
fn delivery_parser_rejects_cross_tenant_or_key_mismatch() {
    let delivery = delivery();
    let mut item = DynamoSsfStore::delivery_item(&delivery).unwrap();
    assert!(DynamoSsfStore::delivery_from_item(&item, Some("t2"), Some("receiver-1")).is_err());

    item.insert(
        "record_key".to_string(),
        AttributeValue::S(
            "delivery#receiver-2#00000000000000000007#evt-credential-change".to_string(),
        ),
    );
    assert!(DynamoSsfStore::delivery_from_item(&item, Some("t1"), Some("receiver-1")).is_err());
}

#[test]
fn delivery_parser_rejects_inconsistent_signed_and_due_fields() {
    let delivery = delivery();
    let mut item = DynamoSsfStore::delivery_item(&delivery).unwrap();
    item.remove("signing_kid");
    assert!(DynamoSsfStore::delivery_from_item(&item, Some("t1"), Some("receiver-1")).is_err());

    let mut item = DynamoSsfStore::delivery_item(&delivery).unwrap();
    item.insert("due_at".to_string(), AttributeValue::N("999".to_string()));
    assert!(DynamoSsfStore::delivery_from_item(&item, Some("t1"), Some("receiver-1")).is_err());
}
