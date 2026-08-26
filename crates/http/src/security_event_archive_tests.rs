use super::*;
use crate::security_event::{
    SecurityActor, SecurityEventCategory, SecurityEventCorrelation, SecurityEventOutcome,
    SecuritySubject,
};
use serde_json::json;
use std::sync::{Arc, Mutex};

type ArchiveWrites = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

fn fixture() -> (SecurityEvent, Value) {
    let event = SecurityEvent::new_at(
        "evt-test",
        1_785_415_471,
        "t1",
        SecurityActor::admin("admin-1"),
        Some(SecuritySubject::user("user:alice@example.com")),
        SecurityEventCategory::UserLifecycle,
        "user.disable",
        SecurityEventOutcome::Success,
        SecurityEventCorrelation::default(),
    )
    .unwrap();
    let payload = json!({
        "Records": [{
            "eventName": "INSERT",
            "dynamodb": {
                "NewImage": {
                    "event_id": { "S": event.event_id },
                    "tenant_id": { "S": event.tenant_id },
                    "occurred_at": { "N": event.occurred_at.to_string() },
                    "envelope": { "S": serde_json::to_string(&event).unwrap() }
                }
            }
        }]
    });
    (event, payload)
}

#[test]
fn ingress_receive_count_reconstructs_prior_failed_attempts() {
    let (event, _) = fixture();
    let mut ingress = SecurityEventIngress::new(event);

    prepare_ingress_receive(&mut ingress, 4, 1_785_415_500).unwrap();

    assert_eq!(ingress.ingress_attempts, 4);
    assert_eq!(
        ingress
            .delivery
            .history
            .iter()
            .filter(|attempt| attempt.status == SecurityEventDeliveryStatus::Failed)
            .count(),
        3
    );
    assert_eq!(
        ingress
            .delivery
            .history
            .iter()
            .filter(|attempt| attempt.status == SecurityEventDeliveryStatus::Retrying)
            .count(),
        3
    );
    assert_eq!(
        ingress.delivery.status,
        SecurityEventDeliveryStatus::Pending
    );
}

#[test]
fn ingress_receive_history_is_bounded_during_a_prolonged_terminal_outage() {
    let (event, _) = fixture();
    let mut ingress = SecurityEventIngress::new(event);

    prepare_ingress_receive(&mut ingress, 1_000_000, 1_785_415_500).unwrap();

    assert_eq!(ingress.ingress_attempts, 1_000_000);
    assert_eq!(ingress.delivery.attempts, 1_000_000);
    assert_eq!(
        ingress.delivery.history.len(),
        INGRESS_DELIVERY_HISTORY_LIMIT
    );
    assert_eq!(
        ingress.delivery.status,
        SecurityEventDeliveryStatus::Pending
    );

    ingress
        .delivery
        .record(SecurityEventDeliveryStatus::Failed, 1_785_415_501);
    ingress
        .delivery
        .record(SecurityEventDeliveryStatus::DeadLettered, 1_785_415_502);
    assert_eq!(
        ingress.delivery.history.len(),
        INGRESS_DELIVERY_HISTORY_LIMIT + 2
    );
    assert_eq!(
        ingress.delivery.history.last().unwrap().status,
        SecurityEventDeliveryStatus::DeadLettered
    );
}

#[test]
fn distinguishes_s3_notifications_from_security_event_ingress_bodies() {
    let notification = json!({
        "Records": [{
            "eventSource": "aws:s3",
            "s3": {
                "bucket": {"name": "failure-bucket"},
                "object": {"key": "failed%2Frecord.json"}
            }
        }]
    });
    assert_eq!(
        parse_s3_notification_records(&notification.to_string())
            .unwrap()
            .unwrap()[0]["eventSource"],
        "aws:s3"
    );
    let test_event = json!({
        "Service": "Amazon S3",
        "Event": "s3:TestEvent",
        "Time": "2026-07-31T11:38:24.244Z",
        "Bucket": "failure-bucket",
        "RequestId": "request-id",
        "HostId": "host-id"
    });
    assert!(
        parse_s3_notification_records(&test_event.to_string())
            .unwrap()
            .unwrap()
            .is_empty(),
        "S3 notification configuration probes must be consumed as no-op notifications"
    );

    let (event, _) = fixture();
    assert!(
        parse_s3_notification_records(&serde_json::to_string(&event).unwrap())
            .unwrap()
            .is_none()
    );
    assert!(parse_s3_notification_records("not-json").unwrap().is_none());
}

#[test]
fn parses_validated_stream_image_and_derives_deterministic_partition_key() {
    let (event, payload) = fixture();
    let records = parse_dynamodb_records(&payload).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].event_id, event.event_id);
    assert_eq!(
        archive_key(&records[0]).unwrap(),
        "security-events/tenant_id=t1/year=2026/month=07/day=30/evt-test.json"
    );
}

#[test]
fn rejects_mismatched_envelope_and_validates_ingress_event() {
    let (_, mut payload) = fixture();
    payload["Records"][0]["dynamodb"]["NewImage"]["tenant_id"]["S"] = json!("t2");
    assert!(parse_dynamodb_records(&payload).is_err());

    let (event, _) = fixture();
    let ingress = parse_ingress_event(&serde_json::to_string(&event).unwrap()).unwrap();
    assert_eq!(ingress.event, event);
    assert_eq!(ingress.delivery.history.len(), 1);
}

#[derive(Clone, Default)]
struct ControlledSink {
    fail_writes: Arc<Mutex<usize>>,
    fail_loads: Arc<Mutex<usize>>,
    fail_dead_letter_marks: Arc<Mutex<usize>>,
    fail_archive_marks: Arc<Mutex<usize>>,
    fail_load_on_call: Arc<Mutex<Option<usize>>>,
    load_calls: Arc<Mutex<usize>>,
    before_write_statuses: Arc<Mutex<Vec<(String, String)>>>,
    refresh_leases: Arc<Mutex<std::collections::HashMap<String, i64>>>,
    redrive_attempts: Arc<Mutex<std::collections::HashMap<String, u32>>>,
    objects: Arc<Mutex<std::collections::HashMap<String, Vec<u8>>>>,
    writes: ArchiveWrites,
    statuses: Arc<Mutex<Vec<(String, String)>>>,
    dead_letters: Arc<Mutex<Vec<ArchiveRecord>>>,
    dead_letter_pending: Arc<Mutex<std::collections::HashSet<String>>>,
    terminal: Arc<Mutex<std::collections::HashSet<String>>>,
}

impl ArchiveDeliverySink for ControlledSink {
    async fn mark_attempt(&self, event_id: &str) -> Result<bool, String> {
        if self.dead_letter_pending.lock().unwrap().contains(event_id)
            || self.terminal.lock().unwrap().contains(event_id)
        {
            return Ok(false);
        }
        self.statuses
            .lock()
            .unwrap()
            .push((event_id.to_string(), "retrying".to_string()));
        Ok(true)
    }

    async fn put_object(&self, key: &str, body: Vec<u8>) -> Result<i64, String> {
        self.statuses
            .lock()
            .unwrap()
            .extend(self.before_write_statuses.lock().unwrap().drain(..));
        let proposed_archived_at = archive_object_archived_at(&body)?;
        let mut objects = self.objects.lock().unwrap();
        if let Some(existing) = objects.get(key) {
            match compare_archive_objects(existing, &body)? {
                ArchiveWriteDecision::KeepExisting => {
                    return archive_object_archived_at(existing);
                }
                ArchiveWriteDecision::ReplaceExisting => {}
            }
        }
        objects.insert(key.to_string(), body.clone());
        drop(objects);
        self.writes.lock().unwrap().push((key.to_string(), body));
        let mut remaining = self.fail_writes.lock().unwrap();
        if *remaining > 0 {
            *remaining -= 1;
            return Err("controlled archive timeout".to_string());
        }
        Ok(proposed_archived_at)
    }

    async fn put_object_if_absent(&self, key: &str, body: Vec<u8>) -> Result<bool, String> {
        let mut objects = self.objects.lock().unwrap();
        if objects.contains_key(key) {
            return Ok(false);
        }
        objects.insert(key.to_string(), body.clone());
        drop(objects);
        self.writes.lock().unwrap().push((key.to_string(), body));
        Ok(true)
    }

    async fn load_delivery(&self, event_id: &str) -> Result<Option<SecurityEventDelivery>, String> {
        let call = {
            let mut calls = self.load_calls.lock().unwrap();
            *calls += 1;
            *calls
        };
        if *self.fail_load_on_call.lock().unwrap() == Some(call) {
            return Err("controlled delivery read failure".to_string());
        }
        let mut failures = self.fail_loads.lock().unwrap();
        if *failures > 0 {
            *failures -= 1;
            return Err("controlled delivery read failure".to_string());
        }
        drop(failures);
        let mut delivery = SecurityEventDelivery::pending(1_785_415_471);
        for (index, (_, status)) in self
            .statuses
            .lock()
            .unwrap()
            .iter()
            .filter(|(candidate, _)| candidate == event_id)
            .enumerate()
        {
            let status = SecurityEventDeliveryStatus::parse(status)?;
            if status == SecurityEventDeliveryStatus::Retrying {
                delivery.attempts = delivery.attempts.saturating_add(1);
            }
            delivery.record(status, 1_785_415_472 + index as i64);
        }
        delivery.attempts = delivery.attempts.saturating_add(
            self.redrive_attempts
                .lock()
                .unwrap()
                .get(event_id)
                .copied()
                .unwrap_or_default(),
        );
        Ok(Some(delivery))
    }

    async fn claim_archive_refresh(&self, event_id: &str) -> Result<Option<i64>, String> {
        let refresh_pending = self
            .statuses
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(candidate, _)| candidate == event_id)
            .is_some_and(|(_, status)| status == "archive_refresh_pending");
        let mut leases = self.refresh_leases.lock().unwrap();
        if !refresh_pending || leases.contains_key(event_id) {
            return Ok(None);
        }
        let lease_until = 1_785_415_600;
        leases.insert(event_id.to_string(), lease_until);
        Ok(Some(lease_until))
    }

    async fn send_dead_letter(
        &self,
        record: &ArchiveRecord,
        _delivery: &SecurityEventDelivery,
    ) -> Result<(), String> {
        self.dead_letters.lock().unwrap().push(record.clone());
        Ok(())
    }

    async fn dead_letter_pending(&self, event_id: &str) -> Result<bool, String> {
        Ok(self.dead_letter_pending.lock().unwrap().contains(event_id))
    }

    async fn mark_dead_letter_pending(&self, event_id: &str) -> Result<bool, String> {
        if self.terminal.lock().unwrap().contains(event_id) {
            return Ok(false);
        }
        self.dead_letter_pending
            .lock()
            .unwrap()
            .insert(event_id.to_string());
        self.statuses
            .lock()
            .unwrap()
            .push((event_id.to_string(), "dead_letter_pending".to_string()));
        Ok(true)
    }

    async fn mark_dead_lettered(&self, event_id: &str) -> Result<(), String> {
        let mut failures = self.fail_dead_letter_marks.lock().unwrap();
        if *failures > 0 {
            *failures -= 1;
            return Err("controlled terminal status failure".to_string());
        }
        drop(failures);
        self.dead_letter_pending.lock().unwrap().remove(event_id);
        self.terminal.lock().unwrap().insert(event_id.to_string());
        self.statuses
            .lock()
            .unwrap()
            .push((event_id.to_string(), "dead_lettered".to_string()));
        Ok(())
    }

    async fn mark_failed(&self, event_id: &str) -> Result<(), String> {
        self.statuses
            .lock()
            .unwrap()
            .push((event_id.to_string(), "failed".to_string()));
        Ok(())
    }

    async fn mark_archived(&self, commit: ArchiveCommit<'_>) -> Result<bool, String> {
        let failed = {
            let mut failures = self.fail_archive_marks.lock().unwrap();
            if *failures > 0 {
                *failures -= 1;
                true
            } else {
                false
            }
        };
        if failed {
            return Err("controlled archive status failure".to_string());
        }
        let delivery = self
            .load_delivery(commit.event_id)
            .await?
            .ok_or_else(|| "controlled event disappeared".to_string())?;
        if delivery.status != commit.expected_status
            || delivery.attempts != commit.expected_attempts
            || delivery.history != commit.expected_history
        {
            return Ok(false);
        }
        if let Some(expected_lease) = commit.expected_refresh_lease_until {
            if self
                .refresh_leases
                .lock()
                .unwrap()
                .get(commit.event_id)
                .copied()
                != Some(expected_lease)
            {
                return Ok(false);
            }
        }
        self.refresh_leases.lock().unwrap().remove(commit.event_id);
        self.terminal.lock().unwrap().remove(commit.event_id);
        self.statuses
            .lock()
            .unwrap()
            .push((commit.event_id.to_string(), "archived".to_string()));
        Ok(true)
    }

    async fn mark_redrive_attempt(&self, event_id: &str) -> Result<bool, String> {
        if !self.terminal.lock().unwrap().contains(event_id) {
            return Ok(false);
        }
        let mut attempts = self.redrive_attempts.lock().unwrap();
        *attempts.entry(event_id.to_string()).or_default() += 1;
        Ok(true)
    }

    async fn mark_redrive_failed(&self, event_id: &str) -> Result<(), String> {
        self.terminal.lock().unwrap().insert(event_id.to_string());
        Ok(())
    }
}

#[tokio::test]
async fn terminal_ingress_is_written_to_the_queryable_tenant_archive() {
    let (event, _) = fixture();
    let mut ingress = SecurityEventIngress::new(event);
    ingress.delivery.start_attempt(1_785_415_500);
    ingress
        .delivery
        .record(SecurityEventDeliveryStatus::Failed, 1_785_415_501);
    ingress
        .delivery
        .record(SecurityEventDeliveryStatus::DeadLettered, 1_785_415_502);
    let sink = ControlledSink::default();

    let (key, created) = archive_terminal_ingress(&sink, &ingress).await.unwrap();

    assert!(created);
    assert_eq!(
        key,
        "security-events/tenant_id=t1/year=2026/month=07/day=30/evt-test.json"
    );
    let writes = sink.writes.lock().unwrap();
    assert_eq!(writes.len(), 1);
    let body: Value = serde_json::from_slice(&writes[0].1).unwrap();
    assert_eq!(body["event_id"], "evt-test");
    assert_eq!(body["delivery"]["status"], "dead_lettered");
}

#[tokio::test]
async fn terminal_ingress_never_overwrites_an_existing_trusted_archive() {
    let (event, _) = fixture();
    let ingress = SecurityEventIngress::new(event);
    let sink = ControlledSink::default();
    let trusted_body = b"{\"trusted\":true}\n".to_vec();
    let key = "security-events/tenant_id=t1/year=2026/month=07/day=30/evt-test.json";
    sink.put_object_if_absent(key, trusted_body.clone())
        .await
        .unwrap();

    let (returned_key, created) = archive_terminal_ingress(&sink, &ingress).await.unwrap();

    assert_eq!(returned_key, key);
    assert!(!created);
    let writes = sink.writes.lock().unwrap();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].1, trusted_body);
}

#[tokio::test]
async fn failed_delivery_retries_with_the_same_event_id_and_object_key() {
    let (_, payload) = fixture();
    let records = parse_dynamodb_records(&payload).unwrap();
    let sink = ControlledSink::default();
    *sink.fail_writes.lock().unwrap() = 1;

    deliver_records(&sink, &records).await.unwrap();

    let writes = sink.writes.lock().unwrap();
    assert_eq!(writes.len(), 2);
    assert_eq!(writes[0].0, writes[1].0);
    assert!(writes[0].0.ends_with("/evt-test.json"));
    let archived: Value = serde_json::from_slice(&writes[1].1).unwrap();
    assert_eq!(archived["event_id"], "evt-test");
    assert_eq!(archived["delivery"]["status"], "archived");
    assert_eq!(archived["delivery"]["attempts"], 2);
    assert!(archived["delivery"]["history"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["status"] == "failed"));
    drop(writes);

    assert_eq!(
        *sink.statuses.lock().unwrap(),
        [
            ("evt-test".to_string(), "retrying".to_string()),
            ("evt-test".to_string(), "failed".to_string()),
            ("evt-test".to_string(), "retrying".to_string()),
            ("evt-test".to_string(), "archived".to_string()),
        ]
    );
    assert!(sink.dead_letters.lock().unwrap().is_empty());
}

#[tokio::test]
async fn one_failed_record_does_not_starve_later_archive_records() {
    let (_, payload) = fixture();
    let mut records = parse_dynamodb_records(&payload).unwrap();
    let mut second = records[0].clone();
    second.event_id = "evt-second".to_string();
    let mut second_envelope: Value = serde_json::from_str(&second.envelope).unwrap();
    second_envelope["event_id"] = json!("evt-second");
    second.envelope = second_envelope.to_string();
    records.push(second);
    let sink = ControlledSink::default();
    *sink.fail_load_on_call.lock().unwrap() = Some(1);

    let error = deliver_records(&sink, &records).await.unwrap_err();

    assert!(error.contains("event_id=evt-test"));
    assert!(sink
        .statuses
        .lock()
        .unwrap()
        .iter()
        .any(|(event_id, status)| event_id == "evt-second" && status == "archived"));
}

#[tokio::test]
async fn failed_pending_outbox_does_not_starve_redrive_or_refresh_classes() {
    let (_, payload) = fixture();
    let records = parse_dynamodb_records(&payload).unwrap();
    let pending = records[0].clone();
    let mut dead_letter = pending.clone();
    dead_letter.event_id = "evt-redrive".to_string();
    let mut redrive_envelope: Value = serde_json::from_str(&dead_letter.envelope).unwrap();
    redrive_envelope["event_id"] = json!("evt-redrive");
    dead_letter.envelope = redrive_envelope.to_string();
    let mut refresh = pending.clone();
    refresh.event_id = "evt-refresh".to_string();
    let mut refresh_envelope: Value = serde_json::from_str(&refresh.envelope).unwrap();
    refresh_envelope["event_id"] = json!("evt-refresh");
    refresh.envelope = refresh_envelope.to_string();

    let sink = ControlledSink::default();
    sink.dead_letter_pending
        .lock()
        .unwrap()
        .insert(pending.event_id.clone());
    sink.terminal
        .lock()
        .unwrap()
        .insert(dead_letter.event_id.clone());
    sink.statuses.lock().unwrap().push((
        refresh.event_id.clone(),
        "archive_refresh_pending".to_string(),
    ));
    *sink.fail_load_on_call.lock().unwrap() = Some(1);

    let error = recover_scheduled_records(&sink, &[pending], &[dead_letter], &[refresh])
        .await
        .unwrap_err();

    assert!(!error.is_empty());
    let statuses = sink.statuses.lock().unwrap();
    assert!(statuses
        .iter()
        .any(|(event_id, status)| event_id == "evt-redrive" && status == "archived"));
    assert!(statuses
        .iter()
        .any(|(event_id, status)| event_id == "evt-refresh" && status == "archived"));
}

#[tokio::test]
async fn failed_managed_reconciliation_record_does_not_starve_its_neighbor() {
    let (_, payload) = fixture();
    let records = parse_dynamodb_records(&payload).unwrap();
    let first = records[0].clone();
    let mut second = first.clone();
    second.event_id = "evt-second".to_string();
    let mut second_envelope: Value = serde_json::from_str(&second.envelope).unwrap();
    second_envelope["event_id"] = json!("evt-second");
    second.envelope = second_envelope.to_string();
    let sink = ControlledSink::default();
    *sink.fail_load_on_call.lock().unwrap() = Some(1);

    let error = reconcile_managed_failure_records(&sink, &[first, second])
        .await
        .unwrap_err();

    assert!(error.contains("event_id=evt-test"));
    assert!(sink
        .statuses
        .lock()
        .unwrap()
        .iter()
        .any(|(event_id, status)| event_id == "evt-second" && status == "dead_lettered"));
}

#[tokio::test]
async fn exhausted_delivery_preserves_the_full_event_in_the_terminal_queue() {
    let (_, payload) = fixture();
    let records = parse_dynamodb_records(&payload).unwrap();
    let sink = ControlledSink::default();
    *sink.fail_writes.lock().unwrap() = ARCHIVE_DELIVERY_ATTEMPTS;

    deliver_records(&sink, &records).await.unwrap();

    assert_eq!(sink.writes.lock().unwrap().len(), ARCHIVE_DELIVERY_ATTEMPTS);
    assert_eq!(*sink.dead_letters.lock().unwrap(), records);
    assert_eq!(
        sink.statuses.lock().unwrap().last().unwrap().1,
        "dead_lettered"
    );

    let writes_before_redrive = sink.writes.lock().unwrap().len();
    redrive_dead_letters(&sink, &records).await.unwrap();
    assert_eq!(sink.writes.lock().unwrap().len(), writes_before_redrive + 1);
    assert_eq!(sink.statuses.lock().unwrap().last().unwrap().1, "archived");
}

#[tokio::test]
async fn terminal_status_failure_resumes_the_pending_outbox_without_rewriting_s3() {
    let (_, payload) = fixture();
    let records = parse_dynamodb_records(&payload).unwrap();
    let sink = ControlledSink::default();
    *sink.fail_writes.lock().unwrap() = ARCHIVE_DELIVERY_ATTEMPTS;
    *sink.fail_dead_letter_marks.lock().unwrap() = 1;

    assert!(deliver_records(&sink, &records).await.is_err());
    assert!(sink
        .dead_letter_pending
        .lock()
        .unwrap()
        .contains("evt-test"));
    let writes_after_failure = sink.writes.lock().unwrap().len();

    deliver_records(&sink, &records).await.unwrap();

    assert_eq!(sink.writes.lock().unwrap().len(), writes_after_failure);
    assert_eq!(sink.dead_letters.lock().unwrap().len(), 2);
    assert_eq!(
        sink.statuses.lock().unwrap().last().unwrap().1,
        "dead_lettered"
    );
}

#[tokio::test]
async fn scheduled_recovery_resumes_pending_outbox_after_source_exhaustion() {
    let (_, payload) = fixture();
    let records = parse_dynamodb_records(&payload).unwrap();
    let sink = ControlledSink::default();
    sink.dead_letter_pending
        .lock()
        .unwrap()
        .insert("evt-test".to_string());
    sink.statuses
        .lock()
        .unwrap()
        .push(("evt-test".to_string(), "dead_letter_pending".to_string()));

    recover_scheduled_records(&sink, &records, &[], &[])
        .await
        .unwrap();

    assert!(!sink
        .dead_letter_pending
        .lock()
        .unwrap()
        .contains("evt-test"));
    assert_eq!(sink.dead_letters.lock().unwrap().len(), 1);
    assert_eq!(
        sink.statuses.lock().unwrap().last().unwrap().1,
        "dead_lettered"
    );
}

#[tokio::test]
async fn scheduled_redrive_status_failure_remains_eligible_for_the_next_pass() {
    let (_, payload) = fixture();
    let records = parse_dynamodb_records(&payload).unwrap();
    let sink = ControlledSink::default();
    *sink.fail_writes.lock().unwrap() = ARCHIVE_DELIVERY_ATTEMPTS;
    deliver_records(&sink, &records).await.unwrap();
    *sink.fail_archive_marks.lock().unwrap() = 1;

    assert!(redrive_dead_letters(&sink, &records).await.is_err());
    assert!(sink.terminal.lock().unwrap().contains("evt-test"));

    redrive_dead_letters(&sink, &records).await.unwrap();
    assert!(!sink.terminal.lock().unwrap().contains("evt-test"));
    assert_eq!(sink.statuses.lock().unwrap().last().unwrap().1, "archived");
}

#[tokio::test]
async fn scheduled_redrive_records_prewrite_failures_before_releasing_the_lease() {
    let (_, payload) = fixture();
    let records = parse_dynamodb_records(&payload).unwrap();
    let sink = ControlledSink::default();
    *sink.fail_writes.lock().unwrap() = ARCHIVE_DELIVERY_ATTEMPTS;
    deliver_records(&sink, &records).await.unwrap();
    let writes_before_redrive = sink.writes.lock().unwrap().len();
    *sink.fail_loads.lock().unwrap() = 1;

    let error = redrive_dead_letters(&sink, &records).await.unwrap_err();

    assert!(error.contains("stage=prepare_redrive"));
    assert_eq!(sink.writes.lock().unwrap().len(), writes_before_redrive);
    assert_eq!(
        sink.statuses.lock().unwrap().last().unwrap().1,
        "dead_lettered"
    );
    assert_eq!(
        sink.redrive_attempts
            .lock()
            .unwrap()
            .get("evt-test")
            .copied(),
        Some(1)
    );

    redrive_dead_letters(&sink, &records).await.unwrap();
    assert_eq!(sink.statuses.lock().unwrap().last().unwrap().1, "archived");
}

#[tokio::test]
async fn scheduled_redrive_write_failure_is_reported_and_remains_retryable() {
    let (_, payload) = fixture();
    let records = parse_dynamodb_records(&payload).unwrap();
    let sink = ControlledSink::default();
    *sink.fail_writes.lock().unwrap() = ARCHIVE_DELIVERY_ATTEMPTS;
    deliver_records(&sink, &records).await.unwrap();
    *sink.fail_writes.lock().unwrap() = 1;

    let error = redrive_dead_letters(&sink, &records).await.unwrap_err();

    assert!(error.contains("stage=write_redrive"));
    assert!(sink.terminal.lock().unwrap().contains("evt-test"));
    redrive_dead_letters(&sink, &records).await.unwrap();
    assert_eq!(sink.statuses.lock().unwrap().last().unwrap().1, "archived");
}

#[tokio::test]
async fn concurrent_refresh_worker_cannot_write_without_the_durable_lease() {
    let (_, payload) = fixture();
    let records = parse_dynamodb_records(&payload).unwrap();
    let sink = ControlledSink::default();
    sink.statuses.lock().unwrap().push((
        "evt-test".to_string(),
        "archive_refresh_pending".to_string(),
    ));
    sink.refresh_leases
        .lock()
        .unwrap()
        .insert("evt-test".to_string(), 1_785_415_600);

    assert!(!refresh_archived_record(&sink, &records[0]).await.unwrap());

    assert!(sink.writes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn durable_archive_refresh_pending_commits_archived_after_s3() {
    let (_, payload) = fixture();
    let records = parse_dynamodb_records(&payload).unwrap();
    let sink = ControlledSink::default();
    sink.statuses.lock().unwrap().push((
        "evt-test".to_string(),
        "archive_refresh_pending".to_string(),
    ));

    assert!(refresh_archived_record(&sink, &records[0]).await.unwrap());

    let writes = sink.writes.lock().unwrap();
    assert_eq!(writes.len(), 1);
    let archived: Value = serde_json::from_slice(&writes[0].1).unwrap();
    assert_eq!(archived["delivery"]["status"], "archived");
    drop(writes);
    assert_eq!(sink.statuses.lock().unwrap().last().unwrap().1, "archived");
}

#[tokio::test]
async fn stale_refresh_cannot_replace_a_newer_committed_snapshot_before_crashing() {
    let (_, payload) = fixture();
    let records = parse_dynamodb_records(&payload).unwrap();
    let sink = ControlledSink::default();
    sink.statuses.lock().unwrap().push((
        "evt-test".to_string(),
        "archive_refresh_pending".to_string(),
    ));
    sink.before_write_statuses.lock().unwrap().extend([
        ("evt-test".to_string(), "retrying".to_string()),
        (
            "evt-test".to_string(),
            "archive_refresh_pending".to_string(),
        ),
    ]);
    *sink.fail_load_on_call.lock().unwrap() = Some(2);

    assert!(refresh_archived_record(&sink, &records[0]).await.is_err());
    assert_eq!(
        sink.statuses.lock().unwrap().last().unwrap().1,
        "archive_refresh_pending"
    );
    sink.refresh_leases.lock().unwrap().remove("evt-test");
    *sink.fail_load_on_call.lock().unwrap() = None;

    assert!(refresh_archived_record(&sink, &records[0]).await.unwrap());
    let body: Value =
        serde_json::from_slice(&sink.writes.lock().unwrap().last().unwrap().1).unwrap();
    assert_eq!(
        body["delivery"]["attempts"], 1,
        "the last S3 snapshot must not lag the committed Dynamo delivery revision"
    );
}

#[tokio::test]
async fn archive_commit_rejects_a_worker_whose_observed_status_is_stale() {
    let sink = ControlledSink::default();
    sink.statuses.lock().unwrap().push((
        "evt-test".to_string(),
        "archive_refresh_pending".to_string(),
    ));
    let observed = sink.load_delivery("evt-test").await.unwrap().unwrap();

    assert!(sink
        .mark_archived(ArchiveCommit {
            event_id: "evt-test",
            key: "security-events/evt-test.json",
            occurred_at: 1_785_415_471,
            archived_at: 1_785_415_500,
            expected_attempts: observed.attempts,
            expected_status: observed.status,
            expected_history: &observed.history,
            expected_refresh_lease_until: None,
        })
        .await
        .unwrap());
    assert!(!sink
        .mark_archived(ArchiveCommit {
            event_id: "evt-test",
            key: "security-events/evt-test.json",
            occurred_at: 1_785_415_471,
            archived_at: 1_785_415_501,
            expected_attempts: observed.attempts,
            expected_status: observed.status,
            expected_history: &observed.history,
            expected_refresh_lease_until: None,
        })
        .await
        .unwrap());
}

#[tokio::test]
async fn archive_commit_rejects_same_attempt_history_extension() {
    let sink = ControlledSink::default();
    sink.statuses.lock().unwrap().push((
        "evt-test".to_string(),
        "archive_refresh_pending".to_string(),
    ));
    let observed = sink.load_delivery("evt-test").await.unwrap().unwrap();
    sink.statuses.lock().unwrap().push((
        "evt-test".to_string(),
        "archive_refresh_pending".to_string(),
    ));

    assert!(!sink
        .mark_archived(ArchiveCommit {
            event_id: "evt-test",
            key: "security-events/evt-test.json",
            occurred_at: 1_785_415_471,
            archived_at: 1_785_415_500,
            expected_attempts: observed.attempts,
            expected_status: observed.status,
            expected_history: &observed.history,
            expected_refresh_lease_until: None,
        })
        .await
        .unwrap());
}

#[tokio::test]
async fn archive_object_cas_preserves_a_dominating_snapshot_and_rejects_collisions() {
    let (event, _) = fixture();
    let record = ArchiveRecord {
        event_id: event.event_id.clone(),
        tenant_id: event.tenant_id.clone(),
        occurred_at: event.occurred_at,
        envelope: serde_json::to_string(&event).unwrap(),
    };
    let key = archive_key(&record).unwrap();
    let mut older = SecurityEventDelivery::pending(event.occurred_at);
    older.start_attempt(event.occurred_at + 1);
    let older_body = archive_body(
        &record,
        &archived_delivery(older.clone(), &key, event.occurred_at + 2),
    )
    .unwrap();
    let mut newer = older;
    newer.record(SecurityEventDeliveryStatus::Failed, event.occurred_at + 3);
    newer.start_attempt(event.occurred_at + 4);
    let newer_body = archive_body(
        &record,
        &archived_delivery(newer, &key, event.occurred_at + 5),
    )
    .unwrap();
    assert_eq!(
        compare_archive_objects(&older_body, &newer_body).unwrap(),
        ArchiveWriteDecision::ReplaceExisting
    );
    assert_eq!(
        compare_archive_objects(&newer_body, &older_body).unwrap(),
        ArchiveWriteDecision::KeepExisting
    );

    let sink = ControlledSink::default();
    sink.put_object(&key, newer_body.clone()).await.unwrap();
    assert_eq!(
        sink.put_object(&key, older_body).await.unwrap(),
        event.occurred_at + 5
    );
    assert_eq!(sink.writes.lock().unwrap().len(), 1);
    assert_eq!(sink.objects.lock().unwrap().get(&key), Some(&newer_body));

    let mut collision = record.clone();
    let mut collision_event: Value = serde_json::from_str(&collision.envelope).unwrap();
    collision_event["action"] = json!("user.enable");
    collision.envelope = collision_event.to_string();
    let collision_body = archive_body(
        &collision,
        &archived_delivery(
            SecurityEventDelivery::pending(event.occurred_at),
            &key,
            event.occurred_at + 6,
        ),
    )
    .unwrap();
    assert!(sink.put_object(&key, collision_body).await.is_err());
    assert_eq!(sink.objects.lock().unwrap().get(&key), Some(&newer_body));

    let mut extended_schema: Value = serde_json::from_slice(&newer_body).unwrap();
    extended_schema["future_immutable_field"] = json!("must-not-be-ignored");
    assert!(
        compare_archive_objects(&newer_body, &serde_json::to_vec(&extended_schema).unwrap())
            .is_err()
    );
}

#[test]
fn archive_object_cas_rejects_divergent_delivery_histories() {
    let (event, _) = fixture();
    let record = ArchiveRecord {
        event_id: event.event_id.clone(),
        tenant_id: event.tenant_id.clone(),
        occurred_at: event.occurred_at,
        envelope: serde_json::to_string(&event).unwrap(),
    };
    let key = archive_key(&record).unwrap();
    let mut left = SecurityEventDelivery::pending(event.occurred_at);
    left.record(SecurityEventDeliveryStatus::Failed, event.occurred_at + 1);
    let mut right = SecurityEventDelivery::pending(event.occurred_at);
    right.record(
        SecurityEventDeliveryStatus::DeadLetterPending,
        event.occurred_at + 1,
    );
    let left = archive_body(
        &record,
        &archived_delivery(left, &key, event.occurred_at + 2),
    )
    .unwrap();
    let right = archive_body(
        &record,
        &archived_delivery(right, &key, event.occurred_at + 2),
    )
    .unwrap();

    assert!(compare_archive_objects(&left, &right)
        .unwrap_err()
        .contains("diverges"));
}

#[test]
fn archive_object_cas_upgrades_a_recovered_terminal_ingress_snapshot() {
    let (event, _) = fixture();
    let record = ArchiveRecord {
        event_id: event.event_id.clone(),
        tenant_id: event.tenant_id.clone(),
        occurred_at: event.occurred_at,
        envelope: serde_json::to_string(&event).unwrap(),
    };
    let key = archive_key(&record).unwrap();
    let mut terminal = SecurityEventDelivery::pending(event.occurred_at);
    terminal.start_attempt(event.occurred_at + 1);
    terminal.record(SecurityEventDeliveryStatus::Failed, event.occurred_at + 2);
    terminal.record(
        SecurityEventDeliveryStatus::DeadLettered,
        event.occurred_at + 3,
    );
    let terminal_body = archive_body(&record, &terminal).unwrap();
    let same_history_body = archive_body(
        &record,
        &archived_delivery(terminal.clone(), &key, event.occurred_at + 4),
    )
    .unwrap();
    assert_eq!(
        compare_archive_objects(&terminal_body, &same_history_body).unwrap(),
        ArchiveWriteDecision::ReplaceExisting
    );

    let mut recovered = terminal;
    recovered.record(SecurityEventDeliveryStatus::Retrying, event.occurred_at + 4);
    recovered.start_attempt(event.occurred_at + 5);
    let recovered_body = archive_body(
        &record,
        &archived_delivery(recovered, &key, event.occurred_at + 6),
    )
    .unwrap();

    assert_eq!(
        compare_archive_objects(&terminal_body, &recovered_body).unwrap(),
        ArchiveWriteDecision::ReplaceExisting
    );
}

#[test]
fn parses_failed_stream_destination_payload() {
    let (_, request_payload) = fixture();
    for invocation in [
        json!({"requestPayload": request_payload}),
        json!({"payload": request_payload.to_string()}),
    ] {
        let records = parse_failed_stream_invocation(&invocation).unwrap();
        assert_eq!(records[0].event_id, "evt-test");
    }
}
