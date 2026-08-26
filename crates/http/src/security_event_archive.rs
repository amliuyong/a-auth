//! Parsing, deterministic S3 keys, and delivery-state orchestration for the
//! security-event archive worker.

use std::future::Future;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::security_event::{
    SecurityEvent, SecurityEventDelivery, SecurityEventDeliveryAttempt,
    SecurityEventDeliveryStatus, SecurityEventIngress, SECURITY_EVENT_SCHEMA_VERSION,
};

pub const ARCHIVE_DELIVERY_ATTEMPTS: usize = 4;
pub const INGRESS_DELIVERY_ATTEMPTS: u32 = 4;
const INGRESS_DELIVERY_HISTORY_LIMIT: usize = 64;

pub fn parse_s3_notification_records(body: &str) -> Result<Option<Vec<Value>>, String> {
    let notification: Value = match serde_json::from_str(body) {
        Ok(notification) => notification,
        Err(_) => return Ok(None),
    };
    if notification.get("Service").and_then(Value::as_str) == Some("Amazon S3")
        && notification.get("Event").and_then(Value::as_str) == Some("s3:TestEvent")
    {
        return Ok(Some(Vec::new()));
    }
    let Some(records) = notification.get("Records").and_then(Value::as_array) else {
        return Ok(None);
    };
    if records.is_empty() {
        return Err("S3 notification has no records".to_string());
    }
    let event_source = records.first().and_then(|record| {
        record
            .get("eventSource")
            .or_else(|| record.get("EventSource"))
            .and_then(Value::as_str)
    });
    if event_source != Some("aws:s3") {
        return Ok(None);
    }
    Ok(Some(records.clone()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveRecord {
    pub event_id: String,
    pub tenant_id: String,
    pub occurred_at: i64,
    pub envelope: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveCommit<'a> {
    pub event_id: &'a str,
    pub key: &'a str,
    pub occurred_at: i64,
    pub archived_at: i64,
    pub expected_attempts: u32,
    pub expected_status: SecurityEventDeliveryStatus,
    pub expected_history: &'a [SecurityEventDeliveryAttempt],
    pub expected_refresh_lease_until: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveWriteDecision {
    KeepExisting,
    ReplaceExisting,
}

/// Reconstruct failed source-queue receives from SQS's durable receive count,
/// then open the current attempt. SQS does not expose the original receive
/// timestamps, so reconstructed transitions use the current observation time.
pub fn prepare_ingress_receive(
    ingress: &mut SecurityEventIngress,
    receive_count: u32,
    observed_at: i64,
) -> Result<(), &'static str> {
    if receive_count == 0 {
        return Err("SQS ingress receive count must be positive");
    }
    let prior_attempts = ingress
        .ingress_attempts
        .saturating_add(receive_count.saturating_sub(1));
    while ingress.ingress_attempts < prior_attempts
        && ingress.delivery.history.len() < INGRESS_DELIVERY_HISTORY_LIMIT
    {
        if ingress.ingress_attempts > 0 {
            ingress.delivery.record_bounded(
                SecurityEventDeliveryStatus::Retrying,
                observed_at,
                INGRESS_DELIVERY_HISTORY_LIMIT,
            );
        }
        ingress
            .delivery
            .start_attempt_bounded(observed_at, INGRESS_DELIVERY_HISTORY_LIMIT);
        ingress.delivery.record_bounded(
            SecurityEventDeliveryStatus::Failed,
            observed_at,
            INGRESS_DELIVERY_HISTORY_LIMIT,
        );
        ingress.ingress_attempts = ingress.ingress_attempts.saturating_add(1);
    }
    if ingress.ingress_attempts < prior_attempts {
        let rolled_up_attempts = prior_attempts - ingress.ingress_attempts;
        ingress.delivery.attempts = ingress.delivery.attempts.saturating_add(rolled_up_attempts);
        ingress.delivery.record_bounded(
            SecurityEventDeliveryStatus::Failed,
            observed_at,
            INGRESS_DELIVERY_HISTORY_LIMIT,
        );
        ingress.ingress_attempts = prior_attempts;
    }
    if ingress.ingress_attempts > 0 {
        ingress.delivery.record_bounded(
            SecurityEventDeliveryStatus::Retrying,
            observed_at,
            INGRESS_DELIVERY_HISTORY_LIMIT,
        );
    }
    ingress
        .delivery
        .start_attempt_bounded(observed_at, INGRESS_DELIVERY_HISTORY_LIMIT);
    ingress.ingress_attempts = ingress.ingress_attempts.saturating_add(1);
    Ok(())
}

pub trait ArchiveDeliverySink: Send + Sync {
    /// Returns false when a prior terminal transition already won.
    fn mark_attempt(&self, event_id: &str) -> impl Future<Output = Result<bool, String>> + Send;

    /// Conditionally retain the dominating archive revision and return the
    /// `archived_at` timestamp stored in the winning object.
    fn put_object(
        &self,
        key: &str,
        body: Vec<u8>,
    ) -> impl Future<Output = Result<i64, String>> + Send;

    /// Creates an object only when the key is absent. Returns false when an
    /// existing trusted archive object was preserved.
    fn put_object_if_absent(
        &self,
        key: &str,
        body: Vec<u8>,
    ) -> impl Future<Output = Result<bool, String>> + Send;

    fn load_delivery(
        &self,
        event_id: &str,
    ) -> impl Future<Output = Result<Option<SecurityEventDelivery>, String>> + Send;

    /// Fence a refresh worker before its ledger read and S3 write.
    fn claim_archive_refresh(
        &self,
        event_id: &str,
    ) -> impl Future<Output = Result<Option<i64>, String>> + Send;

    fn mark_failed(&self, event_id: &str) -> impl Future<Output = Result<(), String>> + Send;

    fn dead_letter_pending(
        &self,
        event_id: &str,
    ) -> impl Future<Output = Result<bool, String>> + Send;

    /// Persist the outbox transition before publishing the terminal message.
    /// Returns false when an archived/dead-lettered terminal state already won.
    fn mark_dead_letter_pending(
        &self,
        event_id: &str,
    ) -> impl Future<Output = Result<bool, String>> + Send;

    fn send_dead_letter(
        &self,
        record: &ArchiveRecord,
        delivery: &SecurityEventDelivery,
    ) -> impl Future<Output = Result<(), String>> + Send;

    fn mark_dead_lettered(&self, event_id: &str)
        -> impl Future<Output = Result<(), String>> + Send;

    fn mark_archived(
        &self,
        commit: ArchiveCommit<'_>,
    ) -> impl Future<Output = Result<bool, String>> + Send;

    /// Re-open a durable dead-letter row for one scheduled S3 redrive.
    fn mark_redrive_attempt(
        &self,
        event_id: &str,
    ) -> impl Future<Output = Result<bool, String>> + Send;

    /// Return a failed scheduled redrive to its durable dead-letter state.
    fn mark_redrive_failed(
        &self,
        event_id: &str,
    ) -> impl Future<Output = Result<(), String>> + Send;
}

pub async fn deliver_records(
    sink: &impl ArchiveDeliverySink,
    records: &[ArchiveRecord],
) -> Result<(), String> {
    let mut errors = Vec::new();
    for record in records {
        if let Err(error) = deliver_record(sink, record).await {
            record_batch_error(&mut errors, &record.event_id, "archive", &error);
        }
    }
    finish_batch(errors)
}

async fn deliver_record(
    sink: &impl ArchiveDeliverySink,
    record: &ArchiveRecord,
) -> Result<(), String> {
    if sink
        .dead_letter_pending(&record.event_id)
        .await
        .map_err(|error| format!("stage=load_pending_outbox: {error}"))?
    {
        return finish_dead_letter(sink, record).await;
    }
    let key = archive_key(record)?;
    for attempt in 1..=ARCHIVE_DELIVERY_ATTEMPTS {
        if !sink
            .mark_attempt(&record.event_id)
            .await
            .map_err(|error| format!("stage=mark_attempt attempt={attempt}: {error}"))?
        {
            refresh_archived_record(sink, record).await?;
            return Ok(());
        }
        let delivery = sink
            .load_delivery(&record.event_id)
            .await
            .map_err(|error| format!("stage=load_delivery attempt={attempt}: {error}"))?
            .ok_or_else(|| {
                format!("stage=load_delivery attempt={attempt}: security event disappeared")
            })?;
        let expected_status = delivery.status;
        let expected_history = delivery.history.clone();
        let archived_at = unix_now();
        let archived = archived_delivery(delivery, &key, archived_at);
        let body = archive_body(record, &archived)
            .map_err(|error| format!("stage=encode_archive attempt={attempt}: {error}"))?;
        match sink.put_object(&key, body.clone()).await {
            Ok(object_archived_at) => {
                match sink
                    .mark_archived(ArchiveCommit {
                        event_id: &record.event_id,
                        key: &key,
                        occurred_at: record.occurred_at,
                        archived_at: object_archived_at,
                        expected_attempts: archived.attempts,
                        expected_status,
                        expected_history: &expected_history,
                        expected_refresh_lease_until: None,
                    })
                    .await
                {
                    Ok(true) => return Ok(()),
                    Ok(false) if attempt < ARCHIVE_DELIVERY_ATTEMPTS => {}
                    Ok(false) => {
                        return Err(
                            "stage=commit_archive: security event changed during delivery"
                                .to_string(),
                        )
                    }
                    Err(error) => {
                        let status = sink.mark_failed(&record.event_id).await;
                        return Err(match status {
                            Ok(()) => format!("stage=commit_archive attempt={attempt}: {error}"),
                            Err(status_error) => format!(
                                "stage=commit_archive attempt={attempt}: {error}; \
                                 stage=record_failure: {status_error}"
                            ),
                        });
                    }
                }
            }
            Err(error) => {
                if let Err(status_error) = sink.mark_failed(&record.event_id).await {
                    return Err(format!(
                        "stage=write_archive attempt={attempt}: {error}; \
                         stage=record_failure: {status_error}"
                    ));
                }
                if attempt == ARCHIVE_DELIVERY_ATTEMPTS {
                    if sink
                        .mark_dead_letter_pending(&record.event_id)
                        .await
                        .map_err(|error| format!("stage=mark_dead_letter_pending: {error}"))?
                    {
                        finish_dead_letter(sink, record).await?;
                    }
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}

/// Refresh an already archived event after a late fallback duplicate extends
/// its source-delivery history. The durable lease is a fencing token included
/// in the final DynamoDB CAS.
pub async fn refresh_archived_record(
    sink: &impl ArchiveDeliverySink,
    record: &ArchiveRecord,
) -> Result<bool, String> {
    let key = archive_key(record)?;
    let Some(lease_until) = sink.claim_archive_refresh(&record.event_id).await? else {
        return Ok(false);
    };
    let Some(delivery) = sink.load_delivery(&record.event_id).await? else {
        return Err("security event disappeared during archive refresh".to_string());
    };
    if delivery.status != SecurityEventDeliveryStatus::ArchiveRefreshPending {
        return Ok(false);
    }
    let expected_status = delivery.status;
    let expected_history = delivery.history.clone();
    let archived_at = unix_now();
    let archived = archived_delivery(delivery, &key, archived_at);
    let object_archived_at = sink
        .put_object(&key, archive_body(record, &archived)?)
        .await?;
    sink.mark_archived(ArchiveCommit {
        event_id: &record.event_id,
        key: &key,
        occurred_at: record.occurred_at,
        archived_at: object_archived_at,
        expected_attempts: archived.attempts,
        expected_status,
        expected_history: &expected_history,
        expected_refresh_lease_until: Some(lease_until),
    })
    .await
}

/// Retry rows whose incident copy may have expired from SQS. The DynamoDB row
/// remains the durable source until this transition succeeds.
pub async fn redrive_dead_letters(
    sink: &impl ArchiveDeliverySink,
    records: &[ArchiveRecord],
) -> Result<(), String> {
    let mut errors = Vec::new();
    for record in records {
        if let Err(error) = redrive_dead_letter(sink, record).await {
            record_batch_error(&mut errors, &record.event_id, "redrive", &error);
        }
    }
    finish_batch(errors)
}

async fn redrive_dead_letter(
    sink: &impl ArchiveDeliverySink,
    record: &ArchiveRecord,
) -> Result<(), String> {
    if !sink
        .mark_redrive_attempt(&record.event_id)
        .await
        .map_err(|error| format!("stage=mark_redrive_attempt: {error}"))?
    {
        return Ok(());
    }
    let prepared = async {
        let key = archive_key(record)?;
        let delivery = sink
            .load_delivery(&record.event_id)
            .await?
            .ok_or_else(|| "security event disappeared during archive redrive".to_string())?;
        let expected_status = delivery.status;
        let expected_history = delivery.history.clone();
        let archived_at = unix_now();
        let archived = archived_delivery(delivery, &key, archived_at);
        let body = archive_body(record, &archived)?;
        Ok::<_, String>((
            key,
            archived.attempts,
            expected_status,
            expected_history,
            body,
        ))
    }
    .await;
    let (key, expected_attempts, expected_status, expected_history, body) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            sink.mark_redrive_failed(&record.event_id)
                .await
                .map_err(|status_error| {
                    format!(
                        "stage=prepare_redrive: {error}; \
                         stage=restore_dead_letter: {status_error}"
                    )
                })?;
            return Err(format!("stage=prepare_redrive: {error}"));
        }
    };
    match sink.put_object(&key, body).await {
        Ok(object_archived_at) => {
            match sink
                .mark_archived(ArchiveCommit {
                    event_id: &record.event_id,
                    key: &key,
                    occurred_at: record.occurred_at,
                    archived_at: object_archived_at,
                    expected_attempts,
                    expected_status,
                    expected_history: &expected_history,
                    expected_refresh_lease_until: None,
                })
                .await
            {
                Ok(true) => {}
                Ok(false) => sink.mark_redrive_failed(&record.event_id).await?,
                Err(error) => {
                    sink.mark_redrive_failed(&record.event_id)
                        .await
                        .map_err(|status_error| {
                            format!(
                                "stage=commit_redrive: {error}; \
                                 stage=restore_dead_letter: {status_error}"
                            )
                        })?;
                    return Err(format!("stage=commit_redrive: {error}"));
                }
            }
        }
        Err(error) => {
            sink.mark_redrive_failed(&record.event_id)
                .await
                .map_err(|status_error| {
                    format!(
                        "stage=write_redrive: {error}; \
                         stage=restore_dead_letter: {status_error}"
                    )
                })?;
            return Err(format!("stage=write_redrive: {error}"));
        }
    }
    Ok(())
}

pub async fn recover_scheduled_records(
    sink: &impl ArchiveDeliverySink,
    pending_dead_letters: &[ArchiveRecord],
    dead_letters: &[ArchiveRecord],
    archive_refreshes: &[ArchiveRecord],
) -> Result<(), String> {
    let mut errors = Vec::new();
    if let Err(error) = deliver_records(sink, pending_dead_letters).await {
        errors.push(error);
    }
    if let Err(error) = redrive_dead_letters(sink, dead_letters).await {
        errors.push(error);
    }
    for record in archive_refreshes {
        if let Err(error) = refresh_archived_record(sink, record).await {
            record_batch_error(&mut errors, &record.event_id, "archive_refresh", &error);
        }
    }
    finish_batch(errors)
}

pub async fn reconcile_managed_failure_records(
    sink: &impl ArchiveDeliverySink,
    records: &[ArchiveRecord],
) -> Result<(), String> {
    let mut errors = Vec::new();
    for record in records {
        let result = async {
            if sink.mark_dead_letter_pending(&record.event_id).await? {
                finish_dead_letter(sink, record).await?;
            }
            Ok::<(), String>(())
        }
        .await;
        if let Err(error) = result {
            record_batch_error(
                &mut errors,
                &record.event_id,
                "managed_failure_reconciliation",
                &error,
            );
        }
    }
    finish_batch(errors)
}

async fn finish_dead_letter(
    sink: &impl ArchiveDeliverySink,
    record: &ArchiveRecord,
) -> Result<(), String> {
    let delivery = sink
        .load_delivery(&record.event_id)
        .await
        .map_err(|error| format!("stage=load_dead_letter: {error}"))?
        .ok_or_else(|| "stage=load_dead_letter: security event disappeared".to_string())?;
    sink.send_dead_letter(record, &delivery)
        .await
        .map_err(|error| format!("stage=send_dead_letter: {error}"))?;
    sink.mark_dead_lettered(&record.event_id)
        .await
        .map_err(|error| format!("stage=commit_dead_letter: {error}"))
}

fn finish_batch(errors: Vec<String>) -> Result<(), String> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join(" | "))
    }
}

fn record_batch_error(errors: &mut Vec<String>, event_id: &str, phase: &str, error: &str) {
    eprintln!(
        "SECURITY_EVENT_ARCHIVE event_id={event_id} result=failed phase={phase} error={error}"
    );
    errors.push(format!("event_id={event_id} phase={phase} error={error}"));
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn archived_delivery(
    mut delivery: SecurityEventDelivery,
    key: &str,
    archived_at: i64,
) -> SecurityEventDelivery {
    delivery.status = SecurityEventDeliveryStatus::Archived;
    delivery.last_attempt_at = Some(archived_at);
    delivery.archived_at = Some(archived_at);
    delivery.archive_key = Some(key.to_string());
    delivery.history.push(SecurityEventDeliveryAttempt {
        status: SecurityEventDeliveryStatus::Archived,
        occurred_at: archived_at,
    });
    delivery
}

#[derive(Serialize)]
struct ArchivedSecurityEvent<'a> {
    #[serde(flatten)]
    event: &'a SecurityEvent,
    delivery: &'a SecurityEventDelivery,
}

struct StoredArchivedSecurityEvent {
    event: Value,
    delivery: SecurityEventDelivery,
}

fn parse_archive_revision(label: &str, body: &[u8]) -> Result<StoredArchivedSecurityEvent, String> {
    let mut value: Value = serde_json::from_slice(body)
        .map_err(|error| format!("{label} archive object is invalid: {error}"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| format!("{label} archive object is not a JSON object"))?;
    let delivery = object
        .remove("delivery")
        .ok_or_else(|| format!("{label} archive object is missing delivery"))
        .and_then(|delivery| {
            serde_json::from_value(delivery)
                .map_err(|error| format!("{label} archive delivery is invalid: {error}"))
        })?;
    let event = Value::Object(object.clone());
    let typed_event: SecurityEvent = serde_json::from_value(event.clone())
        .map_err(|error| format!("{label} immutable event is invalid: {error}"))?;
    if typed_event.schema_version != SECURITY_EVENT_SCHEMA_VERSION {
        return Err(format!(
            "{label} archive object uses unsupported schema version {}",
            typed_event.schema_version
        ));
    }
    let archive = StoredArchivedSecurityEvent { event, delivery };
    let final_attempt = archive
        .delivery
        .history
        .last()
        .ok_or_else(|| format!("{label} archive object has empty delivery history"))?;
    match archive.delivery.status {
        SecurityEventDeliveryStatus::Archived
            if final_attempt.status == SecurityEventDeliveryStatus::Archived
                && archive.delivery.archived_at == Some(final_attempt.occurred_at) => {}
        SecurityEventDeliveryStatus::DeadLettered
            if final_attempt.status == SecurityEventDeliveryStatus::DeadLettered
                && archive.delivery.dead_lettered_at == Some(final_attempt.occurred_at) => {}
        _ => {
            return Err(format!(
                "{label} archive object does not contain a committed terminal delivery"
            ));
        }
    }
    Ok(archive)
}

fn archive_source_history(
    archive: &StoredArchivedSecurityEvent,
) -> &[SecurityEventDeliveryAttempt] {
    if archive.delivery.status == SecurityEventDeliveryStatus::Archived {
        &archive.delivery.history[..archive.delivery.history.len().saturating_sub(1)]
    } else {
        &archive.delivery.history
    }
}

fn is_history_prefix(
    prefix: &[SecurityEventDeliveryAttempt],
    history: &[SecurityEventDeliveryAttempt],
) -> bool {
    history.starts_with(prefix)
}

pub fn archive_object_archived_at(body: &[u8]) -> Result<i64, String> {
    let archive = parse_archive_revision("archive", body)?;
    if archive.delivery.status != SecurityEventDeliveryStatus::Archived {
        return Err("archive object is not an archived delivery".to_string());
    }
    archive
        .delivery
        .archived_at
        .ok_or_else(|| "archive object is missing archived_at".to_string())
}

pub fn archive_object_event(body: &[u8]) -> Result<SecurityEvent, String> {
    let archive = parse_archive_revision("archive", body)?;
    serde_json::from_value(archive.event)
        .map_err(|error| format!("archive immutable event is invalid: {error}"))
}

pub fn compare_archive_objects(
    existing_body: &[u8],
    proposed_body: &[u8],
) -> Result<ArchiveWriteDecision, String> {
    let existing = parse_archive_revision("existing", existing_body)?;
    let proposed = parse_archive_revision("proposed", proposed_body)?;
    if existing.event != proposed.event {
        return Err("archive object key collides with a different immutable event".to_string());
    }
    if proposed.delivery.status != SecurityEventDeliveryStatus::Archived {
        return Err("proposed archive object is not an archived delivery".to_string());
    }

    let existing_history = archive_source_history(&existing);
    let proposed_history = archive_source_history(&proposed);
    let existing_dominates = existing.delivery.attempts >= proposed.delivery.attempts
        && is_history_prefix(proposed_history, existing_history);
    let proposed_dominates = proposed.delivery.attempts >= existing.delivery.attempts
        && is_history_prefix(existing_history, proposed_history);

    if existing.delivery.status == SecurityEventDeliveryStatus::DeadLettered {
        return if proposed_dominates {
            Ok(ArchiveWriteDecision::ReplaceExisting)
        } else if existing_dominates {
            Err(
                "existing dead-lettered archive source history dominates the proposed revision"
                    .to_string(),
            )
        } else {
            Err("archive object delivery history diverges from the proposed revision".to_string())
        };
    }

    match (existing_dominates, proposed_dominates) {
        (true, _) => Ok(ArchiveWriteDecision::KeepExisting),
        (false, true) => Ok(ArchiveWriteDecision::ReplaceExisting),
        (false, false) => {
            Err("archive object delivery history diverges from the proposed revision".to_string())
        }
    }
}

pub fn archive_body(
    record: &ArchiveRecord,
    delivery: &SecurityEventDelivery,
) -> Result<Vec<u8>, String> {
    let event: SecurityEvent = serde_json::from_str(&record.envelope)
        .map_err(|error| format!("invalid security event envelope: {error}"))?;
    let mut body = serde_json::to_vec(&ArchivedSecurityEvent {
        event: &event,
        delivery,
    })
    .map_err(|error| format!("failed to serialize archived security event: {error}"))?;
    body.push(b'\n');
    Ok(body)
}

pub async fn archive_terminal_ingress<S: ArchiveDeliverySink>(
    sink: &S,
    ingress: &SecurityEventIngress,
) -> Result<(String, bool), String> {
    let record = ArchiveRecord {
        event_id: ingress.event.event_id.clone(),
        tenant_id: ingress.event.tenant_id.clone(),
        occurred_at: ingress.event.occurred_at,
        envelope: serde_json::to_string(&ingress.event)
            .map_err(|error| format!("failed to serialize terminal ingress event: {error}"))?,
    };
    let key = archive_key(&record)?;
    let body = archive_body(&record, &ingress.delivery)?;
    let created = sink.put_object_if_absent(&key, body).await?;
    Ok((key, created))
}

fn stream_string<'a>(image: &'a Value, name: &str) -> Result<&'a str, String> {
    image
        .get(name)
        .and_then(|value| value.get("S"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("stream image missing {name}.S"))
}

fn stream_i64(image: &Value, name: &str) -> Result<i64, String> {
    image
        .get(name)
        .and_then(|value| value.get("N"))
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| format!("stream image has invalid {name}.N"))
}

pub fn validate_record(record: ArchiveRecord) -> Result<ArchiveRecord, String> {
    let envelope: SecurityEvent = serde_json::from_str(&record.envelope)
        .map_err(|error| format!("invalid security event envelope: {error}"))?;
    if envelope.schema_version != SECURITY_EVENT_SCHEMA_VERSION
        || envelope.event_id != record.event_id
        || envelope.tenant_id != record.tenant_id
        || envelope.occurred_at != record.occurred_at
    {
        return Err("security event stream image/envelope mismatch".to_string());
    }
    SecurityEvent::new_at(
        envelope.event_id,
        envelope.occurred_at,
        envelope.tenant_id,
        envelope.actor,
        Some(envelope.subject),
        envelope.category,
        envelope.action,
        envelope.outcome,
        envelope.correlation,
    )
    .map_err(|error| format!("invalid security event envelope: {error}"))?;
    Ok(record)
}

pub fn parse_dynamodb_records(payload: &Value) -> Result<Vec<ArchiveRecord>, String> {
    let records = payload
        .get("Records")
        .and_then(Value::as_array)
        .ok_or_else(|| "DynamoDB payload is missing Records".to_string())?;
    records
        .iter()
        .filter(|record| record.get("eventName").and_then(Value::as_str) == Some("INSERT"))
        .map(|record| {
            let image = record
                .get("dynamodb")
                .and_then(|value| value.get("NewImage"))
                .ok_or_else(|| "DynamoDB INSERT is missing NewImage".to_string())?;
            validate_record(ArchiveRecord {
                event_id: stream_string(image, "event_id")?.to_string(),
                tenant_id: stream_string(image, "tenant_id")?.to_string(),
                occurred_at: stream_i64(image, "occurred_at")?,
                envelope: stream_string(image, "envelope")?.to_string(),
            })
        })
        .collect()
}

pub fn archive_key(record: &ArchiveRecord) -> Result<String, String> {
    let occurred_at = OffsetDateTime::from_unix_timestamp(record.occurred_at)
        .map_err(|error| format!("invalid occurred_at: {error}"))?;
    Ok(format!(
        "security-events/tenant_id={}/year={:04}/month={:02}/day={:02}/{}.json",
        record.tenant_id,
        occurred_at.year(),
        occurred_at.month() as u8,
        occurred_at.day(),
        record.event_id
    ))
}

pub fn parse_ingress_event(body: &str) -> Result<SecurityEventIngress, String> {
    let mut ingress = match serde_json::from_str::<SecurityEventIngress>(body) {
        Ok(ingress) => ingress,
        Err(_) => {
            let event: SecurityEvent = serde_json::from_str(body)
                .map_err(|error| format!("invalid security event ingress payload: {error}"))?;
            SecurityEventIngress::new(event)
        }
    };
    let event = ingress.event;
    if event.schema_version != SECURITY_EVENT_SCHEMA_VERSION {
        return Err(format!(
            "unsupported security event schema version {}",
            event.schema_version
        ));
    }
    ingress.event = SecurityEvent::new_at(
        event.event_id,
        event.occurred_at,
        event.tenant_id,
        event.actor,
        Some(event.subject),
        event.category,
        event.action,
        event.outcome,
        event.correlation,
    )
    .map_err(|error| format!("invalid security event ingress payload: {error}"))?;
    Ok(ingress)
}

pub fn parse_failed_stream_invocation(payload: &Value) -> Result<Vec<ArchiveRecord>, String> {
    let request_payload = payload
        .get("requestPayload")
        .or_else(|| payload.get("payload"))
        .ok_or_else(|| "failed stream invocation is missing payload".to_string())?;
    match request_payload {
        Value::String(encoded) => {
            let decoded: Value = serde_json::from_str(encoded)
                .map_err(|error| format!("invalid failed stream payload: {error}"))?;
            parse_dynamodb_records(&decoded)
        }
        value => parse_dynamodb_records(value),
    }
}

pub fn archive_dead_letter_body(
    record: &ArchiveRecord,
    delivery: &SecurityEventDelivery,
) -> Result<String, String> {
    let event: SecurityEvent = serde_json::from_str(&record.envelope)
        .map_err(|error| format!("invalid security event envelope: {error}"))?;
    serde_json::to_string(&ArchivedSecurityEvent {
        event: &event,
        delivery,
    })
    .map_err(|error| format!("failed to serialize archive dead letter: {error}"))
}

#[cfg(test)]
#[path = "security_event_archive_tests.rs"]
mod tests;
