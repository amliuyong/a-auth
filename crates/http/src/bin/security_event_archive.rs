#[cfg(all(feature = "lambda", feature = "aws"))]
use agent_auth_http::adapters::aws::DynamoSecurityEventStore;
#[cfg(all(feature = "lambda", feature = "aws"))]
use agent_auth_http::ports::StoreError;
#[cfg(all(feature = "lambda", feature = "aws"))]
use agent_auth_http::security_event::SecurityEventStore;
#[cfg(all(feature = "lambda", feature = "aws"))]
use agent_auth_http::security_event::{
    SecurityEventDeliveryAttempt, SecurityEventDeliveryStatus, SECURITY_EVENT_HOT_RETENTION_DAYS,
    SECURITY_EVENT_LONG_RETENTION_DAYS,
};
#[cfg(all(feature = "lambda", feature = "aws"))]
use agent_auth_http::security_event_archive::{
    archive_dead_letter_body, archive_object_archived_at, archive_terminal_ingress,
    compare_archive_objects, deliver_records, parse_dynamodb_records,
    parse_failed_stream_invocation, parse_ingress_event, parse_s3_notification_records,
    prepare_ingress_receive, reconcile_managed_failure_records, recover_scheduled_records,
    refresh_archived_record, validate_record, ArchiveCommit, ArchiveDeliverySink, ArchiveRecord,
    ArchiveWriteDecision, INGRESS_DELIVERY_ATTEMPTS,
};
#[cfg(all(feature = "lambda", feature = "aws"))]
use aws_sdk_dynamodb::error::ProvideErrorMetadata;
#[cfg(all(feature = "lambda", feature = "aws"))]
use aws_sdk_dynamodb::types::AttributeValue;
#[cfg(all(feature = "lambda", feature = "aws"))]
use lambda_runtime::{service_fn, Error, LambdaEvent};

#[cfg(all(feature = "lambda", feature = "aws"))]
const REDRIVE_LEASE_SECS: i64 = 10 * 60;
#[cfg(all(feature = "lambda", feature = "aws"))]
const ARCHIVE_REFRESH_LEASE_SECS: i64 = 60;
#[cfg(all(feature = "lambda", feature = "aws"))]
const ARCHIVE_OBJECT_CAS_ATTEMPTS: usize = 4;
#[cfg(all(feature = "lambda", feature = "aws"))]
const ARCHIVE_COMMIT_CONDITION: &str =
    "attribute_exists(event_id) AND delivery_status = :expected_status \
     AND delivery_attempts = :expected_attempts \
     AND delivery_history = :expected_history";
#[cfg(all(feature = "lambda", feature = "aws"))]
const REDRIVE_ATTEMPT_UPDATE_EXPRESSION: &str =
    "SET last_delivery_at = :now, redrive_lease_until = :lease_until \
     ADD delivery_attempts :one";
#[cfg(all(feature = "lambda", feature = "aws"))]
const REDRIVE_FAILED_UPDATE_EXPRESSION: &str =
    "SET last_delivery_at = :now REMOVE redrive_lease_until";

#[cfg(all(feature = "lambda", feature = "aws"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IngressStoreFailureAction {
    Retry,
    ArchiveTerminal,
    Quarantine,
}

#[cfg(all(feature = "lambda", feature = "aws"))]
fn ingress_store_failure_action(
    error: &StoreError,
    ingress_attempts: u32,
) -> IngressStoreFailureAction {
    match error {
        StoreError::Permanent(_) => IngressStoreFailureAction::Quarantine,
        StoreError::Transient(_) if ingress_attempts < INGRESS_DELIVERY_ATTEMPTS => {
            IngressStoreFailureAction::Retry
        }
        StoreError::Transient(_) => IngressStoreFailureAction::ArchiveTerminal,
    }
}

#[cfg(all(feature = "lambda", feature = "aws"))]
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(all(feature = "lambda", feature = "aws"))]
fn history_entry(status: SecurityEventDeliveryStatus, occurred_at: i64) -> AttributeValue {
    history_entries(&[status], occurred_at)
}

#[cfg(all(feature = "lambda", feature = "aws"))]
fn history_entries(statuses: &[SecurityEventDeliveryStatus], occurred_at: i64) -> AttributeValue {
    AttributeValue::L(
        statuses
            .iter()
            .map(|status| {
                AttributeValue::M(
                    [
                        (
                            "status".to_string(),
                            AttributeValue::S(status.as_str().to_string()),
                        ),
                        (
                            "occurred_at".to_string(),
                            AttributeValue::N(occurred_at.to_string()),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                )
            })
            .collect(),
    )
}

#[cfg(all(feature = "lambda", feature = "aws"))]
fn delivery_history_value(history: &[SecurityEventDeliveryAttempt]) -> AttributeValue {
    AttributeValue::L(
        history
            .iter()
            .map(|attempt| {
                AttributeValue::M(
                    [
                        (
                            "status".to_string(),
                            AttributeValue::S(attempt.status.as_str().to_string()),
                        ),
                        (
                            "occurred_at".to_string(),
                            AttributeValue::N(attempt.occurred_at.to_string()),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                )
            })
            .collect(),
    )
}

#[cfg(all(feature = "lambda", feature = "aws"))]
fn status_value(status: SecurityEventDeliveryStatus) -> AttributeValue {
    AttributeValue::S(status.as_str().to_string())
}

#[cfg(all(feature = "lambda", feature = "aws"))]
fn non_terminal_delivery_update(
    request: aws_sdk_dynamodb::operation::update_item::builders::UpdateItemFluentBuilder,
) -> aws_sdk_dynamodb::operation::update_item::builders::UpdateItemFluentBuilder {
    request
        .condition_expression(
            "attribute_exists(event_id) AND delivery_status <> :archived \
             AND delivery_status <> :dead_lettered \
             AND delivery_status <> :dead_letter_pending \
             AND delivery_status <> :archive_refresh_pending",
        )
        .expression_attribute_values(
            ":archived",
            status_value(SecurityEventDeliveryStatus::Archived),
        )
        .expression_attribute_values(
            ":dead_lettered",
            status_value(SecurityEventDeliveryStatus::DeadLettered),
        )
        .expression_attribute_values(
            ":dead_letter_pending",
            status_value(SecurityEventDeliveryStatus::DeadLetterPending),
        )
        .expression_attribute_values(
            ":archive_refresh_pending",
            status_value(SecurityEventDeliveryStatus::ArchiveRefreshPending),
        )
}

#[cfg(all(feature = "lambda", feature = "aws"))]
#[derive(Clone)]
struct AwsArchiveDeliverySink<'a> {
    db: &'a aws_sdk_dynamodb::Client,
    s3: &'a aws_sdk_s3::Client,
    sqs: &'a aws_sdk_sqs::Client,
    table: &'a str,
    bucket: &'a str,
    dead_letter_queue_url: &'a str,
}

#[cfg(all(feature = "lambda", feature = "aws"))]
impl ArchiveDeliverySink for AwsArchiveDeliverySink<'_> {
    async fn mark_attempt(&self, event_id: &str) -> Result<bool, String> {
        let now = unix_now();
        let result = non_terminal_delivery_update(
            self.db
                .update_item()
                .table_name(self.table)
                .key("event_id", AttributeValue::S(event_id.to_string()))
                .update_expression(
                    "SET delivery_status = :status, last_delivery_at = :now, \
                 delivery_history = list_append(if_not_exists(delivery_history, :empty), :history) \
                 ADD delivery_attempts :one",
                ),
        )
        .expression_attribute_values(
            ":status",
            status_value(SecurityEventDeliveryStatus::Retrying),
        )
        .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
        .expression_attribute_values(":empty", AttributeValue::L(Vec::new()))
        .expression_attribute_values(
            ":history",
            history_entry(SecurityEventDeliveryStatus::Retrying, now),
        )
        .expression_attribute_values(":one", AttributeValue::N("1".to_string()))
        .send()
        .await;
        match result {
            Ok(_) => {
                eprintln!("SECURITY_EVENT_ARCHIVE event_id={event_id} result=retrying");
                Ok(true)
            }
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                Ok(false)
            }
            Err(error) => Err(error.to_string()),
        }
    }

    async fn put_object(&self, key: &str, body: Vec<u8>) -> Result<i64, String> {
        let proposed_archived_at = archive_object_archived_at(&body)?;
        for _ in 0..ARCHIVE_OBJECT_CAS_ATTEMPTS {
            let create = self
                .s3
                .put_object()
                .bucket(self.bucket)
                .key(key)
                .content_type("application/x-ndjson")
                .if_none_match("*")
                .body(aws_sdk_s3::primitives::ByteStream::from(body.clone()))
                .send()
                .await;
            match create {
                Ok(_) => return Ok(proposed_archived_at),
                Err(error)
                    if error.raw_response().is_some_and(|response| {
                        matches!(response.status().as_u16(), 409 | 412)
                    }) => {}
                Err(error) => return Err(error.to_string()),
            }

            let existing = self
                .s3
                .get_object()
                .bucket(self.bucket)
                .key(key)
                .send()
                .await
                .map_err(|error| error.to_string())?;
            let etag = existing
                .e_tag()
                .map(str::to_string)
                .ok_or_else(|| "existing archive object is missing its ETag".to_string())?;
            let existing_body = existing
                .body
                .collect()
                .await
                .map_err(|error| error.to_string())?
                .into_bytes();
            match compare_archive_objects(&existing_body, &body)? {
                ArchiveWriteDecision::KeepExisting => {
                    return archive_object_archived_at(&existing_body);
                }
                ArchiveWriteDecision::ReplaceExisting => {}
            }

            let replace = self
                .s3
                .put_object()
                .bucket(self.bucket)
                .key(key)
                .content_type("application/x-ndjson")
                .if_match(etag)
                .body(aws_sdk_s3::primitives::ByteStream::from(body.clone()))
                .send()
                .await;
            match replace {
                Ok(_) => return Ok(proposed_archived_at),
                Err(error)
                    if error.raw_response().is_some_and(|response| {
                        matches!(response.status().as_u16(), 409 | 412)
                    }) => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        Err("archive object changed during every conditional write attempt".to_string())
    }

    async fn put_object_if_absent(&self, key: &str, body: Vec<u8>) -> Result<bool, String> {
        let result = self
            .s3
            .put_object()
            .bucket(self.bucket)
            .key(key)
            .content_type("application/x-ndjson")
            .if_none_match("*")
            .body(aws_sdk_s3::primitives::ByteStream::from(body))
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .raw_response()
                    .is_some_and(|response| response.status().as_u16() == 412) =>
            {
                Ok(false)
            }
            Err(error) => Err(error.to_string()),
        }
    }

    async fn claim_archive_refresh(&self, event_id: &str) -> Result<Option<i64>, String> {
        let now = unix_now();
        let lease_until = now.saturating_add(ARCHIVE_REFRESH_LEASE_SECS);
        let result = self
            .db
            .update_item()
            .table_name(self.table)
            .key("event_id", AttributeValue::S(event_id.to_string()))
            .update_expression("SET archive_refresh_lease_until = :lease_until")
            .condition_expression(
                "attribute_exists(event_id) AND delivery_status = :refresh_pending \
                 AND (attribute_not_exists(archive_refresh_lease_until) \
                 OR archive_refresh_lease_until <= :now)",
            )
            .expression_attribute_values(
                ":refresh_pending",
                status_value(SecurityEventDeliveryStatus::ArchiveRefreshPending),
            )
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .expression_attribute_values(":lease_until", AttributeValue::N(lease_until.to_string()))
            .send()
            .await;
        match result {
            Ok(_) => Ok(Some(lease_until)),
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                Ok(None)
            }
            Err(error) => Err(error.to_string()),
        }
    }

    async fn load_delivery(
        &self,
        event_id: &str,
    ) -> Result<Option<agent_auth_http::security_event::SecurityEventDelivery>, String> {
        DynamoSecurityEventStore::new(self.db.clone(), self.table)
            .get_delivery(event_id)
            .await
            .map_err(|error| format!("{error:?}"))
    }

    async fn mark_failed(&self, event_id: &str) -> Result<(), String> {
        let now = unix_now();
        let result = non_terminal_delivery_update(
            self.db
                .update_item()
                .table_name(self.table)
                .key("event_id", AttributeValue::S(event_id.to_string()))
                .update_expression(
                    "SET delivery_status = :status, last_delivery_at = :now, \
                 delivery_history = list_append(if_not_exists(delivery_history, :empty), :history)",
                ),
        )
        .expression_attribute_values(":status", status_value(SecurityEventDeliveryStatus::Failed))
        .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
        .expression_attribute_values(":empty", AttributeValue::L(Vec::new()))
        .expression_attribute_values(
            ":history",
            history_entry(SecurityEventDeliveryStatus::Failed, now),
        )
        .send()
        .await;
        match result {
            Ok(_) => {
                eprintln!("SECURITY_EVENT_ARCHIVE event_id={event_id} result=attempt_failed");
                Ok(())
            }
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                Ok(())
            }
            Err(error) => Err(error.to_string()),
        }
    }

    async fn dead_letter_pending(&self, event_id: &str) -> Result<bool, String> {
        let response = self
            .db
            .get_item()
            .table_name(self.table)
            .key("event_id", AttributeValue::S(event_id.to_string()))
            .projection_expression("delivery_status")
            .consistent_read(true)
            .send()
            .await
            .map_err(|error| error.to_string())?;
        Ok(response
            .item
            .as_ref()
            .and_then(|item| item.get("delivery_status"))
            .and_then(|value| value.as_s().ok())
            .is_some_and(|status| {
                status == SecurityEventDeliveryStatus::DeadLetterPending.as_str()
            }))
    }

    async fn mark_dead_letter_pending(&self, event_id: &str) -> Result<bool, String> {
        let now = unix_now();
        let expires_at = now
            .checked_add(i64::from(SECURITY_EVENT_LONG_RETENTION_DAYS) * 86_400)
            .ok_or_else(|| "security event long retention timestamp overflow".to_string())?;
        let result = self
            .db
            .update_item()
            .table_name(self.table)
            .key("event_id", AttributeValue::S(event_id.to_string()))
            .update_expression(
                "SET delivery_status = :status, last_delivery_at = :now, \
                 expires_at = :expires_at, \
                 delivery_history = list_append(if_not_exists(delivery_history, :empty), :history)",
            )
            .condition_expression(
                "attribute_exists(event_id) AND delivery_status <> :archived \
                 AND delivery_status <> :dead_lettered",
            )
            .expression_attribute_values(
                ":status",
                status_value(SecurityEventDeliveryStatus::DeadLetterPending),
            )
            .expression_attribute_values(
                ":archived",
                status_value(SecurityEventDeliveryStatus::Archived),
            )
            .expression_attribute_values(
                ":dead_lettered",
                status_value(SecurityEventDeliveryStatus::DeadLettered),
            )
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .expression_attribute_values(":expires_at", AttributeValue::N(expires_at.to_string()))
            .expression_attribute_values(":empty", AttributeValue::L(Vec::new()))
            .expression_attribute_values(
                ":history",
                history_entry(SecurityEventDeliveryStatus::DeadLetterPending, now),
            )
            .send()
            .await;
        match result {
            Ok(_) => {
                eprintln!("SECURITY_EVENT_ARCHIVE event_id={event_id} result=dead_letter_pending");
                Ok(true)
            }
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                Ok(false)
            }
            Err(error) => Err(error.to_string()),
        }
    }

    async fn send_dead_letter(
        &self,
        record: &agent_auth_http::security_event_archive::ArchiveRecord,
        delivery: &agent_auth_http::security_event::SecurityEventDelivery,
    ) -> Result<(), String> {
        self.sqs
            .send_message()
            .queue_url(self.dead_letter_queue_url)
            .message_body(archive_dead_letter_body(record, delivery)?)
            .message_group_id(&record.tenant_id)
            .message_deduplication_id(&record.event_id)
            .send()
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    async fn mark_dead_lettered(&self, event_id: &str) -> Result<(), String> {
        let now = unix_now();
        let expires_at = now
            .checked_add(i64::from(SECURITY_EVENT_LONG_RETENTION_DAYS) * 86_400)
            .ok_or_else(|| "security event long retention timestamp overflow".to_string())?;
        let result = self
            .db
            .update_item()
            .table_name(self.table)
            .key("event_id", AttributeValue::S(event_id.to_string()))
            .update_expression(
                "SET delivery_status = :status, dead_lettered_at = :now, \
                 last_delivery_at = :now, \
                 expires_at = :expires_at, \
                 delivery_history = list_append(if_not_exists(delivery_history, :empty), :history)",
            )
            .condition_expression("attribute_exists(event_id) AND delivery_status = :pending")
            .expression_attribute_values(
                ":status",
                status_value(SecurityEventDeliveryStatus::DeadLettered),
            )
            .expression_attribute_values(
                ":pending",
                status_value(SecurityEventDeliveryStatus::DeadLetterPending),
            )
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .expression_attribute_values(":expires_at", AttributeValue::N(expires_at.to_string()))
            .expression_attribute_values(":empty", AttributeValue::L(Vec::new()))
            .expression_attribute_values(
                ":history",
                history_entry(SecurityEventDeliveryStatus::DeadLettered, now),
            )
            .send()
            .await;
        match result {
            Ok(_) => {
                eprintln!("SECURITY_EVENT_ARCHIVE event_id={event_id} result=dead_lettered");
                Ok(())
            }
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                Ok(())
            }
            Err(error) => Err(error.to_string()),
        }
    }

    async fn mark_archived(&self, commit: ArchiveCommit<'_>) -> Result<bool, String> {
        let expires_at = commit
            .occurred_at
            .checked_add(i64::from(SECURITY_EVENT_HOT_RETENTION_DAYS) * 86_400)
            .ok_or_else(|| "security event hot retention timestamp overflow".to_string())?;
        let mut request = self
            .db
            .update_item()
            .table_name(self.table)
            .key("event_id", AttributeValue::S(commit.event_id.to_string()))
            .update_expression(
                "SET delivery_status = :status, archive_key = :key, archived_at = :now, \
                 last_delivery_at = :now, \
                 expires_at = :expires_at, \
                 delivery_history = list_append(if_not_exists(delivery_history, :empty), :history) \
                 REMOVE redrive_lease_until, archive_refresh_lease_until",
            )
            .condition_expression(ARCHIVE_COMMIT_CONDITION)
            .expression_attribute_values(
                ":status",
                status_value(SecurityEventDeliveryStatus::Archived),
            )
            .expression_attribute_values(":expected_status", status_value(commit.expected_status))
            .expression_attribute_values(":key", AttributeValue::S(commit.key.to_string()))
            .expression_attribute_values(":now", AttributeValue::N(commit.archived_at.to_string()))
            .expression_attribute_values(
                ":expected_attempts",
                AttributeValue::N(commit.expected_attempts.to_string()),
            )
            .expression_attribute_values(
                ":expected_history",
                delivery_history_value(commit.expected_history),
            )
            .expression_attribute_values(":expires_at", AttributeValue::N(expires_at.to_string()))
            .expression_attribute_values(":empty", AttributeValue::L(Vec::new()))
            .expression_attribute_values(
                ":history",
                history_entry(SecurityEventDeliveryStatus::Archived, commit.archived_at),
            );
        if let Some(lease_until) = commit.expected_refresh_lease_until {
            request = request
                .condition_expression(
                    "attribute_exists(event_id) AND delivery_status = :expected_status \
                     AND delivery_attempts = :expected_attempts \
                     AND delivery_history = :expected_history \
                     AND archive_refresh_lease_until = :expected_refresh_lease_until",
                )
                .expression_attribute_values(
                    ":expected_refresh_lease_until",
                    AttributeValue::N(lease_until.to_string()),
                );
        }
        let result = request.send().await;
        match result {
            Ok(_) => {
                eprintln!(
                    "SECURITY_EVENT_ARCHIVE event_id={} result=success key={}",
                    commit.event_id, commit.key
                );
                Ok(true)
            }
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                Ok(false)
            }
            Err(error) => Err(error.to_string()),
        }
    }

    async fn mark_redrive_attempt(&self, event_id: &str) -> Result<bool, String> {
        let now = unix_now();
        let lease_until = now.saturating_add(REDRIVE_LEASE_SECS);
        let result = self
            .db
            .update_item()
            .table_name(self.table)
            .key("event_id", AttributeValue::S(event_id.to_string()))
            .update_expression(REDRIVE_ATTEMPT_UPDATE_EXPRESSION)
            .condition_expression(
                "attribute_exists(event_id) AND delivery_status = :dead_lettered \
                 AND (attribute_not_exists(redrive_lease_until) OR redrive_lease_until <= :now)",
            )
            .expression_attribute_values(
                ":dead_lettered",
                AttributeValue::S(
                    SecurityEventDeliveryStatus::DeadLettered
                        .as_str()
                        .to_string(),
                ),
            )
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .expression_attribute_values(":lease_until", AttributeValue::N(lease_until.to_string()))
            .expression_attribute_values(":one", AttributeValue::N("1".to_string()))
            .send()
            .await;
        match result {
            Ok(_) => {
                eprintln!("SECURITY_EVENT_ARCHIVE event_id={event_id} result=redriving");
                Ok(true)
            }
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                Ok(false)
            }
            Err(error) => Err(error.to_string()),
        }
    }

    async fn mark_redrive_failed(&self, event_id: &str) -> Result<(), String> {
        let now = unix_now();
        self.db
            .update_item()
            .table_name(self.table)
            .key("event_id", AttributeValue::S(event_id.to_string()))
            .update_expression(REDRIVE_FAILED_UPDATE_EXPRESSION)
            .condition_expression("attribute_exists(event_id) AND delivery_status = :dead_lettered")
            .expression_attribute_values(
                ":dead_lettered",
                AttributeValue::S(
                    SecurityEventDeliveryStatus::DeadLettered
                        .as_str()
                        .to_string(),
                ),
            )
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .send()
            .await
            .map_err(|error| error.to_string())?;
        eprintln!("SECURITY_EVENT_ARCHIVE event_id={event_id} result=redrive_failed");
        Ok(())
    }
}

#[cfg(all(feature = "lambda", feature = "aws"))]
async fn send_ingress_message(
    sqs: &aws_sdk_sqs::Client,
    queue_url: &str,
    ingress: &agent_auth_http::security_event::SecurityEventIngress,
    source_message_id: &str,
) -> Result<(), Error> {
    let body = serde_json::to_string(ingress)?;
    sqs.send_message()
        .queue_url(queue_url)
        .message_body(body)
        .message_group_id(&ingress.event.tenant_id)
        .message_deduplication_id(source_message_id)
        .send()
        .await
        .map_err(|error| format!("security event ingress enqueue failed: {error}"))?;
    Ok(())
}

#[cfg(all(feature = "lambda", feature = "aws"))]
async fn persist_ingress_failure(
    s3: &aws_sdk_s3::Client,
    bucket: &str,
    key_id: &str,
    body: &str,
) -> Result<(), Error> {
    let key = format!("security-event-ingress-failures/{key_id}.json");
    s3.put_object()
        .bucket(bucket)
        .key(&key)
        .content_type("application/json")
        .body(aws_sdk_s3::primitives::ByteStream::from(
            body.as_bytes().to_vec(),
        ))
        .send()
        .await
        .map_err(|error| format!("failed to retain security event ingress payload: {error}"))?;
    eprintln!("SECURITY_EVENT_INGRESS message_id={key_id} result=failure_artifact key={key}");
    Ok(())
}

#[cfg(all(feature = "lambda", feature = "aws"))]
fn parse_delivery_record(
    item: &std::collections::HashMap<String, AttributeValue>,
) -> Result<ArchiveRecord, String> {
    let string = |name: &str| {
        item.get(name)
            .and_then(|value| value.as_s().ok())
            .cloned()
            .ok_or_else(|| format!("delivery row is missing {name}"))
    };
    let occurred_at = item
        .get("occurred_at")
        .and_then(|value| value.as_n().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| "delivery row has invalid occurred_at".to_string())?;
    validate_record(ArchiveRecord {
        event_id: string("event_id")?,
        tenant_id: string("tenant_id")?,
        occurred_at,
        envelope: string("envelope")?,
    })
}

#[cfg(all(feature = "lambda", feature = "aws"))]
#[derive(Default)]
struct DeliveryRecordQuery {
    records: Vec<ArchiveRecord>,
    errors: Vec<String>,
}

#[cfg(all(feature = "lambda", feature = "aws"))]
#[derive(Default)]
struct DeliveryStatusRecovery {
    processed: usize,
    errors: Vec<String>,
}

#[cfg(all(feature = "lambda", feature = "aws"))]
fn append_delivery_items(
    status: SecurityEventDeliveryStatus,
    items: &[std::collections::HashMap<String, AttributeValue>],
    result: &mut DeliveryRecordQuery,
) {
    for item in items {
        match parse_delivery_record(item) {
            Ok(record) => result.records.push(record),
            Err(error) => {
                let event_id = item
                    .get("event_id")
                    .and_then(|value| value.as_s().ok())
                    .map_or("unknown", String::as_str);
                let error = format!(
                    "stage=validate_delivery_row status={} event_id={event_id} error={error}",
                    status.as_str()
                );
                eprintln!("SECURITY_EVENT_ARCHIVE result=invalid_scheduled_row {error}");
                result.errors.push(error);
            }
        }
    }
}

#[cfg(all(feature = "lambda", feature = "aws"))]
async fn recover_delivery_status(
    db: &aws_sdk_dynamodb::Client,
    table: &str,
    status: SecurityEventDeliveryStatus,
    sink: &AwsArchiveDeliverySink<'_>,
) -> DeliveryStatusRecovery {
    let through = unix_now();
    let mut result = DeliveryStatusRecovery::default();
    let mut start_key = None;
    loop {
        let response = db
            .query()
            .table_name(table)
            .index_name("delivery_status-index")
            .key_condition_expression("delivery_status = :status AND last_delivery_at <= :through")
            .expression_attribute_values(":status", AttributeValue::S(status.as_str().to_string()))
            .expression_attribute_values(":through", AttributeValue::N(through.to_string()))
            .scan_index_forward(true)
            .limit(100)
            .set_exclusive_start_key(start_key)
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                result.errors.push(format!(
                    "stage=query_delivery_status status={} error={error}",
                    status.as_str()
                ));
                break;
            }
        };
        let next_key = response
            .last_evaluated_key()
            .filter(|key| !key.is_empty())
            .cloned();
        let mut page = DeliveryRecordQuery::default();
        append_delivery_items(status, response.items(), &mut page);
        result.processed = result.processed.saturating_add(page.records.len());
        result.errors.append(&mut page.errors);
        let recovery = match status {
            SecurityEventDeliveryStatus::DeadLetterPending => {
                recover_scheduled_records(sink, &page.records, &[], &[]).await
            }
            SecurityEventDeliveryStatus::DeadLettered => {
                recover_scheduled_records(sink, &[], &page.records, &[]).await
            }
            SecurityEventDeliveryStatus::ArchiveRefreshPending => {
                recover_scheduled_records(sink, &[], &[], &page.records).await
            }
            _ => Err(format!(
                "unsupported scheduled delivery status {}",
                status.as_str()
            )),
        };
        if let Err(error) = recovery {
            result.errors.push(format!(
                "stage=recover_delivery_status status={} error={error}",
                status.as_str()
            ));
        }
        start_key = next_key;
        if start_key.is_none() {
            break;
        }
    }
    result
}

#[cfg(all(feature = "lambda", feature = "aws"))]
#[derive(Clone)]
struct ArchiveRuntime {
    db: aws_sdk_dynamodb::Client,
    s3: aws_sdk_s3::Client,
    sqs: aws_sdk_sqs::Client,
    table: String,
    bucket: String,
    dead_letter_queue_url: String,
    ingress_dead_letter_queue_url: String,
    failure_bucket: String,
}

#[cfg(all(feature = "lambda", feature = "aws"))]
async fn reconcile_failed_stream_records(
    sink: &AwsArchiveDeliverySink<'_>,
    s3: &aws_sdk_s3::Client,
    records: &[serde_json::Value],
) -> Result<(), Error> {
    let mut errors = Vec::new();
    for (index, record) in records.iter().enumerate() {
        let result = async {
            let failure_bucket = record
                .pointer("/s3/bucket/name")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "S3 failure record is missing bucket name".to_string())?;
            let encoded_key = record
                .pointer("/s3/object/key")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "S3 failure record is missing object key".to_string())?;
            let encoded_key = encoded_key.replace('+', " ");
            let key = percent_encoding::percent_decode_str(&encoded_key)
                .decode_utf8()
                .map_err(|error| format!("invalid S3 failure object key: {error}"))?;
            let object = s3
                .get_object()
                .bucket(failure_bucket)
                .key(key.as_ref())
                .send()
                .await
                .map_err(|error| error.to_string())?;
            let body = object
                .body
                .collect()
                .await
                .map_err(|error| error.to_string())?
                .into_bytes();
            let failure: serde_json::Value =
                serde_json::from_slice(&body).map_err(|error| error.to_string())?;
            let archived = parse_failed_stream_invocation(&failure)?;
            reconcile_managed_failure_records(sink, &archived).await
        }
        .await;
        if let Err(error) = result {
            errors.push(format!(
                "stage=reconcile_failed_stream_record notification_index={index} error={error}"
            ));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join(" | ").into())
    }
}

#[cfg(all(feature = "lambda", feature = "aws"))]
async fn handler(
    event: LambdaEvent<serde_json::Value>,
    runtime: ArchiveRuntime,
) -> Result<(), Error> {
    let ArchiveRuntime {
        db,
        s3,
        sqs,
        table,
        bucket,
        dead_letter_queue_url,
        ingress_dead_letter_queue_url,
        failure_bucket,
    } = runtime;
    let payload = event.payload;
    let sink = AwsArchiveDeliverySink {
        db: &db,
        s3: &s3,
        sqs: &sqs,
        table: &table,
        bucket: &bucket,
        dead_letter_queue_url: &dead_letter_queue_url,
    };
    if payload.get("source").and_then(serde_json::Value::as_str) == Some("aws.events") {
        let (pending_dead_letters, dead_letters, refreshes) = tokio::join!(
            recover_delivery_status(
                &db,
                &table,
                SecurityEventDeliveryStatus::DeadLetterPending,
                &sink
            ),
            recover_delivery_status(
                &db,
                &table,
                SecurityEventDeliveryStatus::DeadLettered,
                &sink
            ),
            recover_delivery_status(
                &db,
                &table,
                SecurityEventDeliveryStatus::ArchiveRefreshPending,
                &sink
            ),
        );
        let mut errors = pending_dead_letters.errors;
        errors.extend(dead_letters.errors);
        errors.extend(refreshes.errors);
        eprintln!(
            "SECURITY_EVENT_ARCHIVE result=scheduled_redrive_complete \
             pending_dead_letters={} dead_letters={} archive_refreshes={}",
            pending_dead_letters.processed, dead_letters.processed, refreshes.processed
        );
        if !errors.is_empty() {
            return Err(errors.join("; ").into());
        }
        return Ok(());
    }
    let records = payload
        .get("Records")
        .and_then(serde_json::Value::as_array)
        .ok_or("event payload is missing Records")?;
    let event_source = records.first().and_then(|record| {
        record
            .get("eventSource")
            .or_else(|| record.get("EventSource"))
            .and_then(serde_json::Value::as_str)
    });
    if event_source == Some("aws:sqs") {
        let store = DynamoSecurityEventStore::new(db.clone(), table.clone());
        for record in records {
            let message_id = record
                .get("messageId")
                .and_then(serde_json::Value::as_str)
                .ok_or("SQS ingress record is missing messageId")?;
            let body = record
                .get("body")
                .and_then(serde_json::Value::as_str)
                .ok_or("SQS ingress record is missing body")?;
            if let Some(notification_records) = parse_s3_notification_records(body)? {
                reconcile_failed_stream_records(&sink, &s3, &notification_records).await?;
                eprintln!(
                    "SECURITY_EVENT_ARCHIVE result=managed_failure_notification \
                     message_id={message_id}"
                );
                continue;
            }
            let mut ingress = match parse_ingress_event(body) {
                Ok(ingress) => ingress,
                Err(error) => {
                    // A deployment-incompatible or corrupt message cannot enter
                    // the typed retry loop. Preserve its exact SQS body in the
                    // terminal FIFO queue before acknowledging the source copy.
                    persist_ingress_failure(&s3, &failure_bucket, message_id, body).await?;
                    sqs.send_message()
                        .queue_url(&ingress_dead_letter_queue_url)
                        .message_body(body)
                        .message_group_id("invalid-ingress")
                        .message_deduplication_id(message_id)
                        .send()
                        .await
                        .map_err(|send_error| {
                            format!(
                                "invalid security event ingress could not be dead-lettered: \
                                 parse={error}; send={send_error}"
                            )
                        })?;
                    eprintln!(
                        "SECURITY_EVENT_INGRESS event_id=unvalidated result=dead_lettered \
                         attempt=1 error={error}"
                    );
                    continue;
                }
            };
            let receive_count = record
                .pointer("/attributes/ApproximateReceiveCount")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| value.parse::<u32>().ok())
                .ok_or("SQS ingress record has invalid ApproximateReceiveCount")?;
            prepare_ingress_receive(&mut ingress, receive_count, unix_now())?;
            if ingress.ingress_attempts > 1 {
                eprintln!(
                    "SECURITY_EVENT_INGRESS event_id={} result=retrying attempt={}",
                    ingress.event.event_id, ingress.ingress_attempts
                );
            }
            let inserted = match store
                .put_with_delivery(&ingress.event, &ingress.delivery)
                .await
            {
                Ok(inserted) => inserted,
                Err(error) => {
                    ingress.delivery.record(
                        agent_auth_http::security_event::SecurityEventDeliveryStatus::Failed,
                        unix_now(),
                    );
                    let failure_action =
                        ingress_store_failure_action(&error, ingress.ingress_attempts);
                    eprintln!(
                        "SECURITY_EVENT_INGRESS event_id={} result=failed attempt={} error={error:?}",
                        ingress.event.event_id, ingress.ingress_attempts
                    );
                    if failure_action == IngressStoreFailureAction::Retry {
                        return Err(format!(
                            "security event ingress retry required: event_id={} attempt={} error={error:?}",
                            ingress.event.event_id, ingress.ingress_attempts
                        )
                        .into());
                    }
                    ingress.delivery.record(
                        agent_auth_http::security_event::SecurityEventDeliveryStatus::DeadLettered,
                        unix_now(),
                    );
                    let retained = serde_json::to_string(&ingress)?;
                    persist_ingress_failure(&s3, &failure_bucket, message_id, &retained).await?;
                    if failure_action == IngressStoreFailureAction::ArchiveTerminal {
                        let (archive_key, created) =
                            archive_terminal_ingress(&sink, &ingress).await?;
                        eprintln!(
                            "SECURITY_EVENT_INGRESS event_id={} \
                             result={} key={archive_key}",
                            ingress.event.event_id,
                            if created {
                                "tenant_archive_retained"
                            } else {
                                "tenant_archive_preserved"
                            }
                        );
                    } else {
                        eprintln!(
                            "SECURITY_EVENT_INGRESS event_id={} \
                             result=quarantined_permanent error={error:?}",
                            ingress.event.event_id
                        );
                    }
                    send_ingress_message(
                        &sqs,
                        &ingress_dead_letter_queue_url,
                        &ingress,
                        message_id,
                    )
                    .await?;
                    eprintln!(
                        "SECURITY_EVENT_INGRESS event_id={} result=dead_lettered attempt={}",
                        ingress.event.event_id, ingress.ingress_attempts
                    );
                    continue;
                }
            };
            if !inserted {
                let archived = ArchiveRecord {
                    event_id: ingress.event.event_id.clone(),
                    tenant_id: ingress.event.tenant_id.clone(),
                    occurred_at: ingress.event.occurred_at,
                    envelope: serde_json::to_string(&ingress.event)?,
                };
                if refresh_archived_record(&sink, &archived).await? {
                    eprintln!(
                        "SECURITY_EVENT_ARCHIVE event_id={} result=late_duplicate_refreshed",
                        ingress.event.event_id
                    );
                }
            }
            eprintln!(
                "SECURITY_EVENT_INGRESS event_id={} result={}",
                ingress.event.event_id,
                if inserted { "success" } else { "duplicate" }
            );
        }
        return Ok(());
    }

    if event_source == Some("aws:s3") {
        reconcile_failed_stream_records(&sink, &s3, records).await?;
        return Ok(());
    }

    let records = parse_dynamodb_records(&payload)?;
    deliver_records(&sink, &records).await.map_err(Into::into)
}

#[cfg(all(feature = "lambda", feature = "aws"))]
#[tokio::main]
async fn main() -> Result<(), Error> {
    let table =
        std::env::var("SECURITY_EVENTS_TABLE").map_err(|_| "SECURITY_EVENTS_TABLE is required")?;
    let bucket = std::env::var("SECURITY_EVENT_ARCHIVE_BUCKET")
        .map_err(|_| "SECURITY_EVENT_ARCHIVE_BUCKET is required")?;
    let dead_letter_queue_url = std::env::var("SECURITY_EVENT_ARCHIVE_DLQ_URL")
        .map_err(|_| "SECURITY_EVENT_ARCHIVE_DLQ_URL is required")?;
    let ingress_dead_letter_queue_url = std::env::var("SECURITY_EVENT_INGRESS_DLQ_URL")
        .map_err(|_| "SECURITY_EVENT_INGRESS_DLQ_URL is required")?;
    let failure_bucket = std::env::var("SECURITY_EVENT_INGRESS_FAILURE_BUCKET")
        .map_err(|_| "SECURITY_EVENT_INGRESS_FAILURE_BUCKET is required")?;
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let db = aws_sdk_dynamodb::Client::new(&config);
    let s3 = aws_sdk_s3::Client::new(&config);
    let sqs = aws_sdk_sqs::Client::new(&config);
    let runtime = ArchiveRuntime {
        db,
        s3,
        sqs,
        table,
        bucket,
        dead_letter_queue_url,
        ingress_dead_letter_queue_url,
        failure_bucket,
    };
    lambda_runtime::run(service_fn(move |event| handler(event, runtime.clone()))).await
}

#[cfg(all(test, feature = "lambda", feature = "aws"))]
mod tests {
    use super::*;

    #[test]
    fn scheduled_query_keeps_valid_rows_when_a_neighbor_is_corrupt() {
        let occurred_at = 1_785_415_471;
        let envelope = serde_json::json!({
            "schema_version": "1.0",
            "event_id": "evt-valid",
            "occurred_at": occurred_at,
            "tenant_id": "t1",
            "actor": {"kind": "system", "id": "archive-test"},
            "subject": {"kind": "tenant", "id": "t1"},
            "category": "delivery",
            "action": "archive.test",
            "outcome": "success",
            "correlation": {}
        })
        .to_string();
        let valid = [
            (
                "event_id".to_string(),
                AttributeValue::S("evt-valid".into()),
            ),
            ("tenant_id".to_string(), AttributeValue::S("t1".into())),
            (
                "occurred_at".to_string(),
                AttributeValue::N(occurred_at.to_string()),
            ),
            ("envelope".to_string(), AttributeValue::S(envelope)),
        ]
        .into_iter()
        .collect();
        let corrupt = [(
            "event_id".to_string(),
            AttributeValue::S("evt-corrupt".into()),
        )]
        .into_iter()
        .collect();
        let mut result = DeliveryRecordQuery::default();

        append_delivery_items(
            SecurityEventDeliveryStatus::DeadLettered,
            &[valid, corrupt],
            &mut result,
        );

        assert_eq!(result.records.len(), 1);
        assert_eq!(result.records[0].event_id, "evt-valid");
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].contains("event_id=evt-corrupt"));
    }

    #[test]
    fn recurring_redrive_uses_bounded_rollup_instead_of_growing_history() {
        assert!(REDRIVE_ATTEMPT_UPDATE_EXPRESSION.contains("ADD delivery_attempts :one"));
        assert!(!REDRIVE_ATTEMPT_UPDATE_EXPRESSION.contains("delivery_history"));
        assert!(!REDRIVE_FAILED_UPDATE_EXPRESSION.contains("delivery_history"));
    }

    #[test]
    fn archive_commit_fences_the_exact_delivery_history_revision() {
        assert!(ARCHIVE_COMMIT_CONDITION.contains("delivery_attempts = :expected_attempts"));
        assert!(ARCHIVE_COMMIT_CONDITION.contains("delivery_history = :expected_history"));
    }

    #[test]
    fn permanent_ingress_failure_never_enters_the_trusted_tenant_archive() {
        assert_eq!(
            ingress_store_failure_action(
                &StoreError::Permanent(
                    "security event id collision has a different envelope".to_string()
                ),
                1,
            ),
            IngressStoreFailureAction::Quarantine
        );
        assert_eq!(
            ingress_store_failure_action(&StoreError::Transient("unavailable".to_string()), 3),
            IngressStoreFailureAction::Retry
        );
        assert_eq!(
            ingress_store_failure_action(&StoreError::Transient("unavailable".to_string()), 4),
            IngressStoreFailureAction::ArchiveTerminal
        );
    }
}

#[cfg(not(all(feature = "lambda", feature = "aws")))]
fn main() {
    eprintln!("agent-auth-security-event-archive requires --features lambda,aws");
}
