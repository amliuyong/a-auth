use aws_sdk_dynamodb::error::ProvideErrorMetadata;
use aws_sdk_dynamodb::types::AttributeValue;

use crate::ports::StoreError;
use crate::security_event::{
    SecurityEvent, SecurityEventCursor, SecurityEventDelivery, SecurityEventDeliveryAttempt,
    SecurityEventDeliveryStatus, SecurityEventFallback, SecurityEventFallbackOutcome,
    SecurityEventIngress, SecurityEventPage, SecurityEventStore, StoredSecurityEvent,
    SECURITY_EVENT_HOT_RETENTION_DAYS, SECURITY_EVENT_SCHEMA_VERSION,
};

use super::ddb_err;

const TENANT_OCCURRED_AT_INDEX: &str = "tenant_occurred_at-index";
const SECONDS_PER_DAY: i64 = 86_400;

#[derive(Clone)]
pub struct DynamoSecurityEventStore {
    db: aws_sdk_dynamodb::Client,
    table: String,
}

#[derive(Clone)]
pub struct SqsSecurityEventFallback {
    sqs: aws_sdk_sqs::Client,
    queue_url: String,
}

impl SqsSecurityEventFallback {
    pub fn new(sqs: aws_sdk_sqs::Client, queue_url: impl Into<String>) -> Self {
        Self {
            sqs,
            queue_url: queue_url.into(),
        }
    }
}

fn batch_entry_index(id: &str, entry_count: usize) -> Option<usize> {
    (0..entry_count).find(|index| id == format!("event_{index}"))
}

fn batch_service_error_is_permanent(
    error: &aws_sdk_sqs::operation::send_message_batch::SendMessageBatchError,
) -> bool {
    error.is_batch_entry_ids_not_distinct()
        || error.is_batch_request_too_long()
        || error.is_empty_batch_request()
        || error.is_invalid_address()
        || error.is_invalid_batch_entry_id()
        || error.is_invalid_security()
        || error.is_kms_access_denied()
        || error.is_kms_disabled()
        || error.is_kms_invalid_key_usage()
        || error.is_kms_invalid_state()
        || error.is_kms_not_found()
        || error.is_kms_opt_in_required()
        || error.is_queue_does_not_exist()
        || error.is_too_many_entries_in_batch_request()
        || error.is_unsupported_operation()
}

fn classify_batch_send_error(
    error: aws_sdk_sqs::error::SdkError<
        aws_sdk_sqs::operation::send_message_batch::SendMessageBatchError,
    >,
) -> StoreError {
    let permanent = matches!(&error, aws_sdk_sqs::error::SdkError::ConstructionFailure(_))
        || error
            .as_service_error()
            .is_some_and(batch_service_error_is_permanent);
    let message = format!("security event fallback batch enqueue failed: {error}");
    if permanent {
        StoreError::Permanent(message)
    } else {
        StoreError::Transient(message)
    }
}

fn classify_batch_output(
    entry_count: usize,
    output: &aws_sdk_sqs::operation::send_message_batch::SendMessageBatchOutput,
) -> Vec<SecurityEventFallbackOutcome> {
    let mut outcomes = vec![
        SecurityEventFallbackOutcome::Retryable(
            "SQS batch response omitted this entry".to_string()
        );
        entry_count
    ];
    let mut observed = vec![false; entry_count];
    for entry in output.successful() {
        if let Some(index) = batch_entry_index(entry.id(), entry_count) {
            if observed[index] {
                outcomes[index] = SecurityEventFallbackOutcome::Retryable(format!(
                    "SQS batch response repeated entry {}",
                    entry.id()
                ));
            } else {
                outcomes[index] = SecurityEventFallbackOutcome::Enqueued;
                observed[index] = true;
            }
        }
    }
    for entry in output.failed() {
        let Some(index) = batch_entry_index(entry.id(), entry_count) else {
            continue;
        };
        if observed[index] {
            outcomes[index] = SecurityEventFallbackOutcome::Retryable(format!(
                "SQS batch response repeated entry {}",
                entry.id()
            ));
            continue;
        }
        observed[index] = true;
        let error = format!("SQS batch entry {} failed: {}", entry.id(), entry.code());
        outcomes[index] = if entry.sender_fault() {
            SecurityEventFallbackOutcome::Permanent(error)
        } else {
            SecurityEventFallbackOutcome::Retryable(error)
        };
    }
    outcomes
}

impl SecurityEventFallback for SqsSecurityEventFallback {
    async fn enqueue(&self, ingress: &SecurityEventIngress) -> Result<(), StoreError> {
        let body = serde_json::to_string(ingress).map_err(|error| {
            StoreError::Permanent(format!(
                "security event fallback serialization failed: {error}"
            ))
        })?;
        self.sqs
            .send_message()
            .queue_url(&self.queue_url)
            .message_body(body)
            .send()
            .await
            .map_err(|error| {
                StoreError::Transient(format!("security event fallback enqueue failed: {error}"))
            })?;
        Ok(())
    }

    async fn enqueue_batch(
        &self,
        ingresses: &[SecurityEventIngress],
    ) -> Result<Vec<SecurityEventFallbackOutcome>, StoreError> {
        if ingresses.is_empty() {
            return Ok(Vec::new());
        }
        if ingresses.len() > 10 {
            return Err(StoreError::Permanent(
                "security event fallback batch exceeds SQS limit".to_string(),
            ));
        }
        let entries = ingresses
            .iter()
            .enumerate()
            .map(|(index, ingress)| {
                let body = serde_json::to_string(ingress).map_err(|error| {
                    StoreError::Permanent(format!(
                        "security event fallback serialization failed: {error}"
                    ))
                })?;
                aws_sdk_sqs::types::SendMessageBatchRequestEntry::builder()
                    .id(format!("event_{index}"))
                    .message_body(body)
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!(
                            "security event fallback batch entry failed: {error}"
                        ))
                    })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        let output = self
            .sqs
            .send_message_batch()
            .queue_url(&self.queue_url)
            .set_entries(Some(entries))
            .send()
            .await
            .map_err(classify_batch_send_error)?;
        Ok(classify_batch_output(ingresses.len(), &output))
    }
}

#[cfg(test)]
#[path = "security_event_batch_tests.rs"]
mod batch_tests;

impl DynamoSecurityEventStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        Self {
            db,
            table: table.into(),
        }
    }

    fn required_string<'a>(
        item: &'a std::collections::HashMap<String, AttributeValue>,
        name: &str,
    ) -> Result<&'a str, StoreError> {
        item.get(name)
            .and_then(|value| value.as_s().ok())
            .map(String::as_str)
            .ok_or_else(|| {
                StoreError::Permanent(format!(
                    "security event row is missing string attribute {name}"
                ))
            })
    }

    fn required_i64(
        item: &std::collections::HashMap<String, AttributeValue>,
        name: &str,
    ) -> Result<i64, StoreError> {
        item.get(name)
            .and_then(|value| value.as_n().ok())
            .and_then(|value| value.parse::<i64>().ok())
            .ok_or_else(|| {
                StoreError::Permanent(format!(
                    "security event row has invalid number attribute {name}"
                ))
            })
    }

    fn optional_i64(
        item: &std::collections::HashMap<String, AttributeValue>,
        name: &str,
    ) -> Result<Option<i64>, StoreError> {
        item.get(name)
            .map(|value| {
                value
                    .as_n()
                    .ok()
                    .and_then(|value| value.parse::<i64>().ok())
                    .ok_or_else(|| {
                        StoreError::Permanent(format!(
                            "security event row has invalid number attribute {name}"
                        ))
                    })
            })
            .transpose()
    }

    fn optional_string(
        item: &std::collections::HashMap<String, AttributeValue>,
        name: &str,
    ) -> Result<Option<String>, StoreError> {
        item.get(name)
            .map(|value| {
                value.as_s().cloned().map_err(|_| {
                    StoreError::Permanent(format!(
                        "security event row has invalid string attribute {name}"
                    ))
                })
            })
            .transpose()
    }

    fn delivery_status(value: &str) -> Result<SecurityEventDeliveryStatus, StoreError> {
        SecurityEventDeliveryStatus::parse(value).map_err(|_| {
            StoreError::Permanent(format!(
                "security event row has invalid delivery status {value}"
            ))
        })
    }

    fn delivery_history_attempts_value(history: &[SecurityEventDeliveryAttempt]) -> AttributeValue {
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

    fn delivery_history_value(delivery: &SecurityEventDelivery) -> AttributeValue {
        Self::delivery_history_attempts_value(&delivery.history)
    }

    fn delivery_history_named(
        item: &std::collections::HashMap<String, AttributeValue>,
        name: &str,
    ) -> Result<Vec<SecurityEventDeliveryAttempt>, StoreError> {
        let Some(value) = item.get(name) else {
            return Ok(Vec::new());
        };
        value
            .as_l()
            .map_err(|_| {
                StoreError::Permanent(format!("security event row has invalid {name} attribute"))
            })?
            .iter()
            .map(|entry| {
                let map = entry.as_m().map_err(|_| {
                    StoreError::Permanent(
                        "security event delivery history entry is not a map".to_string(),
                    )
                })?;
                Ok(SecurityEventDeliveryAttempt {
                    status: Self::delivery_status(Self::required_string(map, "status")?)?,
                    occurred_at: Self::required_i64(map, "occurred_at")?,
                })
            })
            .collect()
    }

    fn delivery_history(
        item: &std::collections::HashMap<String, AttributeValue>,
    ) -> Result<Vec<SecurityEventDeliveryAttempt>, StoreError> {
        Self::delivery_history_named(item, "delivery_history")
    }

    async fn reconcile_duplicate_delivery(
        &self,
        event: &SecurityEvent,
        envelope: &str,
        delivery: &SecurityEventDelivery,
    ) -> Result<(), StoreError> {
        for _ in 0..4 {
            let response = self
                .db
                .get_item()
                .table_name(&self.table)
                .key("event_id", AttributeValue::S(event.event_id.clone()))
                .consistent_read(true)
                .send()
                .await
                .map_err(ddb_err)?;
            let Some(item) = response.item else {
                return Ok(());
            };
            if Self::required_string(&item, "envelope")? != envelope {
                return Err(StoreError::Permanent(
                    "security event id collision has a different envelope".to_string(),
                ));
            }
            let Some(prior_source_attempts) =
                Self::optional_i64(&item, "source_delivery_attempts")?
            else {
                // Rows written before source-delivery reconciliation remain immutable.
                return Ok(());
            };
            let prior_source_attempts = u32::try_from(prior_source_attempts).map_err(|_| {
                StoreError::Permanent(
                    "security event row has invalid source_delivery_attempts".to_string(),
                )
            })?;
            if delivery.attempts < prior_source_attempts {
                return Ok(());
            }
            let prior_history = Self::delivery_history_named(&item, "source_delivery_history")?;
            let prior_covers_delivery = delivery.history.len() <= prior_history.len()
                && delivery
                    .history
                    .iter()
                    .zip(&prior_history)
                    .all(|(current, prior)| current.status == prior.status);
            if delivery.attempts == prior_source_attempts && prior_covers_delivery {
                return Ok(());
            }
            let extends_prior_statuses = delivery.history.len() >= prior_history.len()
                && delivery
                    .history
                    .iter()
                    .zip(&prior_history)
                    .all(|(current, prior)| current.status == prior.status);
            if !extends_prior_statuses {
                return Err(StoreError::Permanent(
                    "security event duplicate has divergent delivery history".to_string(),
                ));
            }
            let prior_status =
                Self::delivery_status(Self::required_string(&item, "delivery_status")?)?;
            let refresh_required = matches!(
                prior_status,
                SecurityEventDeliveryStatus::Archived
                    | SecurityEventDeliveryStatus::ArchiveRefreshPending
            );
            let mut suffix = delivery.history[prior_history.len()..].to_vec();
            let now = crate::current_unix_secs();
            if refresh_required {
                suffix.push(SecurityEventDeliveryAttempt {
                    status: SecurityEventDeliveryStatus::ArchiveRefreshPending,
                    occurred_at: now,
                });
            }
            let attempt_delta = delivery.attempts - prior_source_attempts;
            let mut request = self
                .db
                .update_item()
                .table_name(&self.table)
                .key("event_id", AttributeValue::S(event.event_id.clone()))
                .update_expression(if refresh_required {
                    "SET source_delivery_attempts = :source_attempts, \
                     source_delivery_history = :source_history, \
                     delivery_status = :refresh_pending, last_delivery_at = :now, \
                     delivery_history = list_append(if_not_exists(delivery_history, :empty), :suffix) \
                     ADD delivery_attempts :attempt_delta"
                } else {
                    "SET source_delivery_attempts = :source_attempts, \
                     source_delivery_history = :source_history, \
                     delivery_history = list_append(if_not_exists(delivery_history, :empty), :suffix) \
                     ADD delivery_attempts :attempt_delta"
                })
                .condition_expression(
                    "envelope = :envelope AND source_delivery_attempts = :prior_source_attempts \
                     AND source_delivery_history = :prior_source_history \
                     AND delivery_status = :prior_delivery_status",
                )
                .expression_attribute_values(":envelope", AttributeValue::S(envelope.to_string()))
                .expression_attribute_values(
                    ":source_attempts",
                    AttributeValue::N(delivery.attempts.to_string()),
                )
                .expression_attribute_values(
                    ":prior_source_attempts",
                    AttributeValue::N(prior_source_attempts.to_string()),
                )
                .expression_attribute_values(
                    ":prior_source_history",
                    Self::delivery_history_attempts_value(&prior_history),
                )
                .expression_attribute_values(
                    ":prior_delivery_status",
                    AttributeValue::S(prior_status.as_str().to_string()),
                )
                .expression_attribute_values(
                    ":source_history",
                    Self::delivery_history_value(delivery),
                )
                .expression_attribute_values(
                    ":suffix",
                    Self::delivery_history_attempts_value(&suffix),
                )
                .expression_attribute_values(":empty", AttributeValue::L(Vec::new()))
                .expression_attribute_values(
                    ":attempt_delta",
                    AttributeValue::N(attempt_delta.to_string()),
                );
            if refresh_required {
                request = request
                    .expression_attribute_values(
                        ":refresh_pending",
                        AttributeValue::S(
                            SecurityEventDeliveryStatus::ArchiveRefreshPending
                                .as_str()
                                .to_string(),
                        ),
                    )
                    .expression_attribute_values(":now", AttributeValue::N(now.to_string()));
            }
            match request.send().await {
                Ok(_) => return Ok(()),
                Err(error)
                    if error
                        .code()
                        .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
                {
                    // The archive state or a newer duplicate changed after the
                    // consistent read. Re-read before deciding whether S3 needs
                    // a durable refresh marker.
                }
                Err(error) => return Err(ddb_err(error)),
            }
        }
        Err(StoreError::Transient(
            "security event duplicate reconciliation did not converge".to_string(),
        ))
    }

    fn delivery_from_item(
        item: &std::collections::HashMap<String, AttributeValue>,
    ) -> Result<SecurityEventDelivery, StoreError> {
        let attempts = Self::required_i64(item, "delivery_attempts")?;
        let attempts = u32::try_from(attempts).map_err(|_| {
            StoreError::Permanent(
                "security event row has invalid delivery_attempts attribute".to_string(),
            )
        })?;
        Ok(SecurityEventDelivery {
            status: Self::delivery_status(Self::required_string(item, "delivery_status")?)?,
            attempts,
            last_attempt_at: Self::optional_i64(item, "last_delivery_at")?,
            archived_at: Self::optional_i64(item, "archived_at")?,
            dead_lettered_at: Self::optional_i64(item, "dead_lettered_at")?,
            archive_key: Self::optional_string(item, "archive_key")?,
            history: Self::delivery_history(item)?,
        })
    }

    pub async fn get_delivery(
        &self,
        event_id: &str,
    ) -> Result<Option<SecurityEventDelivery>, StoreError> {
        let response = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("event_id", AttributeValue::S(event_id.to_string()))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        response
            .item
            .as_ref()
            .map(Self::delivery_from_item)
            .transpose()
    }

    fn event_from_item(
        item: &std::collections::HashMap<String, AttributeValue>,
        requested_tenant: &str,
        from_inclusive: i64,
        through_inclusive: i64,
    ) -> Result<StoredSecurityEvent, StoreError> {
        let stored_event_id = Self::required_string(item, "event_id")?;
        let stored_tenant = Self::required_string(item, "tenant_id")?;
        let stored_occurred_at = Self::required_i64(item, "occurred_at")?;
        let envelope = Self::required_string(item, "envelope")?;
        let event: SecurityEvent = serde_json::from_str(envelope).map_err(|error| {
            StoreError::Permanent(format!("security event envelope is invalid JSON: {error}"))
        })?;

        if event.schema_version != SECURITY_EVENT_SCHEMA_VERSION {
            return Err(StoreError::Permanent(format!(
                "unsupported security event schema version {}",
                event.schema_version
            )));
        }
        let validated = SecurityEvent::new_at(
            event.event_id.clone(),
            event.occurred_at,
            event.tenant_id.clone(),
            event.actor.clone(),
            Some(event.subject.clone()),
            event.category,
            event.action.clone(),
            event.outcome,
            event.correlation.clone(),
        )
        .map_err(|error| {
            StoreError::Permanent(format!(
                "security event envelope validation failed: {error}"
            ))
        })?;

        if stored_event_id != validated.event_id
            || stored_tenant != validated.tenant_id
            || stored_occurred_at != validated.occurred_at
            || stored_tenant != requested_tenant
            || !(from_inclusive..=through_inclusive).contains(&stored_occurred_at)
        {
            return Err(StoreError::Permanent(
                "security event row key/envelope/query scope mismatch".to_string(),
            ));
        }
        Ok(StoredSecurityEvent {
            event: validated,
            delivery: Self::delivery_from_item(item)?,
        })
    }
}

impl SecurityEventStore for DynamoSecurityEventStore {
    async fn put(&self, event: &SecurityEvent) -> Result<bool, StoreError> {
        self.put_with_delivery(event, &SecurityEventDelivery::pending(event.occurred_at))
            .await
    }

    async fn put_with_delivery(
        &self,
        event: &SecurityEvent,
        delivery: &SecurityEventDelivery,
    ) -> Result<bool, StoreError> {
        let expires_at = event
            .occurred_at
            .checked_add(i64::from(SECURITY_EVENT_HOT_RETENTION_DAYS) * SECONDS_PER_DAY)
            .ok_or_else(|| {
                StoreError::Permanent("security event retention timestamp overflow".to_string())
            })?;
        let envelope = serde_json::to_string(event).map_err(|error| {
            StoreError::Permanent(format!("security event serialization failed: {error}"))
        })?;
        let result = self
            .db
            .put_item()
            .table_name(&self.table)
            .item("event_id", AttributeValue::S(event.event_id.clone()))
            .item("tenant_id", AttributeValue::S(event.tenant_id.clone()))
            .item(
                "occurred_at",
                AttributeValue::N(event.occurred_at.to_string()),
            )
            .item(
                "schema_version",
                AttributeValue::S(event.schema_version.clone()),
            )
            .item(
                "category",
                AttributeValue::S(event.category.as_str().to_string()),
            )
            .item("action", AttributeValue::S(event.action.clone()))
            .item(
                "outcome",
                AttributeValue::S(event.outcome.as_str().to_string()),
            )
            .item("envelope", AttributeValue::S(envelope.clone()))
            .item(
                "delivery_status",
                AttributeValue::S(delivery.status.as_str().to_string()),
            )
            .item(
                "delivery_attempts",
                AttributeValue::N(delivery.attempts.to_string()),
            )
            .item(
                "source_delivery_attempts",
                AttributeValue::N(delivery.attempts.to_string()),
            )
            .item("delivery_history", Self::delivery_history_value(delivery))
            .item(
                "source_delivery_history",
                Self::delivery_history_value(delivery),
            )
            .item("expires_at", AttributeValue::N(expires_at.to_string()))
            .condition_expression("attribute_not_exists(event_id)")
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                self.reconcile_duplicate_delivery(event, &envelope, delivery)
                    .await?;
                Ok(false)
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn list_by_tenant(
        &self,
        tenant_id: &str,
        from_inclusive: i64,
        through_inclusive: i64,
        limit: usize,
    ) -> Result<Vec<StoredSecurityEvent>, StoreError> {
        let tenant_id = if tenant_id.is_empty() {
            "default"
        } else {
            tenant_id
        };
        let limit = limit.clamp(1, 1000);
        let mut events = Vec::with_capacity(limit);
        let mut last_key = None;
        while events.len() < limit {
            let response = self
                .db
                .query()
                .table_name(&self.table)
                .index_name(TENANT_OCCURRED_AT_INDEX)
                .key_condition_expression(
                    "tenant_id = :tenant AND occurred_at BETWEEN :from AND :through",
                )
                .expression_attribute_values(":tenant", AttributeValue::S(tenant_id.to_string()))
                .expression_attribute_values(":from", AttributeValue::N(from_inclusive.to_string()))
                .expression_attribute_values(
                    ":through",
                    AttributeValue::N(through_inclusive.to_string()),
                )
                .limit((limit - events.len()) as i32)
                .scan_index_forward(false)
                .set_exclusive_start_key(last_key)
                .send()
                .await
                .map_err(ddb_err)?;

            for item in response.items() {
                match Self::event_from_item(item, tenant_id, from_inclusive, through_inclusive) {
                    Ok(event) => events.push(event),
                    Err(error) => eprintln!(
                        "SECURITY_EVENT_INVALID source=tenant_export tenant={tenant_id} error={error:?}"
                    ),
                }
            }
            match response.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        Ok(events)
    }

    async fn list_by_tenant_page(
        &self,
        tenant_id: &str,
        from_inclusive: i64,
        through_inclusive: i64,
        limit: usize,
        cursor: Option<&SecurityEventCursor>,
    ) -> Result<SecurityEventPage, StoreError> {
        let tenant_id = if tenant_id.is_empty() {
            "default"
        } else {
            tenant_id
        };
        let limit = limit.clamp(1, 1000);
        let mut events = Vec::with_capacity(limit);
        let mut last_key = cursor
            .map(|cursor| {
                if cursor.tenant_id() != tenant_id {
                    return Err(StoreError::Permanent(
                        "security event cursor tenant mismatch".to_string(),
                    ));
                }
                Ok([
                    (
                        "event_id".to_string(),
                        AttributeValue::S(cursor.event_id().to_string()),
                    ),
                    (
                        "tenant_id".to_string(),
                        AttributeValue::S(cursor.tenant_id().to_string()),
                    ),
                    (
                        "occurred_at".to_string(),
                        AttributeValue::N(cursor.occurred_at().to_string()),
                    ),
                ]
                .into_iter()
                .collect())
            })
            .transpose()?;
        let mut next_cursor = None;
        while events.len() < limit {
            let response = self
                .db
                .query()
                .table_name(&self.table)
                .index_name(TENANT_OCCURRED_AT_INDEX)
                .key_condition_expression(
                    "tenant_id = :tenant AND occurred_at BETWEEN :from AND :through",
                )
                .expression_attribute_values(":tenant", AttributeValue::S(tenant_id.to_string()))
                .expression_attribute_values(":from", AttributeValue::N(from_inclusive.to_string()))
                .expression_attribute_values(
                    ":through",
                    AttributeValue::N(through_inclusive.to_string()),
                )
                .limit((limit - events.len()) as i32)
                .scan_index_forward(false)
                .set_exclusive_start_key(last_key)
                .send()
                .await
                .map_err(ddb_err)?;

            for item in response.items() {
                match Self::event_from_item(item, tenant_id, from_inclusive, through_inclusive) {
                    Ok(event) => events.push(event),
                    Err(error) => eprintln!(
                        "SECURITY_EVENT_INVALID source=tenant_export tenant={tenant_id} error={error:?}"
                    ),
                }
            }
            match response.last_evaluated_key() {
                Some(key) if !key.is_empty() => {
                    let event_id = Self::required_string(key, "event_id")?;
                    let key_tenant = Self::required_string(key, "tenant_id")?;
                    let occurred_at = Self::required_i64(key, "occurred_at")?;
                    next_cursor = Some(
                        SecurityEventCursor::from_parts(key_tenant, occurred_at, event_id)
                            .map_err(|error| StoreError::Permanent(error.to_string()))?
                            .encode()?,
                    );
                    last_key = Some(key.clone());
                }
                _ => {
                    next_cursor = None;
                    break;
                }
            }
        }
        Ok(SecurityEventPage {
            events,
            next_cursor,
        })
    }
}

#[cfg(test)]
#[path = "security_event_dynamo_tests.rs"]
mod security_event_dynamo_tests;
