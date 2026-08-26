use std::collections::HashMap;

use aws_sdk_dynamodb::error::ProvideErrorMetadata;
use aws_sdk_dynamodb::types::{
    AttributeValue, ConditionCheck, Put, ReturnValue, TransactWriteItem, Update,
};

use crate::{
    ports::StoreError,
    security_event::SecurityEvent,
    ssf::{
        apply_attempt_result, apply_stream_mutation, compact_set_sha256, delivery_is_redriveable,
        delivery_retry_window_expired, project_security_event, validate_stream_configuration,
        validate_stream_identity, SignedSet, SsfAttemptResult, SsfDelivery, SsfDeliveryAttempt,
        SsfDeliveryAttemptOutcome, SsfDeliveryCursor, SsfDeliveryLease, SsfDeliveryPage,
        SsfDeliveryStatus, SsfRedriveOutcome, SsfStore, SsfStream, SsfStreamCreateOutcome,
        SsfStreamMutation, SsfStreamMutationOutcome, SsfStreamStatus, SsfVerificationOutcome,
        SSF_DELIVERY_RETENTION_SECS, SSF_MAX_ATTEMPTS_PER_CYCLE, SSF_MAX_DELIVERY_PAGE_SIZE,
        SSF_MAX_REGISTERED_STREAMS_PER_TENANT, SSF_MAX_RETRY_AGE_SECS, SSF_MAX_TOTAL_ATTEMPTS,
        SSF_VERIFICATION_EVENT, SUPPORTED_EVENT_TYPES,
    },
};

use super::{ddb_err, send_idempotent_transaction};

const DUE_INDEX: &str = "due-index";
const DUE_PARTITION: &str = "active";
const STREAM_CREATED_AT_INDEX: &str = "stream-created-at-index";
const STREAM_PREFIX: &str = "stream#";
const DELIVERY_PREFIX: &str = "delivery#";
const STREAM_REGISTRY_KEY: &str = "meta#stream-registry";
const STREAM_REGISTRY_ENTITY_TYPE: &str = "stream_registry";
const MAX_CAS_ATTEMPTS: usize = 4;
const GOVERNANCE_TARGET_WRITE_BATCH: usize = 95;

type Item = HashMap<String, AttributeValue>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GovernanceSsfInventory {
    pub live_streams: usize,
    pub revoked_stream_tombstones: usize,
    pub live_deliveries: usize,
    pub suppressed_delivery_tombstones: usize,
    pub terminal_retained_deliveries: usize,
    pub registry_rows: usize,
}

#[derive(Clone)]
pub struct DynamoSsfStore {
    db: aws_sdk_dynamodb::Client,
    table: String,
}

impl DynamoSsfStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        Self {
            db,
            table: table.into(),
        }
    }

    fn stream_key(stream_id: &str) -> String {
        format!("{STREAM_PREFIX}{stream_id}")
    }

    fn delivery_prefix(stream_id: &str) -> String {
        format!("{DELIVERY_PREFIX}{stream_id}#")
    }

    fn delivery_key(stream_id: &str, revision: u64, event_id: &str) -> String {
        format!(
            "{}{:020}#{event_id}",
            Self::delivery_prefix(stream_id),
            revision
        )
    }

    fn stream_partition(tenant_id: &str, stream_id: &str) -> String {
        format!("{tenant_id}#{stream_id}")
    }

    fn stream_created_at_key(created_at: i64, revision: u64, event_id: &str) -> String {
        format!("{created_at:020}#{revision:020}#{event_id}")
    }

    fn key(tenant_id: &str, record_key: String) -> Item {
        [
            (
                "tenant_id".to_string(),
                AttributeValue::S(tenant_id.to_string()),
            ),
            ("record_key".to_string(), AttributeValue::S(record_key)),
        ]
        .into_iter()
        .collect()
    }

    fn required_string<'a>(item: &'a Item, name: &str) -> Result<&'a str, StoreError> {
        item.get(name)
            .and_then(|value| value.as_s().ok())
            .map(String::as_str)
            .ok_or_else(|| {
                StoreError::Permanent(format!("SSF row is missing string attribute {name}"))
            })
    }

    fn optional_string(item: &Item, name: &str) -> Result<Option<String>, StoreError> {
        item.get(name)
            .map(|value| {
                value.as_s().cloned().map_err(|_| {
                    StoreError::Permanent(format!("SSF row has invalid string attribute {name}"))
                })
            })
            .transpose()
    }

    fn required_i64(item: &Item, name: &str) -> Result<i64, StoreError> {
        item.get(name)
            .and_then(|value| value.as_n().ok())
            .and_then(|value| value.parse::<i64>().ok())
            .ok_or_else(|| {
                StoreError::Permanent(format!("SSF row has invalid number attribute {name}"))
            })
    }

    fn optional_i64(item: &Item, name: &str) -> Result<Option<i64>, StoreError> {
        item.get(name)
            .map(|value| {
                value
                    .as_n()
                    .ok()
                    .and_then(|value| value.parse::<i64>().ok())
                    .ok_or_else(|| {
                        StoreError::Permanent(format!(
                            "SSF row has invalid number attribute {name}"
                        ))
                    })
            })
            .transpose()
    }

    fn required_u32(item: &Item, name: &str) -> Result<u32, StoreError> {
        u32::try_from(Self::required_i64(item, name)?).map_err(|_| {
            StoreError::Permanent(format!("SSF row has out-of-range number attribute {name}"))
        })
    }

    fn required_u64(item: &Item, name: &str) -> Result<u64, StoreError> {
        u64::try_from(Self::required_i64(item, name)?).map_err(|_| {
            StoreError::Permanent(format!("SSF row has out-of-range number attribute {name}"))
        })
    }

    fn string_list(item: &Item, name: &str) -> Result<Vec<String>, StoreError> {
        item.get(name)
            .and_then(|value| value.as_l().ok())
            .ok_or_else(|| {
                StoreError::Permanent(format!("SSF row has invalid list attribute {name}"))
            })?
            .iter()
            .map(|value| {
                value.as_s().cloned().map_err(|_| {
                    StoreError::Permanent(format!(
                        "SSF row has non-string entry in attribute {name}"
                    ))
                })
            })
            .collect()
    }

    fn string_list_value(values: &[String]) -> AttributeValue {
        AttributeValue::L(values.iter().cloned().map(AttributeValue::S).collect())
    }

    fn attempt_history_value(attempts: &[SsfDeliveryAttempt]) -> AttributeValue {
        AttributeValue::L(
            attempts
                .iter()
                .map(|attempt| {
                    let mut item = Item::from([
                        (
                            "attempted_at".to_string(),
                            AttributeValue::N(attempt.attempted_at.to_string()),
                        ),
                        (
                            "outcome".to_string(),
                            AttributeValue::S(attempt.outcome.as_str().to_string()),
                        ),
                    ]);
                    if let Some(status_code) = attempt.status_code {
                        item.insert(
                            "status_code".to_string(),
                            AttributeValue::N(status_code.to_string()),
                        );
                    }
                    if let Some(error_class) = &attempt.error_class {
                        item.insert(
                            "error_class".to_string(),
                            AttributeValue::S(error_class.clone()),
                        );
                    }
                    if let Some(set_sha256) = &attempt.set_sha256 {
                        item.insert(
                            "set_sha256".to_string(),
                            AttributeValue::S(set_sha256.clone()),
                        );
                    }
                    if let Some(signing_kid) = &attempt.signing_kid {
                        item.insert(
                            "signing_kid".to_string(),
                            AttributeValue::S(signing_kid.clone()),
                        );
                    }
                    AttributeValue::M(item)
                })
                .collect(),
        )
    }

    fn attempt_history(item: &Item) -> Result<Vec<SsfDeliveryAttempt>, StoreError> {
        item.get("attempt_history")
            .and_then(|value| value.as_l().ok())
            .ok_or_else(|| {
                StoreError::Permanent(
                    "SSF row has invalid list attribute attempt_history".to_string(),
                )
            })?
            .iter()
            .map(|value| {
                let entry = value.as_m().map_err(|_| {
                    StoreError::Permanent("SSF attempt history entry is not a map".to_string())
                })?;
                let status_code = Self::optional_i64(entry, "status_code")?
                    .map(|status| {
                        u16::try_from(status).map_err(|_| {
                            StoreError::Permanent(
                                "SSF attempt status code is out of range".to_string(),
                            )
                        })
                    })
                    .transpose()?;
                Ok(SsfDeliveryAttempt {
                    attempted_at: Self::required_i64(entry, "attempted_at")?,
                    outcome: SsfDeliveryAttemptOutcome::parse(Self::required_string(
                        entry, "outcome",
                    )?)?,
                    status_code,
                    error_class: Self::optional_string(entry, "error_class")?,
                    set_sha256: Self::optional_string(entry, "set_sha256")?,
                    signing_kid: Self::optional_string(entry, "signing_kid")?,
                })
            })
            .collect()
    }

    fn stream_item(stream: &SsfStream) -> Item {
        Item::from([
            (
                "tenant_id".to_string(),
                AttributeValue::S(stream.tenant_id.clone()),
            ),
            (
                "record_key".to_string(),
                AttributeValue::S(Self::stream_key(&stream.stream_id)),
            ),
            (
                "entity_type".to_string(),
                AttributeValue::S("stream".to_string()),
            ),
            (
                "stream_id".to_string(),
                AttributeValue::S(stream.stream_id.clone()),
            ),
            (
                "revision".to_string(),
                AttributeValue::N(stream.revision.to_string()),
            ),
            (
                "endpoint".to_string(),
                AttributeValue::S(stream.endpoint.clone()),
            ),
            (
                "audience".to_string(),
                AttributeValue::S(stream.audience.clone()),
            ),
            (
                "requested_events".to_string(),
                Self::string_list_value(&stream.requested_events),
            ),
            (
                "delivered_events".to_string(),
                Self::string_list_value(&stream.delivered_events),
            ),
            (
                "status".to_string(),
                AttributeValue::S(stream.status.as_str().to_string()),
            ),
            (
                "activation_at".to_string(),
                AttributeValue::N(stream.activation_at.to_string()),
            ),
            (
                "created_at".to_string(),
                AttributeValue::N(stream.created_at.to_string()),
            ),
            (
                "updated_at".to_string(),
                AttributeValue::N(stream.updated_at.to_string()),
            ),
        ])
    }

    fn stream_from_item(
        item: &Item,
        expected_tenant: &str,
        expected_stream: Option<&str>,
    ) -> Result<SsfStream, StoreError> {
        if Self::required_string(item, "entity_type")? != "stream"
            || Self::required_string(item, "tenant_id")? != expected_tenant
        {
            return Err(StoreError::Permanent(
                "SSF stream row scope or type mismatch".to_string(),
            ));
        }
        let stream_id = Self::required_string(item, "stream_id")?;
        validate_stream_identity(expected_tenant, stream_id).map_err(|error| {
            StoreError::Permanent(format!("invalid stored SSF stream identity: {error}"))
        })?;
        if expected_stream.is_some_and(|expected| stream_id != expected)
            || Self::required_string(item, "record_key")? != Self::stream_key(stream_id)
        {
            return Err(StoreError::Permanent(
                "SSF stream row key mismatch".to_string(),
            ));
        }
        let stream = SsfStream {
            tenant_id: expected_tenant.to_string(),
            stream_id: stream_id.to_string(),
            revision: Self::required_u64(item, "revision")?,
            endpoint: Self::required_string(item, "endpoint")?.to_string(),
            audience: Self::required_string(item, "audience")?.to_string(),
            requested_events: Self::string_list(item, "requested_events")?,
            delivered_events: Self::string_list(item, "delivered_events")?,
            status: SsfStreamStatus::parse(Self::required_string(item, "status")?)?,
            activation_at: Self::required_i64(item, "activation_at")?,
            created_at: Self::required_i64(item, "created_at")?,
            updated_at: Self::required_i64(item, "updated_at")?,
        };
        validate_stream_configuration(&stream.endpoint, &stream.audience, &stream.requested_events)
            .map_err(|error| {
                StoreError::Permanent(format!("invalid stored SSF stream: {error}"))
            })?;
        let expected_delivered = stream
            .requested_events
            .iter()
            .filter(|event| SUPPORTED_EVENT_TYPES.contains(&event.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        if stream.delivered_events.is_empty() || stream.delivered_events != expected_delivered {
            return Err(StoreError::Permanent(
                "SSF stream row has invalid delivered events".to_string(),
            ));
        }
        Ok(stream)
    }

    fn delivery_item(delivery: &SsfDelivery) -> Result<Item, StoreError> {
        let mut item = Item::from([
            (
                "tenant_id".to_string(),
                AttributeValue::S(delivery.tenant_id.clone()),
            ),
            (
                "record_key".to_string(),
                AttributeValue::S(Self::delivery_key(
                    &delivery.stream_id,
                    delivery.stream_revision,
                    &delivery.event_id,
                )),
            ),
            (
                "entity_type".to_string(),
                AttributeValue::S("delivery".to_string()),
            ),
            (
                "stream_id".to_string(),
                AttributeValue::S(delivery.stream_id.clone()),
            ),
            (
                "stream_partition".to_string(),
                AttributeValue::S(Self::stream_partition(
                    &delivery.tenant_id,
                    &delivery.stream_id,
                )),
            ),
            (
                "stream_created_at".to_string(),
                AttributeValue::S(Self::stream_created_at_key(
                    delivery.created_at,
                    delivery.stream_revision,
                    &delivery.event_id,
                )),
            ),
            (
                "stream_revision".to_string(),
                AttributeValue::N(delivery.stream_revision.to_string()),
            ),
            (
                "event_id".to_string(),
                AttributeValue::S(delivery.event_id.clone()),
            ),
            (
                "issuer".to_string(),
                AttributeValue::S(delivery.issuer.clone()),
            ),
            (
                "endpoint".to_string(),
                AttributeValue::S(delivery.endpoint.clone()),
            ),
            (
                "audience".to_string(),
                AttributeValue::S(delivery.audience.clone()),
            ),
            (
                "event_uri".to_string(),
                AttributeValue::S(delivery.event_uri.clone()),
            ),
            (
                "subject_json".to_string(),
                AttributeValue::S(serde_json::to_string(&delivery.subject).map_err(|error| {
                    StoreError::Permanent(format!("SSF subject serialization failed: {error}"))
                })?),
            ),
            (
                "payload_json".to_string(),
                AttributeValue::S(serde_json::to_string(&delivery.payload).map_err(|error| {
                    StoreError::Permanent(format!("SSF payload serialization failed: {error}"))
                })?),
            ),
            (
                "status".to_string(),
                AttributeValue::S(delivery.status.as_str().to_string()),
            ),
            (
                "attempts".to_string(),
                AttributeValue::N(delivery.attempts.to_string()),
            ),
            (
                "cycle_attempts".to_string(),
                AttributeValue::N(delivery.cycle_attempts.to_string()),
            ),
            (
                "redrive_count".to_string(),
                AttributeValue::N(delivery.redrive_count.to_string()),
            ),
            (
                "attempt_history".to_string(),
                Self::attempt_history_value(&delivery.attempt_history),
            ),
            (
                "event_occurred_at".to_string(),
                AttributeValue::N(delivery.event_occurred_at.to_string()),
            ),
            (
                "created_at".to_string(),
                AttributeValue::N(delivery.created_at.to_string()),
            ),
            (
                "updated_at".to_string(),
                AttributeValue::N(delivery.updated_at.to_string()),
            ),
            (
                "cycle_started_at".to_string(),
                AttributeValue::N(delivery.cycle_started_at.to_string()),
            ),
            (
                "next_attempt_at".to_string(),
                AttributeValue::N(delivery.next_attempt_at.to_string()),
            ),
            (
                "expires_at".to_string(),
                AttributeValue::N(delivery.expires_at.to_string()),
            ),
        ]);
        if matches!(
            delivery.status,
            SsfDeliveryStatus::Pending | SsfDeliveryStatus::RetryWait
        ) {
            item.insert(
                "due_partition".to_string(),
                AttributeValue::S(DUE_PARTITION.to_string()),
            );
            item.insert(
                "due_at".to_string(),
                AttributeValue::N(
                    delivery
                        .lease_expires_at
                        .unwrap_or(delivery.next_attempt_at)
                        .to_string(),
                ),
            );
        }
        for (name, value) in [
            ("compact_set", delivery.compact_set.as_ref()),
            ("jti", delivery.jti.as_ref()),
            ("signing_kid", delivery.signing_kid.as_ref()),
            ("lease_id", delivery.lease_id.as_ref()),
        ] {
            if let Some(value) = value {
                item.insert(name.to_string(), AttributeValue::S(value.clone()));
            }
        }
        for (name, value) in [
            ("issued_at", delivery.issued_at),
            ("lease_expires_at", delivery.lease_expires_at),
        ] {
            if let Some(value) = value {
                item.insert(name.to_string(), AttributeValue::N(value.to_string()));
            }
        }
        Ok(item)
    }

    fn delivery_from_item(
        item: &Item,
        expected_tenant: Option<&str>,
        expected_stream: Option<&str>,
    ) -> Result<SsfDelivery, StoreError> {
        if Self::required_string(item, "entity_type")? != "delivery" {
            return Err(StoreError::Permanent(
                "SSF delivery row type mismatch".to_string(),
            ));
        }
        let tenant_id = Self::required_string(item, "tenant_id")?;
        let stream_id = Self::required_string(item, "stream_id")?;
        let stream_revision = Self::required_u64(item, "stream_revision")?;
        let event_id = Self::required_string(item, "event_id")?;
        validate_stream_identity(tenant_id, stream_id).map_err(|error| {
            StoreError::Permanent(format!("invalid stored SSF delivery identity: {error}"))
        })?;
        if expected_tenant.is_some_and(|expected| tenant_id != expected)
            || expected_stream.is_some_and(|expected| stream_id != expected)
            || stream_revision == 0
            || event_id.is_empty()
            || event_id.len() > 128
            || event_id
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b'\x7f')
            || Self::required_string(item, "record_key")?
                != Self::delivery_key(stream_id, stream_revision, event_id)
            || Self::required_string(item, "stream_partition")?
                != Self::stream_partition(tenant_id, stream_id)
            || Self::required_string(item, "stream_created_at")?
                != Self::stream_created_at_key(
                    Self::required_i64(item, "created_at")?,
                    stream_revision,
                    event_id,
                )
        {
            return Err(StoreError::Permanent(
                "SSF delivery row key or scope mismatch".to_string(),
            ));
        }
        let parse_json = |name: &str| -> Result<serde_json::Value, StoreError> {
            serde_json::from_str(Self::required_string(item, name)?).map_err(|error| {
                StoreError::Permanent(format!("SSF row has invalid {name}: {error}"))
            })
        };
        let delivery = SsfDelivery {
            tenant_id: tenant_id.to_string(),
            stream_id: stream_id.to_string(),
            stream_revision,
            event_id: event_id.to_string(),
            issuer: Self::required_string(item, "issuer")?.to_string(),
            endpoint: Self::required_string(item, "endpoint")?.to_string(),
            audience: Self::required_string(item, "audience")?.to_string(),
            event_uri: Self::required_string(item, "event_uri")?.to_string(),
            subject: parse_json("subject_json")?,
            payload: parse_json("payload_json")?,
            status: SsfDeliveryStatus::parse(Self::required_string(item, "status")?)?,
            attempts: Self::required_u32(item, "attempts")?,
            cycle_attempts: Self::required_u32(item, "cycle_attempts")?,
            redrive_count: Self::required_u32(item, "redrive_count")?,
            attempt_history: Self::attempt_history(item)?,
            event_occurred_at: Self::required_i64(item, "event_occurred_at")?,
            created_at: Self::required_i64(item, "created_at")?,
            updated_at: Self::required_i64(item, "updated_at")?,
            cycle_started_at: Self::required_i64(item, "cycle_started_at")?,
            next_attempt_at: Self::required_i64(item, "next_attempt_at")?,
            expires_at: Self::required_i64(item, "expires_at")?,
            compact_set: Self::optional_string(item, "compact_set")?,
            jti: Self::optional_string(item, "jti")?,
            signing_kid: Self::optional_string(item, "signing_kid")?,
            issued_at: Self::optional_i64(item, "issued_at")?,
            lease_id: Self::optional_string(item, "lease_id")?,
            lease_expires_at: Self::optional_i64(item, "lease_expires_at")?,
        };
        Self::validate_delivery_item(item, &delivery)?;
        Ok(delivery)
    }

    fn validate_delivery_item(item: &Item, delivery: &SsfDelivery) -> Result<(), StoreError> {
        let event_supported = SUPPORTED_EVENT_TYPES.contains(&delivery.event_uri.as_str())
            || delivery.event_uri == SSF_VERIFICATION_EVENT;
        let timestamps_valid = delivery.event_occurred_at > 0
            && delivery.created_at > 0
            && delivery.updated_at >= delivery.created_at
            && delivery.cycle_started_at >= delivery.created_at
            && delivery.next_attempt_at > 0
            && delivery.expires_at > delivery.created_at;
        let history_valid = delivery.cycle_attempts <= delivery.attempts
            && delivery.attempts <= SSF_MAX_TOTAL_ATTEMPTS
            && delivery.attempt_history.len()
                == usize::try_from(delivery.attempts).unwrap_or(usize::MAX);
        let signed_fields = [
            delivery.compact_set.is_some(),
            delivery.jti.is_some(),
            delivery.signing_kid.is_some(),
            delivery.issued_at.is_some(),
        ];
        let signed_fields_valid = signed_fields.iter().all(|present| *present)
            || signed_fields.iter().all(|present| !*present);
        let lease_fields_valid = delivery.lease_id.is_some() == delivery.lease_expires_at.is_some();
        let signed_terminal_valid = !matches!(
            delivery.status,
            SsfDeliveryStatus::Delivered | SsfDeliveryStatus::Terminal
        ) || delivery.compact_set.is_some();
        if !event_supported
            || !timestamps_valid
            || !history_valid
            || !signed_fields_valid
            || !lease_fields_valid
            || !signed_terminal_valid
        {
            return Err(StoreError::Permanent(
                "SSF delivery row invariant mismatch".to_string(),
            ));
        }
        if let Some(compact_set) = &delivery.compact_set {
            let expected_digest = compact_set_sha256(compact_set);
            let expected_kid = delivery
                .signing_kid
                .as_deref()
                .expect("signed fields were checked together");
            if compact_set.len() > 256 * 1024
                || compact_set.split('.').count() != 3
                || delivery.jti.as_ref().is_none_or(|jti| jti.is_empty())
                || delivery
                    .signing_kid
                    .as_ref()
                    .is_none_or(|kid| kid.is_empty() || kid.len() > 512)
                || delivery.issued_at.is_none_or(|issued_at| issued_at <= 0)
            {
                return Err(StoreError::Permanent(
                    "SSF delivery row has invalid signed SET evidence".to_string(),
                ));
            }
            if delivery.attempt_history.iter().any(|attempt| {
                attempt
                    .set_sha256
                    .as_deref()
                    .is_some_and(|digest| digest != expected_digest)
                    || attempt
                        .signing_kid
                        .as_deref()
                        .is_some_and(|kid| kid != expected_kid)
                    || attempt.set_sha256.is_some() != attempt.signing_kid.is_some()
            }) {
                return Err(StoreError::Permanent(
                    "SSF attempt history has inconsistent signed SET evidence".to_string(),
                ));
            }
        }
        let active = matches!(
            delivery.status,
            SsfDeliveryStatus::Pending | SsfDeliveryStatus::RetryWait
        );
        let due_partition = Self::optional_string(item, "due_partition")?;
        let due_at = Self::optional_i64(item, "due_at")?;
        if active {
            let expected_due_at = delivery
                .lease_expires_at
                .unwrap_or(delivery.next_attempt_at);
            if due_partition.as_deref() != Some(DUE_PARTITION) || due_at != Some(expected_due_at) {
                return Err(StoreError::Permanent(
                    "SSF active delivery row has invalid due index fields".to_string(),
                ));
            }
        } else if due_partition.is_some()
            || due_at.is_some()
            || delivery.lease_id.is_some()
            || delivery.lease_expires_at.is_some()
        {
            return Err(StoreError::Permanent(
                "SSF terminal delivery row retains active lease or due fields".to_string(),
            ));
        }
        validate_stream_configuration(
            &delivery.endpoint,
            &delivery.audience,
            std::slice::from_ref(&delivery.event_uri),
        )
        .map_err(|error| {
            StoreError::Permanent(format!(
                "invalid stored SSF delivery configuration: {error}"
            ))
        })
    }

    async fn get_delivery_consistent(
        &self,
        tenant_id: &str,
        stream_id: &str,
        stream_revision: u64,
        event_id: &str,
    ) -> Result<Option<SsfDelivery>, StoreError> {
        let response = self
            .db
            .get_item()
            .table_name(&self.table)
            .set_key(Some(Self::key(
                tenant_id,
                Self::delivery_key(stream_id, stream_revision, event_id),
            )))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        response
            .item
            .as_ref()
            .map(|item| Self::delivery_from_item(item, Some(tenant_id), Some(stream_id)))
            .transpose()
    }

    async fn registered_stream_count(&self, tenant_id: &str) -> Result<Option<u32>, StoreError> {
        let response = self
            .db
            .get_item()
            .table_name(&self.table)
            .set_key(Some(Self::key(tenant_id, STREAM_REGISTRY_KEY.to_string())))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        let Some(item) = response.item.as_ref() else {
            return Ok(None);
        };
        if Self::required_string(item, "tenant_id")? != tenant_id
            || Self::required_string(item, "record_key")? != STREAM_REGISTRY_KEY
            || Self::required_string(item, "entity_type")? != STREAM_REGISTRY_ENTITY_TYPE
        {
            return Err(StoreError::Permanent(
                "SSF stream registry row has invalid identity".to_string(),
            ));
        }
        let count = Self::required_u32(item, "registered_stream_count")?;
        if usize::try_from(count).unwrap_or(usize::MAX) > SSF_MAX_REGISTERED_STREAMS_PER_TENANT {
            return Err(StoreError::Permanent(
                "SSF stream registry count exceeds the configured quota".to_string(),
            ));
        }
        Ok(Some(count))
    }

    async fn query_streams(&self, tenant_id: &str) -> Result<Vec<SsfStream>, StoreError> {
        let mut streams = Vec::new();
        let mut last_key = None;
        loop {
            let remaining = SSF_MAX_REGISTERED_STREAMS_PER_TENANT
                .saturating_add(1)
                .saturating_sub(streams.len());
            if remaining == 0 {
                return Err(StoreError::Permanent(
                    "SSF tenant stream count exceeds the configured quota".to_string(),
                ));
            }
            let response = self
                .db
                .query()
                .table_name(&self.table)
                .key_condition_expression(
                    "tenant_id = :tenant AND begins_with(record_key, :prefix)",
                )
                .expression_attribute_values(":tenant", AttributeValue::S(tenant_id.to_string()))
                .expression_attribute_values(
                    ":prefix",
                    AttributeValue::S(STREAM_PREFIX.to_string()),
                )
                .consistent_read(true)
                .limit(i32::try_from(remaining).expect("SSF stream quota fits i32"))
                .set_exclusive_start_key(last_key)
                .send()
                .await
                .map_err(ddb_err)?;
            for item in response.items() {
                streams.push(Self::stream_from_item(item, tenant_id, None)?);
            }
            if streams.len() > SSF_MAX_REGISTERED_STREAMS_PER_TENANT {
                return Err(StoreError::Permanent(
                    "SSF tenant stream count exceeds the configured quota".to_string(),
                ));
            }
            match response.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        Ok(streams)
    }

    fn new_delivery(
        stream: &SsfStream,
        event: &SecurityEvent,
        issuer: &str,
        now: i64,
    ) -> Option<SsfDelivery> {
        let projection = project_security_event(event, issuer)?;
        Some(SsfDelivery {
            tenant_id: stream.tenant_id.clone(),
            stream_id: stream.stream_id.clone(),
            stream_revision: stream.revision,
            event_id: event.event_id.clone(),
            issuer: issuer.to_string(),
            endpoint: stream.endpoint.clone(),
            audience: stream.audience.clone(),
            event_uri: projection.event_uri.to_string(),
            subject: projection.subject,
            payload: projection.payload,
            status: SsfDeliveryStatus::Pending,
            attempts: 0,
            cycle_attempts: 0,
            redrive_count: 0,
            attempt_history: Vec::new(),
            event_occurred_at: event.occurred_at,
            created_at: now,
            updated_at: now,
            cycle_started_at: now,
            next_attempt_at: now,
            expires_at: now.saturating_add(SSF_DELIVERY_RETENTION_SECS),
            compact_set: None,
            jti: None,
            signing_kid: None,
            issued_at: None,
            lease_id: None,
            lease_expires_at: None,
        })
    }

    fn new_verification_delivery(
        stream: &SsfStream,
        event_id: &str,
        issuer: &str,
        state: Option<&str>,
        now: i64,
    ) -> SsfDelivery {
        let mut payload = serde_json::Map::new();
        if let Some(state) = state {
            payload.insert(
                "state".to_string(),
                serde_json::Value::String(state.to_string()),
            );
        }
        SsfDelivery {
            tenant_id: stream.tenant_id.clone(),
            stream_id: stream.stream_id.clone(),
            stream_revision: stream.revision,
            event_id: event_id.to_string(),
            issuer: issuer.to_string(),
            endpoint: stream.endpoint.clone(),
            audience: stream.audience.clone(),
            event_uri: SSF_VERIFICATION_EVENT.to_string(),
            subject: serde_json::json!({
                "format": "opaque",
                "id": stream.stream_id,
            }),
            payload: serde_json::Value::Object(payload),
            status: SsfDeliveryStatus::Pending,
            attempts: 0,
            cycle_attempts: 0,
            redrive_count: 0,
            attempt_history: Vec::new(),
            event_occurred_at: now,
            created_at: now,
            updated_at: now,
            cycle_started_at: now,
            next_attempt_at: now,
            expires_at: now.saturating_add(SSF_DELIVERY_RETENTION_SECS),
            compact_set: None,
            jti: None,
            signing_kid: None,
            issued_at: None,
            lease_id: None,
            lease_expires_at: None,
        }
    }

    async fn put_delivery_if_stream_current(
        &self,
        stream: &SsfStream,
        delivery: &SsfDelivery,
    ) -> Result<bool, StoreError> {
        let stream_check = ConditionCheck::builder()
            .table_name(&self.table)
            .set_key(Some(Self::key(
                &stream.tenant_id,
                Self::stream_key(&stream.stream_id),
            )))
            .condition_expression(
                "revision = :revision AND #status = :enabled \
                 AND activation_at <= :occurred AND contains(delivered_events, :event_uri)",
            )
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(
                ":revision",
                AttributeValue::N(stream.revision.to_string()),
            )
            .expression_attribute_values(
                ":enabled",
                AttributeValue::S(SsfStreamStatus::Enabled.as_str().to_string()),
            )
            .expression_attribute_values(
                ":occurred",
                AttributeValue::N(delivery.event_occurred_at.to_string()),
            )
            .expression_attribute_values(
                ":event_uri",
                AttributeValue::S(delivery.event_uri.clone()),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("SSF stream condition build failed: {error}"))
            })?;
        let put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(Self::delivery_item(delivery)?))
            .condition_expression("attribute_not_exists(record_key)")
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("SSF delivery put build failed: {error}"))
            })?;
        send_idempotent_transaction(
            self.db
                .transact_write_items()
                .transact_items(
                    TransactWriteItem::builder()
                        .condition_check(stream_check)
                        .build(),
                )
                .transact_items(TransactWriteItem::builder().put(put).build()),
        )
        .await
    }

    async fn suppress_or_dead_letter(
        &self,
        delivery: &SsfDelivery,
        status: SsfDeliveryStatus,
        now: i64,
    ) -> Result<bool, StoreError> {
        let result = self
            .db
            .update_item()
            .table_name(&self.table)
            .set_key(Some(Self::key(
                &delivery.tenant_id,
                Self::delivery_key(
                    &delivery.stream_id,
                    delivery.stream_revision,
                    &delivery.event_id,
                ),
            )))
            .update_expression(
                "SET #status = :new_status, updated_at = :now \
                 REMOVE lease_id, lease_expires_at, due_partition, due_at",
            )
            .condition_expression(
                "#status IN (:pending, :retry_wait) AND due_at <= :now \
                 AND (attribute_not_exists(lease_expires_at) OR lease_expires_at <= :now)",
            )
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(
                ":new_status",
                AttributeValue::S(status.as_str().to_string()),
            )
            .expression_attribute_values(
                ":pending",
                AttributeValue::S(SsfDeliveryStatus::Pending.as_str().to_string()),
            )
            .expression_attribute_values(
                ":retry_wait",
                AttributeValue::S(SsfDeliveryStatus::RetryWait.as_str().to_string()),
            )
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                Ok(false)
            }
            Err(error) => Err(ddb_err(error)),
        }
    }
}

impl SsfStore for DynamoSsfStore {
    async fn create_stream(&self, stream: SsfStream) -> Result<SsfStreamCreateOutcome, StoreError> {
        for _ in 0..MAX_CAS_ATTEMPTS {
            let registry_update = Update::builder()
                .table_name(&self.table)
                .set_key(Some(Self::key(
                    &stream.tenant_id,
                    STREAM_REGISTRY_KEY.to_string(),
                )))
                .update_expression(
                    "SET #entity_type = if_not_exists(#entity_type, :registry), \
                     #registered_count = if_not_exists(#registered_count, :zero) + :one",
                )
                .condition_expression(
                    "(attribute_not_exists(record_key) AND attribute_not_exists(#entity_type) \
                     AND attribute_not_exists(#registered_count)) OR \
                     (#entity_type = :registry AND #registered_count BETWEEN :zero AND :max_before)",
                )
                .expression_attribute_names("#entity_type", "entity_type")
                .expression_attribute_names("#registered_count", "registered_stream_count")
                .expression_attribute_values(
                    ":registry",
                    AttributeValue::S(STREAM_REGISTRY_ENTITY_TYPE.to_string()),
                )
                .expression_attribute_values(":zero", AttributeValue::N("0".to_string()))
                .expression_attribute_values(":one", AttributeValue::N("1".to_string()))
                .expression_attribute_values(
                    ":max_before",
                    AttributeValue::N(
                        SSF_MAX_REGISTERED_STREAMS_PER_TENANT
                            .saturating_sub(1)
                            .to_string(),
                    ),
                )
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!(
                        "SSF stream registry update build failed: {error}"
                    ))
                })?;
            let stream_put = Put::builder()
                .table_name(&self.table)
                .set_item(Some(Self::stream_item(&stream)))
                .condition_expression("attribute_not_exists(record_key)")
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!("SSF stream put build failed: {error}"))
                })?;
            if send_idempotent_transaction(
                self.db
                    .transact_write_items()
                    .transact_items(TransactWriteItem::builder().update(registry_update).build())
                    .transact_items(TransactWriteItem::builder().put(stream_put).build()),
            )
            .await?
            {
                return Ok(SsfStreamCreateOutcome::Created(stream));
            }
            if self
                .get_stream(&stream.tenant_id, &stream.stream_id)
                .await?
                .is_some()
            {
                return Ok(SsfStreamCreateOutcome::AlreadyExists);
            }
            if self.registered_stream_count(&stream.tenant_id).await?
                == Some(
                    u32::try_from(SSF_MAX_REGISTERED_STREAMS_PER_TENANT)
                        .expect("SSF stream quota fits u32"),
                )
            {
                return Ok(SsfStreamCreateOutcome::QuotaExceeded {
                    limit: SSF_MAX_REGISTERED_STREAMS_PER_TENANT,
                });
            }
        }
        Err(StoreError::Transient(
            "SSF stream registration transaction did not converge".to_string(),
        ))
    }

    async fn get_stream(
        &self,
        tenant_id: &str,
        stream_id: &str,
    ) -> Result<Option<SsfStream>, StoreError> {
        let response = self
            .db
            .get_item()
            .table_name(&self.table)
            .set_key(Some(Self::key(tenant_id, Self::stream_key(stream_id))))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        response
            .item
            .as_ref()
            .map(|item| Self::stream_from_item(item, tenant_id, Some(stream_id)))
            .transpose()
    }

    async fn list_streams(&self, tenant_id: &str) -> Result<Vec<SsfStream>, StoreError> {
        self.query_streams(tenant_id).await
    }

    async fn mutate_stream(
        &self,
        tenant_id: &str,
        stream_id: &str,
        expected_revision: u64,
        mutation: SsfStreamMutation,
        now: i64,
    ) -> Result<SsfStreamMutationOutcome, StoreError> {
        if now <= 0 {
            return Err(StoreError::Permanent(
                "stream timestamp must be positive".to_string(),
            ));
        }
        for _ in 0..MAX_CAS_ATTEMPTS {
            let Some(current) = self.get_stream(tenant_id, stream_id).await? else {
                return Ok(SsfStreamMutationOutcome::NotFound);
            };
            let outcome = apply_stream_mutation(&current, expected_revision, &mutation, now)?;
            let updated = match outcome {
                SsfStreamMutationOutcome::Updated(updated) if updated != current => updated,
                SsfStreamMutationOutcome::Updated(updated) => {
                    return Ok(SsfStreamMutationOutcome::Updated(updated))
                }
                outcome => return Ok(outcome),
            };

            let result = self
                .db
                .update_item()
                .table_name(&self.table)
                .set_key(Some(Self::key(
                    tenant_id,
                    Self::stream_key(stream_id),
                )))
                .update_expression(
                    "SET revision = :next_revision, endpoint = :endpoint, audience = :audience, \
                     requested_events = :requested, delivered_events = :delivered, #status = :next_status, \
                     activation_at = :activation, updated_at = :now",
                )
                .condition_expression(
                    "revision = :expected_revision AND #status = :prior_status",
                )
                .expression_attribute_names("#status", "status")
                .expression_attribute_values(
                    ":next_revision",
                    AttributeValue::N(updated.revision.to_string()),
                )
                .expression_attribute_values(
                    ":endpoint",
                    AttributeValue::S(updated.endpoint.clone()),
                )
                .expression_attribute_values(
                    ":audience",
                    AttributeValue::S(updated.audience.clone()),
                )
                .expression_attribute_values(
                    ":requested",
                    Self::string_list_value(&updated.requested_events),
                )
                .expression_attribute_values(
                    ":delivered",
                    Self::string_list_value(&updated.delivered_events),
                )
                .expression_attribute_values(
                    ":next_status",
                    AttributeValue::S(updated.status.as_str().to_string()),
                )
                .expression_attribute_values(
                    ":activation",
                    AttributeValue::N(updated.activation_at.to_string()),
                )
                .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
                .expression_attribute_values(
                    ":expected_revision",
                    AttributeValue::N(current.revision.to_string()),
                )
                .expression_attribute_values(
                    ":prior_status",
                    AttributeValue::S(current.status.as_str().to_string()),
                )
                .send()
                .await;
            match result {
                Ok(_) => return Ok(SsfStreamMutationOutcome::Updated(updated)),
                Err(error)
                    if error
                        .code()
                        .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
                {
                    continue;
                }
                Err(error) => return Err(ddb_err(error)),
            }
        }
        Err(StoreError::Transient(
            "SSF stream mutation CAS did not converge".to_string(),
        ))
    }

    async fn enqueue_event(
        &self,
        event: &SecurityEvent,
        issuer: &str,
        now: i64,
    ) -> Result<Vec<SsfDelivery>, StoreError> {
        if now <= 0 {
            return Err(StoreError::Permanent(
                "delivery timestamp must be positive".to_string(),
            ));
        }
        let Some(projection) = project_security_event(event, issuer) else {
            return Ok(Vec::new());
        };
        let streams = self.query_streams(&event.tenant_id).await?;
        let mut created = Vec::new();
        for stream in streams {
            if stream.status != SsfStreamStatus::Enabled
                || event.occurred_at < stream.activation_at
                || !stream
                    .delivered_events
                    .iter()
                    .any(|event_uri| event_uri == projection.event_uri)
            {
                continue;
            }
            let delivery = Self::new_delivery(&stream, event, issuer, now)
                .expect("the event was already projected");
            if self
                .put_delivery_if_stream_current(&stream, &delivery)
                .await?
            {
                created.push(delivery);
            }
        }
        Ok(created)
    }

    async fn enqueue_verification(
        &self,
        tenant_id: &str,
        stream_id: &str,
        expected_revision: u64,
        event_id: &str,
        issuer: &str,
        state: Option<&str>,
        now: i64,
    ) -> Result<SsfVerificationOutcome, StoreError> {
        crate::ssf::validate_verification_request(event_id, state, now)
            .map_err(|error| StoreError::Permanent(error.to_string()))?;
        for _ in 0..MAX_CAS_ATTEMPTS {
            let Some(stream) = self.get_stream(tenant_id, stream_id).await? else {
                return Ok(SsfVerificationOutcome::NotFound);
            };
            if stream.revision != expected_revision {
                return Ok(SsfVerificationOutcome::RevisionConflict {
                    current_revision: stream.revision,
                });
            }
            if stream.status != SsfStreamStatus::Enabled {
                return Ok(SsfVerificationOutcome::NotEnabled);
            }
            let delivery = Self::new_verification_delivery(&stream, event_id, issuer, state, now);
            let stream_check = ConditionCheck::builder()
                .table_name(&self.table)
                .set_key(Some(Self::key(tenant_id, Self::stream_key(stream_id))))
                .condition_expression("revision = :revision AND #status = :enabled")
                .expression_attribute_names("#status", "status")
                .expression_attribute_values(
                    ":revision",
                    AttributeValue::N(stream.revision.to_string()),
                )
                .expression_attribute_values(
                    ":enabled",
                    AttributeValue::S(SsfStreamStatus::Enabled.as_str().to_string()),
                )
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!(
                        "SSF verification stream condition build failed: {error}"
                    ))
                })?;
            let put = Put::builder()
                .table_name(&self.table)
                .set_item(Some(Self::delivery_item(&delivery)?))
                .condition_expression("attribute_not_exists(record_key)")
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!(
                        "SSF verification delivery put build failed: {error}"
                    ))
                })?;
            let inserted = send_idempotent_transaction(
                self.db
                    .transact_write_items()
                    .transact_items(
                        TransactWriteItem::builder()
                            .condition_check(stream_check)
                            .build(),
                    )
                    .transact_items(TransactWriteItem::builder().put(put).build()),
            )
            .await?;
            if inserted {
                return Ok(SsfVerificationOutcome::Enqueued(delivery));
            }
            if self
                .get_delivery_consistent(tenant_id, stream_id, stream.revision, event_id)
                .await?
                .is_some()
            {
                return Err(StoreError::Permanent(
                    "verification event id already exists".to_string(),
                ));
            }
        }
        Err(StoreError::Transient(
            "SSF verification enqueue CAS did not converge".to_string(),
        ))
    }

    async fn get_delivery(
        &self,
        tenant_id: &str,
        stream_id: &str,
        stream_revision: u64,
        event_id: &str,
    ) -> Result<Option<SsfDelivery>, StoreError> {
        self.get_delivery_consistent(tenant_id, stream_id, stream_revision, event_id)
            .await
    }

    async fn list_deliveries(
        &self,
        tenant_id: &str,
        stream_id: &str,
        limit: usize,
        cursor: Option<&SsfDeliveryCursor>,
    ) -> Result<SsfDeliveryPage, StoreError> {
        if !(1..=SSF_MAX_DELIVERY_PAGE_SIZE).contains(&limit)
            || cursor.is_some_and(|cursor| {
                cursor.tenant_id != tenant_id || cursor.stream_id != stream_id
            })
        {
            return Err(StoreError::Permanent(
                "invalid SSF delivery page request".to_string(),
            ));
        }
        let stream_partition = Self::stream_partition(tenant_id, stream_id);
        let start_key = cursor.map(|cursor| {
            let mut key = Self::key(
                tenant_id,
                Self::delivery_key(stream_id, cursor.stream_revision, &cursor.event_id),
            );
            key.insert(
                "stream_partition".to_string(),
                AttributeValue::S(stream_partition.clone()),
            );
            key.insert(
                "stream_created_at".to_string(),
                AttributeValue::S(Self::stream_created_at_key(
                    cursor.created_at,
                    cursor.stream_revision,
                    &cursor.event_id,
                )),
            );
            key
        });
        let response = self
            .db
            .query()
            .table_name(&self.table)
            .index_name(STREAM_CREATED_AT_INDEX)
            .key_condition_expression("stream_partition = :stream")
            .expression_attribute_values(":stream", AttributeValue::S(stream_partition))
            .scan_index_forward(false)
            .limit(i32::try_from(limit).expect("SSF page size fits i32"))
            .set_exclusive_start_key(start_key)
            .send()
            .await
            .map_err(ddb_err)?;
        let deliveries = response
            .items()
            .iter()
            .map(|item| Self::delivery_from_item(item, Some(tenant_id), Some(stream_id)))
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = response
            .last_evaluated_key()
            .filter(|key| !key.is_empty())
            .and_then(|_| deliveries.last())
            .map(SsfDeliveryCursor::new)
            .map(|cursor| cursor.encode());
        Ok(SsfDeliveryPage {
            deliveries,
            next_cursor,
        })
    }

    async fn acquire_due(
        &self,
        now: i64,
        lease_duration_secs: i64,
        limit: usize,
    ) -> Result<Vec<SsfDeliveryLease>, StoreError> {
        if now <= 0 || !(1..=300).contains(&lease_duration_secs) || !(1..=100).contains(&limit) {
            return Err(StoreError::Permanent(
                "invalid delivery lease request".to_string(),
            ));
        }
        let mut leases = Vec::with_capacity(limit);
        let mut last_key = None;
        while leases.len() < limit {
            let response = self
                .db
                .query()
                .table_name(&self.table)
                .index_name(DUE_INDEX)
                .key_condition_expression("due_partition = :due_partition AND due_at <= :now")
                .expression_attribute_values(
                    ":due_partition",
                    AttributeValue::S(DUE_PARTITION.to_string()),
                )
                .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
                .limit(((limit - leases.len()) * 4).clamp(1, 100) as i32)
                .set_exclusive_start_key(last_key)
                .send()
                .await
                .map_err(ddb_err)?;
            if let Some(oldest_due_at) = response
                .items()
                .first()
                .map(|item| Self::required_i64(item, "due_at"))
                .transpose()?
            {
                let age = now.saturating_sub(oldest_due_at);
                if age >= 60 {
                    eprintln!(r#"{{"ssf_delivery_backlog_age_seconds":{age}}}"#);
                }
            }

            for item in response.items() {
                if leases.len() == limit {
                    break;
                }
                let mut delivery = Self::delivery_from_item(item, None, None)?;
                let stream = self
                    .get_stream(&delivery.tenant_id, &delivery.stream_id)
                    .await?;
                if stream.as_ref().is_none_or(|stream| {
                    stream.revision != delivery.stream_revision
                        || stream.status != SsfStreamStatus::Enabled
                }) {
                    self.suppress_or_dead_letter(&delivery, SsfDeliveryStatus::Suppressed, now)
                        .await?;
                    continue;
                }
                if delivery.expires_at <= now
                    || delivery_retry_window_expired(&delivery, now)
                    || now.saturating_sub(delivery.cycle_started_at) >= SSF_MAX_RETRY_AGE_SECS
                    || delivery.cycle_attempts >= SSF_MAX_ATTEMPTS_PER_CYCLE
                    || delivery.attempts >= SSF_MAX_TOTAL_ATTEMPTS
                {
                    if self
                        .suppress_or_dead_letter(&delivery, SsfDeliveryStatus::DeadLettered, now)
                        .await?
                    {
                        eprintln!(
                            "SSF_DELIVERY_FAILURE result=dead_lettered source=lease_acquisition"
                        );
                    }
                    continue;
                }
                let stream = stream.expect("checked as present");
                let lease_id = format!("lease_{}", crate::security_event::new_event_id());
                let lease_expires_at = now.saturating_add(lease_duration_secs);
                let stream_check = ConditionCheck::builder()
                    .table_name(&self.table)
                    .set_key(Some(Self::key(
                        &delivery.tenant_id,
                        Self::stream_key(&delivery.stream_id),
                    )))
                    .condition_expression("revision = :revision AND #status = :enabled")
                    .expression_attribute_names("#status", "status")
                    .expression_attribute_values(
                        ":revision",
                        AttributeValue::N(stream.revision.to_string()),
                    )
                    .expression_attribute_values(
                        ":enabled",
                        AttributeValue::S(SsfStreamStatus::Enabled.as_str().to_string()),
                    )
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!(
                            "SSF lease stream condition build failed: {error}"
                        ))
                    })?;
                let update = Update::builder()
                    .table_name(&self.table)
                    .set_key(Some(Self::key(
                        &delivery.tenant_id,
                        Self::delivery_key(
                            &delivery.stream_id,
                            delivery.stream_revision,
                            &delivery.event_id,
                        ),
                    )))
                    .update_expression(
                        "SET lease_id = :lease_id, lease_expires_at = :lease_expires, \
                         due_at = :lease_expires, updated_at = :now",
                    )
                    .condition_expression(
                        "#status IN (:pending, :retry_wait) AND due_at <= :now \
                         AND (attribute_not_exists(lease_expires_at) OR lease_expires_at <= :now)",
                    )
                    .expression_attribute_names("#status", "status")
                    .expression_attribute_values(":lease_id", AttributeValue::S(lease_id.clone()))
                    .expression_attribute_values(
                        ":lease_expires",
                        AttributeValue::N(lease_expires_at.to_string()),
                    )
                    .expression_attribute_values(
                        ":pending",
                        AttributeValue::S(SsfDeliveryStatus::Pending.as_str().to_string()),
                    )
                    .expression_attribute_values(
                        ":retry_wait",
                        AttributeValue::S(SsfDeliveryStatus::RetryWait.as_str().to_string()),
                    )
                    .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!("SSF lease update build failed: {error}"))
                    })?;
                if send_idempotent_transaction(
                    self.db
                        .transact_write_items()
                        .transact_items(
                            TransactWriteItem::builder()
                                .condition_check(stream_check)
                                .build(),
                        )
                        .transact_items(TransactWriteItem::builder().update(update).build()),
                )
                .await?
                {
                    delivery.lease_id = Some(lease_id.clone());
                    delivery.lease_expires_at = Some(lease_expires_at);
                    delivery.updated_at = now;
                    leases.push(SsfDeliveryLease {
                        delivery,
                        lease_id,
                        lease_expires_at,
                    });
                }
            }
            match response.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        Ok(leases)
    }

    async fn persist_signed_set(
        &self,
        lease: &SsfDeliveryLease,
        signed: &SignedSet,
        issued_at: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        let delivery = &lease.delivery;
        let stream_check = ConditionCheck::builder()
            .table_name(&self.table)
            .set_key(Some(Self::key(
                &delivery.tenant_id,
                Self::stream_key(&delivery.stream_id),
            )))
            .condition_expression("revision = :revision AND #status = :enabled")
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(
                ":revision",
                AttributeValue::N(delivery.stream_revision.to_string()),
            )
            .expression_attribute_values(
                ":enabled",
                AttributeValue::S(SsfStreamStatus::Enabled.as_str().to_string()),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "SSF signed SET stream condition build failed: {error}"
                ))
            })?;
        let update = Update::builder()
            .table_name(&self.table)
            .set_key(Some(Self::key(
                &delivery.tenant_id,
                Self::delivery_key(
                    &delivery.stream_id,
                    delivery.stream_revision,
                    &delivery.event_id,
                ),
            )))
            .update_expression(
                "SET compact_set = :compact_set, jti = :jti, signing_kid = :kid, \
                 issued_at = :issued_at, updated_at = :now",
            )
            .condition_expression(
                "lease_id = :lease_id AND lease_expires_at >= :now \
                 AND attribute_not_exists(compact_set) \
                 AND #status IN (:pending, :retry_wait)",
            )
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(
                ":compact_set",
                AttributeValue::S(signed.compact_jws.clone()),
            )
            .expression_attribute_values(":jti", AttributeValue::S(signed.jti.clone()))
            .expression_attribute_values(":kid", AttributeValue::S(signed.kid.clone()))
            .expression_attribute_values(":issued_at", AttributeValue::N(issued_at.to_string()))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .expression_attribute_values(":lease_id", AttributeValue::S(lease.lease_id.clone()))
            .expression_attribute_values(
                ":pending",
                AttributeValue::S(SsfDeliveryStatus::Pending.as_str().to_string()),
            )
            .expression_attribute_values(
                ":retry_wait",
                AttributeValue::S(SsfDeliveryStatus::RetryWait.as_str().to_string()),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("SSF signed SET update build failed: {error}"))
            })?;
        send_idempotent_transaction(
            self.db
                .transact_write_items()
                .transact_items(
                    TransactWriteItem::builder()
                        .condition_check(stream_check)
                        .build(),
                )
                .transact_items(TransactWriteItem::builder().update(update).build()),
        )
        .await
    }

    async fn finish_attempt(
        &self,
        lease: &SsfDeliveryLease,
        result: SsfAttemptResult,
        now: i64,
    ) -> Result<Option<SsfDelivery>, StoreError> {
        let delivery = &lease.delivery;
        let Some(mut current) = self
            .get_delivery(
                &delivery.tenant_id,
                &delivery.stream_id,
                delivery.stream_revision,
                &delivery.event_id,
            )
            .await?
        else {
            return Ok(None);
        };
        if current.lease_id.as_deref() != Some(lease.lease_id.as_str())
            || current
                .lease_expires_at
                .is_none_or(|expires_at| expires_at < now)
        {
            return Ok(None);
        }
        let prior_attempts = current.attempts;
        let prior_cycle_attempts = current.cycle_attempts;
        apply_attempt_result(&mut current, result, now);

        let active = current.status == SsfDeliveryStatus::RetryWait;
        let update_expression = if active {
            "SET #status = :status, attempts = :attempts, cycle_attempts = :cycle_attempts, \
             attempt_history = :history, updated_at = :now, next_attempt_at = :next_attempt, \
             due_partition = :due_partition, due_at = :next_attempt \
             REMOVE lease_id, lease_expires_at"
        } else {
            "SET #status = :status, attempts = :attempts, cycle_attempts = :cycle_attempts, \
             attempt_history = :history, updated_at = :now \
             REMOVE lease_id, lease_expires_at, due_partition, due_at"
        };
        let mut request = self
            .db
            .update_item()
            .table_name(&self.table)
            .set_key(Some(Self::key(
                &current.tenant_id,
                Self::delivery_key(
                    &current.stream_id,
                    current.stream_revision,
                    &current.event_id,
                ),
            )))
            .update_expression(update_expression)
            .condition_expression(
                "lease_id = :lease_id AND lease_expires_at >= :now \
                 AND attempts = :prior_attempts AND cycle_attempts = :prior_cycle_attempts",
            )
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(
                ":status",
                AttributeValue::S(current.status.as_str().to_string()),
            )
            .expression_attribute_values(
                ":attempts",
                AttributeValue::N(current.attempts.to_string()),
            )
            .expression_attribute_values(
                ":cycle_attempts",
                AttributeValue::N(current.cycle_attempts.to_string()),
            )
            .expression_attribute_values(
                ":history",
                Self::attempt_history_value(&current.attempt_history),
            )
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .expression_attribute_values(":lease_id", AttributeValue::S(lease.lease_id.clone()))
            .expression_attribute_values(
                ":prior_attempts",
                AttributeValue::N(prior_attempts.to_string()),
            )
            .expression_attribute_values(
                ":prior_cycle_attempts",
                AttributeValue::N(prior_cycle_attempts.to_string()),
            )
            .return_values(ReturnValue::AllNew);
        if active {
            request = request
                .expression_attribute_values(
                    ":next_attempt",
                    AttributeValue::N(current.next_attempt_at.to_string()),
                )
                .expression_attribute_values(
                    ":due_partition",
                    AttributeValue::S(DUE_PARTITION.to_string()),
                );
        }
        match request.send().await {
            Ok(output) => output
                .attributes
                .as_ref()
                .map(|item| {
                    Self::delivery_from_item(
                        item,
                        Some(&current.tenant_id),
                        Some(&current.stream_id),
                    )
                })
                .transpose(),
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                Ok(None)
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn redrive_delivery(
        &self,
        tenant_id: &str,
        stream_id: &str,
        stream_revision: u64,
        event_id: &str,
        now: i64,
    ) -> Result<SsfRedriveOutcome, StoreError> {
        for _ in 0..MAX_CAS_ATTEMPTS {
            let stream = self.get_stream(tenant_id, stream_id).await?;
            if stream.as_ref().is_none_or(|stream| {
                stream.status != SsfStreamStatus::Enabled || stream.revision != stream_revision
            }) {
                return Ok(SsfRedriveOutcome::StreamNotCurrent);
            }
            let Some(mut delivery) = self
                .get_delivery_consistent(tenant_id, stream_id, stream_revision, event_id)
                .await?
            else {
                return Ok(SsfRedriveOutcome::NotFound);
            };
            if !delivery_is_redriveable(&delivery, now) {
                return Ok(SsfRedriveOutcome::Expired);
            }
            if !matches!(
                delivery.status,
                SsfDeliveryStatus::Terminal | SsfDeliveryStatus::DeadLettered
            ) {
                return Ok(SsfRedriveOutcome::NotTerminal);
            }
            let prior_status = delivery.status;
            let prior_redrive_count = delivery.redrive_count;
            let stream_check = ConditionCheck::builder()
                .table_name(&self.table)
                .set_key(Some(Self::key(tenant_id, Self::stream_key(stream_id))))
                .condition_expression("revision = :revision AND #status = :enabled")
                .expression_attribute_names("#status", "status")
                .expression_attribute_values(
                    ":revision",
                    AttributeValue::N(stream_revision.to_string()),
                )
                .expression_attribute_values(
                    ":enabled",
                    AttributeValue::S(SsfStreamStatus::Enabled.as_str().to_string()),
                )
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!(
                        "SSF redrive stream condition build failed: {error}"
                    ))
                })?;
            let update = Update::builder()
                .table_name(&self.table)
                .set_key(Some(Self::key(
                    tenant_id,
                    Self::delivery_key(stream_id, stream_revision, event_id),
                )))
                .update_expression(
                    "SET #status = :pending, cycle_attempts = :zero, redrive_count = :redrive_count, \
                     cycle_started_at = :now, next_attempt_at = :now, updated_at = :now, \
                     due_partition = :due_partition, due_at = :now \
                     REMOVE lease_id, lease_expires_at",
                )
                .condition_expression(
                    "#status = :prior_status AND redrive_count = :prior_redrive_count \
                     AND expires_at > :now AND \
                     attempts < :max_attempts AND \
                     ((attribute_exists(issued_at) AND issued_at > :retry_window_start) OR \
                     (attribute_not_exists(issued_at) AND created_at > :retry_window_start))",
                )
                .expression_attribute_names("#status", "status")
                .expression_attribute_values(
                    ":pending",
                    AttributeValue::S(SsfDeliveryStatus::Pending.as_str().to_string()),
                )
                .expression_attribute_values(":zero", AttributeValue::N("0".to_string()))
                .expression_attribute_values(
                    ":redrive_count",
                    AttributeValue::N(
                        delivery.redrive_count.saturating_add(1).to_string(),
                    ),
                )
                .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
                .expression_attribute_values(
                    ":retry_window_start",
                    AttributeValue::N(now.saturating_sub(SSF_MAX_RETRY_AGE_SECS).to_string()),
                )
                .expression_attribute_values(
                    ":max_attempts",
                    AttributeValue::N(SSF_MAX_TOTAL_ATTEMPTS.to_string()),
                )
                .expression_attribute_values(
                    ":due_partition",
                    AttributeValue::S(DUE_PARTITION.to_string()),
                )
                .expression_attribute_values(
                    ":prior_status",
                    AttributeValue::S(prior_status.as_str().to_string()),
                )
                .expression_attribute_values(
                    ":prior_redrive_count",
                    AttributeValue::N(prior_redrive_count.to_string()),
                )
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!("SSF redrive update build failed: {error}"))
                })?;
            if !send_idempotent_transaction(
                self.db
                    .transact_write_items()
                    .transact_items(
                        TransactWriteItem::builder()
                            .condition_check(stream_check)
                            .build(),
                    )
                    .transact_items(TransactWriteItem::builder().update(update).build()),
            )
            .await?
            {
                continue;
            }
            delivery.status = SsfDeliveryStatus::Pending;
            delivery.cycle_attempts = 0;
            delivery.redrive_count = delivery.redrive_count.saturating_add(1);
            delivery.cycle_started_at = now;
            delivery.next_attempt_at = now;
            delivery.updated_at = now;
            delivery.lease_id = None;
            delivery.lease_expires_at = None;
            return Ok(SsfRedriveOutcome::Redriven(delivery));
        }
        Err(StoreError::Transient(
            "SSF delivery redrive CAS did not converge".to_string(),
        ))
    }

    async fn revoke_all_by_tenant(&self, tenant_id: &str, now: i64) -> Result<usize, StoreError> {
        if now <= 0 {
            return Err(StoreError::Permanent(
                "stream timestamp must be positive".to_string(),
            ));
        }
        let mut changed = 0usize;
        for stream in self.query_streams(tenant_id).await? {
            if stream.status == SsfStreamStatus::Revoked {
                continue;
            }
            match self
                .mutate_stream(
                    tenant_id,
                    &stream.stream_id,
                    stream.revision,
                    SsfStreamMutation::Revoke,
                    now,
                )
                .await?
            {
                SsfStreamMutationOutcome::Updated(_) => {
                    changed = changed.saturating_add(1);
                }
                SsfStreamMutationOutcome::Revoked => {}
                SsfStreamMutationOutcome::NotFound
                | SsfStreamMutationOutcome::RevisionConflict { .. } => {
                    return Err(StoreError::Transient(
                        "SSF governance stream revocation did not converge".to_string(),
                    ));
                }
            }
        }

        let mut last_key: Option<Item> = None;
        loop {
            let response = self
                .db
                .query()
                .table_name(&self.table)
                .key_condition_expression(
                    "tenant_id = :tenant AND begins_with(record_key, :delivery_prefix)",
                )
                .projection_expression("tenant_id, record_key, #status")
                .expression_attribute_names("#status", "status")
                .expression_attribute_values(":tenant", AttributeValue::S(tenant_id.to_string()))
                .expression_attribute_values(
                    ":delivery_prefix",
                    AttributeValue::S(DELIVERY_PREFIX.to_string()),
                )
                .consistent_read(true)
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in response.items() {
                let status = SsfDeliveryStatus::parse(Self::required_string(item, "status")?)?;
                if !matches!(
                    status,
                    SsfDeliveryStatus::Pending | SsfDeliveryStatus::RetryWait
                ) {
                    continue;
                }
                let record_key = Self::required_string(item, "record_key")?;
                let result = self
                    .db
                    .update_item()
                    .set_key(Some(Self::key(tenant_id, record_key.to_string())))
                    .table_name(&self.table)
                    .update_expression(
                        "SET #status = :suppressed, updated_at = :now \
                         REMOVE lease_id, lease_expires_at, due_partition, due_at",
                    )
                    .condition_expression("#status IN (:pending, :retry_wait)")
                    .expression_attribute_names("#status", "status")
                    .expression_attribute_values(
                        ":suppressed",
                        AttributeValue::S(SsfDeliveryStatus::Suppressed.as_str().to_string()),
                    )
                    .expression_attribute_values(
                        ":pending",
                        AttributeValue::S(SsfDeliveryStatus::Pending.as_str().to_string()),
                    )
                    .expression_attribute_values(
                        ":retry_wait",
                        AttributeValue::S(SsfDeliveryStatus::RetryWait.as_str().to_string()),
                    )
                    .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
                    .send()
                    .await;
                match result {
                    Ok(_) => changed = changed.saturating_add(1),
                    Err(error)
                        if error
                            .code()
                            .is_some_and(|code| code.contains("ConditionalCheckFailed")) => {}
                    Err(error) => return Err(ddb_err(error)),
                }
            }
            match response.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        Ok(changed)
    }
}

impl DynamoSsfStore {
    fn governance_fence_conflict(operation: &str) -> StoreError {
        StoreError::Transient(format!(
            "{operation}: governance destructive fence conflict"
        ))
    }

    fn governed_stream_revoke(
        &self,
        tenant_id: &str,
        stream: &SsfStream,
        now: i64,
    ) -> Result<TransactWriteItem, StoreError> {
        let next_revision = stream
            .revision
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("SSF stream revision exhausted".into()))?;
        let update = Update::builder()
            .table_name(&self.table)
            .set_key(Some(Self::key(
                tenant_id,
                Self::stream_key(&stream.stream_id),
            )))
            .update_expression("SET revision = :next, #status = :revoked, updated_at = :now")
            .condition_expression(
                "entity_type = :stream AND revision = :expected AND #status = :prior",
            )
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":stream", AttributeValue::S("stream".into()))
            .expression_attribute_values(
                ":expected",
                AttributeValue::N(stream.revision.to_string()),
            )
            .expression_attribute_values(":prior", AttributeValue::S(stream.status.as_str().into()))
            .expression_attribute_values(":next", AttributeValue::N(next_revision.to_string()))
            .expression_attribute_values(
                ":revoked",
                AttributeValue::S(SsfStreamStatus::Revoked.as_str().into()),
            )
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("SSF governed stream revoke build failed: {error}"))
            })?;
        Ok(TransactWriteItem::builder().update(update).build())
    }

    fn governed_delivery_suppress(
        &self,
        tenant_id: &str,
        item: &Item,
        now: i64,
    ) -> Result<Option<TransactWriteItem>, StoreError> {
        let delivery = Self::delivery_from_item(item, Some(tenant_id), None)?;
        let record_key = Self::required_string(item, "record_key")?;
        let status = delivery.status;
        if !matches!(
            status,
            SsfDeliveryStatus::Pending | SsfDeliveryStatus::RetryWait
        ) {
            return Ok(None);
        }
        let update = Update::builder()
            .table_name(&self.table)
            .set_key(Some(Self::key(tenant_id, record_key.to_string())))
            .update_expression(
                "SET #status = :suppressed, updated_at = :now \
                 REMOVE lease_id, lease_expires_at, due_partition, due_at",
            )
            .condition_expression("entity_type = :delivery AND #status = :prior")
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":delivery", AttributeValue::S("delivery".into()))
            .expression_attribute_values(":prior", AttributeValue::S(status.as_str().into()))
            .expression_attribute_values(
                ":suppressed",
                AttributeValue::S(SsfDeliveryStatus::Suppressed.as_str().into()),
            )
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "SSF governed delivery suppression build failed: {error}"
                ))
            })?;
        Ok(Some(TransactWriteItem::builder().update(update).build()))
    }

    async fn governance_delivery_rows(&self, tenant_id: &str) -> Result<Vec<Item>, StoreError> {
        let mut rows = Vec::new();
        let mut last_key = None;
        loop {
            let response = self
                .db
                .query()
                .table_name(&self.table)
                .key_condition_expression(
                    "tenant_id = :tenant AND begins_with(record_key, :delivery_prefix)",
                )
                .expression_attribute_values(":tenant", AttributeValue::S(tenant_id.into()))
                .expression_attribute_values(
                    ":delivery_prefix",
                    AttributeValue::S(DELIVERY_PREFIX.into()),
                )
                .consistent_read(true)
                .set_exclusive_start_key(last_key)
                .send()
                .await
                .map_err(ddb_err)?;
            rows.extend(response.items().iter().cloned());
            match response.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        Ok(rows)
    }

    pub(crate) async fn governance_revoke_all_by_tenant_fenced(
        &self,
        governance: &super::governance::DynamoGovernanceStore,
        logical_tenant: &str,
        data_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
    ) -> Result<usize, StoreError> {
        use super::governance::GovernanceDestructiveWriteOutcome;

        if now <= 0 {
            return Err(StoreError::Permanent(
                "stream timestamp must be positive".into(),
            ));
        }
        let mut changed = 0usize;
        for stream in self.query_streams(data_tenant).await? {
            if stream.status == SsfStreamStatus::Revoked {
                continue;
            }
            let write = self.governed_stream_revoke(data_tenant, &stream, now)?;
            match governance
                .execute_destructive_transaction(logical_tenant, fence.clone(), now, vec![write])
                .await?
            {
                GovernanceDestructiveWriteOutcome::Applied => {
                    changed = changed.saturating_add(1);
                }
                GovernanceDestructiveWriteOutcome::FenceConflict => {
                    return Err(Self::governance_fence_conflict(
                        "revoke governed SSF stream",
                    ))
                }
            }
        }

        let rows = self.governance_delivery_rows(data_tenant).await?;
        let writes = rows
            .iter()
            .map(|item| self.governed_delivery_suppress(data_tenant, item, now))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        for batch in writes.chunks(GOVERNANCE_TARGET_WRITE_BATCH) {
            match governance
                .execute_destructive_transaction(logical_tenant, fence.clone(), now, batch.to_vec())
                .await?
            {
                GovernanceDestructiveWriteOutcome::Applied => {
                    changed = changed.saturating_add(batch.len());
                }
                GovernanceDestructiveWriteOutcome::FenceConflict => {
                    return Err(Self::governance_fence_conflict(
                        "suppress governed SSF deliveries",
                    ))
                }
            }
        }
        Ok(changed)
    }

    pub(crate) async fn governance_tenant_inventory(
        &self,
        data_tenant: &str,
    ) -> Result<GovernanceSsfInventory, StoreError> {
        let mut inventory = GovernanceSsfInventory {
            live_streams: 0,
            revoked_stream_tombstones: 0,
            live_deliveries: 0,
            suppressed_delivery_tombstones: 0,
            terminal_retained_deliveries: 0,
            registry_rows: 0,
        };
        let mut last_key = None;
        loop {
            let response = self
                .db
                .query()
                .table_name(&self.table)
                .key_condition_expression("tenant_id = :tenant")
                .expression_attribute_values(":tenant", AttributeValue::S(data_tenant.to_string()))
                .consistent_read(true)
                .set_exclusive_start_key(last_key)
                .send()
                .await
                .map_err(ddb_err)?;
            for item in response.items() {
                match Self::required_string(item, "entity_type")? {
                    "stream" => {
                        let stream = Self::stream_from_item(item, data_tenant, None)?;
                        if stream.status == SsfStreamStatus::Revoked {
                            inventory.revoked_stream_tombstones =
                                inventory.revoked_stream_tombstones.saturating_add(1);
                        } else {
                            inventory.live_streams = inventory.live_streams.saturating_add(1);
                        }
                    }
                    "delivery" => {
                        let delivery = Self::delivery_from_item(item, Some(data_tenant), None)?;
                        match delivery.status {
                            SsfDeliveryStatus::Pending | SsfDeliveryStatus::RetryWait => {
                                inventory.live_deliveries =
                                    inventory.live_deliveries.saturating_add(1);
                            }
                            SsfDeliveryStatus::Suppressed => {
                                inventory.suppressed_delivery_tombstones =
                                    inventory.suppressed_delivery_tombstones.saturating_add(1);
                            }
                            SsfDeliveryStatus::Delivered
                            | SsfDeliveryStatus::Terminal
                            | SsfDeliveryStatus::DeadLettered => {
                                inventory.terminal_retained_deliveries =
                                    inventory.terminal_retained_deliveries.saturating_add(1);
                            }
                        }
                    }
                    STREAM_REGISTRY_ENTITY_TYPE => {
                        if Self::required_string(item, "record_key")? != STREAM_REGISTRY_KEY
                            || usize::try_from(Self::required_u32(item, "registered_stream_count")?)
                                .unwrap_or(usize::MAX)
                                > SSF_MAX_REGISTERED_STREAMS_PER_TENANT
                        {
                            return Err(StoreError::Permanent(
                                "SSF governance inventory found malformed stream registry".into(),
                            ));
                        }
                        inventory.registry_rows = inventory.registry_rows.saturating_add(1);
                    }
                    other => {
                        return Err(StoreError::Permanent(format!(
                            "SSF governance inventory found unknown entity type {other}"
                        )))
                    }
                }
            }
            match response.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        Ok(inventory)
    }
}

#[cfg(test)]
#[path = "ssf_tests.rs"]
mod tests;

#[cfg(test)]
mod governance_tests {
    use super::*;

    fn store() -> DynamoSsfStore {
        DynamoSsfStore::new(
            aws_sdk_dynamodb::Client::from_conf(
                aws_sdk_dynamodb::Config::builder()
                    .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
                    .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                    .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                    .build(),
            ),
            "ssf",
        )
    }

    #[test]
    fn governed_stream_revoke_keeps_a_conditioned_tombstone() {
        let write = store()
            .governed_stream_revoke(
                "tenant-1",
                &SsfStream {
                    tenant_id: "tenant-1".into(),
                    stream_id: "stream-1".into(),
                    revision: 4,
                    endpoint: "https://example.com/ssf".into(),
                    audience: "audience".into(),
                    requested_events: Vec::new(),
                    delivered_events: Vec::new(),
                    status: SsfStreamStatus::Enabled,
                    activation_at: 1,
                    created_at: 1,
                    updated_at: 1,
                },
                10,
            )
            .unwrap();
        let update = write.update().unwrap();
        assert!(update.update_expression().contains("#status = :revoked"));
        assert!(update
            .condition_expression()
            .unwrap()
            .contains("revision = :expected"));
        assert!(write.delete().is_none());
    }

    #[test]
    fn governed_delivery_suppression_is_exact_and_removes_due_authority() {
        let item = DynamoSsfStore::delivery_item(&SsfDelivery {
            tenant_id: "tenant-1".into(),
            stream_id: "stream-1".into(),
            stream_revision: 1,
            event_id: "event-1".into(),
            issuer: "https://issuer.example.com".into(),
            endpoint: "https://receiver.example.com/ssf".into(),
            audience: "https://receiver.example.com".into(),
            event_uri: SUPPORTED_EVENT_TYPES[0].into(),
            subject: serde_json::json!({"sub": "user-1"}),
            payload: serde_json::json!({}),
            status: SsfDeliveryStatus::Pending,
            attempts: 0,
            cycle_attempts: 0,
            redrive_count: 0,
            attempt_history: Vec::new(),
            event_occurred_at: 1,
            created_at: 1,
            updated_at: 1,
            cycle_started_at: 1,
            next_attempt_at: 10,
            expires_at: 100,
            compact_set: None,
            jti: None,
            signing_kid: None,
            issued_at: None,
            lease_id: None,
            lease_expires_at: None,
        })
        .unwrap();
        let write = store()
            .governed_delivery_suppress("tenant-1", &item, 10)
            .unwrap()
            .unwrap();
        let update = write.update().unwrap();
        assert!(update
            .condition_expression()
            .unwrap()
            .contains("#status = :prior"));
        assert!(update.update_expression().contains("REMOVE lease_id"));
    }

    #[test]
    fn governance_batches_leave_room_for_all_authority_checks() {
        const { assert!(GOVERNANCE_TARGET_WRITE_BATCH + 4 <= 100) };
    }
}
