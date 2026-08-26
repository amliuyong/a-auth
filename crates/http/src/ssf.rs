//! OpenID Shared Signals projection from canonical security events.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use utoipa::ToSchema;

use crate::ports::{Signer, SignerError, StoreError};
use crate::security_event::{
    SecurityEvent, SecurityEventCategory, SecurityEventOutcome, SecuritySubjectKind,
};

pub const SSF_SPEC_VERSION: &str = "1_0";
pub const RISC_ACCOUNT_DISABLED_EVENT: &str =
    "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
pub const CAEP_SESSION_REVOKED_EVENT: &str =
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
pub const CAEP_CREDENTIAL_CHANGE_EVENT: &str =
    "https://schemas.openid.net/secevent/caep/event-type/credential-change";
pub const SSF_VERIFICATION_EVENT: &str =
    "https://schemas.openid.net/secevent/ssf/event-type/verification";
pub const SUPPORTED_EVENT_TYPES: [&str; 3] = [
    RISC_ACCOUNT_DISABLED_EVENT,
    CAEP_CREDENTIAL_CHANGE_EVENT,
    CAEP_SESSION_REVOKED_EVENT,
];
pub const SSF_DELIVERY_RETENTION_SECS: i64 = 400 * 24 * 60 * 60;
pub const SSF_MAX_RETRY_AGE_SECS: i64 = 24 * 60 * 60;
pub const SSF_MAX_ATTEMPTS_PER_CYCLE: u32 = 8;
pub const SSF_MAX_TOTAL_ATTEMPTS: u32 = 64;
pub const SSF_MAX_DELIVERY_PAGE_SIZE: usize = 100;
pub const SSF_MAX_REGISTERED_STREAMS_PER_TENANT: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SsfStreamStatus {
    Enabled,
    Paused,
    Revoked,
}

impl SsfStreamStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Paused => "paused",
            Self::Revoked => "revoked",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "enabled" => Ok(Self::Enabled),
            "paused" => Ok(Self::Paused),
            "revoked" => Ok(Self::Revoked),
            _ => Err(StoreError::Permanent(format!(
                "invalid SSF stream status {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SsfStream {
    pub tenant_id: String,
    pub stream_id: String,
    pub revision: u64,
    pub endpoint: String,
    pub audience: String,
    pub requested_events: Vec<String>,
    pub delivered_events: Vec<String>,
    pub status: SsfStreamStatus,
    pub activation_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SsfDeliveryStatus {
    Pending,
    RetryWait,
    Delivered,
    Terminal,
    DeadLettered,
    Suppressed,
}

impl SsfDeliveryStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::RetryWait => "retry_wait",
            Self::Delivered => "delivered",
            Self::Terminal => "terminal",
            Self::DeadLettered => "dead_lettered",
            Self::Suppressed => "suppressed",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "pending" => Ok(Self::Pending),
            "retry_wait" => Ok(Self::RetryWait),
            "delivered" => Ok(Self::Delivered),
            "terminal" => Ok(Self::Terminal),
            "dead_lettered" => Ok(Self::DeadLettered),
            "suppressed" => Ok(Self::Suppressed),
            _ => Err(StoreError::Permanent(format!(
                "invalid SSF delivery status {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SsfDeliveryAttemptOutcome {
    Accepted,
    Retryable,
    Terminal,
}

impl SsfDeliveryAttemptOutcome {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Retryable => "retryable",
            Self::Terminal => "terminal",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "accepted" => Ok(Self::Accepted),
            "retryable" => Ok(Self::Retryable),
            "terminal" => Ok(Self::Terminal),
            _ => Err(StoreError::Permanent(format!(
                "invalid SSF attempt outcome {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SsfDeliveryAttempt {
    pub attempted_at: i64,
    pub outcome: SsfDeliveryAttemptOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub set_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_kid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SsfDelivery {
    pub tenant_id: String,
    pub stream_id: String,
    pub stream_revision: u64,
    pub event_id: String,
    pub issuer: String,
    pub endpoint: String,
    pub audience: String,
    pub event_uri: String,
    pub subject: serde_json::Value,
    pub payload: serde_json::Value,
    pub status: SsfDeliveryStatus,
    pub attempts: u32,
    pub cycle_attempts: u32,
    pub redrive_count: u32,
    pub attempt_history: Vec<SsfDeliveryAttempt>,
    pub event_occurred_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub cycle_started_at: i64,
    pub next_attempt_at: i64,
    pub expires_at: i64,
    #[serde(skip_serializing)]
    pub compact_set: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<i64>,
    #[serde(skip_serializing)]
    #[schema(ignore)]
    pub(crate) lease_id: Option<String>,
    #[serde(skip_serializing)]
    #[schema(ignore)]
    pub(crate) lease_expires_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SsfDeliveryPage {
    pub deliveries: Vec<SsfDelivery>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsfDeliveryCursor {
    pub(crate) tenant_id: String,
    pub(crate) stream_id: String,
    pub(crate) created_at: i64,
    pub(crate) stream_revision: u64,
    pub(crate) event_id: String,
}

impl SsfDeliveryCursor {
    pub(crate) fn new(delivery: &SsfDelivery) -> Self {
        Self {
            tenant_id: delivery.tenant_id.clone(),
            stream_id: delivery.stream_id.clone(),
            created_at: delivery.created_at,
            stream_revision: delivery.stream_revision,
            event_id: delivery.event_id.clone(),
        }
    }

    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(self).expect("SSF delivery cursor serialization is infallible"),
        )
    }

    pub fn decode_for_stream(
        encoded: &str,
        tenant_id: &str,
        stream_id: &str,
    ) -> Result<Self, StoreError> {
        if encoded.is_empty() || encoded.len() > 2048 {
            return Err(StoreError::Permanent(
                "invalid SSF delivery cursor".to_string(),
            ));
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| StoreError::Permanent("invalid SSF delivery cursor".to_string()))?;
        let cursor: Self = serde_json::from_slice(&decoded)
            .map_err(|_| StoreError::Permanent("invalid SSF delivery cursor".to_string()))?;
        validate_stream_identity(&cursor.tenant_id, &cursor.stream_id)
            .map_err(|_| StoreError::Permanent("invalid SSF delivery cursor".to_string()))?;
        if cursor.tenant_id != tenant_id
            || cursor.stream_id != stream_id
            || cursor.created_at <= 0
            || cursor.stream_revision == 0
            || cursor.event_id.is_empty()
            || cursor.event_id.len() > 128
            || cursor
                .event_id
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b'\x7f')
        {
            return Err(StoreError::Permanent(
                "invalid SSF delivery cursor".to_string(),
            ));
        }
        Ok(cursor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsfDeliveryLease {
    pub delivery: SsfDelivery,
    pub(crate) lease_id: String,
    pub lease_expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsfAttemptResult {
    Accepted,
    Retryable {
        status_code: Option<u16>,
        error_class: String,
    },
    Terminal {
        status_code: u16,
        error_class: String,
    },
    Fatal {
        error_class: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsfRedriveOutcome {
    Redriven(SsfDelivery),
    NotFound,
    NotTerminal,
    StreamNotCurrent,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsfVerificationOutcome {
    Enqueued(SsfDelivery),
    NotFound,
    RevisionConflict { current_revision: u64 },
    NotEnabled,
}

impl SsfVerificationOutcome {
    pub fn enqueued(self) -> Option<SsfDelivery> {
        match self {
            Self::Enqueued(delivery) => Some(delivery),
            _ => None,
        }
    }
}

impl SsfStream {
    pub fn new(
        tenant_id: impl Into<String>,
        stream_id: impl Into<String>,
        endpoint: impl Into<String>,
        audience: impl Into<String>,
        requested_events: Vec<String>,
        now: i64,
    ) -> Result<Self, &'static str> {
        let tenant_id = tenant_id.into();
        let stream_id = stream_id.into();
        let endpoint = endpoint.into();
        let audience = audience.into();
        validate_stream_identity(&tenant_id, &stream_id)?;
        validate_stream_configuration(&endpoint, &audience, &requested_events)?;
        if now <= 0 {
            return Err("stream timestamp must be positive");
        }
        let requested_events = unique_events(requested_events);
        let delivered_events = requested_events
            .iter()
            .filter(|event| SUPPORTED_EVENT_TYPES.contains(&event.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        if delivered_events.is_empty() {
            return Err("stream must request at least one supported event");
        }
        Ok(Self {
            tenant_id,
            stream_id,
            revision: 1,
            endpoint,
            audience,
            requested_events,
            delivered_events,
            status: SsfStreamStatus::Enabled,
            activation_at: now,
            created_at: now,
            updated_at: now,
        })
    }
}

fn unique_events(events: Vec<String>) -> Vec<String> {
    let mut unique = Vec::with_capacity(events.len());
    for event in events {
        if !unique.contains(&event) {
            unique.push(event);
        }
    }
    unique
}

pub(crate) fn validate_stream_identity(
    tenant_id: &str,
    stream_id: &str,
) -> Result<(), &'static str> {
    if tenant_id.is_empty()
        || tenant_id.len() > 63
        || !tenant_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("invalid stream tenant");
    }
    if stream_id.is_empty()
        || stream_id.len() > 128
        || !stream_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
    {
        return Err("invalid stream id");
    }
    Ok(())
}

pub(crate) fn validate_stream_configuration(
    endpoint: &str,
    audience: &str,
    requested_events: &[String],
) -> Result<(), &'static str> {
    if endpoint.len() > 2048 || agent_auth_ciba::validate_endpoint_url(endpoint, None).is_err() {
        return Err(
            "stream endpoint must be an HTTPS URL on port 443 without userinfo, fragment, or a private literal IP",
        );
    }
    if audience.is_empty()
        || audience.len() > 512
        || audience
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\x7f')
    {
        return Err("invalid stream audience");
    }
    if requested_events.is_empty()
        || requested_events.len() > 32
        || requested_events.iter().any(|event| {
            event.is_empty()
                || event.len() > 512
                || event
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte == b'\x7f')
        })
    {
        return Err("invalid requested event set");
    }
    Ok(())
}

pub(crate) fn validate_verification_request(
    event_id: &str,
    state: Option<&str>,
    now: i64,
) -> Result<(), &'static str> {
    if now <= 0
        || event_id.is_empty()
        || event_id.len() > 64
        || state.is_some_and(|value| {
            value.len() > 1024
                || value
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte == b'\x7f')
        })
    {
        return Err("invalid verification request");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsfStreamCreateOutcome {
    Created(SsfStream),
    AlreadyExists,
    QuotaExceeded { limit: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsfStreamMutation {
    Replace {
        endpoint: String,
        audience: String,
        requested_events: Vec<String>,
    },
    Pause,
    Resume,
    Revoke,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsfStreamMutationOutcome {
    Updated(SsfStream),
    NotFound,
    RevisionConflict { current_revision: u64 },
    Revoked,
}

impl SsfStreamMutationOutcome {
    pub fn updated(self) -> Option<SsfStream> {
        match self {
            Self::Updated(stream) => Some(stream),
            _ => None,
        }
    }
}

pub(crate) fn apply_stream_mutation(
    current: &SsfStream,
    expected_revision: u64,
    mutation: &SsfStreamMutation,
    now: i64,
) -> Result<SsfStreamMutationOutcome, StoreError> {
    if now <= 0 {
        return Err(StoreError::Permanent(
            "stream timestamp must be positive".to_string(),
        ));
    }
    if current.status == SsfStreamStatus::Revoked {
        return Ok(SsfStreamMutationOutcome::Revoked);
    }
    if current.revision != expected_revision {
        return Ok(SsfStreamMutationOutcome::RevisionConflict {
            current_revision: current.revision,
        });
    }

    let mut updated = current.clone();
    match mutation {
        SsfStreamMutation::Replace {
            endpoint,
            audience,
            requested_events,
        } => {
            validate_stream_configuration(endpoint, audience, requested_events)
                .map_err(|error| StoreError::Permanent(error.to_string()))?;
            let requested_events = unique_events(requested_events.clone());
            let delivered_events = requested_events
                .iter()
                .filter(|event| SUPPORTED_EVENT_TYPES.contains(&event.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            if delivered_events.is_empty() {
                return Err(StoreError::Permanent(
                    "stream must request at least one supported event".to_string(),
                ));
            }
            updated.endpoint = endpoint.clone();
            updated.audience = audience.clone();
            updated.requested_events = requested_events;
            updated.delivered_events = delivered_events;
            updated.status = SsfStreamStatus::Enabled;
            updated.activation_at = now;
        }
        SsfStreamMutation::Pause => {
            if current.status == SsfStreamStatus::Paused {
                return Ok(SsfStreamMutationOutcome::Updated(current.clone()));
            }
            updated.status = SsfStreamStatus::Paused;
        }
        SsfStreamMutation::Resume => {
            if current.status == SsfStreamStatus::Enabled {
                return Ok(SsfStreamMutationOutcome::Updated(current.clone()));
            }
            updated.status = SsfStreamStatus::Enabled;
            updated.activation_at = now;
        }
        SsfStreamMutation::Revoke => {
            updated.status = SsfStreamStatus::Revoked;
        }
    }
    updated.revision = current
        .revision
        .checked_add(1)
        .ok_or_else(|| StoreError::Permanent("stream revision exhausted".to_string()))?;
    updated.updated_at = now;
    Ok(SsfStreamMutationOutcome::Updated(updated))
}

pub trait SsfStore: Send + Sync {
    fn create_stream(
        &self,
        stream: SsfStream,
    ) -> impl Future<Output = Result<SsfStreamCreateOutcome, StoreError>> + Send;

    fn get_stream(
        &self,
        tenant_id: &str,
        stream_id: &str,
    ) -> impl Future<Output = Result<Option<SsfStream>, StoreError>> + Send;

    fn list_streams(
        &self,
        tenant_id: &str,
    ) -> impl Future<Output = Result<Vec<SsfStream>, StoreError>> + Send;

    fn mutate_stream(
        &self,
        tenant_id: &str,
        stream_id: &str,
        expected_revision: u64,
        mutation: SsfStreamMutation,
        now: i64,
    ) -> impl Future<Output = Result<SsfStreamMutationOutcome, StoreError>> + Send;

    fn enqueue_event(
        &self,
        event: &SecurityEvent,
        issuer: &str,
        now: i64,
    ) -> impl Future<Output = Result<Vec<SsfDelivery>, StoreError>> + Send;

    fn enqueue_verification(
        &self,
        tenant_id: &str,
        stream_id: &str,
        expected_revision: u64,
        event_id: &str,
        issuer: &str,
        state: Option<&str>,
        now: i64,
    ) -> impl Future<Output = Result<SsfVerificationOutcome, StoreError>> + Send;

    fn get_delivery(
        &self,
        tenant_id: &str,
        stream_id: &str,
        stream_revision: u64,
        event_id: &str,
    ) -> impl Future<Output = Result<Option<SsfDelivery>, StoreError>> + Send;

    fn list_deliveries(
        &self,
        tenant_id: &str,
        stream_id: &str,
        limit: usize,
        cursor: Option<&SsfDeliveryCursor>,
    ) -> impl Future<Output = Result<SsfDeliveryPage, StoreError>> + Send;

    fn acquire_due(
        &self,
        now: i64,
        lease_duration_secs: i64,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<SsfDeliveryLease>, StoreError>> + Send;

    fn persist_signed_set(
        &self,
        lease: &SsfDeliveryLease,
        signed: &SignedSet,
        issued_at: i64,
        now: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    fn finish_attempt(
        &self,
        lease: &SsfDeliveryLease,
        result: SsfAttemptResult,
        now: i64,
    ) -> impl Future<Output = Result<Option<SsfDelivery>, StoreError>> + Send;

    fn redrive_delivery(
        &self,
        tenant_id: &str,
        stream_id: &str,
        stream_revision: u64,
        event_id: &str,
        now: i64,
    ) -> impl Future<Output = Result<SsfRedriveOutcome, StoreError>> + Send;

    /// Governance-only revocation. Stream tombstones and delivery audit remain
    /// retained, while every still-deliverable row becomes suppressed.
    fn revoke_all_by_tenant(
        &self,
        tenant_id: &str,
        now: i64,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

#[derive(Debug, Clone, Default)]
pub struct MemorySsfStore {
    streams: Arc<Mutex<BTreeMap<String, BTreeMap<String, SsfStream>>>>,
    deliveries: Arc<Mutex<BTreeMap<(String, String, u64, String), SsfDelivery>>>,
}

impl SsfStore for MemorySsfStore {
    async fn create_stream(&self, stream: SsfStream) -> Result<SsfStreamCreateOutcome, StoreError> {
        let mut streams = self.streams.lock().await;
        let tenant_streams = streams.entry(stream.tenant_id.clone()).or_default();
        if tenant_streams.contains_key(&stream.stream_id) {
            return Ok(SsfStreamCreateOutcome::AlreadyExists);
        }
        if tenant_streams.len() >= SSF_MAX_REGISTERED_STREAMS_PER_TENANT {
            return Ok(SsfStreamCreateOutcome::QuotaExceeded {
                limit: SSF_MAX_REGISTERED_STREAMS_PER_TENANT,
            });
        }
        tenant_streams.insert(stream.stream_id.clone(), stream.clone());
        Ok(SsfStreamCreateOutcome::Created(stream))
    }

    async fn get_stream(
        &self,
        tenant_id: &str,
        stream_id: &str,
    ) -> Result<Option<SsfStream>, StoreError> {
        Ok(self
            .streams
            .lock()
            .await
            .get(tenant_id)
            .and_then(|streams| streams.get(stream_id))
            .cloned())
    }

    async fn list_streams(&self, tenant_id: &str) -> Result<Vec<SsfStream>, StoreError> {
        Ok(self
            .streams
            .lock()
            .await
            .get(tenant_id)
            .map(|streams| streams.values().cloned().collect())
            .unwrap_or_default())
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
        let mut streams = self.streams.lock().await;
        let Some(current) = streams
            .get_mut(tenant_id)
            .and_then(|streams| streams.get_mut(stream_id))
        else {
            return Ok(SsfStreamMutationOutcome::NotFound);
        };
        let outcome = apply_stream_mutation(current, expected_revision, &mutation, now)?;
        if let SsfStreamMutationOutcome::Updated(updated) = &outcome {
            *current = updated.clone();
        }
        Ok(outcome)
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
        let streams = self
            .streams
            .lock()
            .await
            .get(&event.tenant_id)
            .into_iter()
            .flat_map(|streams| streams.values())
            .filter(|stream| {
                stream.status == SsfStreamStatus::Enabled
                    && event.occurred_at >= stream.activation_at
                    && stream
                        .delivered_events
                        .iter()
                        .any(|event_uri| event_uri == projection.event_uri)
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut deliveries = self.deliveries.lock().await;
        let mut created = Vec::with_capacity(streams.len());
        for stream in streams {
            let key = (
                stream.tenant_id.clone(),
                stream.stream_id.clone(),
                stream.revision,
                event.event_id.clone(),
            );
            if deliveries.contains_key(&key) {
                continue;
            }
            let delivery = SsfDelivery {
                tenant_id: stream.tenant_id.clone(),
                stream_id: stream.stream_id.clone(),
                stream_revision: stream.revision,
                event_id: event.event_id.clone(),
                issuer: issuer.to_string(),
                endpoint: stream.endpoint.clone(),
                audience: stream.audience.clone(),
                event_uri: projection.event_uri.to_string(),
                subject: projection.subject.clone(),
                payload: projection.payload.clone(),
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
            };
            deliveries.insert(key, delivery.clone());
            created.push(delivery);
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
        validate_verification_request(event_id, state, now)
            .map_err(|error| StoreError::Permanent(error.to_string()))?;
        let stream = self
            .streams
            .lock()
            .await
            .get(tenant_id)
            .and_then(|streams| streams.get(stream_id))
            .cloned();
        let Some(stream) = stream else {
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
        let key = (
            tenant_id.to_string(),
            stream_id.to_string(),
            stream.revision,
            event_id.to_string(),
        );
        let mut deliveries = self.deliveries.lock().await;
        if deliveries.contains_key(&key) {
            return Err(StoreError::Permanent(
                "verification event id already exists".to_string(),
            ));
        }
        let mut payload = serde_json::Map::new();
        if let Some(state) = state {
            payload.insert(
                "state".to_string(),
                serde_json::Value::String(state.to_string()),
            );
        }
        let delivery = SsfDelivery {
            tenant_id: tenant_id.to_string(),
            stream_id: stream_id.to_string(),
            stream_revision: stream.revision,
            event_id: event_id.to_string(),
            issuer: issuer.to_string(),
            endpoint: stream.endpoint,
            audience: stream.audience,
            event_uri: SSF_VERIFICATION_EVENT.to_string(),
            subject: serde_json::json!({
                "format": "opaque",
                "id": stream_id,
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
        };
        deliveries.insert(key, delivery.clone());
        Ok(SsfVerificationOutcome::Enqueued(delivery))
    }

    async fn get_delivery(
        &self,
        tenant_id: &str,
        stream_id: &str,
        stream_revision: u64,
        event_id: &str,
    ) -> Result<Option<SsfDelivery>, StoreError> {
        Ok(self
            .deliveries
            .lock()
            .await
            .get(&(
                tenant_id.to_string(),
                stream_id.to_string(),
                stream_revision,
                event_id.to_string(),
            ))
            .cloned())
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
        let mut deliveries = self
            .deliveries
            .lock()
            .await
            .values()
            .filter(|delivery| delivery.tenant_id == tenant_id && delivery.stream_id == stream_id)
            .filter(|delivery| {
                cursor.is_none_or(|cursor| {
                    (
                        delivery.created_at,
                        delivery.stream_revision,
                        delivery.event_id.as_str(),
                    ) < (
                        cursor.created_at,
                        cursor.stream_revision,
                        cursor.event_id.as_str(),
                    )
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        deliveries.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right.stream_revision.cmp(&left.stream_revision))
                .then_with(|| right.event_id.cmp(&left.event_id))
        });
        let has_more = deliveries.len() > limit;
        deliveries.truncate(limit);
        let next_cursor = has_more
            .then(|| deliveries.last().map(SsfDeliveryCursor::new))
            .flatten()
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
        let streams = self.streams.lock().await.clone();
        let mut deliveries = self.deliveries.lock().await;
        let mut keys = deliveries
            .iter()
            .filter(|(_, delivery)| {
                matches!(
                    delivery.status,
                    SsfDeliveryStatus::Pending | SsfDeliveryStatus::RetryWait
                ) && delivery.next_attempt_at <= now
                    && delivery
                        .lease_expires_at
                        .is_none_or(|expires_at| expires_at <= now)
            })
            .map(|(key, delivery)| (key.clone(), delivery.next_attempt_at, delivery.created_at))
            .collect::<Vec<_>>();
        keys.sort_by_key(|(_, next_attempt_at, created_at)| (*next_attempt_at, *created_at));

        let mut leases = Vec::with_capacity(limit.min(keys.len()));
        for (key, _, _) in keys {
            let delivery = deliveries
                .get_mut(&key)
                .expect("delivery key came from the same locked map");
            let current_stream = streams
                .get(&delivery.tenant_id)
                .and_then(|streams| streams.get(&delivery.stream_id));
            if current_stream.is_none_or(|stream| {
                stream.revision != delivery.stream_revision
                    || stream.status != SsfStreamStatus::Enabled
            }) {
                delivery.status = SsfDeliveryStatus::Suppressed;
                delivery.updated_at = now;
                delivery.lease_id = None;
                delivery.lease_expires_at = None;
                continue;
            }
            if delivery.expires_at <= now
                || delivery_retry_window_expired(delivery, now)
                || now.saturating_sub(delivery.cycle_started_at) >= SSF_MAX_RETRY_AGE_SECS
                || delivery.cycle_attempts >= SSF_MAX_ATTEMPTS_PER_CYCLE
                || delivery.attempts >= SSF_MAX_TOTAL_ATTEMPTS
            {
                delivery.status = SsfDeliveryStatus::DeadLettered;
                delivery.updated_at = now;
                delivery.lease_id = None;
                delivery.lease_expires_at = None;
                continue;
            }
            let lease_id = format!("lease_{}", crate::security_event::new_event_id());
            let lease_expires_at = now.saturating_add(lease_duration_secs);
            delivery.lease_id = Some(lease_id.clone());
            delivery.lease_expires_at = Some(lease_expires_at);
            leases.push(SsfDeliveryLease {
                delivery: delivery.clone(),
                lease_id,
                lease_expires_at,
            });
            if leases.len() == limit {
                break;
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
        let streams = self.streams.lock().await;
        let stream = streams
            .get(&lease.delivery.tenant_id)
            .and_then(|streams| streams.get(&lease.delivery.stream_id));
        if stream.is_none_or(|stream| {
            stream.status != SsfStreamStatus::Enabled
                || stream.revision != lease.delivery.stream_revision
        }) {
            return Ok(false);
        }
        let key = delivery_key(&lease.delivery);
        let mut deliveries = self.deliveries.lock().await;
        let Some(delivery) = deliveries.get_mut(&key) else {
            return Ok(false);
        };
        if !lease_is_current(delivery, lease, now) || delivery.compact_set.is_some() {
            return Ok(false);
        }
        delivery.compact_set = Some(signed.compact_jws.clone());
        delivery.jti = Some(signed.jti.clone());
        delivery.signing_kid = Some(signed.kid.clone());
        delivery.issued_at = Some(issued_at);
        delivery.updated_at = now;
        Ok(true)
    }

    async fn finish_attempt(
        &self,
        lease: &SsfDeliveryLease,
        result: SsfAttemptResult,
        now: i64,
    ) -> Result<Option<SsfDelivery>, StoreError> {
        let key = delivery_key(&lease.delivery);
        let mut deliveries = self.deliveries.lock().await;
        let Some(delivery) = deliveries.get_mut(&key) else {
            return Ok(None);
        };
        if !lease_is_current(delivery, lease, now) {
            return Ok(None);
        }
        apply_attempt_result(delivery, result, now);
        Ok(Some(delivery.clone()))
    }

    async fn redrive_delivery(
        &self,
        tenant_id: &str,
        stream_id: &str,
        stream_revision: u64,
        event_id: &str,
        now: i64,
    ) -> Result<SsfRedriveOutcome, StoreError> {
        let current_stream = self
            .streams
            .lock()
            .await
            .get(tenant_id)
            .and_then(|streams| streams.get(stream_id))
            .cloned();
        if current_stream.is_none_or(|stream| {
            stream.status != SsfStreamStatus::Enabled || stream.revision != stream_revision
        }) {
            return Ok(SsfRedriveOutcome::StreamNotCurrent);
        }
        let key = (
            tenant_id.to_string(),
            stream_id.to_string(),
            stream_revision,
            event_id.to_string(),
        );
        let mut deliveries = self.deliveries.lock().await;
        let Some(delivery) = deliveries.get_mut(&key) else {
            return Ok(SsfRedriveOutcome::NotFound);
        };
        if !delivery_is_redriveable(delivery, now) {
            return Ok(SsfRedriveOutcome::Expired);
        }
        if !matches!(
            delivery.status,
            SsfDeliveryStatus::Terminal | SsfDeliveryStatus::DeadLettered
        ) {
            return Ok(SsfRedriveOutcome::NotTerminal);
        }
        delivery.status = SsfDeliveryStatus::Pending;
        delivery.cycle_attempts = 0;
        delivery.redrive_count = delivery.redrive_count.saturating_add(1);
        delivery.cycle_started_at = now;
        delivery.next_attempt_at = now;
        delivery.updated_at = now;
        delivery.lease_id = None;
        delivery.lease_expires_at = None;
        Ok(SsfRedriveOutcome::Redriven(delivery.clone()))
    }

    async fn revoke_all_by_tenant(&self, tenant_id: &str, now: i64) -> Result<usize, StoreError> {
        if now <= 0 {
            return Err(StoreError::Permanent(
                "stream timestamp must be positive".to_string(),
            ));
        }
        let mut changed = 0usize;
        let mut streams = self.streams.lock().await;
        if let Some(tenant_streams) = streams.get_mut(tenant_id) {
            for stream in tenant_streams.values_mut() {
                if stream.status == SsfStreamStatus::Revoked {
                    continue;
                }
                stream.revision = stream.revision.checked_add(1).ok_or_else(|| {
                    StoreError::Permanent("stream revision exhausted".to_string())
                })?;
                stream.status = SsfStreamStatus::Revoked;
                stream.updated_at = now;
                changed = changed.saturating_add(1);
            }
        }

        let mut deliveries = self.deliveries.lock().await;
        for delivery in deliveries.values_mut().filter(|delivery| {
            delivery.tenant_id == tenant_id
                && matches!(
                    delivery.status,
                    SsfDeliveryStatus::Pending | SsfDeliveryStatus::RetryWait
                )
        }) {
            delivery.status = SsfDeliveryStatus::Suppressed;
            delivery.updated_at = now;
            delivery.lease_id = None;
            delivery.lease_expires_at = None;
            changed = changed.saturating_add(1);
        }
        Ok(changed)
    }
}

fn delivery_key(delivery: &SsfDelivery) -> (String, String, u64, String) {
    (
        delivery.tenant_id.clone(),
        delivery.stream_id.clone(),
        delivery.stream_revision,
        delivery.event_id.clone(),
    )
}

fn lease_is_current(delivery: &SsfDelivery, lease: &SsfDeliveryLease, now: i64) -> bool {
    delivery.lease_id.as_deref() == Some(lease.lease_id.as_str())
        && delivery
            .lease_expires_at
            .is_some_and(|expires_at| expires_at >= now)
}

pub(crate) fn retry_backoff_secs(attempts: u32) -> i64 {
    match attempts {
        0 | 1 => 5,
        2 => 30,
        3 => 120,
        4 => 600,
        5 => 1_800,
        _ => 3_600,
    }
}

pub(crate) fn bounded_error_class(value: String) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(128)
        .collect()
}

pub(crate) fn compact_set_sha256(compact_set: &str) -> String {
    format!(
        "sha256:{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(compact_set.as_bytes()))
    )
}

pub(crate) fn apply_attempt_result(delivery: &mut SsfDelivery, result: SsfAttemptResult, now: i64) {
    delivery.attempts = delivery.attempts.saturating_add(1);
    delivery.cycle_attempts = delivery.cycle_attempts.saturating_add(1);
    delivery.updated_at = now;
    delivery.lease_id = None;
    delivery.lease_expires_at = None;

    let set_sha256 = delivery.compact_set.as_deref().map(compact_set_sha256);
    let signing_kid = delivery.signing_kid.clone();
    let (outcome, status_code, error_class, status) = match result {
        SsfAttemptResult::Accepted => (
            SsfDeliveryAttemptOutcome::Accepted,
            Some(202),
            None,
            SsfDeliveryStatus::Delivered,
        ),
        SsfAttemptResult::Retryable {
            status_code,
            error_class,
        } => {
            let next_attempt_at = now.saturating_add(retry_backoff_secs(delivery.cycle_attempts));
            let exhausted = delivery.cycle_attempts >= SSF_MAX_ATTEMPTS_PER_CYCLE
                || delivery.attempts >= SSF_MAX_TOTAL_ATTEMPTS
                || now.saturating_sub(delivery.cycle_started_at) >= SSF_MAX_RETRY_AGE_SECS
                || delivery_retry_window_expired(delivery, next_attempt_at);
            if !exhausted {
                delivery.next_attempt_at = next_attempt_at;
            }
            (
                SsfDeliveryAttemptOutcome::Retryable,
                status_code,
                Some(bounded_error_class(error_class)),
                if exhausted {
                    SsfDeliveryStatus::DeadLettered
                } else {
                    SsfDeliveryStatus::RetryWait
                },
            )
        }
        SsfAttemptResult::Terminal {
            status_code,
            error_class,
        } => (
            SsfDeliveryAttemptOutcome::Terminal,
            Some(status_code),
            Some(bounded_error_class(error_class)),
            SsfDeliveryStatus::Terminal,
        ),
        SsfAttemptResult::Fatal { error_class } => (
            SsfDeliveryAttemptOutcome::Terminal,
            None,
            Some(bounded_error_class(error_class)),
            SsfDeliveryStatus::DeadLettered,
        ),
    };
    delivery.status = status;
    if delivery.attempt_history.len() < SSF_MAX_TOTAL_ATTEMPTS as usize {
        delivery.attempt_history.push(SsfDeliveryAttempt {
            attempted_at: now,
            outcome,
            status_code,
            error_class,
            set_sha256,
            signing_kid,
        });
    }
}

pub(crate) fn delivery_retry_window_expired(delivery: &SsfDelivery, now: i64) -> bool {
    let set_window_started_at = delivery.issued_at.unwrap_or(delivery.created_at);
    now.saturating_sub(set_window_started_at) >= SSF_MAX_RETRY_AGE_SECS
}

pub(crate) fn delivery_is_redriveable(delivery: &SsfDelivery, now: i64) -> bool {
    delivery.expires_at > now
        && delivery.attempts < SSF_MAX_TOTAL_ATTEMPTS
        && !delivery_retry_window_expired(delivery, now)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SsfEventProjection {
    pub event_uri: &'static str,
    pub subject: serde_json::Value,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetSigningContext<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub stream_id: &'a str,
    pub stream_revision: u64,
    pub issued_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSet {
    pub compact_jws: String,
    pub jti: String,
    pub kid: String,
}

pub fn project_security_event(event: &SecurityEvent, issuer: &str) -> Option<SsfEventProjection> {
    if event.schema_version != crate::security_event::SECURITY_EVENT_SCHEMA_VERSION
        || event.outcome != SecurityEventOutcome::Success
        || event.subject.kind() != SecuritySubjectKind::User
    {
        return None;
    }

    let (event_uri, credential_change, session_fingerprint) =
        match (event.category, event.action.as_str()) {
            (SecurityEventCategory::UserLifecycle, "user.disable") => {
                (RISC_ACCOUNT_DISABLED_EVENT, None, None)
            }
            (SecurityEventCategory::Authentication, "session.revoke") => (
                CAEP_SESSION_REVOKED_EVENT,
                None,
                Some(event.correlation.session_fingerprint.as_deref()?),
            ),
            (SecurityEventCategory::Credential, "credential.passkey.register") => (
                CAEP_CREDENTIAL_CHANGE_EVENT,
                Some(("fido2-roaming", "create")),
                None,
            ),
            (SecurityEventCategory::Credential, "credential.passkey.delete") => (
                CAEP_CREDENTIAL_CHANGE_EVENT,
                Some(("fido2-roaming", "delete")),
                None,
            ),
            (
                SecurityEventCategory::Credential,
                "credential.password.set" | "credential.password.reset",
            ) => (
                CAEP_CREDENTIAL_CHANGE_EVENT,
                Some(("password", "update")),
                None,
            ),
            (SecurityEventCategory::Credential, "credential.recovery.rotate") => (
                CAEP_CREDENTIAL_CHANGE_EVENT,
                Some(("agent-auth-recovery-code", "update")),
                None,
            ),
            _ => return None,
        };
    let mut payload = serde_json::json!({
        "event_timestamp": event.occurred_at,
    });
    if let Some((credential_type, change_type)) = credential_change {
        payload["credential_type"] = serde_json::Value::String(credential_type.to_string());
        payload["change_type"] = serde_json::Value::String(change_type.to_string());
    }

    let user_subject = serde_json::json!({
            "format": "iss_sub",
            "iss": issuer,
            "sub": event.subject.id(),
    });
    let subject = session_fingerprint.map_or_else(
        || user_subject.clone(),
        |session_fingerprint| {
            serde_json::json!({
                "format": "complex",
                "session": {
                    "format": "opaque",
                    "id": session_fingerprint,
                },
                "user": user_subject,
                "tenant": {
                    "format": "opaque",
                    "id": event.tenant_id,
                },
            })
        },
    );

    Some(SsfEventProjection {
        event_uri,
        subject,
        payload,
    })
}

pub async fn sign_projected_set<S: Signer>(
    signer: &S,
    event: &SecurityEvent,
    projection: &SsfEventProjection,
    context: &SetSigningContext<'_>,
) -> Result<SignedSet, SignerError> {
    sign_set(
        signer,
        &event.tenant_id,
        context.stream_id,
        context.stream_revision,
        &event.event_id,
        context.issuer,
        context.audience,
        &projection.subject,
        projection.event_uri,
        &projection.payload,
        context.issued_at,
    )
    .await
}

pub async fn sign_delivery_set<S: Signer>(
    signer: &S,
    delivery: &SsfDelivery,
    issued_at: i64,
) -> Result<SignedSet, SignerError> {
    sign_set(
        signer,
        &delivery.tenant_id,
        &delivery.stream_id,
        delivery.stream_revision,
        &delivery.event_id,
        &delivery.issuer,
        &delivery.audience,
        &delivery.subject,
        &delivery.event_uri,
        &delivery.payload,
        issued_at,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn sign_set<S: Signer>(
    signer: &S,
    tenant_id: &str,
    stream_id: &str,
    stream_revision: u64,
    event_id: &str,
    issuer: &str,
    audience: &str,
    subject: &serde_json::Value,
    event_uri: &str,
    payload: &serde_json::Value,
    issued_at: i64,
) -> Result<SignedSet, SignerError> {
    let jti = stable_jti(tenant_id, stream_id, stream_revision, event_id);
    let mut events = serde_json::Map::new();
    events.insert(event_uri.to_string(), payload.clone());
    let claims = serde_json::json!({
        "iss": issuer,
        "iat": issued_at,
        "jti": jti,
        "txn": event_id,
        "aud": audience,
        "sub_id": subject,
        "events": events,
    });
    let kid = signer.active_kid().await?;
    let header = serde_json::json!({
        "alg": "ES256",
        "kid": kid,
        "typ": "secevent+jwt",
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&header)
                .map_err(|error| SignerError::Permanent(error.to_string()))?
        ),
        URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&claims)
                .map_err(|error| SignerError::Permanent(error.to_string()))?
        ),
    );
    let signature = signer.sign_es256(signing_input.as_bytes()).await?;

    Ok(SignedSet {
        compact_jws: format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature)),
        jti,
        kid,
    })
}

fn stable_jti(tenant_id: &str, stream_id: &str, stream_revision: u64, event_id: &str) -> String {
    let mut hash = Sha256::new();
    for part in [
        tenant_id.as_bytes(),
        stream_id.as_bytes(),
        &stream_revision.to_be_bytes(),
        event_id.as_bytes(),
    ] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    format!("set_{}", URL_SAFE_NO_PAD.encode(hash.finalize()))
}
