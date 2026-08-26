//! External resource lifecycle used by durable governance actions.
//!
//! Callers must first persist and claim an action in `GovernanceStore`. This
//! module verifies resource identity and performs only the named idempotent
//! control-plane operation; it never reads SecretString.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    future::Future,
    sync::Arc,
};

use tokio::sync::Mutex;

use crate::{
    governance::{resource_fingerprint, GovernanceReplicaEvidence, GovernanceRetentionEvidence},
    ports::StoreError,
};

pub const SECRET_DELETION_RECOVERY_DAYS: i64 = 7;
pub const SECRET_DELETION_OPERATION_BOUND_SECS: i64 = 5;
const SECRET_DELETION_RECOVERY_SECS: i64 = SECRET_DELETION_RECOVERY_DAYS * 24 * 60 * 60;
#[cfg(feature = "aws")]
const MAX_RETENTION_OBJECT_BYTES: i64 = 8 * 1024 * 1024;
#[cfg(feature = "aws")]
const RETENTION_S3_ROLES: [RetentionS3Role; 4] = [
    RetentionS3Role::SecurityEventArchive,
    RetentionS3Role::SecurityEventIngressFailures,
    RetentionS3Role::SecurityEventStreamFailures,
    RetentionS3Role::SsfStreamFailures,
];

#[cfg(feature = "aws")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetentionS3Role {
    SecurityEventArchive,
    SecurityEventIngressFailures,
    SecurityEventStreamFailures,
    SsfStreamFailures,
}

#[cfg(feature = "aws")]
impl RetentionS3Role {
    fn parse(role: &str) -> Result<Self, StoreError> {
        match role {
            "security_event_archive" => Ok(Self::SecurityEventArchive),
            "security_event_ingress_failures" => Ok(Self::SecurityEventIngressFailures),
            "security_event_stream_failures" => Ok(Self::SecurityEventStreamFailures),
            "ssf_stream_failures" => Ok(Self::SsfStreamFailures),
            _ => Err(StoreError::Permanent(format!(
                "unknown governance retention S3 role: {role}"
            ))),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::SecurityEventArchive => "security_event_archive",
            Self::SecurityEventIngressFailures => "security_event_ingress_failures",
            Self::SecurityEventStreamFailures => "security_event_stream_failures",
            Self::SsfStreamFailures => "ssf_stream_failures",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretDeletionStatus {
    Present,
    ReplicaRemovalRequired,
    ReplicaRemovalPending,
    Scheduled { deletion_at: i64 },
    Absent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceRetentionTarget {
    User {
        tenant_id: String,
        job_id: String,
        user_id: String,
        aliases: Vec<String>,
    },
    Tenant {
        tenant_id: String,
        job_id: String,
    },
}

#[cfg(feature = "aws")]
impl GovernanceRetentionTarget {
    fn tenant_id(&self) -> &str {
        match self {
            Self::User { tenant_id, .. } | Self::Tenant { tenant_id, .. } => tenant_id,
        }
    }

    fn job_id(&self) -> &str {
        match self {
            Self::User { job_id, .. } | Self::Tenant { job_id, .. } => job_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceRetentionRequest {
    pub target: GovernanceRetentionTarget,
    pub storage_tenant: String,
    pub configured_regions: Vec<String>,
    pub primary_erasure_at: i64,
    pub retention_anchor_at: i64,
    pub verified_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceRetentionObservation {
    pub complete: bool,
    pub replica_live_counts: BTreeMap<String, GovernanceReplicaEvidence>,
    pub retention_resources: BTreeMap<String, GovernanceRetentionEvidence>,
}

impl GovernanceRetentionObservation {
    pub fn replicas_verified_absent(&self, configured_regions: &[String]) -> bool {
        self.replica_live_counts.len() == configured_regions.len()
            && configured_regions.iter().all(|region| {
                self.replica_live_counts
                    .get(region)
                    .is_some_and(|evidence| {
                        evidence.verification_state == "provider_strong_read"
                            && evidence.live_counts.values().all(|count| *count == 0)
                    })
            })
    }

    pub fn pending_until(&self) -> Option<i64> {
        self.retention_resources
            .values()
            .filter_map(|evidence| evidence.retention_until)
            .max()
    }
}

pub trait GovernanceResourceBackend: Send + Sync {
    fn schedule_secret_deletion(
        &self,
        secret_ref: &str,
        expected_fingerprint: &str,
        now: i64,
    ) -> impl Future<Output = Result<SecretDeletionStatus, StoreError>> + Send;

    fn inspect_secret_deletion(
        &self,
        secret_ref: &str,
        expected_fingerprint: &str,
    ) -> impl Future<Output = Result<SecretDeletionStatus, StoreError>> + Send;

    fn verify_replicas(
        &self,
        request: GovernanceRetentionRequest,
    ) -> impl Future<Output = Result<Option<BTreeMap<String, GovernanceReplicaEvidence>>, StoreError>>
           + Send;

    fn verify_retention(
        &self,
        request: GovernanceRetentionRequest,
    ) -> impl Future<Output = Result<Option<GovernanceRetentionObservation>, StoreError>> + Send;
}

#[derive(Debug, Clone)]
struct MemorySecret {
    fingerprint: String,
    deletion_at: Option<i64>,
    replica_regions: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemorySecretScheduleFault {
    BeforeCommit,
    AfterCommit,
    AfterReplicaRemoval,
}

#[derive(Default)]
struct MemoryGovernanceResourceState {
    secrets: HashMap<String, MemorySecret>,
    schedule_attempts: HashMap<String, u64>,
    next_schedule_fault: Option<MemorySecretScheduleFault>,
}

#[derive(Clone, Default)]
pub struct MemoryGovernanceResourceBackend {
    state: Arc<Mutex<MemoryGovernanceResourceState>>,
}

impl MemoryGovernanceResourceBackend {
    pub async fn insert_secret(&self, secret_ref: &str) {
        self.state.lock().await.secrets.insert(
            secret_ref.to_string(),
            MemorySecret {
                fingerprint: resource_fingerprint(secret_ref),
                deletion_at: None,
                replica_regions: BTreeSet::new(),
            },
        );
    }

    #[cfg(test)]
    pub async fn insert_replicated_secret(&self, secret_ref: &str, replica_regions: &[&str]) {
        self.state.lock().await.secrets.insert(
            secret_ref.to_string(),
            MemorySecret {
                fingerprint: resource_fingerprint(secret_ref),
                deletion_at: None,
                replica_regions: replica_regions
                    .iter()
                    .map(|region| (*region).to_string())
                    .collect(),
            },
        );
    }

    #[cfg(test)]
    pub async fn remove_secret(&self, secret_ref: &str) {
        self.state.lock().await.secrets.remove(secret_ref);
    }

    pub async fn fail_next_schedule(&self, fault: MemorySecretScheduleFault) {
        self.state.lock().await.next_schedule_fault = Some(fault);
    }

    pub async fn schedule_attempts(&self, secret_ref: &str) -> u64 {
        self.state
            .lock()
            .await
            .schedule_attempts
            .get(secret_ref)
            .copied()
            .unwrap_or(0)
    }
}

impl GovernanceResourceBackend for MemoryGovernanceResourceBackend {
    async fn schedule_secret_deletion(
        &self,
        secret_ref: &str,
        expected_fingerprint: &str,
        now: i64,
    ) -> Result<SecretDeletionStatus, StoreError> {
        let mut state = self.state.lock().await;
        let next_attempt = state
            .schedule_attempts
            .get(secret_ref)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("secret schedule attempts exhausted".into()))?;
        state
            .schedule_attempts
            .insert(secret_ref.to_string(), next_attempt);
        let fault = state.next_schedule_fault.take();
        let Some(secret) = state.secrets.get_mut(secret_ref) else {
            return Ok(SecretDeletionStatus::Absent);
        };
        if secret.fingerprint != expected_fingerprint {
            return Err(StoreError::Permanent(
                "secret resource fingerprint mismatch".into(),
            ));
        }
        if fault == Some(MemorySecretScheduleFault::BeforeCommit) {
            return Err(StoreError::Transient(
                "injected Secret deletion failure before commit".into(),
            ));
        }
        if !secret.replica_regions.is_empty() {
            secret.replica_regions.clear();
            if fault == Some(MemorySecretScheduleFault::AfterReplicaRemoval) {
                return Err(StoreError::Transient(
                    "injected ambiguous Secret replica removal outcome".into(),
                ));
            }
            return Ok(SecretDeletionStatus::ReplicaRemovalPending);
        }
        let deletion_at = *secret
            .deletion_at
            .get_or_insert(now.saturating_add(SECRET_DELETION_RECOVERY_SECS));
        if fault == Some(MemorySecretScheduleFault::AfterCommit) {
            return Err(StoreError::Transient(
                "injected ambiguous Secret deletion outcome".into(),
            ));
        }
        Ok(SecretDeletionStatus::Scheduled { deletion_at })
    }

    async fn inspect_secret_deletion(
        &self,
        secret_ref: &str,
        expected_fingerprint: &str,
    ) -> Result<SecretDeletionStatus, StoreError> {
        let state = self.state.lock().await;
        let Some(secret) = state.secrets.get(secret_ref) else {
            return Ok(SecretDeletionStatus::Absent);
        };
        if secret.fingerprint != expected_fingerprint {
            return Err(StoreError::Permanent(
                "secret resource fingerprint mismatch".into(),
            ));
        }
        Ok(match secret.deletion_at {
            Some(deletion_at) => SecretDeletionStatus::Scheduled { deletion_at },
            None if !secret.replica_regions.is_empty() => {
                SecretDeletionStatus::ReplicaRemovalRequired
            }
            None => SecretDeletionStatus::Present,
        })
    }

    async fn verify_retention(
        &self,
        _request: GovernanceRetentionRequest,
    ) -> Result<Option<GovernanceRetentionObservation>, StoreError> {
        Ok(None)
    }

    async fn verify_replicas(
        &self,
        _request: GovernanceRetentionRequest,
    ) -> Result<Option<BTreeMap<String, GovernanceReplicaEvidence>>, StoreError> {
        Ok(None)
    }
}

#[derive(Clone)]
pub enum GovernanceResourceBackendImpl {
    Memory(MemoryGovernanceResourceBackend),
    #[cfg(feature = "aws")]
    SecretsManager(AwsGovernanceResourceBackend),
}

impl GovernanceResourceBackend for GovernanceResourceBackendImpl {
    async fn schedule_secret_deletion(
        &self,
        secret_ref: &str,
        expected_fingerprint: &str,
        now: i64,
    ) -> Result<SecretDeletionStatus, StoreError> {
        match self {
            Self::Memory(backend) => {
                backend
                    .schedule_secret_deletion(secret_ref, expected_fingerprint, now)
                    .await
            }
            #[cfg(feature = "aws")]
            Self::SecretsManager(backend) => {
                backend
                    .schedule_secret_deletion(secret_ref, expected_fingerprint, now)
                    .await
            }
        }
    }

    async fn inspect_secret_deletion(
        &self,
        secret_ref: &str,
        expected_fingerprint: &str,
    ) -> Result<SecretDeletionStatus, StoreError> {
        match self {
            Self::Memory(backend) => {
                backend
                    .inspect_secret_deletion(secret_ref, expected_fingerprint)
                    .await
            }
            #[cfg(feature = "aws")]
            Self::SecretsManager(backend) => {
                backend
                    .inspect_secret_deletion(secret_ref, expected_fingerprint)
                    .await
            }
        }
    }

    async fn verify_retention(
        &self,
        request: GovernanceRetentionRequest,
    ) -> Result<Option<GovernanceRetentionObservation>, StoreError> {
        match self {
            Self::Memory(backend) => backend.verify_retention(request).await,
            #[cfg(feature = "aws")]
            Self::SecretsManager(backend) => backend.verify_retention(request).await,
        }
    }

    async fn verify_replicas(
        &self,
        request: GovernanceRetentionRequest,
    ) -> Result<Option<BTreeMap<String, GovernanceReplicaEvidence>>, StoreError> {
        match self {
            Self::Memory(backend) => backend.verify_replicas(request).await,
            #[cfg(feature = "aws")]
            Self::SecretsManager(backend) => backend.verify_replicas(request).await,
        }
    }
}

#[cfg(feature = "aws")]
#[derive(Debug, Clone, serde::Deserialize)]
struct AwsGovernanceRetentionConfig {
    replicated_tables: BTreeMap<String, String>,
    backup_vault_name: String,
    recovery_table_arns: Vec<String>,
    s3_buckets: BTreeMap<String, String>,
    log_groups: BTreeMap<String, String>,
    queue_urls: BTreeMap<String, String>,
}

#[cfg(feature = "aws")]
struct ReplicaScanObservation {
    evidence: BTreeMap<String, GovernanceReplicaEvidence>,
    retained_until: Option<i64>,
}

#[cfg(feature = "aws")]
impl AwsGovernanceRetentionConfig {
    fn parse(value: Option<&str>) -> Result<Option<Self>, String> {
        let Some(value) = value.filter(|value| !value.trim().is_empty()) else {
            return Ok(None);
        };
        let config: Self = serde_json::from_str(value)
            .map_err(|error| format!("GOVERNANCE_RETENTION_CONFIG invalid JSON: {error}"))?;
        if config.replicated_tables.is_empty()
            || config.backup_vault_name.is_empty()
            || config.recovery_table_arns.is_empty()
            || config.s3_buckets.is_empty()
            || config.log_groups.is_empty()
            || config.queue_urls.is_empty()
            || config
                .replicated_tables
                .iter()
                .any(|(role, table)| role.is_empty() || table.is_empty())
            || config
                .s3_buckets
                .iter()
                .any(|(role, bucket)| role.is_empty() || bucket.is_empty())
            || config.s3_buckets.len() != RETENTION_S3_ROLES.len()
            || RETENTION_S3_ROLES
                .iter()
                .any(|role| !config.s3_buckets.contains_key(role.as_str()))
            || config
                .log_groups
                .iter()
                .any(|(role, group)| role.is_empty() || group.is_empty())
            || config
                .queue_urls
                .iter()
                .any(|(role, queue)| role.is_empty() || queue.is_empty())
            || config.recovery_table_arns.iter().any(|arn| {
                arn.is_empty() || !arn.contains(":dynamodb:") || !arn.contains(":table/")
            })
        {
            return Err("GOVERNANCE_RETENTION_CONFIG is incomplete".into());
        }
        Ok(Some(config))
    }
}

#[cfg(feature = "aws")]
fn attribute_strings<'a>(
    value: &'a aws_sdk_dynamodb::types::AttributeValue,
    strings: &mut Vec<&'a str>,
) {
    use aws_sdk_dynamodb::types::AttributeValue;

    match value {
        AttributeValue::S(value) => strings.push(value),
        AttributeValue::Ss(values) => strings.extend(values.iter().map(String::as_str)),
        AttributeValue::L(values) => {
            for value in values {
                attribute_strings(value, strings);
            }
        }
        AttributeValue::M(values) => {
            for value in values.values() {
                attribute_strings(value, strings);
            }
        }
        _ => {}
    }
}

#[cfg(feature = "aws")]
fn plain_json_strings<'a>(value: &'a serde_json::Value, strings: &mut Vec<&'a str>) {
    match value {
        serde_json::Value::String(value) => strings.push(value),
        serde_json::Value::Array(values) => {
            for value in values {
                plain_json_strings(value, strings);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values() {
                plain_json_strings(value, strings);
            }
        }
        _ => {}
    }
}

#[cfg(feature = "aws")]
fn security_event_archive_prefix(tenant_id: &str) -> String {
    format!("security-events/tenant_id={tenant_id}/")
}

#[cfg(feature = "aws")]
fn security_event_log_filter(tenant_id: &str) -> String {
    format!("\"tenant={tenant_id}\"")
}

#[cfg(feature = "aws")]
fn cloudwatch_retention_end_time(
    target: &GovernanceRetentionTarget,
    retention_anchor_at: i64,
) -> Option<i64> {
    matches!(target, GovernanceRetentionTarget::User { .. })
        .then(|| retention_anchor_at.saturating_mul(1_000))
}

#[cfg(feature = "aws")]
fn sqs_queue_retention_complete(
    elapsed: i64,
    retention: i64,
    visible: i64,
    in_flight: i64,
    delayed: i64,
) -> Result<bool, StoreError> {
    if retention <= 0
        || retention > crate::governance_worker::INCIDENT_QUEUE_RETENTION_SECS
        || visible < 0
        || in_flight < 0
        || delayed < 0
    {
        return Err(StoreError::Permanent(
            "SQS retention verification returned invalid queue attributes".into(),
        ));
    }
    Ok(elapsed >= retention && visible == 0 && in_flight == 0 && delayed == 0)
}

#[cfg(feature = "aws")]
fn archive_event_matches_retention_target(
    event: &crate::security_event::SecurityEvent,
    target: &GovernanceRetentionTarget,
    retention_anchor_at: i64,
) -> bool {
    if event.tenant_id != target.tenant_id() {
        return false;
    }
    if event.occurred_at > retention_anchor_at {
        return false;
    }
    if event.correlation.operation_id.as_deref() == Some(target.job_id()) {
        return true;
    }
    match target {
        GovernanceRetentionTarget::Tenant { .. } => true,
        GovernanceRetentionTarget::User { user_id, .. } => {
            event.subject.kind() == crate::security_event::SecuritySubjectKind::User
                && event.subject.id() == user_id
        }
    }
}

#[cfg(feature = "aws")]
fn security_event_item_matches_retention_target(
    item: &HashMap<String, aws_sdk_dynamodb::types::AttributeValue>,
    target: &GovernanceRetentionTarget,
    retention_anchor_at: i64,
) -> Result<bool, StoreError> {
    let envelope = item
        .get("envelope")
        .and_then(|value| value.as_s().ok())
        .ok_or_else(|| {
            StoreError::Permanent("security event retention row has no envelope".into())
        })?;
    let event: crate::security_event::SecurityEvent =
        serde_json::from_str(envelope).map_err(|error| {
            StoreError::Permanent(format!(
                "security event retention row has an invalid envelope: {error}"
            ))
        })?;
    Ok(archive_event_matches_retention_target(
        &event,
        target,
        retention_anchor_at,
    ))
}

#[cfg(feature = "aws")]
impl RetentionS3Role {
    fn prefix(self, target: &GovernanceRetentionTarget) -> Option<String> {
        match self {
            Self::SecurityEventArchive => Some(security_event_archive_prefix(target.tenant_id())),
            Self::SecurityEventIngressFailures => Some("security-event-ingress-failures/".into()),
            Self::SecurityEventStreamFailures | Self::SsfStreamFailures => None,
        }
    }

    fn object_matches(
        self,
        body: &[u8],
        target: &GovernanceRetentionTarget,
        retention_anchor_at: i64,
        object_modified_at: i64,
    ) -> Result<bool, StoreError> {
        let matches_event = |event: &crate::security_event::SecurityEvent| {
            archive_event_matches_retention_target(event, target, retention_anchor_at)
        };
        match self {
            Self::SecurityEventArchive => {
                let event =
                    crate::security_event_archive::archive_object_event(body).map_err(|error| {
                        StoreError::Permanent(format!(
                            "S3 retention archive validation failed: {error}"
                        ))
                    })?;
                if event.tenant_id != target.tenant_id() {
                    return Err(StoreError::Permanent(
                        "security-event archive object crossed its tenant prefix".into(),
                    ));
                }
                Ok(matches_event(&event))
            }
            Self::SecurityEventIngressFailures => {
                let encoded = std::str::from_utf8(body).map_err(|error| {
                    StoreError::Permanent(format!(
                        "S3 retention ingress quarantine is not UTF-8: {error}"
                    ))
                })?;
                match crate::security_event_archive::parse_ingress_event(encoded) {
                    Ok(ingress) => Ok(matches_event(&ingress.event)),
                    Err(_) => Ok(object_modified_at <= retention_anchor_at),
                }
            }
            Self::SecurityEventStreamFailures | Self::SsfStreamFailures => {
                let payload: serde_json::Value = match serde_json::from_slice(body) {
                    Ok(payload) => payload,
                    Err(_) => return Ok(object_modified_at <= retention_anchor_at),
                };
                let records =
                    match crate::security_event_archive::parse_failed_stream_invocation(&payload) {
                        Ok(records) => records,
                        Err(_) => return Ok(object_modified_at <= retention_anchor_at),
                    };
                for record in records {
                    let event: crate::security_event::SecurityEvent =
                        serde_json::from_str(&record.envelope).map_err(|error| {
                            StoreError::Permanent(format!(
                                "S3 retention stream failure contains an invalid event: {error}"
                            ))
                        })?;
                    if matches_event(&event) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }
}

#[cfg(feature = "aws")]
fn json_tenant_claims(
    value: &serde_json::Value,
    logical: &mut std::collections::BTreeSet<String>,
    physical: &mut std::collections::BTreeSet<String>,
) {
    match value {
        serde_json::Value::String(value) => {
            if let Some((tenant, logical_id)) = value.split_once(crate::tenant::SEP) {
                if !tenant.is_empty() && !logical_id.is_empty() {
                    physical.insert(tenant.to_string());
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                json_tenant_claims(value, logical, physical);
            }
        }
        serde_json::Value::Object(values) => {
            for (name, value) in values {
                if matches!(name.as_str(), "tenant" | "tenant_id") {
                    if let Some(value) = value.as_str() {
                        logical.insert(value.to_string());
                    }
                }
                json_tenant_claims(value, logical, physical);
            }
        }
        _ => {}
    }
}

#[cfg(feature = "aws")]
fn item_matches_retention_target(
    item: &HashMap<String, aws_sdk_dynamodb::types::AttributeValue>,
    target: &GovernanceRetentionTarget,
    storage_tenant: &str,
) -> Result<bool, StoreError> {
    const TENANT_FIELDS: &[&str] = &["tenant", "tenant_id"];
    const JSON_FIELDS: &[&str] = &[
        "binding_json",
        "config_json",
        "cred_json",
        "envelope",
        "grant_json",
        "record",
        "record_json",
    ];

    let tenant_id = target.tenant_id();
    let storage_prefix =
        (!storage_tenant.is_empty()).then(|| format!("{storage_tenant}{}", crate::tenant::SEP));
    let mut logical_claims = std::collections::BTreeSet::new();
    let mut physical_claims = std::collections::BTreeSet::new();
    for name in TENANT_FIELDS {
        let mut strings = Vec::new();
        if let Some(value) = item.get(*name) {
            attribute_strings(value, &mut strings);
        }
        logical_claims.extend(strings.into_iter().map(str::to_string));
    }
    for value in item.values() {
        let mut strings = Vec::new();
        attribute_strings(value, &mut strings);
        for value in strings {
            if let Some((tenant, logical_id)) = value.split_once(crate::tenant::SEP) {
                if !tenant.is_empty() && !logical_id.is_empty() {
                    physical_claims.insert(tenant.to_string());
                }
            }
        }
    }

    let mut candidates = Vec::new();
    if let GovernanceRetentionTarget::User {
        user_id, aliases, ..
    } = target
    {
        candidates.push(user_id.as_str());
        candidates.extend(aliases.iter().map(String::as_str));
    }
    let matches_string = |value: &str| match (target, storage_prefix.as_deref()) {
        (GovernanceRetentionTarget::Tenant { .. }, None) => true,
        (GovernanceRetentionTarget::Tenant { .. }, Some(prefix)) => {
            value == tenant_id || value.starts_with(prefix)
        }
        (GovernanceRetentionTarget::User { .. }, _) => candidates.iter().any(|candidate| {
            value == *candidate
                || storage_prefix
                    .as_deref()
                    .and_then(|prefix| value.strip_prefix(prefix))
                    .is_some_and(|logical| logical == *candidate)
        }),
    };

    let mut content_matches =
        matches!(target, GovernanceRetentionTarget::Tenant { .. }) && storage_tenant.is_empty();
    for value in item.values() {
        let mut strings = Vec::new();
        attribute_strings(value, &mut strings);
        if strings.into_iter().any(&matches_string) {
            content_matches = true;
            break;
        }
    }
    for name in JSON_FIELDS {
        let Some(aws_sdk_dynamodb::types::AttributeValue::S(encoded)) = item.get(*name) else {
            continue;
        };
        let decoded: serde_json::Value = serde_json::from_str(encoded).map_err(|error| {
            StoreError::Permanent(format!(
                "retention verification found invalid {name}: {error}"
            ))
        })?;
        json_tenant_claims(&decoded, &mut logical_claims, &mut physical_claims);
        let mut strings = Vec::new();
        plain_json_strings(&decoded, &mut strings);
        if strings.into_iter().any(&matches_string) {
            content_matches = true;
        }
    }
    if !content_matches {
        return Ok(false);
    }

    let logical_matches = logical_claims.iter().any(|claim| claim == tenant_id);
    let logical_conflicts = logical_claims.iter().any(|claim| claim != tenant_id);
    let physical_matches =
        !storage_tenant.is_empty() && physical_claims.iter().any(|claim| claim == storage_tenant);
    let physical_conflicts = if storage_tenant.is_empty() {
        !physical_claims.is_empty()
    } else {
        physical_claims.iter().any(|claim| claim != storage_tenant)
    };
    if (logical_matches || physical_matches) && (logical_conflicts || physical_conflicts) {
        return Err(StoreError::Permanent(
            "retention verification found mixed tenant authority".into(),
        ));
    }
    if logical_conflicts || physical_conflicts {
        return Ok(false);
    }
    if storage_tenant.is_empty() || logical_matches || physical_matches {
        return Ok(true);
    }
    Err(StoreError::Permanent(
        "retention verification matched an unscoped partitioned row".into(),
    ))
}

#[cfg(feature = "aws")]
fn tenant_key_item_is_live(
    item: &HashMap<String, aws_sdk_dynamodb::types::AttributeValue>,
    target: &GovernanceRetentionTarget,
    storage_tenant: &str,
) -> Result<bool, StoreError> {
    if !matches!(target, GovernanceRetentionTarget::Tenant { .. })
        || !item_matches_retention_target(item, target, storage_tenant)?
    {
        return Ok(false);
    }
    let encoded = item
        .get("record_json")
        .and_then(|value| value.as_s().ok())
        .ok_or_else(|| {
            StoreError::Permanent("tenant key retention verification found no record_json".into())
        })?;
    let record: agent_auth_infra_core::TenantKeyRecord =
        serde_json::from_str(encoded).map_err(|error| {
            StoreError::Permanent(format!(
                "tenant key retention verification found invalid record_json: {error}"
            ))
        })?;
    if record.tenant_id != target.tenant_id() {
        return Err(StoreError::Permanent(
            "tenant key retention verification found mismatched tenant identity".into(),
        ));
    }
    let retained_control_only = record.lifecycle
        == agent_auth_infra_core::TenantKeyLifecycle::Offboarded
        && record.served_snapshot.is_none()
        && record.operation.is_none()
        && record.last_failure.is_none()
        && record.pending_deletion_arns.is_empty()
        && record
            .offboarding_operation_id
            .as_deref()
            .is_some_and(|operation_id| !operation_id.is_empty());
    Ok(!retained_control_only)
}

#[cfg(feature = "aws")]
#[derive(Clone)]
pub struct AwsGovernanceResourceBackend {
    config: aws_config::SdkConfig,
    secrets: aws_sdk_secretsmanager::Client,
    backup: aws_sdk_backup::Client,
    logs: aws_sdk_cloudwatchlogs::Client,
    s3: aws_sdk_s3::Client,
    sqs: aws_sdk_sqs::Client,
    retention: Option<AwsGovernanceRetentionConfig>,
}

#[cfg(feature = "aws")]
struct AwsSecretDescription {
    status: SecretDeletionStatus,
    replica_regions: Vec<String>,
}

#[cfg(feature = "aws")]
impl AwsGovernanceResourceBackend {
    pub fn new(
        config: &aws_config::SdkConfig,
        retention_config: Option<&str>,
    ) -> Result<Self, String> {
        let timeout = aws_config::timeout::TimeoutConfig::builder()
            .operation_timeout(std::time::Duration::from_secs(
                SECRET_DELETION_OPERATION_BOUND_SECS as u64,
            ))
            .build();
        let secrets_config = aws_sdk_secretsmanager::config::Builder::from(config)
            .timeout_config(timeout)
            .build();
        Ok(Self {
            config: config.clone(),
            secrets: aws_sdk_secretsmanager::Client::from_conf(secrets_config),
            backup: aws_sdk_backup::Client::new(config),
            logs: aws_sdk_cloudwatchlogs::Client::new(config),
            s3: aws_sdk_s3::Client::new(config),
            sqs: aws_sdk_sqs::Client::new(config),
            retention: AwsGovernanceRetentionConfig::parse(retention_config)?,
        })
    }

    async fn describe(
        &self,
        secret_ref: &str,
        expected_fingerprint: &str,
    ) -> Result<AwsSecretDescription, StoreError> {
        use aws_sdk_secretsmanager::error::ProvideErrorMetadata;

        let output = match self
            .secrets
            .describe_secret()
            .secret_id(secret_ref)
            .send()
            .await
        {
            Ok(output) => output,
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ResourceNotFound")) =>
            {
                return Ok(AwsSecretDescription {
                    status: SecretDeletionStatus::Absent,
                    replica_regions: Vec::new(),
                })
            }
            Err(error) => return Err(secret_error(error)),
        };
        let arn = output
            .arn()
            .ok_or_else(|| StoreError::Permanent("DescribeSecret returned no ARN".into()))?;
        if arn != secret_ref || resource_fingerprint(arn) != expected_fingerprint {
            return Err(StoreError::Permanent(
                "secret resource fingerprint mismatch".into(),
            ));
        }
        let replica_regions: Vec<String> = output
            .replication_status()
            .iter()
            .map(|replica| {
                replica.region().map(str::to_string).ok_or_else(|| {
                    StoreError::Permanent(
                        "DescribeSecret returned a replica without its Region".into(),
                    )
                })
            })
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?
            .into_iter()
            .collect();
        let status = if let Some(date) = output.deleted_date() {
            // DescribeSecret reports when deletion was requested, not the recovery deadline.
            SecretDeletionStatus::Scheduled {
                deletion_at: date.secs().saturating_add(SECRET_DELETION_RECOVERY_SECS),
            }
        } else if replica_regions.is_empty() {
            SecretDeletionStatus::Present
        } else {
            SecretDeletionStatus::ReplicaRemovalRequired
        };
        Ok(AwsSecretDescription {
            status,
            replica_regions,
        })
    }

    async fn replica_counts(
        &self,
        config: &AwsGovernanceRetentionConfig,
        request: &GovernanceRetentionRequest,
    ) -> Result<ReplicaScanObservation, StoreError> {
        let mut observations = BTreeMap::new();
        let mut retained_until = None;
        for region in &request.configured_regions {
            let regional = aws_sdk_dynamodb::config::Builder::from(&self.config)
                .region(aws_sdk_dynamodb::config::Region::new(region.clone()))
                .build();
            let db = aws_sdk_dynamodb::Client::from_conf(regional);
            let mut live_counts = BTreeMap::new();
            let mut retained_counts = BTreeMap::new();
            for (role, table) in &config.replicated_tables {
                if matches!(role.as_str(), "governance" | "governance_suppression") {
                    continue;
                }
                let mut count = 0_u64;
                let mut start_key = None;
                loop {
                    let output = db
                        .scan()
                        .table_name(table)
                        .consistent_read(true)
                        .set_exclusive_start_key(start_key)
                        .send()
                        .await
                        .map_err(|error| {
                            StoreError::Transient(format!(
                                "regional DynamoDB retention scan failed: {error}"
                            ))
                        })?;
                    for item in output.items() {
                        let live = if role == "security_events" {
                            security_event_item_matches_retention_target(
                                item,
                                &request.target,
                                request.retention_anchor_at,
                            )?
                        } else if role == "tenant_keys" {
                            tenant_key_item_is_live(item, &request.target, &request.storage_tenant)?
                        } else {
                            item_matches_retention_target(
                                item,
                                &request.target,
                                &request.storage_tenant,
                            )?
                        };
                        if live && role == "security_events" {
                            let expires_at = item
                                .get("expires_at")
                                .and_then(|value| value.as_n().ok())
                                .and_then(|value| value.parse::<i64>().ok())
                                .ok_or_else(|| {
                                    StoreError::Permanent(
                                        "security event retention row has no valid expires_at"
                                            .into(),
                                    )
                                })?;
                            retained_until =
                                Some(retained_until.unwrap_or(i64::MIN).max(expires_at));
                            count = count.saturating_add(1);
                        } else if live {
                            count = count.saturating_add(1);
                        }
                    }
                    match output.last_evaluated_key() {
                        Some(key) if !key.is_empty() => start_key = Some(key.clone()),
                        _ => break,
                    }
                }
                if role == "security_events" {
                    retained_counts.insert(role.clone(), count);
                } else {
                    live_counts.insert(role.clone(), count);
                }
            }
            observations.insert(
                region.clone(),
                GovernanceReplicaEvidence {
                    verification_state: "provider_strong_read".into(),
                    verified_at: Some(request.verified_at),
                    live_counts,
                    retained_counts,
                },
            );
        }
        Ok(ReplicaScanObservation {
            evidence: observations,
            retained_until,
        })
    }

    async fn backup_evidence(
        &self,
        config: &AwsGovernanceRetentionConfig,
        request: &GovernanceRetentionRequest,
    ) -> Result<(bool, GovernanceRetentionEvidence), StoreError> {
        let mut old_recovery_points = 0_u64;
        for resource_arn in &config.recovery_table_arns {
            let mut next_token = None;
            loop {
                let output = self
                    .backup
                    .list_recovery_points_by_backup_vault()
                    .backup_vault_name(&config.backup_vault_name)
                    .by_resource_arn(resource_arn)
                    .set_next_token(next_token)
                    .send()
                    .await
                    .map_err(|error| {
                        StoreError::Transient(format!(
                            "AWS Backup retention verification failed: {error}"
                        ))
                    })?;
                old_recovery_points = old_recovery_points.saturating_add(
                    output
                        .recovery_points()
                        .iter()
                        .filter(|point| {
                            point
                                .creation_date()
                                .is_some_and(|created| created.secs() <= request.primary_erasure_at)
                        })
                        .count() as u64,
                );
                next_token = output.next_token().map(str::to_string);
                if next_token.is_none() {
                    break;
                }
            }
        }
        Ok((
            old_recovery_points == 0,
            GovernanceRetentionEvidence {
                state: if old_recovery_points == 0 {
                    "provider_verified_absent"
                } else {
                    "provider_objects_present"
                }
                .into(),
                evidence_basis: "aws_backup_list_recovery_points".into(),
                lifecycle_source: "AWS Backup recovery point inventory".into(),
                retention_until: Some(
                    request
                        .primary_erasure_at
                        .saturating_add(crate::governance_worker::BACKUP_RETENTION_SECS),
                ),
            },
        ))
    }

    async fn s3_evidence(
        &self,
        config: &AwsGovernanceRetentionConfig,
        request: &GovernanceRetentionRequest,
    ) -> Result<(bool, GovernanceRetentionEvidence), StoreError> {
        let mut retained_versions = 0_u64;
        let mut latest_retained_at = None;
        for (role_name, bucket) in &config.s3_buckets {
            let role = RetentionS3Role::parse(role_name)?;
            let prefix = role.prefix(&request.target);
            let mut key_marker = None;
            let mut version_marker = None;
            loop {
                let output = self
                    .s3
                    .list_object_versions()
                    .bucket(bucket)
                    .set_prefix(prefix.clone())
                    .set_key_marker(key_marker)
                    .set_version_id_marker(version_marker)
                    .send()
                    .await
                    .map_err(|error| {
                        StoreError::Transient(format!("S3 retention verification failed: {error}"))
                    })?;
                for version in output.versions() {
                    let key = version.key().ok_or_else(|| {
                        StoreError::Permanent(
                            "S3 retention inventory returned a version without a key".into(),
                        )
                    })?;
                    let object_modified_at = version
                        .last_modified()
                        .map(|time| time.secs())
                        .ok_or_else(|| {
                            StoreError::Permanent(
                                "S3 retention inventory returned a version without last_modified"
                                    .into(),
                            )
                        })?;
                    let object = self
                        .s3
                        .get_object()
                        .bucket(bucket)
                        .key(key)
                        .set_version_id(version.version_id().map(str::to_string))
                        .send()
                        .await
                        .map_err(|error| {
                            StoreError::Transient(format!(
                                "S3 retention object read failed: {error}"
                            ))
                        })?;
                    if object
                        .content_length()
                        .is_some_and(|length| length < 0 || length > MAX_RETENTION_OBJECT_BYTES)
                    {
                        return Err(StoreError::Permanent(
                            "S3 retention object exceeds the verification size bound".into(),
                        ));
                    }
                    let body = object.body.collect().await.map_err(|error| {
                        StoreError::Transient(format!(
                            "S3 retention object body read failed: {error}"
                        ))
                    })?;
                    let body = body.into_bytes();
                    if body.len() > MAX_RETENTION_OBJECT_BYTES as usize {
                        return Err(StoreError::Permanent(
                            "S3 retention object exceeds the verification size bound".into(),
                        ));
                    }
                    if role.object_matches(
                        body.as_ref(),
                        &request.target,
                        request.retention_anchor_at,
                        object_modified_at,
                    )? {
                        retained_versions = retained_versions.saturating_add(1);
                        latest_retained_at = Some(
                            latest_retained_at
                                .unwrap_or(i64::MIN)
                                .max(object_modified_at),
                        );
                    }
                }
                key_marker = output.next_key_marker().map(str::to_string);
                version_marker = output.next_version_id_marker().map(str::to_string);
                if key_marker.is_none() {
                    break;
                }
            }
        }
        Ok((
            retained_versions == 0,
            GovernanceRetentionEvidence {
                state: if retained_versions == 0 {
                    "provider_verified_absent"
                } else {
                    "provider_objects_present"
                }
                .into(),
                evidence_basis: "s3_list_object_versions".into(),
                lifecycle_source: "S3 retained object-version inventory".into(),
                retention_until: Some(
                    latest_retained_at
                        .unwrap_or(request.retention_anchor_at)
                        .saturating_add(
                            crate::governance_worker::SECURITY_EVENT_ARCHIVE_RETENTION_SECS,
                        ),
                ),
            },
        ))
    }

    async fn logs_evidence(
        &self,
        config: &AwsGovernanceRetentionConfig,
        request: &GovernanceRetentionRequest,
    ) -> Result<(bool, GovernanceRetentionEvidence), StoreError> {
        let filter_pattern = security_event_log_filter(request.target.tenant_id());
        let end_time = cloudwatch_retention_end_time(&request.target, request.retention_anchor_at);
        let mut retained_events = 0_u64;
        let mut latest_retained_at = None;
        for log_group in config.log_groups.values() {
            let mut next_token: Option<String> = None;
            loop {
                let output = self
                    .logs
                    .filter_log_events()
                    .log_group_name(log_group)
                    .filter_pattern(&filter_pattern)
                    .set_end_time(end_time)
                    .limit(1)
                    .set_next_token(next_token.clone())
                    .send()
                    .await
                    .map_err(|error| {
                        StoreError::Transient(format!(
                            "CloudWatch Logs retention verification failed: {error}"
                        ))
                    })?;
                if let Some(event) = output.events().first() {
                    retained_events = retained_events.saturating_add(1);
                    if let Some(timestamp) = event.timestamp() {
                        latest_retained_at = Some(
                            latest_retained_at
                                .unwrap_or(i64::MIN)
                                .max(timestamp.div_euclid(1_000)),
                        );
                    }
                    break;
                }
                let returned_token = output.next_token().map(str::to_string);
                match returned_token {
                    None => break,
                    Some(token) if Some(token.as_str()) == next_token.as_deref() => {
                        return Err(StoreError::Transient(
                            "CloudWatch Logs retention pagination made no progress".into(),
                        ));
                    }
                    Some(token) => next_token = Some(token),
                }
            }
        }
        Ok((
            retained_events == 0,
            GovernanceRetentionEvidence {
                state: if retained_events == 0 {
                    "provider_verified_absent"
                } else {
                    "provider_events_present"
                }
                .into(),
                evidence_basis: "cloudwatch_logs_filter_events".into(),
                lifecycle_source: "CloudWatch Logs retained event inventory".into(),
                retention_until: Some(
                    latest_retained_at
                        .unwrap_or(request.retention_anchor_at)
                        .saturating_add(
                            crate::governance_worker::SECURITY_EVENT_ARCHIVE_RETENTION_SECS,
                        ),
                ),
            },
        ))
    }

    async fn queue_evidence(
        &self,
        config: &AwsGovernanceRetentionConfig,
        request: &GovernanceRetentionRequest,
    ) -> Result<(bool, GovernanceRetentionEvidence), StoreError> {
        use aws_sdk_sqs::types::QueueAttributeName;

        let elapsed = request
            .verified_at
            .saturating_sub(request.retention_anchor_at);
        let mut verified = true;
        let mut observed_messages = 0_u64;
        let mut retention_until = request.retention_anchor_at;
        for queue_url in config.queue_urls.values() {
            let output = self
                .sqs
                .get_queue_attributes()
                .queue_url(queue_url)
                .set_attribute_names(Some(vec![
                    QueueAttributeName::MessageRetentionPeriod,
                    QueueAttributeName::ApproximateNumberOfMessages,
                    QueueAttributeName::ApproximateNumberOfMessagesNotVisible,
                    QueueAttributeName::ApproximateNumberOfMessagesDelayed,
                ]))
                .send()
                .await
                .map_err(|error| {
                    StoreError::Transient(format!("SQS retention verification failed: {error}"))
                })?;
            let attributes = output.attributes().ok_or_else(|| {
                StoreError::Permanent(
                    "SQS retention verification returned no queue attributes".into(),
                )
            })?;
            let parse_attribute =
                |name: QueueAttributeName, label: &str| -> Result<i64, StoreError> {
                    attributes
                        .get(&name)
                        .and_then(|value| value.parse::<i64>().ok())
                        .ok_or_else(|| {
                            StoreError::Permanent(format!(
                                "SQS retention verification returned no valid {label}"
                            ))
                        })
                };
            let retention = parse_attribute(
                QueueAttributeName::MessageRetentionPeriod,
                "retention period",
            )?;
            let visible = parse_attribute(
                QueueAttributeName::ApproximateNumberOfMessages,
                "visible message count",
            )?;
            let in_flight = parse_attribute(
                QueueAttributeName::ApproximateNumberOfMessagesNotVisible,
                "in-flight message count",
            )?;
            let delayed = parse_attribute(
                QueueAttributeName::ApproximateNumberOfMessagesDelayed,
                "delayed message count",
            )?;
            verified &=
                sqs_queue_retention_complete(elapsed, retention, visible, in_flight, delayed)?;
            observed_messages = observed_messages.saturating_add(
                visible
                    .saturating_add(in_flight)
                    .saturating_add(delayed)
                    .try_into()
                    .map_err(|_| {
                        StoreError::Permanent(
                            "SQS retention verification returned invalid message counts".into(),
                        )
                    })?,
            );
            retention_until =
                retention_until.max(request.retention_anchor_at.saturating_add(retention));
        }
        Ok((
            verified,
            GovernanceRetentionEvidence {
                state: if observed_messages > 0 {
                    "provider_messages_present"
                } else if verified {
                    "provider_observed_empty"
                } else {
                    "provider_retention_bound_pending"
                }
                .into(),
                evidence_basis: "sqs_get_queue_attributes_with_message_counts".into(),
                lifecycle_source:
                    "SQS provider-enforced MessageRetentionPeriod and queue message counts".into(),
                retention_until: Some(retention_until),
            },
        ))
    }

    async fn stable_queue_evidence(
        &self,
        config: &AwsGovernanceRetentionConfig,
        request: &GovernanceRetentionRequest,
        sample_interval: std::time::Duration,
    ) -> Result<(bool, GovernanceRetentionEvidence), StoreError> {
        let (first_complete, first_evidence) = self.queue_evidence(config, request).await?;
        if !first_complete {
            return Ok((false, first_evidence));
        }

        tokio::time::sleep(sample_interval).await;
        let (second_complete, mut second_evidence) = self.queue_evidence(config, request).await?;
        second_evidence.evidence_basis = "sqs_get_queue_attributes_two_consecutive_samples".into();
        second_evidence.lifecycle_source =
            "SQS provider-enforced MessageRetentionPeriod and two consecutive queue count samples"
                .into();
        if second_complete {
            second_evidence.state = "provider_observed_stably_empty".into();
        }
        Ok((first_complete && second_complete, second_evidence))
    }

    async fn verify_aws_retention(
        &self,
        config: &AwsGovernanceRetentionConfig,
        request: GovernanceRetentionRequest,
    ) -> Result<GovernanceRetentionObservation, StoreError> {
        self.validate_retention_request(&request)?;
        let replica_scan = self.replica_counts(config, &request).await?;
        let replicas_complete = replica_scan
            .evidence
            .values()
            .flat_map(|evidence| evidence.live_counts.values())
            .all(|count| *count == 0);
        let security_events_complete = replica_scan
            .evidence
            .values()
            .flat_map(|evidence| evidence.retained_counts.values())
            .all(|count| *count == 0);
        let (backup_complete, backup) = self.backup_evidence(config, &request).await?;
        let (s3_complete, s3) = self.s3_evidence(config, &request).await?;
        let (logs_complete, logs) = self.logs_evidence(config, &request).await?;
        let (queues_complete, queues) = self
            .stable_queue_evidence(config, &request, std::time::Duration::from_secs(10))
            .await?;
        let retention_resources = BTreeMap::from([
            ("aws_backup_recovery_points".into(), backup),
            ("s3_security_event_archive".into(), s3),
            ("cloudwatch_logs".into(), logs),
            ("sqs_queues".into(), queues),
            (
                "dynamodb_replicated_authority".into(),
                GovernanceRetentionEvidence {
                    state: if replicas_complete {
                        "provider_verified_absent"
                    } else {
                        "provider_rows_present"
                    }
                    .into(),
                    evidence_basis: "dynamodb_regional_strong_scan".into(),
                    lifecycle_source: "DynamoDB Global Table replica base-table reads".into(),
                    retention_until: None,
                },
            ),
            (
                "dynamodb_security_event_hot_ledger".into(),
                GovernanceRetentionEvidence {
                    state: if security_events_complete {
                        "provider_verified_absent"
                    } else {
                        "provider_rows_present"
                    }
                    .into(),
                    evidence_basis: "dynamodb_regional_strong_scan".into(),
                    lifecycle_source: "DynamoDB security-event expires_at TTL".into(),
                    retention_until: replica_scan.retained_until,
                },
            ),
        ]);
        Ok(GovernanceRetentionObservation {
            complete: replicas_complete
                && security_events_complete
                && backup_complete
                && s3_complete
                && logs_complete
                && queues_complete,
            replica_live_counts: replica_scan.evidence,
            retention_resources,
        })
    }

    fn validate_retention_request(
        &self,
        request: &GovernanceRetentionRequest,
    ) -> Result<(), StoreError> {
        if request.configured_regions.is_empty()
            || request.target.tenant_id().is_empty()
            || (!request.storage_tenant.is_empty()
                && request.storage_tenant != request.target.tenant_id())
            || request.primary_erasure_at <= 0
            || request.retention_anchor_at < request.primary_erasure_at
            || request.verified_at < request.retention_anchor_at
            || !request.configured_regions.iter().any(|region| {
                self.config
                    .region()
                    .is_some_and(|local| local.as_ref() == region)
            })
        {
            return Err(StoreError::Permanent(
                "invalid AWS governance retention request".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "aws")]
impl GovernanceResourceBackend for AwsGovernanceResourceBackend {
    async fn schedule_secret_deletion(
        &self,
        secret_ref: &str,
        expected_fingerprint: &str,
        now: i64,
    ) -> Result<SecretDeletionStatus, StoreError> {
        let description = self.describe(secret_ref, expected_fingerprint).await?;
        match description.status {
            SecretDeletionStatus::Absent | SecretDeletionStatus::Scheduled { .. } => {
                return Ok(description.status);
            }
            SecretDeletionStatus::ReplicaRemovalRequired => {}
            SecretDeletionStatus::Present => {
                let output = self
                    .secrets
                    .delete_secret()
                    .secret_id(secret_ref)
                    .recovery_window_in_days(SECRET_DELETION_RECOVERY_DAYS)
                    .send()
                    .await
                    .map_err(secret_error)?;
                return Ok(SecretDeletionStatus::Scheduled {
                    deletion_at: output.deletion_date().map_or_else(
                        || now.saturating_add(SECRET_DELETION_RECOVERY_SECS),
                        |date| date.secs(),
                    ),
                });
            }
            SecretDeletionStatus::ReplicaRemovalPending => {
                return Err(StoreError::Permanent(
                    "DescribeSecret returned an operation-only deletion status".into(),
                ));
            }
        }

        let removal = self
            .secrets
            .remove_regions_from_replication()
            .secret_id(secret_ref)
            .set_remove_replica_regions(Some(description.replica_regions))
            .send()
            .await;
        if let Err(error) = removal {
            use aws_sdk_secretsmanager::error::ProvideErrorMetadata;

            let reconcile = error.code().is_some_and(|code| {
                code.contains("InvalidRequest")
                    || code.contains("InvalidParameter")
                    || code.contains("ResourceNotFound")
            });
            let observed = self.describe(secret_ref, expected_fingerprint).await?;
            if observed.status != SecretDeletionStatus::ReplicaRemovalRequired {
                return Ok(observed.status);
            }
            if reconcile {
                return Err(StoreError::Transient(
                    "Secret replica removal has not converged".into(),
                ));
            }
            return Err(secret_error(error));
        }
        Ok(SecretDeletionStatus::ReplicaRemovalPending)
    }

    async fn inspect_secret_deletion(
        &self,
        secret_ref: &str,
        expected_fingerprint: &str,
    ) -> Result<SecretDeletionStatus, StoreError> {
        self.describe(secret_ref, expected_fingerprint)
            .await
            .map(|description| description.status)
    }

    async fn verify_retention(
        &self,
        request: GovernanceRetentionRequest,
    ) -> Result<Option<GovernanceRetentionObservation>, StoreError> {
        let Some(config) = self.retention.as_ref() else {
            return Ok(None);
        };
        self.verify_aws_retention(config, request).await.map(Some)
    }

    async fn verify_replicas(
        &self,
        request: GovernanceRetentionRequest,
    ) -> Result<Option<BTreeMap<String, GovernanceReplicaEvidence>>, StoreError> {
        let Some(config) = self.retention.as_ref() else {
            return Ok(None);
        };
        self.validate_retention_request(&request)?;
        self.replica_counts(config, &request)
            .await
            .map(|observation| Some(observation.evidence))
    }
}

#[cfg(feature = "aws")]
fn secret_error<E, R>(error: aws_sdk_secretsmanager::error::SdkError<E, R>) -> StoreError
where
    aws_sdk_secretsmanager::error::SdkError<E, R>:
        aws_sdk_secretsmanager::error::ProvideErrorMetadata,
{
    use aws_sdk_secretsmanager::error::ProvideErrorMetadata;

    if matches!(
        &error,
        aws_sdk_secretsmanager::error::SdkError::TimeoutError(_)
            | aws_sdk_secretsmanager::error::SdkError::DispatchFailure(_)
            | aws_sdk_secretsmanager::error::SdkError::ResponseError(_)
    ) {
        return StoreError::Transient("Secrets Manager transport failure".into());
    }
    let code = error.code().unwrap_or("");
    if code.contains("Throttling")
        || code.contains("InternalService")
        || code.contains("ServiceUnavailable")
        || code.contains("RequestTimeout")
    {
        StoreError::Transient(code.into())
    } else {
        StoreError::Permanent(format!("{code}: {}", error.message().unwrap_or("")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_observation_requires_every_configured_strong_replica() {
        let regions = vec!["us-east-1".to_string(), "us-west-2".to_string()];
        let clean = GovernanceReplicaEvidence {
            verification_state: "provider_strong_read".into(),
            verified_at: Some(100),
            live_counts: BTreeMap::from([("users".into(), 0)]),
            retained_counts: BTreeMap::from([("security_events".into(), 1)]),
        };
        let mut observation = GovernanceRetentionObservation {
            complete: false,
            replica_live_counts: BTreeMap::from([
                ("us-east-1".into(), clean.clone()),
                ("us-west-2".into(), clean.clone()),
            ]),
            retention_resources: BTreeMap::from([
                (
                    "archive".into(),
                    GovernanceRetentionEvidence {
                        state: "provider_objects_present".into(),
                        evidence_basis: "provider".into(),
                        lifecycle_source: "test".into(),
                        retention_until: Some(200),
                    },
                ),
                (
                    "queue".into(),
                    GovernanceRetentionEvidence {
                        state: "provider_retention_bound_pending".into(),
                        evidence_basis: "provider".into(),
                        lifecycle_source: "test".into(),
                        retention_until: Some(150),
                    },
                ),
            ]),
        };
        assert!(observation.replicas_verified_absent(&regions));
        assert_eq!(observation.pending_until(), Some(200));

        observation
            .replica_live_counts
            .get_mut("us-west-2")
            .unwrap()
            .live_counts
            .insert("users".into(), 1);
        assert!(!observation.replicas_verified_absent(&regions));
        observation.replica_live_counts.remove("us-west-2");
        assert!(!observation.replicas_verified_absent(&regions));
    }

    #[tokio::test]
    async fn memory_secret_deletion_is_identity_checked_and_idempotent() {
        let backend = MemoryGovernanceResourceBackend::default();
        let secret_ref = "arn:aws:secretsmanager:us-east-1:123456789012:secret:tenant-t1-AbCd";
        backend.insert_secret(secret_ref).await;
        let fingerprint = resource_fingerprint(secret_ref);
        assert_eq!(
            backend
                .schedule_secret_deletion(secret_ref, &fingerprint, 100)
                .await
                .unwrap(),
            SecretDeletionStatus::Scheduled {
                deletion_at: 100 + SECRET_DELETION_RECOVERY_SECS
            }
        );
        assert_eq!(
            backend
                .schedule_secret_deletion(secret_ref, &fingerprint, 200)
                .await
                .unwrap(),
            SecretDeletionStatus::Scheduled {
                deletion_at: 100 + SECRET_DELETION_RECOVERY_SECS
            }
        );
        assert!(matches!(
            backend
                .schedule_secret_deletion(secret_ref, "wrong", 200)
                .await,
            Err(StoreError::Permanent(_))
        ));
    }

    #[cfg(feature = "aws")]
    fn valid_retention_config() -> String {
        serde_json::json!({
            "replicated_tables": {"users": "users-table"},
            "backup_vault_name": "governance-vault",
            "recovery_table_arns": [
                "arn:aws:dynamodb:us-east-1:123456789012:table/users-table"
            ],
            "s3_buckets": {
                "security_event_archive": "security-event-archive-bucket",
                "security_event_ingress_failures": "security-event-ingress-failures-bucket",
                "security_event_stream_failures": "security-event-stream-failures-bucket",
                "ssf_stream_failures": "ssf-stream-failures-bucket"
            },
            "log_groups": {"auth": "/aws/lambda/auth"},
            "queue_urls": {"worker": "https://sqs.us-east-1.amazonaws.com/123/worker"}
        })
        .to_string()
    }

    #[cfg(feature = "aws")]
    fn retention_event(
        tenant_id: &str,
        user_id: &str,
        occurred_at: i64,
    ) -> crate::security_event::SecurityEvent {
        use crate::security_event::{
            SecurityActor, SecurityEvent, SecurityEventCategory, SecurityEventCorrelation,
            SecurityEventOutcome, SecuritySubject,
        };

        SecurityEvent::new_at(
            format!("evt-{tenant_id}-{user_id}-{occurred_at}"),
            occurred_at,
            tenant_id,
            SecurityActor::system("governance"),
            Some(SecuritySubject::user(user_id)),
            SecurityEventCategory::Administration,
            "governance.test",
            SecurityEventOutcome::Success,
            SecurityEventCorrelation::default(),
        )
        .unwrap()
    }

    #[cfg(feature = "aws")]
    fn retention_archive_body(event: &crate::security_event::SecurityEvent) -> Vec<u8> {
        use crate::{
            security_event::{
                SecurityEventDelivery, SecurityEventDeliveryAttempt, SecurityEventDeliveryStatus,
            },
            security_event_archive::{archive_body, archive_key, ArchiveRecord},
        };

        let record = ArchiveRecord {
            event_id: event.event_id.clone(),
            tenant_id: event.tenant_id.clone(),
            occurred_at: event.occurred_at,
            envelope: serde_json::to_string(event).unwrap(),
        };
        let key = archive_key(&record).unwrap();
        let archived_at = event.occurred_at + 1;
        let mut delivery = SecurityEventDelivery::pending(event.occurred_at);
        delivery.status = SecurityEventDeliveryStatus::Archived;
        delivery.last_attempt_at = Some(archived_at);
        delivery.archived_at = Some(archived_at);
        delivery.archive_key = Some(key);
        delivery.history.push(SecurityEventDeliveryAttempt {
            status: SecurityEventDeliveryStatus::Archived,
            occurred_at: archived_at,
        });
        archive_body(&record, &delivery).unwrap()
    }

    #[cfg(feature = "aws")]
    fn retention_stream_failure_body(event: &crate::security_event::SecurityEvent) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "requestPayload": {
                "Records": [{
                    "eventName": "INSERT",
                    "dynamodb": {
                        "NewImage": {
                            "event_id": { "S": event.event_id },
                            "tenant_id": { "S": event.tenant_id },
                            "occurred_at": { "N": event.occurred_at.to_string() },
                            "envelope": { "S": serde_json::to_string(event).unwrap() }
                        }
                    }
                }]
            }
        }))
        .unwrap()
    }

    #[cfg(feature = "aws")]
    fn retention_ssf_stream_failure_body(event: &crate::security_event::SecurityEvent) -> Vec<u8> {
        let legacy: serde_json::Value =
            serde_json::from_slice(&retention_stream_failure_body(event)).unwrap();
        serde_json::to_vec(&serde_json::json!({
            "payload": legacy["requestPayload"].to_string()
        }))
        .unwrap()
    }

    #[cfg(feature = "aws")]
    #[test]
    fn aws_retention_config_is_optional_but_rejects_partial_inventory() {
        assert!(AwsGovernanceRetentionConfig::parse(None).unwrap().is_none());
        assert!(
            AwsGovernanceRetentionConfig::parse(Some(&valid_retention_config()))
                .unwrap()
                .is_some()
        );

        let partial = serde_json::json!({
            "replicated_tables": {"users": "users-table"},
            "backup_vault_name": "governance-vault",
            "recovery_table_arns": [
                "arn:aws:dynamodb:us-east-1:123456789012:table/users-table"
            ],
            "s3_buckets": {
                "security_event_archive": "security-event-archive-bucket",
                "security_event_ingress_failures": "security-event-ingress-failures-bucket",
                "security_event_stream_failures": "security-event-stream-failures-bucket"
            },
            "log_groups": {"auth": "/aws/lambda/auth"},
            "queue_urls": {"worker": "https://sqs.us-east-1.amazonaws.com/123/worker"}
        })
        .to_string();
        assert!(AwsGovernanceRetentionConfig::parse(Some(&partial)).is_err());

        let unknown_role = valid_retention_config()
            .replace("\"ssf_stream_failures\"", "\"unknown_stream_failures\"");
        assert!(AwsGovernanceRetentionConfig::parse(Some(&unknown_role)).is_err());
    }

    #[cfg(feature = "aws")]
    #[test]
    fn aws_retention_security_event_queries_are_tenant_scoped() {
        assert_eq!(
            security_event_archive_prefix("tenant-a"),
            "security-events/tenant_id=tenant-a/"
        );
        assert_eq!(security_event_log_filter("tenant-a"), "\"tenant=tenant-a\"");
        assert_ne!(
            security_event_archive_prefix("tenant-a"),
            security_event_archive_prefix("tenant-b")
        );
        assert_eq!(
            cloudwatch_retention_end_time(
                &GovernanceRetentionTarget::User {
                    tenant_id: "tenant-a".into(),
                    job_id: "job-1".into(),
                    user_id: "user-1".into(),
                    aliases: vec![],
                },
                100
            ),
            Some(100_000)
        );
        assert_eq!(
            cloudwatch_retention_end_time(
                &GovernanceRetentionTarget::Tenant {
                    tenant_id: "tenant-a".into(),
                    job_id: "job-1".into(),
                },
                100
            ),
            None
        );
    }

    #[cfg(feature = "aws")]
    #[test]
    fn archive_retention_ignores_post_anchor_and_unrelated_user_events() {
        let target = GovernanceRetentionTarget::User {
            tenant_id: "tenant-a".into(),
            job_id: "job-1".into(),
            user_id: "user-1".into(),
            aliases: vec!["same@example.com".into()],
        };

        assert!(archive_event_matches_retention_target(
            &retention_event("tenant-a", "user-1", 100),
            &target,
            100
        ));
        assert!(!archive_event_matches_retention_target(
            &retention_event("tenant-a", "user-2", 100),
            &target,
            100
        ));
        assert!(!archive_event_matches_retention_target(
            &retention_event("tenant-a", "user-1", 101),
            &target,
            100
        ));
        assert!(!archive_event_matches_retention_target(
            &retention_event("tenant-b", "user-1", 100),
            &target,
            100
        ));
        let mut job_event = retention_event("tenant-a", "user-2", 100);
        job_event.subject = crate::security_event::SecuritySubject::tenant("tenant-a");
        job_event.correlation.operation_id = Some("job-1".into());
        assert!(archive_event_matches_retention_target(
            &job_event, &target, 100
        ));
        let hot_item = HashMap::from([(
            "envelope".into(),
            aws_sdk_dynamodb::types::AttributeValue::S(serde_json::to_string(&job_event).unwrap()),
        )]);
        assert!(security_event_item_matches_retention_target(&hot_item, &target, 100).unwrap());
        assert!(RetentionS3Role::SecurityEventArchive
            .object_matches(
                &retention_archive_body(&job_event),
                &target,
                100,
                job_event.occurred_at,
            )
            .unwrap());
        job_event.correlation.operation_id = Some("job-2".into());
        assert!(!archive_event_matches_retention_target(
            &job_event, &target, 100
        ));
    }

    #[cfg(feature = "aws")]
    #[test]
    fn s3_retention_roles_ignore_unrelated_tenants_and_fail_closed_on_bad_objects() {
        let target = GovernanceRetentionTarget::User {
            tenant_id: "tenant-a".into(),
            job_id: "job-1".into(),
            user_id: "user-1".into(),
            aliases: vec![],
        };
        let retained = retention_event("tenant-a", "user-1", 100);
        let unrelated = retention_event("tenant-b", "user-1", 100);
        let post_anchor = retention_event("tenant-a", "user-1", 101);

        let archive = retention_archive_body(&retained);
        assert!(RetentionS3Role::SecurityEventArchive
            .object_matches(&archive, &target, 100, 100)
            .unwrap());
        assert!(!RetentionS3Role::SecurityEventArchive
            .object_matches(&retention_archive_body(&post_anchor), &target, 100, 101)
            .unwrap());
        assert!(RetentionS3Role::SecurityEventArchive
            .object_matches(&retention_archive_body(&unrelated), &target, 100, 100)
            .is_err());

        for (event, expected) in [
            (&retained, true),
            (&unrelated, false),
            (&post_anchor, false),
        ] {
            assert_eq!(
                RetentionS3Role::SecurityEventIngressFailures
                    .object_matches(
                        &serde_json::to_vec(event).unwrap(),
                        &target,
                        100,
                        event.occurred_at
                    )
                    .unwrap(),
                expected
            );
            for (role, body) in [
                (
                    RetentionS3Role::SecurityEventStreamFailures,
                    retention_stream_failure_body(event),
                ),
                (
                    RetentionS3Role::SsfStreamFailures,
                    retention_ssf_stream_failure_body(event),
                ),
            ] {
                assert_eq!(
                    role.object_matches(&body, &target, 100, event.occurred_at)
                        .unwrap(),
                    expected
                );
            }
        }

        for role in [
            RetentionS3Role::SecurityEventIngressFailures,
            RetentionS3Role::SecurityEventStreamFailures,
            RetentionS3Role::SsfStreamFailures,
        ] {
            assert!(role.object_matches(b"invalid", &target, 100, 100).unwrap());
            assert!(!role.object_matches(b"invalid", &target, 100, 101).unwrap());
        }
    }

    #[cfg(feature = "aws")]
    #[test]
    fn sqs_retention_requires_elapsed_bound_and_an_observed_empty_queue() {
        let retention = 60;
        assert!(sqs_queue_retention_complete(60, retention, 0, 0, 0).unwrap());
        assert!(!sqs_queue_retention_complete(59, retention, 0, 0, 0).unwrap());
        for counts in [(1, 0, 0), (0, 1, 0), (0, 0, 1)] {
            assert!(
                !sqs_queue_retention_complete(60, retention, counts.0, counts.1, counts.2).unwrap()
            );
        }
        assert!(sqs_queue_retention_complete(60, 0, 0, 0, 0).is_err());
    }

    #[cfg(feature = "aws")]
    #[tokio::test]
    async fn replicated_secret_removes_replicas_before_scheduling_deletion() {
        use axum::{
            body::Bytes,
            extract::State,
            http::{HeaderMap, StatusCode},
            response::{IntoResponse, Response},
            routing::post,
            Json, Router,
        };
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        };

        #[derive(Clone)]
        struct SecretState {
            replica_phase: Arc<AtomicUsize>,
            calls: Arc<Mutex<Vec<String>>>,
        }

        async fn secrets(
            State(state): State<SecretState>,
            headers: HeaderMap,
            body: Bytes,
        ) -> Response {
            let target = headers
                .get("x-amz-target")
                .and_then(|value| value.to_str().ok())
                .expect("Secrets Manager target")
                .rsplit('.')
                .next()
                .expect("operation")
                .to_string();
            state.calls.lock().unwrap().push(target.clone());
            match target.as_str() {
                "DescribeSecret" => {
                    let mut response = serde_json::json!({
                        "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:tenant-a-AbCd",
                        "Name": "tenant-a"
                    });
                    let replica_phase = state.replica_phase.load(Ordering::SeqCst);
                    if replica_phase == 3 {
                        response["DeletedDate"] = serde_json::json!(100);
                    }
                    if replica_phase < 2 {
                        response["ReplicationStatus"] = serde_json::json!([{
                            "Region": "us-west-2",
                            "Status": if replica_phase == 0 { "InSync" } else { "InProgress" }
                        }]);
                    }
                    (StatusCode::OK, Json(response)).into_response()
                }
                "RemoveRegionsFromReplication" => {
                    let request: serde_json::Value =
                        serde_json::from_slice(&body).expect("remove request");
                    assert_eq!(
                        request["RemoveReplicaRegions"],
                        serde_json::json!(["us-west-2"])
                    );
                    if state
                        .replica_phase
                        .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        (
                            StatusCode::OK,
                            Json(serde_json::json!({
                                "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:tenant-a-AbCd",
                                "ReplicationStatus": [{
                                    "Region": "us-west-2",
                                    "Status": "InProgress"
                                }]
                            })),
                        )
                            .into_response()
                    } else {
                        state.replica_phase.store(2, Ordering::SeqCst);
                        (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({
                                "__type": "InvalidRequestException",
                                "Message": "replica removal is already in progress"
                            })),
                        )
                            .into_response()
                    }
                }
                "DeleteSecret" if state.replica_phase.load(Ordering::SeqCst) < 2 => (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "__type": "InvalidParameterException",
                        "Message": "secret still has replica regions"
                    })),
                )
                    .into_response(),
                "DeleteSecret" => {
                    let request: serde_json::Value =
                        serde_json::from_slice(&body).expect("delete request");
                    assert_eq!(request["RecoveryWindowInDays"], serde_json::json!(7));
                    state.replica_phase.store(3, Ordering::SeqCst);
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:tenant-a-AbCd",
                            "DeletionDate": 604900
                        })),
                    )
                        .into_response()
                }
                operation => panic!("unexpected Secrets Manager operation: {operation}"),
            }
        }

        let state = SecretState {
            replica_phase: Arc::new(AtomicUsize::new(0)),
            calls: Arc::new(Mutex::new(Vec::new())),
        };
        let app = Router::new()
            .fallback(post(secrets))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let endpoint = format!("http://{address}");
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_secretsmanager::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_secretsmanager::config::Credentials::for_tests())
            .endpoint_url(&endpoint)
            .load()
            .await;
        let backend = AwsGovernanceResourceBackend::new(&sdk_config, None).unwrap();
        let secret_ref = "arn:aws:secretsmanager:us-east-1:123456789012:secret:tenant-a-AbCd";
        let fingerprint = resource_fingerprint(secret_ref);

        assert_eq!(
            backend
                .schedule_secret_deletion(secret_ref, &fingerprint, 100)
                .await
                .unwrap(),
            SecretDeletionStatus::ReplicaRemovalPending
        );
        assert_eq!(
            *state.calls.lock().unwrap(),
            ["DescribeSecret", "RemoveRegionsFromReplication"]
        );

        assert_eq!(
            backend
                .schedule_secret_deletion(secret_ref, &fingerprint, 100)
                .await
                .unwrap(),
            SecretDeletionStatus::Present
        );
        assert_eq!(
            *state.calls.lock().unwrap(),
            [
                "DescribeSecret",
                "RemoveRegionsFromReplication",
                "DescribeSecret",
                "RemoveRegionsFromReplication",
                "DescribeSecret"
            ]
        );

        assert_eq!(
            backend
                .schedule_secret_deletion(secret_ref, &fingerprint, 100)
                .await
                .unwrap(),
            SecretDeletionStatus::Scheduled {
                deletion_at: 604900
            }
        );
        assert_eq!(
            backend
                .inspect_secret_deletion(secret_ref, &fingerprint)
                .await
                .unwrap(),
            SecretDeletionStatus::Scheduled {
                deletion_at: 604900
            }
        );
        assert_eq!(
            *state.calls.lock().unwrap(),
            [
                "DescribeSecret",
                "RemoveRegionsFromReplication",
                "DescribeSecret",
                "RemoveRegionsFromReplication",
                "DescribeSecret",
                "DescribeSecret",
                "DeleteSecret",
                "DescribeSecret"
            ]
        );
        server.abort();
    }

    #[cfg(feature = "aws")]
    #[tokio::test]
    async fn stable_sqs_evidence_requires_two_real_provider_samples() {
        use axum::{
            extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router,
        };
        use std::{
            collections::VecDeque,
            sync::{Arc, Mutex},
        };

        async fn attributes(State(samples): State<Arc<Mutex<VecDeque<i64>>>>) -> impl IntoResponse {
            let visible = samples
                .lock()
                .expect("sample lock")
                .pop_front()
                .expect("expected SQS sample");
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "Attributes": {
                        "MessageRetentionPeriod": "60",
                        "ApproximateNumberOfMessages": visible.to_string(),
                        "ApproximateNumberOfMessagesNotVisible": "0",
                        "ApproximateNumberOfMessagesDelayed": "0"
                    }
                })),
            )
        }

        let samples = Arc::new(Mutex::new(VecDeque::from([0, 0, 0, 1])));
        let app = Router::new()
            .fallback(post(attributes))
            .with_state(samples.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let endpoint = format!("http://{address}");
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_sqs::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_sqs::config::Credentials::for_tests())
            .endpoint_url(&endpoint)
            .load()
            .await;
        let backend = AwsGovernanceResourceBackend::new(&sdk_config, None).unwrap();
        let config = AwsGovernanceRetentionConfig {
            replicated_tables: BTreeMap::new(),
            backup_vault_name: String::new(),
            recovery_table_arns: Vec::new(),
            s3_buckets: BTreeMap::new(),
            log_groups: BTreeMap::new(),
            queue_urls: BTreeMap::from([(
                "worker".into(),
                format!("{endpoint}/123456789012/worker"),
            )]),
        };
        let request = GovernanceRetentionRequest {
            target: GovernanceRetentionTarget::Tenant {
                tenant_id: "tenant-a".into(),
                job_id: "job-1".into(),
            },
            storage_tenant: "tenant-a".into(),
            configured_regions: vec!["us-east-1".into()],
            primary_erasure_at: 100,
            retention_anchor_at: 100,
            verified_at: 160,
        };

        let (complete, evidence) = backend
            .stable_queue_evidence(&config, &request, std::time::Duration::ZERO)
            .await
            .unwrap();
        assert!(complete);
        assert_eq!(evidence.state, "provider_observed_stably_empty");
        assert_eq!(
            evidence.evidence_basis,
            "sqs_get_queue_attributes_two_consecutive_samples"
        );

        let (complete, evidence) = backend
            .stable_queue_evidence(&config, &request, std::time::Duration::ZERO)
            .await
            .unwrap();
        server.abort();
        assert!(!complete);
        assert_eq!(evidence.state, "provider_messages_present");
        assert!(samples.lock().unwrap().is_empty());
    }

    #[cfg(feature = "aws")]
    #[test]
    fn aws_retention_user_matcher_covers_physical_keys_aliases_and_json() {
        use aws_sdk_dynamodb::types::AttributeValue;

        let target = GovernanceRetentionTarget::User {
            tenant_id: "tenant-a".into(),
            job_id: "job-1".into(),
            user_id: "user-1".into(),
            aliases: vec!["same@example.com".into()],
        };
        for item in [
            HashMap::from([(
                "user_id".into(),
                AttributeValue::S("tenant-a\u{1f}user-1".into()),
            )]),
            HashMap::from([
                ("tenant_id".into(), AttributeValue::S("tenant-a".into())),
                ("email".into(), AttributeValue::S("same@example.com".into())),
            ]),
            HashMap::from([(
                "grant_json".into(),
                AttributeValue::S(r#"{"tenant_id":"tenant-a","user_id":"user-1"}"#.into()),
            )]),
            HashMap::from([(
                "envelope".into(),
                AttributeValue::S(
                    r#"{"tenant_id":"tenant-a","subject":{"id":"same@example.com"}}"#.into(),
                ),
            )]),
        ] {
            assert!(item_matches_retention_target(&item, &target, "tenant-a").unwrap());
        }

        let cross_tenant = HashMap::from([(
            "user_id".into(),
            AttributeValue::S("tenant-b\u{1f}user-1".into()),
        )]);
        assert!(!item_matches_retention_target(&cross_tenant, &target, "tenant-a").unwrap());

        let shared_cross_tenant_alias = HashMap::from([
            ("tenant_id".into(), AttributeValue::S("tenant-b".into())),
            ("email".into(), AttributeValue::S("same@example.com".into())),
        ]);
        assert!(
            !item_matches_retention_target(&shared_cross_tenant_alias, &target, "tenant-a")
                .unwrap()
        );
    }

    #[cfg(feature = "aws")]
    #[test]
    fn aws_retention_tenant_matcher_is_delimiter_bounded_and_fail_closed() {
        use aws_sdk_dynamodb::types::AttributeValue;

        let target = GovernanceRetentionTarget::Tenant {
            tenant_id: "tenant-a".into(),
            job_id: "job-1".into(),
        };
        let physical = HashMap::from([(
            "client_id".into(),
            AttributeValue::S("tenant-a\u{1f}client-1".into()),
        )]);
        assert!(item_matches_retention_target(&physical, &target, "tenant-a").unwrap());

        let similar_tenant = HashMap::from([(
            "client_id".into(),
            AttributeValue::S("tenant-ab\u{1f}client-1".into()),
        )]);
        assert!(!item_matches_retention_target(&similar_tenant, &target, "tenant-a").unwrap());

        let malformed_json =
            HashMap::from([("record_json".into(), AttributeValue::S("{not-json".into()))]);
        assert!(matches!(
            item_matches_retention_target(&malformed_json, &target, "tenant-a"),
            Err(StoreError::Permanent(_))
        ));

        let unpartitioned =
            HashMap::from([("client_id".into(), AttributeValue::S("client-1".into()))]);
        let default_target = GovernanceRetentionTarget::Tenant {
            tenant_id: "default".into(),
            job_id: "job-1".into(),
        };
        assert!(item_matches_retention_target(&unpartitioned, &default_target, "").unwrap());
    }

    #[cfg(feature = "aws")]
    #[test]
    fn tenant_key_replica_verification_exempts_only_inert_offboarded_control_rows() {
        use aws_sdk_dynamodb::types::AttributeValue;

        let target = GovernanceRetentionTarget::Tenant {
            tenant_id: "tenant-a".into(),
            job_id: "job-1".into(),
        };
        let item = |record: serde_json::Value| {
            HashMap::from([
                ("tenant_id".into(), AttributeValue::S("tenant-a".into())),
                ("record_json".into(), AttributeValue::S(record.to_string())),
            ])
        };
        let control = serde_json::json!({
            "tenant_id": "tenant-a",
            "revision": 4,
            "lifecycle": "offboarded",
            "scheduled_deletion_arns": ["arn:aws:kms:us-east-1:123:key/pending"],
            "offboarding_operation_id": "offboard-job-1",
            "updated_at": 100
        });
        assert!(!tenant_key_item_is_live(&item(control.clone()), &target, "tenant-a").unwrap());

        for live in [
            serde_json::json!({
                "tenant_id": "tenant-a",
                "revision": 3,
                "lifecycle": "offboarding",
                "pending_deletion_arns": ["arn:aws:kms:us-east-1:123:key/live"],
                "offboarding_operation_id": "offboard-job-1",
                "updated_at": 99
            }),
            serde_json::json!({
                "tenant_id": "tenant-a",
                "revision": 4,
                "lifecycle": "offboarded",
                "updated_at": 100
            }),
        ] {
            assert!(tenant_key_item_is_live(&item(live), &target, "tenant-a").unwrap());
        }

        let malformed = HashMap::from([
            ("tenant_id".into(), AttributeValue::S("tenant-a".into())),
            ("record_json".into(), AttributeValue::S("{not-json".into())),
        ]);
        assert!(matches!(
            tenant_key_item_is_live(&malformed, &target, "tenant-a"),
            Err(StoreError::Permanent(_))
        ));

        let user_target = GovernanceRetentionTarget::User {
            tenant_id: "tenant-a".into(),
            job_id: "job-1".into(),
            user_id: "user-1".into(),
            aliases: vec![],
        };
        assert!(!tenant_key_item_is_live(&item(control), &user_target, "tenant-a").unwrap());
    }
}
