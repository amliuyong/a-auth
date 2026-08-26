//! Durable data-governance control records.
//!
//! The HTTP layer authenticates a purpose-specific Admin action and then uses
//! this module for tenant residency, policy CAS, export manifests, and durable
//! destructive jobs. Physical deletion is advanced by a separate backend; a
//! queued job is never presented as completed erasure.

use std::collections::{BTreeMap, BTreeSet};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

use crate::ports::{GovernanceJobQueue, GovernanceStore, StoreError, UserStatus};

pub const GOVERNANCE_SCHEMA_VERSION: &str = "1.0";
pub const GOVERNANCE_EVIDENCE_SCHEMA_VERSION: &str = "1.1";
pub const EXPORT_MANIFEST_TTL_SECS: i64 = 15 * 60;
pub const GOVERNANCE_REASON_MAX_LEN: usize = 64;
pub const GOVERNANCE_PURPOSE_MAX_LEN: usize = 128;
pub const SUPPRESSION_KEY_VERSION: u32 = 1;
pub const SUPPRESSION_NORMALIZATION_VERSION: u32 = 1;
pub const RECOVERABLE_AUTHORITY_RETENTION_SECS: i64 = 35 * 24 * 60 * 60;
pub const TENANT_MUTATION_PERMIT_LEASE_SECS: i64 = 120;
pub const TENANT_MUTATION_PERMIT_RENEW_SECS: u64 = 30;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TenantResidency {
    pub jurisdiction: String,
    pub allowed_regions: Vec<String>,
    #[serde(default)]
    pub governance_region: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceConfig {
    tenants: BTreeMap<String, TenantResidency>,
}

impl GovernanceConfig {
    pub fn single_region(
        tenant: impl Into<String>,
        jurisdiction: impl Into<String>,
        region: impl Into<String>,
    ) -> Self {
        let tenant = tenant.into();
        let residency = TenantResidency {
            jurisdiction: jurisdiction.into(),
            allowed_regions: vec![region.into()],
            governance_region: String::new(),
        };
        let mut config = Self {
            tenants: BTreeMap::from([(tenant, residency)]),
        };
        config.fill_governance_regions();
        config
    }

    pub fn parse_json(value: &str, expected_tenants: &[String]) -> Result<Self, String> {
        let tenants: BTreeMap<String, TenantResidency> = serde_json::from_str(value)
            .map_err(|_| "AGENT_AUTH_TENANT_RESIDENCY must be a JSON object".to_string())?;
        let mut config = Self { tenants };
        config.fill_governance_regions();
        config.validate(expected_tenants)?;
        Ok(config)
    }

    fn fill_governance_regions(&mut self) {
        for residency in self.tenants.values_mut() {
            if residency.governance_region.is_empty() {
                residency.governance_region = residency
                    .allowed_regions
                    .first()
                    .cloned()
                    .unwrap_or_default();
            }
        }
    }

    pub fn validate(&self, expected_tenants: &[String]) -> Result<(), String> {
        let expected = expected_tenants.iter().cloned().collect::<BTreeSet<_>>();
        let actual = self.tenants.keys().cloned().collect::<BTreeSet<_>>();
        if actual != expected {
            return Err(
                "tenant residency keys must exactly match the configured issuer tenants".into(),
            );
        }
        for (tenant, residency) in &self.tenants {
            validate_identifier("tenant", tenant, 128)?;
            validate_identifier("residency jurisdiction", &residency.jurisdiction, 64)?;
            if residency.allowed_regions.is_empty() {
                return Err(format!(
                    "tenant {tenant} must have at least one allowed storage Region"
                ));
            }
            let regions = residency
                .allowed_regions
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            if regions.len() != residency.allowed_regions.len() {
                return Err(format!(
                    "tenant {tenant} contains duplicate allowed storage Regions"
                ));
            }
            for region in regions {
                validate_region(&region)?;
            }
            if !residency
                .allowed_regions
                .iter()
                .any(|region| region == &residency.governance_region)
            {
                return Err(format!(
                    "tenant {tenant} governance Region must belong to its allowed storage Regions"
                ));
            }
        }
        Ok(())
    }

    pub fn residency(&self, tenant: &str) -> Option<&TenantResidency> {
        self.tenants.get(tenant)
    }

    pub fn admits(&self, tenant: &str, region: &str) -> bool {
        self.residency(tenant).is_some_and(|config| {
            config
                .allowed_regions
                .iter()
                .any(|allowed| allowed == region)
        })
    }

    pub fn admits_destructive_governance(&self, tenant: &str, region: &str) -> bool {
        self.residency(tenant)
            .is_some_and(|config| config.governance_region == region)
    }

    pub fn tenant_ids(&self) -> impl Iterator<Item = &str> {
        self.tenants.keys().map(String::as_str)
    }
}

fn validate_identifier(label: &str, value: &str, max_len: usize) -> Result<(), String> {
    if value.is_empty()
        || value.len() > max_len
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(format!("{label} must be a bounded ASCII identifier"));
    }
    Ok(())
}

fn validate_region(value: &str) -> Result<(), String> {
    if value == "local" {
        return Ok(());
    }
    let mut parts = value.split('-');
    let valid = parts
        .next()
        .is_some_and(|part| part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_lowercase()))
        && parts.clone().count() >= 2
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if valid {
        Ok(())
    } else {
        Err("allowed storage Region is malformed".into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum LegalHoldState {
    Disabled,
    Enabling,
    Enabled,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceRetentionExceptionCapability {
    /// The service fences product-controlled deletion but does not create or
    /// extend Object Lock or AWS Backup retention exceptions.
    #[default]
    ExternalOperatorManaged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernancePolicyRecord {
    pub tenant_id: String,
    pub legal_hold: LegalHoldState,
    pub legal_hold_reason: Option<String>,
    #[serde(default)]
    pub retention_exception_capability: GovernanceRetentionExceptionCapability,
    pub actor: String,
    pub updated_at: i64,
    pub revision: u64,
}

impl GovernancePolicyRecord {
    pub fn default_for(tenant_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            legal_hold: LegalHoldState::Disabled,
            legal_hold_reason: None,
            retention_exception_capability:
                GovernanceRetentionExceptionCapability::ExternalOperatorManaged,
            actor: "system:default".into(),
            updated_at: 0,
            revision: 0,
        }
    }

    pub fn held(&self) -> bool {
        self.legal_hold != LegalHoldState::Disabled
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernancePolicyPutOutcome {
    Stored(GovernancePolicyRecord),
    Conflict(GovernancePolicyRecord),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ExportSection {
    Users,
    Clients,
    Groups,
    RoleMappings,
    SecurityEvents,
    TenantConfiguration,
    SecretMetadata,
    SigningKeys,
}

impl ExportSection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Users => "users",
            Self::Clients => "clients",
            Self::Groups => "groups",
            Self::RoleMappings => "role_mappings",
            Self::SecurityEvents => "security_events",
            Self::TenantConfiguration => "tenant_configuration",
            Self::SecretMetadata => "secret_metadata",
            Self::SigningKeys => "signing_keys",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceExportManifest {
    pub export_id: String,
    pub tenant_id: String,
    pub actor: String,
    pub purpose: String,
    pub policy_revision: u64,
    pub region: String,
    pub region_revision: u64,
    pub sections: BTreeSet<ExportSection>,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceJobKind {
    UserErasure,
    TenantOffboarding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceJobState {
    Queued,
    BlockedLegalHold,
    Running,
    Retryable,
    RetentionPending,
    Completed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceJobPhase {
    IntentRecorded,
    MutationFenced,
    PrimaryCleanup,
    SuppressionRecorded,
    ReplicaVerification,
    RetentionVerification,
    Complete,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantCleanupStage {
    #[default]
    Users,
    Clients,
    InitialAccessTokens,
    DirectoryGroups,
    Federation,
    WorkloadTrust,
    AdminAuthority,
    ProtocolState,
    PolicyAndDomains,
    SharedSignals,
    SigningKeysAndSecrets,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TenantLifecycleState {
    Active,
    Offboarding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceAliasKind {
    CanonicalId,
    Email,
    ScimExternalId,
    ScimUserName,
}

impl GovernanceAliasKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CanonicalId => "canonical_id",
            Self::Email => "email",
            Self::ScimExternalId => "scim_external_id",
            Self::ScimUserName => "scim_user_name",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceTargetAlias {
    pub kind: GovernanceAliasKind,
    pub normalized_value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantLifecycleRecord {
    pub tenant_id: String,
    pub state: TenantLifecycleState,
    pub revision: u64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantMutationGateState {
    Active,
    Frozen,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantMutationGateRecord {
    pub tenant_id: String,
    pub state: TenantMutationGateState,
    pub active_permits: u64,
    pub revision: u64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantMutationPermit {
    pub tenant_id: String,
    pub permit_id: String,
    pub deadline: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantMutationPermitAcquireOutcome {
    Acquired(TenantMutationPermit),
    Frozen { lifecycle_revision: Option<u64> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceJobRecord {
    pub job_id: String,
    pub tenant_id: String,
    pub kind: GovernanceJobKind,
    /// Internal-only unfinished target. API views deliberately omit it.
    pub target_id: Option<String>,
    /// Internal-only aliases required to restart suppression writes after any
    /// process failure. Cleared with `target_id` after live-state verification.
    #[serde(default)]
    pub target_aliases: Vec<GovernanceTargetAlias>,
    /// Encrypted internal handle used only by retained verification after the
    /// plaintext target has been removed from the durable job.
    #[serde(default)]
    pub verification_target: Option<String>,
    /// Tenant offboarding persists one deterministic child erasure at a time.
    /// Re-reading the first user page after the child finishes avoids a cursor
    /// that could be invalidated by physical deletion.
    #[serde(default)]
    pub active_child_job_id: Option<String>,
    #[serde(default)]
    pub processed_records: u64,
    /// Durable tenant-authority class cursor. A stage advances only after a
    /// fresh read proves its preceding class empty.
    #[serde(default)]
    pub tenant_cleanup_stage: TenantCleanupStage,
    pub target_epoch: u64,
    pub state: GovernanceJobState,
    pub phase: GovernanceJobPhase,
    pub policy_revision: u64,
    pub tenant_revision: u64,
    pub revision: u64,
    pub created_at: i64,
    pub updated_at: i64,
    pub primary_erasure_at: Option<i64>,
    #[serde(default)]
    pub retention_anchor_at: Option<i64>,
    pub retention_until: Option<i64>,
    #[serde(default)]
    pub evidence_revision: u64,
    pub error_class: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceJobLeaseRecord {
    pub tenant_id: String,
    pub job_id: String,
    pub job_revision: u64,
    pub policy_revision: u64,
    pub tenant_revision: u64,
    pub token_digest: String,
    pub acquired_at: i64,
    pub deadline: i64,
}

impl GovernanceJobLeaseRecord {
    pub fn destructive_fence(&self, target_epoch: Option<u64>) -> GovernanceDestructiveFence {
        GovernanceDestructiveFence {
            job_id: self.job_id.clone(),
            job_revision: self.job_revision,
            policy_revision: self.policy_revision,
            tenant_revision: self.tenant_revision,
            lease_token_digest: self.token_digest.clone(),
            lease_deadline: self.deadline,
            target_epoch,
        }
    }

    pub fn external_action_fence(&self) -> GovernanceExternalActionFence {
        GovernanceExternalActionFence {
            job_id: self.job_id.clone(),
            job_revision: self.job_revision,
            policy_revision: self.policy_revision,
            tenant_revision: self.tenant_revision,
            lease_token_digest: self.token_digest.clone(),
            lease_deadline: self.deadline,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UserErasureFenceTransition {
    AlreadyFenced,
    Advance,
    LegacyZeroEpochTombstone,
}

pub(crate) fn classify_user_erasure_fence_transition(
    status: UserStatus,
    current_epoch: u64,
    target_epoch: u64,
) -> Result<UserErasureFenceTransition, StoreError> {
    let expected_epoch = target_epoch.checked_sub(1).ok_or_else(|| {
        StoreError::Permanent("user erasure target epoch must be non-zero".into())
    })?;
    if status == UserStatus::Tombstoned && current_epoch == target_epoch {
        return Ok(UserErasureFenceTransition::AlreadyFenced);
    }
    if current_epoch != expected_epoch {
        return Err(StoreError::Permanent(
            "user erasure fence no longer matches the target epoch".into(),
        ));
    }
    match status {
        UserStatus::Tombstoned if current_epoch == 0 => {
            Ok(UserErasureFenceTransition::LegacyZeroEpochTombstone)
        }
        UserStatus::Tombstoned => Err(StoreError::Permanent(
            "user erasure fence no longer matches the target epoch".into(),
        )),
        UserStatus::Active | UserStatus::Disabled => Ok(UserErasureFenceTransition::Advance),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceDestructiveFence {
    pub job_id: String,
    pub job_revision: u64,
    pub policy_revision: u64,
    pub tenant_revision: u64,
    pub lease_token_digest: String,
    pub lease_deadline: i64,
    pub target_epoch: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernanceJobLeaseConflict {
    Policy,
    Job,
    TenantLifecycle,
    Lease,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceJobLeaseOutcome {
    Acquired(GovernanceJobLeaseRecord),
    Renewed(GovernanceJobLeaseRecord),
    Released,
    Conflict(GovernanceJobLeaseConflict),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceJobCommand {
    pub tenant_id: String,
    pub job_id: String,
    pub expected_revision: u64,
    #[serde(default)]
    pub failure_attempt: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceJobStartOutcome {
    Stored(GovernanceJobRecord),
    Existing(GovernanceJobRecord),
    PolicyConflict(GovernancePolicyRecord),
    MutationConflict { active_permits: u64 },
    TenantFrozen { lifecycle_revision: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceJobUpdateOutcome {
    Stored(GovernanceJobRecord),
    Conflict(GovernanceJobRecord),
    PolicyConflict(GovernancePolicyRecord),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceContinuationAction {
    Status,
    Resume,
    Evidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct GovernanceContinuationRecord {
    pub tenant_id: String,
    pub job_id: String,
    pub tenant_revision: u64,
    pub resume_revision: u64,
    pub read_revision: u64,
    pub resume_enabled: bool,
    pub read_enabled: bool,
    pub revision: u64,
    pub created_at: i64,
    pub updated_at: i64,
}

impl GovernanceContinuationRecord {
    pub fn for_offboarding_job(job: &GovernanceJobRecord) -> Result<Self, String> {
        if job.kind != GovernanceJobKind::TenantOffboarding || job.tenant_revision == 0 {
            return Err("governance continuation requires a frozen tenant-offboarding job".into());
        }
        Ok(Self {
            tenant_id: job.tenant_id.clone(),
            job_id: job.job_id.clone(),
            tenant_revision: job.tenant_revision,
            resume_revision: 1,
            read_revision: 1,
            resume_enabled: true,
            read_enabled: true,
            revision: 1,
            created_at: job.updated_at,
            updated_at: job.updated_at,
        })
    }

    pub const fn action_revision(&self, action: GovernanceContinuationAction) -> u64 {
        match action {
            GovernanceContinuationAction::Resume => self.resume_revision,
            GovernanceContinuationAction::Status | GovernanceContinuationAction::Evidence => {
                self.read_revision
            }
        }
    }

    pub const fn action_enabled(&self, action: GovernanceContinuationAction) -> bool {
        match action {
            GovernanceContinuationAction::Resume => self.resume_enabled,
            GovernanceContinuationAction::Status | GovernanceContinuationAction::Evidence => {
                self.read_enabled
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceContinuationUpdateOutcome {
    Stored(GovernanceContinuationRecord),
    Conflict(GovernanceContinuationRecord),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceSuppressionRecord {
    pub tenant_id: String,
    pub target_class: String,
    pub key_version: u32,
    pub normalization_version: u32,
    pub digest: String,
    pub target_epoch: u64,
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceResourceOwnership {
    ProductManaged,
    #[default]
    External,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceSecretReference {
    pub purpose: String,
    pub secret_ref: String,
    #[serde(default)]
    pub ownership: GovernanceResourceOwnership,
    #[serde(default)]
    pub resource_account: Option<String>,
    #[serde(default)]
    pub resource_region: Option<String>,
    #[serde(default)]
    pub resource_fingerprint: Option<String>,
    #[serde(default)]
    pub ownership_revision: u64,
}

impl GovernanceSecretReference {
    pub fn historical_external(purpose: impl Into<String>, secret_ref: impl Into<String>) -> Self {
        let secret_ref = secret_ref.into();
        Self {
            purpose: purpose.into(),
            resource_fingerprint: Some(resource_fingerprint(&secret_ref)),
            secret_ref,
            ownership: GovernanceResourceOwnership::External,
            resource_account: None,
            resource_region: None,
            ownership_revision: 0,
        }
    }

    pub fn normalize(mut self) -> Result<Self, String> {
        validate_identifier("secret purpose", &self.purpose, 64)?;
        if self.secret_ref.is_empty()
            || self.secret_ref.len() > 2_048
            || self.secret_ref.chars().any(char::is_whitespace)
        {
            return Err("secret reference must be bounded and contain no whitespace".into());
        }
        let expected_fingerprint = resource_fingerprint(&self.secret_ref);
        match self.resource_fingerprint.as_deref() {
            Some(fingerprint) if fingerprint != expected_fingerprint => {
                return Err("secret resource fingerprint does not match its reference".into())
            }
            None => self.resource_fingerprint = Some(expected_fingerprint),
            _ => {}
        }
        if self.ownership == GovernanceResourceOwnership::ProductManaged {
            let (region, account) = secrets_manager_arn_region_account(&self.secret_ref)
                .ok_or("product-managed secret reference must be a full Secrets Manager ARN")?;
            if self
                .resource_region
                .as_deref()
                .is_some_and(|value| value != region)
                || self
                    .resource_account
                    .as_deref()
                    .is_some_and(|value| value != account)
            {
                return Err("secret ownership Region/account does not match its ARN".into());
            }
            self.resource_region = Some(region.to_string());
            self.resource_account = Some(account.to_string());
            if self.ownership_revision == 0 {
                return Err("product-managed secret ownership requires a positive revision".into());
            }
        }
        Ok(self)
    }
}

fn secrets_manager_arn_region_account(value: &str) -> Option<(&str, &str)> {
    let mut parts = value.splitn(6, ':');
    (parts.next()? == "arn"
        && parts.next()?.starts_with("aws")
        && parts.next()? == "secretsmanager")
        .then_some((parts.next()?, parts.next()?))
        .filter(|(region, account)| {
            !region.is_empty()
                && !account.is_empty()
                && value
                    .splitn(6, ':')
                    .nth(5)
                    .is_some_and(|tail| tail.starts_with("secret:") && tail.len() > "secret:".len())
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceExternalActionKind {
    TenantKeyDeletion,
    SecretDeletion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceExternalActionState {
    Prepared,
    Claimed,
    ExternalPreparationDispatched,
    ClaimTombstoned,
    ExternallyCommitted,
    Verified,
    OperatorPending,
}

impl GovernanceExternalActionState {
    pub(crate) fn requires_hold_drain(self) -> bool {
        matches!(
            self,
            Self::Claimed | Self::ExternalPreparationDispatched | Self::ExternallyCommitted
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceExternalActionRecord {
    pub action_id: String,
    pub tenant_id: String,
    pub job_id: String,
    pub kind: GovernanceExternalActionKind,
    /// Internal executor input. API and evidence views expose only the action
    /// id, kind, ownership, and lifecycle outcome.
    pub resource_ref: String,
    pub resource_fingerprint: String,
    pub ownership: GovernanceResourceOwnership,
    pub state: GovernanceExternalActionState,
    pub revision: u64,
    pub created_at: i64,
    pub updated_at: i64,
    pub claim_token_digest: Option<String>,
    pub claim_deadline: Option<i64>,
    pub committed_at: Option<i64>,
    pub verified_at: Option<i64>,
    pub retention_until: Option<i64>,
    pub error_class: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceExternalActionFence {
    pub job_id: String,
    pub job_revision: u64,
    pub policy_revision: u64,
    pub tenant_revision: u64,
    pub lease_token_digest: String,
    pub lease_deadline: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceExternalActionReconcileFence {
    pub job_id: String,
    pub tenant_revision: u64,
    pub claim_token_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceExternalActionPutOutcome {
    Stored(GovernanceExternalActionRecord),
    Existing(GovernanceExternalActionRecord),
    FenceConflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceExternalActionUpdateOutcome {
    Stored(GovernanceExternalActionRecord),
    Conflict(GovernanceExternalActionRecord),
    FenceConflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceExternalActionOutcome {
    PendingDeletion,
    Absent,
    ExternalRetained,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct GovernanceEvidenceAction {
    pub action_id: String,
    pub kind: GovernanceExternalActionKind,
    pub ownership: GovernanceResourceOwnership,
    pub state: GovernanceExternalActionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<GovernanceExternalActionOutcome>,
    pub retention_until: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct GovernanceReplicaEvidence {
    pub verification_state: String,
    pub verified_at: Option<i64>,
    pub live_counts: BTreeMap<String, u64>,
    #[serde(default)]
    pub retained_counts: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct GovernanceRetentionEvidence {
    pub state: String,
    pub evidence_basis: String,
    pub lifecycle_source: String,
    pub retention_until: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct GovernanceEvidencePayload {
    pub schema_version: String,
    pub tenant_id: String,
    pub job_id: String,
    pub job_kind: GovernanceJobKind,
    pub job_state: GovernanceJobState,
    pub evidence_revision: u64,
    pub deployment_commit: String,
    pub started_at: i64,
    pub verification_at: i64,
    pub generated_at: i64,
    pub primary_erasure_at: i64,
    pub retention_deadline: i64,
    pub residency_jurisdiction: String,
    pub configured_regions: Vec<String>,
    pub active_writer_region: String,
    pub region_control_revision: u64,
    pub legal_hold: LegalHoldState,
    pub live_counts: BTreeMap<String, u64>,
    pub retained_counts: BTreeMap<String, u64>,
    pub replica_live_counts: BTreeMap<String, GovernanceReplicaEvidence>,
    pub alias_tombstone_count: u64,
    pub retention_resources: BTreeMap<String, GovernanceRetentionEvidence>,
    pub external_actions: Vec<GovernanceEvidenceAction>,
    pub permanent_control_records: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct GovernanceEvidenceRecord {
    pub payload: GovernanceEvidencePayload,
    pub payload_sha256: String,
}

impl GovernanceEvidenceRecord {
    pub fn new(payload: GovernanceEvidencePayload) -> Result<Self, String> {
        let canonical = serde_json::to_vec(&payload)
            .map_err(|error| format!("governance evidence serialization failed: {error}"))?;
        Ok(Self {
            payload,
            payload_sha256: URL_SAFE_NO_PAD.encode(Sha256::digest(canonical)),
        })
    }

    pub fn verify_hash(&self) -> bool {
        serde_json::to_vec(&self.payload)
            .ok()
            .is_some_and(|canonical| {
                URL_SAFE_NO_PAD.encode(Sha256::digest(canonical)) == self.payload_sha256
            })
    }

    pub(crate) fn verifies_completion_of(&self, job: &GovernanceJobRecord) -> bool {
        self.verify_hash()
            && self.payload.schema_version == GOVERNANCE_EVIDENCE_SCHEMA_VERSION
            && self.payload.tenant_id == job.tenant_id
            && self.payload.job_id == job.job_id
            && self.payload.job_kind == job.kind
            && self.payload.job_state == GovernanceJobState::Completed
            && self.payload.evidence_revision != 0
            && self.payload.evidence_revision == job.evidence_revision
            && self.payload.started_at == job.created_at
            && self.payload.generated_at == job.updated_at
            && self.payload.verification_at == job.updated_at
            && job.primary_erasure_at == Some(self.payload.primary_erasure_at)
            && job.retention_until == Some(self.payload.retention_deadline)
            && job.state == GovernanceJobState::Completed
            && job.phase == GovernanceJobPhase::Complete
            && job.target_id.is_none()
            && job.target_aliases.is_empty()
            && job.verification_target.is_none()
            && job.error_class.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceEvidencePutOutcome {
    Stored(GovernanceEvidenceRecord),
    Existing(GovernanceEvidenceRecord),
}

#[derive(Clone)]
pub enum GovernanceStoreImpl {
    Memory(crate::adapters::memory::MemoryGovernanceStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoGovernanceStore),
}

#[derive(Clone)]
pub enum GovernanceJobQueueImpl {
    Memory(crate::adapters::memory::MemoryGovernanceJobQueue),
    #[cfg(feature = "aws")]
    Sqs(crate::adapters::aws::SqsGovernanceJobQueue),
    Unavailable,
}

impl GovernanceJobQueue for GovernanceJobQueueImpl {
    async fn enqueue(&self, command: GovernanceJobCommand) -> Result<(), StoreError> {
        match self {
            Self::Memory(queue) => queue.enqueue(command).await,
            #[cfg(feature = "aws")]
            Self::Sqs(queue) => queue.enqueue(command).await,
            Self::Unavailable => Err(StoreError::Transient(
                "governance worker queue is unavailable in this Region".into(),
            )),
        }
    }
}

impl GovernanceStore for GovernanceStoreImpl {
    async fn acquire_tenant_mutation_permit(
        &self,
        permit: TenantMutationPermit,
        now: i64,
    ) -> Result<TenantMutationPermitAcquireOutcome, StoreError> {
        match self {
            Self::Memory(store) => store.acquire_tenant_mutation_permit(permit, now).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.acquire_tenant_mutation_permit(permit, now).await,
        }
    }

    async fn renew_tenant_mutation_permit(
        &self,
        permit: &TenantMutationPermit,
        now: i64,
        deadline: i64,
    ) -> Result<bool, StoreError> {
        match self {
            Self::Memory(store) => {
                store
                    .renew_tenant_mutation_permit(permit, now, deadline)
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .renew_tenant_mutation_permit(permit, now, deadline)
                    .await
            }
        }
    }

    async fn release_tenant_mutation_permit(
        &self,
        permit: TenantMutationPermit,
        now: i64,
    ) -> Result<bool, StoreError> {
        match self {
            Self::Memory(store) => store.release_tenant_mutation_permit(permit, now).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.release_tenant_mutation_permit(permit, now).await,
        }
    }

    async fn get_policy(
        &self,
        tenant_id: &str,
    ) -> Result<Option<GovernancePolicyRecord>, StoreError> {
        match self {
            Self::Memory(store) => store.get_policy(tenant_id).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.get_policy(tenant_id).await,
        }
    }

    async fn put_policy(
        &self,
        record: GovernancePolicyRecord,
        expected_revision: u64,
    ) -> Result<GovernancePolicyPutOutcome, StoreError> {
        match self {
            Self::Memory(store) => store.put_policy(record, expected_revision).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.put_policy(record, expected_revision).await,
        }
    }

    async fn put_export_manifest(
        &self,
        manifest: GovernanceExportManifest,
    ) -> Result<bool, StoreError> {
        match self {
            Self::Memory(store) => store.put_export_manifest(manifest).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.put_export_manifest(manifest).await,
        }
    }

    async fn get_export_manifest(
        &self,
        tenant_id: &str,
        export_id: &str,
        now: i64,
    ) -> Result<Option<GovernanceExportManifest>, StoreError> {
        match self {
            Self::Memory(store) => store.get_export_manifest(tenant_id, export_id, now).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.get_export_manifest(tenant_id, export_id, now).await,
        }
    }

    async fn start_or_resume_job(
        &self,
        job: GovernanceJobRecord,
        expected_policy_revision: u64,
        freeze_tenant: bool,
    ) -> Result<GovernanceJobStartOutcome, StoreError> {
        match self {
            Self::Memory(store) => {
                store
                    .start_or_resume_job(job, expected_policy_revision, freeze_tenant)
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .start_or_resume_job(job, expected_policy_revision, freeze_tenant)
                    .await
            }
        }
    }

    async fn get_job(
        &self,
        tenant_id: &str,
        job_id: &str,
    ) -> Result<Option<GovernanceJobRecord>, StoreError> {
        match self {
            Self::Memory(store) => store.get_job(tenant_id, job_id).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.get_job(tenant_id, job_id).await,
        }
    }

    async fn list_jobs(&self, tenant_id: &str) -> Result<Vec<GovernanceJobRecord>, StoreError> {
        match self {
            Self::Memory(store) => store.list_jobs(tenant_id).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.list_jobs(tenant_id).await,
        }
    }

    async fn get_continuation(
        &self,
        tenant_id: &str,
        job_id: &str,
    ) -> Result<Option<GovernanceContinuationRecord>, StoreError> {
        match self {
            Self::Memory(store) => store.get_continuation(tenant_id, job_id).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.get_continuation(tenant_id, job_id).await,
        }
    }

    async fn update_continuation(
        &self,
        record: GovernanceContinuationRecord,
        expected_revision: u64,
    ) -> Result<GovernanceContinuationUpdateOutcome, StoreError> {
        match self {
            Self::Memory(store) => store.update_continuation(record, expected_revision).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.update_continuation(record, expected_revision).await,
        }
    }

    async fn consume_continuation_resume(
        &self,
        tenant_id: &str,
        job_id: &str,
        jti_digest: &str,
        expected_resume_revision: u64,
        expires_at: i64,
    ) -> Result<bool, StoreError> {
        match self {
            Self::Memory(store) => {
                store
                    .consume_continuation_resume(
                        tenant_id,
                        job_id,
                        jti_digest,
                        expected_resume_revision,
                        expires_at,
                    )
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .consume_continuation_resume(
                        tenant_id,
                        job_id,
                        jti_digest,
                        expected_resume_revision,
                        expires_at,
                    )
                    .await
            }
        }
    }

    async fn update_job(
        &self,
        job: GovernanceJobRecord,
        expected_revision: u64,
        expected_policy_revision: u64,
    ) -> Result<GovernanceJobUpdateOutcome, StoreError> {
        match self {
            Self::Memory(store) => {
                store
                    .update_job(job, expected_revision, expected_policy_revision)
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .update_job(job, expected_revision, expected_policy_revision)
                    .await
            }
        }
    }

    async fn complete_job_with_evidence(
        &self,
        job: GovernanceJobRecord,
        evidence: GovernanceEvidenceRecord,
        expected_revision: u64,
        expected_policy_revision: u64,
    ) -> Result<GovernanceJobUpdateOutcome, StoreError> {
        match self {
            Self::Memory(store) => {
                store
                    .complete_job_with_evidence(
                        job,
                        evidence,
                        expected_revision,
                        expected_policy_revision,
                    )
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .complete_job_with_evidence(
                        job,
                        evidence,
                        expected_revision,
                        expected_policy_revision,
                    )
                    .await
            }
        }
    }

    async fn claim_job_lease(
        &self,
        tenant_id: &str,
        job_id: &str,
        expected_job_revision: u64,
        token_digest: &str,
        now: i64,
        deadline: i64,
    ) -> Result<GovernanceJobLeaseOutcome, StoreError> {
        match self {
            Self::Memory(store) => {
                store
                    .claim_job_lease(
                        tenant_id,
                        job_id,
                        expected_job_revision,
                        token_digest,
                        now,
                        deadline,
                    )
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .claim_job_lease(
                        tenant_id,
                        job_id,
                        expected_job_revision,
                        token_digest,
                        now,
                        deadline,
                    )
                    .await
            }
        }
    }

    async fn renew_job_lease(
        &self,
        tenant_id: &str,
        fence: GovernanceDestructiveFence,
        now: i64,
        deadline: i64,
    ) -> Result<GovernanceJobLeaseOutcome, StoreError> {
        match self {
            Self::Memory(store) => store.renew_job_lease(tenant_id, fence, now, deadline).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.renew_job_lease(tenant_id, fence, now, deadline).await,
        }
    }

    async fn release_job_lease(
        &self,
        tenant_id: &str,
        fence: GovernanceDestructiveFence,
    ) -> Result<GovernanceJobLeaseOutcome, StoreError> {
        match self {
            Self::Memory(store) => store.release_job_lease(tenant_id, fence).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.release_job_lease(tenant_id, fence).await,
        }
    }

    async fn tenant_has_active_job_leases(
        &self,
        tenant_id: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        match self {
            Self::Memory(store) => store.tenant_has_active_job_leases(tenant_id, now).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.tenant_has_active_job_leases(tenant_id, now).await,
        }
    }

    async fn get_tenant_lifecycle(
        &self,
        tenant_id: &str,
    ) -> Result<Option<TenantLifecycleRecord>, StoreError> {
        match self {
            Self::Memory(store) => store.get_tenant_lifecycle(tenant_id).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.get_tenant_lifecycle(tenant_id).await,
        }
    }

    async fn prepare_external_action(
        &self,
        record: GovernanceExternalActionRecord,
        fence: GovernanceExternalActionFence,
    ) -> Result<GovernanceExternalActionPutOutcome, StoreError> {
        match self {
            Self::Memory(store) => store.prepare_external_action(record, fence).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.prepare_external_action(record, fence).await,
        }
    }

    async fn get_external_action(
        &self,
        tenant_id: &str,
        job_id: &str,
        action_id: &str,
    ) -> Result<Option<GovernanceExternalActionRecord>, StoreError> {
        match self {
            Self::Memory(store) => {
                store
                    .get_external_action(tenant_id, job_id, action_id)
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .get_external_action(tenant_id, job_id, action_id)
                    .await
            }
        }
    }

    async fn list_external_actions(
        &self,
        tenant_id: &str,
        job_id: &str,
    ) -> Result<Vec<GovernanceExternalActionRecord>, StoreError> {
        match self {
            Self::Memory(store) => store.list_external_actions(tenant_id, job_id).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.list_external_actions(tenant_id, job_id).await,
        }
    }

    async fn list_tenant_external_actions(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<GovernanceExternalActionRecord>, StoreError> {
        match self {
            Self::Memory(store) => store.list_tenant_external_actions(tenant_id).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.list_tenant_external_actions(tenant_id).await,
        }
    }

    async fn update_external_action(
        &self,
        record: GovernanceExternalActionRecord,
        expected_revision: u64,
        fence: GovernanceExternalActionFence,
    ) -> Result<GovernanceExternalActionUpdateOutcome, StoreError> {
        match self {
            Self::Memory(store) => {
                store
                    .update_external_action(record, expected_revision, fence)
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .update_external_action(record, expected_revision, fence)
                    .await
            }
        }
    }

    async fn reconcile_external_action(
        &self,
        record: GovernanceExternalActionRecord,
        expected_revision: u64,
        fence: GovernanceExternalActionReconcileFence,
    ) -> Result<GovernanceExternalActionUpdateOutcome, StoreError> {
        match self {
            Self::Memory(store) => {
                store
                    .reconcile_external_action(record, expected_revision, fence)
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .reconcile_external_action(record, expected_revision, fence)
                    .await
            }
        }
    }

    async fn put_evidence(
        &self,
        record: GovernanceEvidenceRecord,
    ) -> Result<GovernanceEvidencePutOutcome, StoreError> {
        match self {
            Self::Memory(store) => store.put_evidence(record).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.put_evidence(record).await,
        }
    }

    async fn latest_evidence(
        &self,
        tenant_id: &str,
        job_id: &str,
    ) -> Result<Option<GovernanceEvidenceRecord>, StoreError> {
        match self {
            Self::Memory(store) => store.latest_evidence(tenant_id, job_id).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.latest_evidence(tenant_id, job_id).await,
        }
    }

    async fn put_suppression(
        &self,
        record: GovernanceSuppressionRecord,
        fence: GovernanceDestructiveFence,
        now: i64,
    ) -> Result<bool, StoreError> {
        match self {
            Self::Memory(store) => store.put_suppression(record, fence, now).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.put_suppression(record, fence, now).await,
        }
    }

    async fn is_suppressed(
        &self,
        tenant_id: &str,
        target_class: &str,
        digest: &str,
    ) -> Result<bool, StoreError> {
        match self {
            Self::Memory(store) => store.is_suppressed(tenant_id, target_class, digest).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.is_suppressed(tenant_id, target_class, digest).await,
        }
    }

    async fn latest_suppression_epoch(
        &self,
        tenant_id: &str,
        target_class: &str,
        digest: &str,
    ) -> Result<Option<u64>, StoreError> {
        match self {
            Self::Memory(store) => {
                store
                    .latest_suppression_epoch(tenant_id, target_class, digest)
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .latest_suppression_epoch(tenant_id, target_class, digest)
                    .await
            }
        }
    }
}

pub fn validate_purpose(value: &str) -> Result<String, &'static str> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > GOVERNANCE_PURPOSE_MAX_LEN
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b' ')
        })
    {
        return Err("purpose must be a bounded printable ASCII value");
    }
    Ok(value.to_string())
}

pub fn validate_reason(value: Option<&str>, enabled: bool) -> Result<Option<String>, &'static str> {
    let value = value.map(str::trim).filter(|value| !value.is_empty());
    if !enabled {
        return match value {
            None => Ok(None),
            Some(_) => Err("a disabled legal hold cannot contain a reason"),
        };
    }
    let Some(value) = value else {
        return Err("an enabled legal hold requires an opaque reason code");
    };
    if value.len() > GOVERNANCE_REASON_MAX_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err("legal hold reason must be an opaque ASCII reason code");
    }
    Ok(Some(value.to_string()))
}

pub fn stable_job_id(
    key: &[u8],
    tenant_id: &str,
    kind: GovernanceJobKind,
    target_id: &str,
    target_epoch: u64,
) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(b"governance-job:v1\0");
    mac.update(&(tenant_id.len() as u64).to_be_bytes());
    mac.update(tenant_id.as_bytes());
    mac.update(&[match kind {
        GovernanceJobKind::UserErasure => 1,
        GovernanceJobKind::TenantOffboarding => 2,
    }]);
    mac.update(&(target_id.len() as u64).to_be_bytes());
    mac.update(target_id.as_bytes());
    mac.update(&target_epoch.to_be_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

pub fn stable_external_action_id(
    key: &[u8],
    tenant_id: &str,
    job_id: &str,
    kind: GovernanceExternalActionKind,
    resource_ref: &str,
) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(b"governance-external-action:v1\0");
    for value in [tenant_id, job_id, resource_ref] {
        mac.update(&(value.len() as u64).to_be_bytes());
        mac.update(value.as_bytes());
    }
    mac.update(&[match kind {
        GovernanceExternalActionKind::TenantKeyDeletion => 1,
        GovernanceExternalActionKind::SecretDeletion => 2,
    }]);
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

pub fn resource_fingerprint(resource_ref: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(resource_ref.as_bytes()))
}

fn verification_target_cipher(key: &[u8]) -> Aes256Gcm {
    let mut digest = Sha256::new();
    digest.update(b"governance-verification-target:v1\0");
    digest.update(key);
    Aes256Gcm::new_from_slice(&digest.finalize()).expect("SHA-256 yields an AES-256 key")
}

pub fn seal_verification_target(key: &[u8], job_id: &str, target: &str) -> Result<String, String> {
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = verification_target_cipher(key)
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: target.as_bytes(),
                aad: job_id.as_bytes(),
            },
        )
        .map_err(|_| "governance verification target encryption failed".to_string())?;
    let mut sealed = nonce.to_vec();
    sealed.extend_from_slice(&ciphertext);
    Ok(URL_SAFE_NO_PAD.encode(sealed))
}

pub fn open_verification_target(key: &[u8], job_id: &str, sealed: &str) -> Result<String, String> {
    let sealed = URL_SAFE_NO_PAD
        .decode(sealed)
        .map_err(|_| "governance verification target is malformed".to_string())?;
    if sealed.len() < 12 {
        return Err("governance verification target is malformed".into());
    }
    let (nonce, ciphertext) = sealed.split_at(12);
    let plaintext = verification_target_cipher(key)
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: job_id.as_bytes(),
            },
        )
        .map_err(|_| "governance verification target authentication failed".to_string())?;
    String::from_utf8(plaintext)
        .map_err(|_| "governance verification target is not UTF-8".to_string())
}

pub fn suppression_digest(
    key: &[u8],
    tenant_id: &str,
    target_class: &str,
    alias_kind: &str,
    normalization_version: u32,
    normalized_value: &str,
) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(b"governance-suppression:v1\0");
    for value in [tenant_id, target_class, alias_kind, normalized_value] {
        mac.update(&(value.len() as u64).to_be_bytes());
        mac.update(value.as_bytes());
    }
    mac.update(&normalization_version.to_be_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

pub fn suppression_partition_key(tenant_id: &str, target_class: &str, digest: &str) -> String {
    format!("{tenant_id}\u{1f}{target_class}\u{1f}{digest}")
}

pub async fn user_alias_is_suppressed(
    state: &crate::state::AppState,
    tenant_id: &str,
    kind: GovernanceAliasKind,
    normalized_value: &str,
) -> Result<bool, StoreError> {
    let digest = suppression_digest(
        &state.governance_hmac_key,
        tenant_id,
        "user",
        kind.as_str(),
        SUPPRESSION_NORMALIZATION_VERSION,
        normalized_value,
    );
    state
        .governance
        .is_suppressed(tenant_id, "user", &digest)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_erasure_fence_only_adopts_zero_epoch_legacy_tombstones() {
        assert_eq!(
            classify_user_erasure_fence_transition(UserStatus::Tombstoned, 0, 1).unwrap(),
            UserErasureFenceTransition::LegacyZeroEpochTombstone
        );
        assert_eq!(
            classify_user_erasure_fence_transition(UserStatus::Active, 3, 4).unwrap(),
            UserErasureFenceTransition::Advance
        );
        assert_eq!(
            classify_user_erasure_fence_transition(UserStatus::Tombstoned, 4, 4).unwrap(),
            UserErasureFenceTransition::AlreadyFenced
        );
        assert!(classify_user_erasure_fence_transition(UserStatus::Active, 0, 0).is_err());
        for (current_epoch, target_epoch) in [(3, 4), (4, 5), (5, 4)] {
            assert!(classify_user_erasure_fence_transition(
                UserStatus::Tombstoned,
                current_epoch,
                target_epoch
            )
            .is_err());
        }
    }

    #[test]
    fn legacy_evidence_action_without_outcome_round_trips_canonically() {
        let legacy = r#"{"action_id":"legacy","kind":"secret_deletion","ownership":"product_managed","state":"verified","retention_until":123}"#;
        let action: GovernanceEvidenceAction = serde_json::from_str(legacy).unwrap();
        assert_eq!(action.outcome, None);
        assert_eq!(serde_json::to_string(&action).unwrap(), legacy);
    }

    fn lease_test_job(job_id: &str, kind: GovernanceJobKind) -> GovernanceJobRecord {
        GovernanceJobRecord {
            job_id: job_id.into(),
            tenant_id: "t1".into(),
            kind,
            target_id: (kind == GovernanceJobKind::UserErasure).then(|| "user-1".into()),
            target_aliases: vec![],
            verification_target: None,
            active_child_job_id: None,
            processed_records: 0,
            tenant_cleanup_stage: TenantCleanupStage::Users,
            target_epoch: 1,
            state: GovernanceJobState::Queued,
            phase: GovernanceJobPhase::IntentRecorded,
            policy_revision: 0,
            tenant_revision: 0,
            revision: 1,
            created_at: 10,
            updated_at: 10,
            primary_erasure_at: None,
            retention_anchor_at: None,
            retention_until: None,
            evidence_revision: 0,
            error_class: None,
        }
    }

    #[test]
    fn residency_requires_exact_tenant_set_and_unique_regions() {
        let expected = vec!["t1".to_string(), "t2".to_string()];
        assert!(GovernanceConfig::parse_json(
            r#"{
                "t1":{"jurisdiction":"us","allowed_regions":["us-east-1","us-west-2"]},
                "t2":{"jurisdiction":"eu","allowed_regions":["eu-west-1"]}
            }"#,
            &expected
        )
        .is_ok());
        assert!(GovernanceConfig::parse_json(
            r#"{"t1":{"jurisdiction":"us","allowed_regions":["us-east-1"]}}"#,
            &expected
        )
        .is_err());
        assert!(GovernanceConfig::parse_json(
            r#"{
                "t1":{"jurisdiction":"us","allowed_regions":["us-east-1"],"governance_region":"us-west-2"},
                "t2":{"jurisdiction":"eu","allowed_regions":["eu-west-1"]}
            }"#,
            &expected
        )
        .is_err());
        assert!(GovernanceConfig::parse_json(
            r#"{
                "t1":{"jurisdiction":"us","allowed_regions":["us-east-1","us-east-1"]},
                "t2":{"jurisdiction":"eu","allowed_regions":["eu-west-1"]}
            }"#,
            &expected
        )
        .is_err());
    }

    #[test]
    fn suppression_digest_is_domain_separated() {
        let key = b"dedicated-governance-test-key";
        let email = suppression_digest(key, "t1", "user", "email", 1, "same@example.com");
        let user_name =
            suppression_digest(key, "t1", "user", "scim_user_name", 1, "same@example.com");
        let other_tenant = suppression_digest(key, "t2", "user", "email", 1, "same@example.com");
        assert_ne!(email, user_name);
        assert_ne!(email, other_tenant);
    }

    #[test]
    fn verification_target_is_authenticated_and_job_bound() {
        let sealed = seal_verification_target(b"governance-key", "job-1", "user-1").unwrap();
        assert_eq!(
            open_verification_target(b"governance-key", "job-1", &sealed).unwrap(),
            "user-1"
        );
        assert!(open_verification_target(b"governance-key", "job-2", &sealed).is_err());
        assert!(open_verification_target(b"other-key", "job-1", &sealed).is_err());
    }

    #[test]
    fn legal_hold_reason_is_an_opaque_code() {
        assert_eq!(
            validate_reason(Some("case-1234"), true).unwrap(),
            Some("case-1234".into())
        );
        assert!(validate_reason(Some("customer alice@example.com"), true).is_err());
        assert!(validate_reason(None, true).is_err());
        assert!(validate_reason(Some("case-1234"), false).is_err());
    }

    #[tokio::test]
    async fn job_checkpoint_cas_rejects_stale_workers_and_policy_changes() {
        let store = crate::adapters::memory::MemoryGovernanceStore::default();
        let job = GovernanceJobRecord {
            job_id: "job-1".into(),
            tenant_id: "t1".into(),
            kind: GovernanceJobKind::UserErasure,
            target_id: Some("user-1".into()),
            target_aliases: vec![],
            verification_target: None,
            active_child_job_id: None,
            processed_records: 0,
            tenant_cleanup_stage: TenantCleanupStage::Users,
            target_epoch: 1,
            state: GovernanceJobState::Queued,
            phase: GovernanceJobPhase::IntentRecorded,
            policy_revision: 0,
            tenant_revision: 0,
            revision: 1,
            created_at: 10,
            updated_at: 10,
            primary_erasure_at: None,
            retention_anchor_at: None,
            retention_until: None,
            evidence_revision: 0,
            error_class: None,
        };
        assert!(matches!(
            store
                .start_or_resume_job(job.clone(), 0, false)
                .await
                .unwrap(),
            GovernanceJobStartOutcome::Stored(_)
        ));

        let mut running = job.clone();
        running.state = GovernanceJobState::Running;
        running.phase = GovernanceJobPhase::MutationFenced;
        let stored = match store.update_job(running.clone(), 1, 0).await.unwrap() {
            GovernanceJobUpdateOutcome::Stored(stored) => stored,
            outcome => panic!("unexpected update outcome: {outcome:?}"),
        };
        assert_eq!(stored.revision, 2);

        assert!(matches!(
            store.update_job(running, 1, 0).await.unwrap(),
            GovernanceJobUpdateOutcome::Conflict(current) if current.revision == 2
        ));

        store
            .put_policy(
                GovernancePolicyRecord {
                    tenant_id: "t1".into(),
                    legal_hold: LegalHoldState::Enabled,
                    legal_hold_reason: Some("case-1".into()),
                    retention_exception_capability: Default::default(),
                    actor: "owner".into(),
                    updated_at: 11,
                    revision: 1,
                },
                0,
            )
            .await
            .unwrap();
        assert!(matches!(
            store.update_job(stored, 2, 0).await.unwrap(),
            GovernanceJobUpdateOutcome::PolicyConflict(policy) if policy.revision == 1
        ));
    }

    #[tokio::test]
    async fn destructive_job_lease_has_one_owner_and_expiry_allows_reclaim() {
        let store = crate::adapters::memory::MemoryGovernanceStore::default();
        let job = lease_test_job("lease-job", GovernanceJobKind::UserErasure);
        assert!(matches!(
            store.start_or_resume_job(job, 0, false).await.unwrap(),
            GovernanceJobStartOutcome::Stored(_)
        ));

        let (worker_a, worker_b) = tokio::join!(
            store.claim_job_lease("t1", "lease-job", 1, "worker-a", 100, 110),
            store.claim_job_lease("t1", "lease-job", 1, "worker-b", 100, 110)
        );
        let outcomes = [worker_a.unwrap(), worker_b.unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, GovernanceJobLeaseOutcome::Acquired(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| {
                    matches!(
                        outcome,
                        GovernanceJobLeaseOutcome::Conflict(GovernanceJobLeaseConflict::Lease)
                    )
                })
                .count(),
            1
        );
        assert!(store.tenant_has_active_job_leases("t1", 109).await.unwrap());
        assert!(!store.tenant_has_active_job_leases("t2", 109).await.unwrap());
        assert!(!store.tenant_has_active_job_leases("t1", 110).await.unwrap());

        let reclaimed = match store
            .claim_job_lease("t1", "lease-job", 1, "worker-c", 110, 120)
            .await
            .unwrap()
        {
            GovernanceJobLeaseOutcome::Acquired(lease) => lease,
            outcome => panic!("unexpected lease reclaim outcome: {outcome:?}"),
        };
        assert!(store.tenant_has_active_job_leases("t1", 119).await.unwrap());
        assert!(!store.tenant_has_active_job_leases("t1", 120).await.unwrap());
        let mut wrong_token = reclaimed.destructive_fence(Some(1));
        wrong_token.lease_token_digest = "wrong-worker".into();
        assert_eq!(
            store
                .renew_job_lease("t1", wrong_token, 111, 130)
                .await
                .unwrap(),
            GovernanceJobLeaseOutcome::Conflict(GovernanceJobLeaseConflict::Lease)
        );

        let renewed = match store
            .renew_job_lease("t1", reclaimed.destructive_fence(Some(1)), 111, 130)
            .await
            .unwrap()
        {
            GovernanceJobLeaseOutcome::Renewed(lease) => lease,
            outcome => panic!("unexpected lease renewal outcome: {outcome:?}"),
        };
        assert_eq!(
            store
                .release_job_lease("t1", reclaimed.destructive_fence(Some(1)))
                .await
                .unwrap(),
            GovernanceJobLeaseOutcome::Conflict(GovernanceJobLeaseConflict::Lease)
        );
        assert_eq!(
            store
                .release_job_lease("t1", renewed.destructive_fence(Some(1)))
                .await
                .unwrap(),
            GovernanceJobLeaseOutcome::Released
        );
    }

    #[tokio::test]
    async fn offboarding_freeze_waits_for_mutation_permits_and_blocks_new_ones() {
        let store = crate::adapters::memory::MemoryGovernanceStore::default();
        let mut permit = TenantMutationPermit {
            tenant_id: "t1".into(),
            permit_id: "request-1".into(),
            deadline: 220,
        };
        assert_eq!(
            store
                .acquire_tenant_mutation_permit(permit.clone(), 100)
                .await
                .unwrap(),
            TenantMutationPermitAcquireOutcome::Acquired(permit.clone())
        );

        let mut job = lease_test_job(
            "offboard-with-request",
            GovernanceJobKind::TenantOffboarding,
        );
        job.created_at = 100;
        job.updated_at = 100;
        assert_eq!(
            store
                .start_or_resume_job(job.clone(), 0, true)
                .await
                .unwrap(),
            GovernanceJobStartOutcome::MutationConflict { active_permits: 1 }
        );

        assert!(store
            .renew_tenant_mutation_permit(&permit, 110, 230)
            .await
            .unwrap());
        permit.deadline = 230;
        assert!(store
            .release_tenant_mutation_permit(permit, 111)
            .await
            .unwrap());
        job.updated_at = 112;
        assert!(matches!(
            store.start_or_resume_job(job, 0, true).await.unwrap(),
            GovernanceJobStartOutcome::Stored(stored) if stored.tenant_revision == 1
        ));

        let rejected = TenantMutationPermit {
            tenant_id: "t1".into(),
            permit_id: "request-2".into(),
            deadline: 240,
        };
        assert_eq!(
            store
                .acquire_tenant_mutation_permit(rejected, 120)
                .await
                .unwrap(),
            TenantMutationPermitAcquireOutcome::Frozen {
                lifecycle_revision: Some(1)
            }
        );
    }

    #[tokio::test]
    async fn offboarding_adopts_existing_erasure_and_invalidates_its_old_lease() {
        let store = crate::adapters::memory::MemoryGovernanceStore::default();
        let mut standalone = lease_test_job("existing-erasure", GovernanceJobKind::UserErasure);
        standalone.updated_at = 100;
        assert!(matches!(
            store
                .start_or_resume_job(standalone.clone(), 0, false)
                .await
                .unwrap(),
            GovernanceJobStartOutcome::Stored(_)
        ));
        let old_lease = match store
            .claim_job_lease("t1", "existing-erasure", 1, "old-worker", 100, 110)
            .await
            .unwrap()
        {
            GovernanceJobLeaseOutcome::Acquired(lease) => lease,
            outcome => panic!("unexpected old lease outcome: {outcome:?}"),
        };

        let mut offboarding =
            lease_test_job("tenant-offboarding", GovernanceJobKind::TenantOffboarding);
        offboarding.updated_at = 101;
        let offboarding = match store
            .start_or_resume_job(offboarding, 0, true)
            .await
            .unwrap()
        {
            GovernanceJobStartOutcome::Stored(job) => job,
            outcome => panic!("unexpected offboarding outcome: {outcome:?}"),
        };
        assert_eq!(offboarding.tenant_revision, 1);
        assert_eq!(
            store
                .start_or_resume_job(standalone.clone(), 0, false)
                .await
                .unwrap(),
            GovernanceJobStartOutcome::TenantFrozen {
                lifecycle_revision: 1
            }
        );

        standalone.tenant_revision = offboarding.tenant_revision;
        standalone.updated_at = 102;
        let adopted = match store
            .start_or_resume_job(standalone, 0, false)
            .await
            .unwrap()
        {
            GovernanceJobStartOutcome::Existing(job) => job,
            outcome => panic!("unexpected child adoption outcome: {outcome:?}"),
        };
        assert_eq!(adopted.tenant_revision, 1);
        assert_eq!(adopted.revision, 2);
        assert!(store
            .acquire_destructive_guard(
                "t1",
                &old_lease.destructive_fence(Some(adopted.target_epoch)),
                103,
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn expired_mutation_permit_cannot_hold_offboarding_forever() {
        let store = crate::adapters::memory::MemoryGovernanceStore::default();
        store
            .acquire_tenant_mutation_permit(
                TenantMutationPermit {
                    tenant_id: "t1".into(),
                    permit_id: "abandoned-request".into(),
                    deadline: 110,
                },
                100,
            )
            .await
            .unwrap();

        let mut job = lease_test_job(
            "offboard-after-expiry",
            GovernanceJobKind::TenantOffboarding,
        );
        job.created_at = 111;
        job.updated_at = 111;
        assert!(matches!(
            store.start_or_resume_job(job, 0, true).await.unwrap(),
            GovernanceJobStartOutcome::Stored(stored) if stored.tenant_revision == 1
        ));
    }

    #[tokio::test]
    async fn destructive_job_lease_rejects_policy_and_lifecycle_conflicts() {
        let policy_store = crate::adapters::memory::MemoryGovernanceStore::default();
        let job = lease_test_job("policy-job", GovernanceJobKind::UserErasure);
        policy_store
            .start_or_resume_job(job, 0, false)
            .await
            .unwrap();
        policy_store
            .put_policy(
                GovernancePolicyRecord {
                    tenant_id: "t1".into(),
                    legal_hold: LegalHoldState::Enabled,
                    legal_hold_reason: Some("case-lease".into()),
                    retention_exception_capability: Default::default(),
                    actor: "owner".into(),
                    updated_at: 20,
                    revision: 0,
                },
                0,
            )
            .await
            .unwrap();
        assert_eq!(
            policy_store
                .claim_job_lease("t1", "policy-job", 1, "worker", 100, 110)
                .await
                .unwrap(),
            GovernanceJobLeaseOutcome::Conflict(GovernanceJobLeaseConflict::Policy)
        );

        let lifecycle_store = crate::adapters::memory::MemoryGovernanceStore::default();
        let job = lease_test_job("lifecycle-job", GovernanceJobKind::TenantOffboarding);
        let mut job = match lifecycle_store
            .start_or_resume_job(job, 0, true)
            .await
            .unwrap()
        {
            GovernanceJobStartOutcome::Stored(job) => job,
            outcome => panic!("unexpected offboarding start outcome: {outcome:?}"),
        };
        job.tenant_revision += 1;
        let job = match lifecycle_store.update_job(job, 1, 0).await.unwrap() {
            GovernanceJobUpdateOutcome::Stored(job) => job,
            outcome => panic!("unexpected offboarding update outcome: {outcome:?}"),
        };
        assert_eq!(
            lifecycle_store
                .claim_job_lease("t1", "lifecycle-job", job.revision, "worker", 100, 110)
                .await
                .unwrap(),
            GovernanceJobLeaseOutcome::Conflict(GovernanceJobLeaseConflict::TenantLifecycle)
        );
    }

    #[tokio::test]
    async fn external_actions_are_idempotent_and_share_the_destructive_fence() {
        let store = crate::adapters::memory::MemoryGovernanceStore::default();
        let job = GovernanceJobRecord {
            job_id: "job-1".into(),
            tenant_id: "t1".into(),
            kind: GovernanceJobKind::TenantOffboarding,
            target_id: None,
            target_aliases: vec![],
            verification_target: None,
            active_child_job_id: None,
            processed_records: 0,
            tenant_cleanup_stage: TenantCleanupStage::SigningKeysAndSecrets,
            target_epoch: 1,
            state: GovernanceJobState::Queued,
            phase: GovernanceJobPhase::PrimaryCleanup,
            policy_revision: 0,
            tenant_revision: 0,
            revision: 1,
            created_at: 10,
            updated_at: 10,
            primary_erasure_at: None,
            retention_anchor_at: None,
            retention_until: None,
            evidence_revision: 0,
            error_class: None,
        };
        let mut job = match store.start_or_resume_job(job, 0, true).await.unwrap() {
            GovernanceJobStartOutcome::Stored(job) => job,
            outcome => panic!("unexpected start outcome: {outcome:?}"),
        };
        let tenant_revision = job.tenant_revision;
        job.state = GovernanceJobState::Running;
        let job = match store.update_job(job, 1, 0).await.unwrap() {
            GovernanceJobUpdateOutcome::Stored(job) => job,
            outcome => panic!("unexpected job update: {outcome:?}"),
        };
        let lease = match store
            .claim_job_lease("t1", &job.job_id, job.revision, "worker-1", 10, 100)
            .await
            .unwrap()
        {
            GovernanceJobLeaseOutcome::Acquired(lease) => lease,
            outcome => panic!("unexpected external action lease outcome: {outcome:?}"),
        };
        assert_eq!(lease.tenant_revision, tenant_revision);
        let fence = lease.external_action_fence();
        let secret_ref = "arn:aws:secretsmanager:us-east-1:123456789012:secret:t1-AbCd";
        let action = GovernanceExternalActionRecord {
            action_id: stable_external_action_id(
                b"governance-test-key",
                "t1",
                &job.job_id,
                GovernanceExternalActionKind::SecretDeletion,
                secret_ref,
            ),
            tenant_id: "t1".into(),
            job_id: job.job_id.clone(),
            kind: GovernanceExternalActionKind::SecretDeletion,
            resource_ref: secret_ref.into(),
            resource_fingerprint: resource_fingerprint(secret_ref),
            ownership: GovernanceResourceOwnership::ProductManaged,
            state: GovernanceExternalActionState::Prepared,
            revision: 1,
            created_at: 11,
            updated_at: 11,
            claim_token_digest: None,
            claim_deadline: None,
            committed_at: None,
            verified_at: None,
            retention_until: None,
            error_class: None,
        };
        let mut stale_token = fence.clone();
        stale_token.lease_token_digest = "stale-worker".into();
        assert_eq!(
            store
                .prepare_external_action(action.clone(), stale_token)
                .await
                .unwrap(),
            GovernanceExternalActionPutOutcome::FenceConflict
        );
        let mut stale_deadline = fence.clone();
        stale_deadline.lease_deadline -= 1;
        assert_eq!(
            store
                .prepare_external_action(action.clone(), stale_deadline)
                .await
                .unwrap(),
            GovernanceExternalActionPutOutcome::FenceConflict
        );
        assert!(matches!(
            store
                .prepare_external_action(action.clone(), fence.clone())
                .await
                .unwrap(),
            GovernanceExternalActionPutOutcome::Stored(_)
        ));
        assert!(matches!(
            store
                .prepare_external_action(action.clone(), fence.clone())
                .await
                .unwrap(),
            GovernanceExternalActionPutOutcome::Existing(existing)
                if existing.action_id == action.action_id
        ));
        let mut after_lease = action.clone();
        after_lease.updated_at = 100;
        assert_eq!(
            store
                .prepare_external_action(after_lease, fence.clone())
                .await
                .unwrap(),
            GovernanceExternalActionPutOutcome::FenceConflict
        );

        let mut claimed = action.clone();
        claimed.state = GovernanceExternalActionState::Claimed;
        claimed.updated_at = 12;
        claimed.claim_token_digest = Some("claim-digest".into());
        claimed.claim_deadline = Some(42);
        let claimed = match store
            .update_external_action(claimed, 1, fence.clone())
            .await
            .unwrap()
        {
            GovernanceExternalActionUpdateOutcome::Stored(action) => action,
            outcome => panic!("unexpected action update: {outcome:?}"),
        };
        assert_eq!(claimed.revision, 2);

        store
            .put_policy(
                GovernancePolicyRecord {
                    tenant_id: "t1".into(),
                    legal_hold: LegalHoldState::Enabled,
                    legal_hold_reason: Some("case-1".into()),
                    retention_exception_capability: Default::default(),
                    actor: "owner".into(),
                    updated_at: 13,
                    revision: 0,
                },
                0,
            )
            .await
            .unwrap();
        let mut committed = claimed;
        committed.state = GovernanceExternalActionState::ExternallyCommitted;
        assert_eq!(
            store
                .update_external_action(committed, 2, fence)
                .await
                .unwrap(),
            GovernanceExternalActionUpdateOutcome::FenceConflict
        );
    }
}
