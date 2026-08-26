//! Runtime-resolved platform and tenant admin credentials.
//!
//! Each configured Secrets Manager identity contains one owner-bound credential set. Available
//! identities are refreshed as a unit so duplicate values or cross-tenant documents fail closed
//! before any platform or tenant credential is accepted. A tenant identity removed during
//! offboarding stays unavailable without disabling unrelated owners.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::{
    sync::{Mutex, Semaphore},
    task::JoinSet,
};

pub const ADMIN_CREDENTIAL_SCHEMA_VERSION: u8 = 1;
pub const DEFAULT_ADMIN_CREDENTIAL_CACHE_TTL_SECS: u64 = 30;
pub const MAX_ADMIN_CREDENTIAL_CACHE_TTL_SECS: u64 = 300;
pub const MAX_ADMIN_CREDENTIAL_LIFETIME_SECS: i64 = 400 * 24 * 60 * 60;
pub const MAX_ADMIN_ROTATION_OVERLAP_SECS: i64 = 7 * 24 * 60 * 60;
pub const MIN_ADMIN_CREDENTIAL_SECRET_BYTES: usize = 16;
pub const ADMIN_CREDENTIAL_VALIDATED_STAGE: &str = "AGENTAUTH_VALIDATED";
pub const ADMIN_CREDENTIAL_PENDING_STAGE: &str = "AGENTAUTH_ROLLBACK_PENDING";
pub const ADMIN_CREDENTIAL_MIGRATED_STAGE: &str = "AGENTAUTH_MIGRATED";
#[cfg_attr(not(feature = "aws"), allow(dead_code))]
const ADMIN_CREDENTIAL_AWS_OPERATION_TIMEOUT_SECS: u64 = 5;
const ADMIN_CREDENTIAL_CHECKPOINT_SAFETY_SECS: i64 = 30;
const ADMIN_CREDENTIAL_STAGE_MUTATION_RESERVE_SECS: i64 =
    2 * ADMIN_CREDENTIAL_AWS_OPERATION_TIMEOUT_SECS as i64;
const MAX_ADMIN_CREDENTIAL_FETCH_CONCURRENCY: usize = 4;

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminCredentialOwner {
    Platform,
    Tenant { tenant_id: String },
    ScimTenant { tenant_id: String },
}

impl AdminCredentialOwner {
    pub fn platform() -> Self {
        Self::Platform
    }

    pub fn tenant(tenant_id: impl Into<String>) -> Self {
        Self::Tenant {
            tenant_id: tenant_id.into(),
        }
    }

    pub fn scim_tenant(tenant_id: impl Into<String>) -> Self {
        Self::ScimTenant {
            tenant_id: tenant_id.into(),
        }
    }

    pub fn audit_scope(&self) -> &str {
        match self {
            Self::Platform => "platform",
            Self::Tenant { tenant_id } | Self::ScimTenant { tenant_id } => tenant_id,
        }
    }

    fn expected_usage(&self) -> AdminCredentialUsage {
        match self {
            Self::Platform | Self::Tenant { .. } => AdminCredentialUsage::BreakGlass,
            Self::ScimTenant { .. } => AdminCredentialUsage::ScimProvisioning,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminCredentialUsage {
    BreakGlass,
    ScimProvisioning,
}

#[cfg(feature = "aws")]
#[derive(Clone, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct AdminCredentialMigrationEntry {
    pub source_secret_arn: String,
    pub target_secret_arn: String,
    pub owner: AdminCredentialOwner,
    pub credential_id: String,
    #[serde(default, deserialize_with = "deserialize_cloudformation_bool")]
    pub allow_removed: bool,
}

#[cfg(feature = "aws")]
fn deserialize_cloudformation_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BoolOrString {
        Bool(bool),
        String(String),
    }

    match BoolOrString::deserialize(deserializer)? {
        BoolOrString::Bool(value) => Ok(value),
        BoolOrString::String(value) if value == "true" => Ok(true),
        BoolOrString::String(value) if value == "false" => Ok(false),
        BoolOrString::String(value) => Err(serde::de::Error::custom(format!(
            "expected true or false, got {value:?}"
        ))),
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminCredentialRecord {
    pub credential_id: String,
    pub secret: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<i64>,
}

impl AdminCredentialRecord {
    pub fn explicit(
        credential_id: impl Into<String>,
        secret: impl Into<String>,
        created_at: i64,
        not_before: i64,
        expires_at: i64,
    ) -> Self {
        Self {
            credential_id: credential_id.into(),
            secret: secret.into(),
            created_at: Some(created_at),
            not_before: Some(not_before),
            expires_at: Some(expires_at),
            ttl_seconds: None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminCredentialRotation {
    pub overlap_starts_at: i64,
    pub cutover_at: i64,
    pub retire_current_at: i64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRetiredCredential {
    pub credential_id: String,
    pub secret_sha256: String,
    pub retired_at: i64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminCredentialSet {
    pub schema_version: u8,
    pub owner: AdminCredentialOwner,
    pub usage: AdminCredentialUsage,
    pub revision: u64,
    pub current: AdminCredentialRecord,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<AdminCredentialRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation: Option<AdminCredentialRotation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retired: Vec<AdminRetiredCredential>,
}

impl AdminCredentialSet {
    pub fn single(owner: AdminCredentialOwner, current: AdminCredentialRecord) -> Self {
        let usage = owner.expected_usage();
        Self {
            schema_version: ADMIN_CREDENTIAL_SCHEMA_VERSION,
            owner,
            usage,
            revision: 1,
            current,
            next: None,
            rotation: None,
            retired: Vec::new(),
        }
    }

    pub fn rotating(
        owner: AdminCredentialOwner,
        revision: u64,
        current: AdminCredentialRecord,
        next: AdminCredentialRecord,
        rotation: AdminCredentialRotation,
    ) -> Self {
        let usage = owner.expected_usage();
        Self {
            schema_version: ADMIN_CREDENTIAL_SCHEMA_VERSION,
            owner,
            usage,
            revision,
            current,
            next: Some(next),
            rotation: Some(rotation),
            retired: Vec::new(),
        }
    }
}

#[derive(Clone)]
struct SecretDocument {
    secret_string: String,
    version_created_at: i64,
    version_id: String,
}

#[derive(Clone)]
struct SecretVersions {
    current: SecretDocument,
    previous: Option<SecretDocument>,
    validated: Option<SecretDocument>,
    pending: Option<SecretDocument>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SecretStageSnapshot {
    current_version_id: String,
    previous_version_id: Option<String>,
    validated_version_id: Option<String>,
    pending_version_id: Option<String>,
}

impl SecretStageSnapshot {
    fn from_versions(versions: &SecretVersions) -> Self {
        Self {
            current_version_id: versions.current.version_id.clone(),
            previous_version_id: versions
                .previous
                .as_ref()
                .map(|document| document.version_id.clone()),
            validated_version_id: versions
                .validated
                .as_ref()
                .map(|document| document.version_id.clone()),
            pending_version_id: versions
                .pending
                .as_ref()
                .map(|document| document.version_id.clone()),
        }
    }

    fn locked(&self) -> Self {
        let mut locked = self.clone();
        locked.pending_version_id = Some(self.current_version_id.clone());
        locked
    }

    fn committed(&self) -> Self {
        let mut committed = self.locked();
        committed.validated_version_id = Some(self.current_version_id.clone());
        committed
    }

    fn finalized(&self) -> Self {
        let mut finalized = self.committed();
        finalized.pending_version_id = None;
        finalized
    }
}

#[derive(Clone)]
struct LoadedSecretVersions {
    stages: SecretStageSnapshot,
    versions: SecretVersions,
}

#[derive(Clone)]
struct CredentialCheckpoint {
    stages: SecretStageSnapshot,
    rollback_deadline: Option<i64>,
    secret_ref: String,
}

#[derive(Clone)]
pub struct MemoryAdminCredentialStore {
    documents: Arc<RwLock<HashMap<String, SecretVersions>>>,
    next_version: Arc<AtomicU64>,
}

impl Default for MemoryAdminCredentialStore {
    fn default() -> Self {
        Self {
            documents: Arc::new(RwLock::new(HashMap::new())),
            next_version: Arc::new(AtomicU64::new(1)),
        }
    }
}

impl MemoryAdminCredentialStore {
    pub fn put_set(
        &self,
        secret_ref: impl Into<String>,
        set: &AdminCredentialSet,
        version_created_at: i64,
    ) {
        let document = SecretDocument {
            secret_string: serde_json::to_string(set).expect("admin credential set serializes"),
            version_created_at,
            version_id: self.new_version_id(),
        };
        self.put_document(secret_ref.into(), document);
    }

    pub fn put_raw(
        &self,
        secret_ref: impl Into<String>,
        secret_string: impl Into<String>,
        version_created_at: i64,
    ) {
        self.put_document(
            secret_ref.into(),
            SecretDocument {
                secret_string: secret_string.into(),
                version_created_at,
                version_id: self.new_version_id(),
            },
        );
    }

    pub fn remove(&self, secret_ref: &str) {
        self.documents
            .write()
            .expect("admin credential memory store lock")
            .remove(secret_ref);
    }

    fn put_document(&self, secret_ref: String, document: SecretDocument) {
        let mut documents = self
            .documents
            .write()
            .expect("admin credential memory store lock");
        if let Some(versions) = documents.get_mut(&secret_ref) {
            versions.previous = Some(std::mem::replace(&mut versions.current, document));
        } else {
            documents.insert(
                secret_ref,
                SecretVersions {
                    current: document.clone(),
                    previous: None,
                    validated: Some(document),
                    pending: None,
                },
            );
        }
    }

    fn new_version_id(&self) -> String {
        format!(
            "memory-version-{}",
            self.next_version.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn mark_validated(
        &self,
        secret_ref: &str,
        version_id: &str,
        expected_validated_version_id: Option<&str>,
    ) -> Result<(), AdminCredentialError> {
        let mut documents = self
            .documents
            .write()
            .expect("admin credential memory store lock");
        let versions = documents
            .get_mut(secret_ref)
            .ok_or(AdminCredentialError::InvalidConfiguration)?;
        if versions.current.version_id != version_id
            || versions
                .pending
                .as_ref()
                .map(|document| document.version_id.as_str())
                != Some(version_id)
            || versions
                .validated
                .as_ref()
                .map(|document| document.version_id.as_str())
                != expected_validated_version_id
        {
            return Err(AdminCredentialError::InvalidConfiguration);
        }
        let document = std::iter::once(&versions.current)
            .chain(versions.previous.iter())
            .chain(versions.validated.iter())
            .find(|document| document.version_id == version_id)
            .cloned()
            .ok_or(AdminCredentialError::InvalidConfiguration)?;
        versions.validated = Some(document);
        Ok(())
    }

    fn mark_pending(&self, secret_ref: &str, version_id: &str) -> Result<(), AdminCredentialError> {
        let mut documents = self
            .documents
            .write()
            .expect("admin credential memory store lock");
        let versions = documents
            .get_mut(secret_ref)
            .ok_or(AdminCredentialError::InvalidConfiguration)?;
        if versions.current.version_id != version_id {
            return Err(AdminCredentialError::InvalidConfiguration);
        }
        if let Some(pending) = versions.pending.as_ref() {
            return if pending.version_id == version_id {
                Ok(())
            } else {
                Err(AdminCredentialError::InvalidConfiguration)
            };
        }
        let document = std::iter::once(&versions.current)
            .chain(versions.previous.iter())
            .chain(versions.validated.iter())
            .find(|document| document.version_id == version_id)
            .cloned()
            .ok_or(AdminCredentialError::InvalidConfiguration)?;
        versions.pending = Some(document);
        Ok(())
    }

    fn clear_pending(
        &self,
        secret_ref: &str,
        version_id: &str,
    ) -> Result<(), AdminCredentialError> {
        let mut documents = self
            .documents
            .write()
            .expect("admin credential memory store lock");
        let versions = documents
            .get_mut(secret_ref)
            .ok_or(AdminCredentialError::InvalidConfiguration)?;
        if versions.current.version_id != version_id {
            return Err(AdminCredentialError::InvalidConfiguration);
        }
        match versions.pending.as_ref() {
            Some(document) if document.version_id == version_id => {
                versions.pending = None;
                Ok(())
            }
            None => Ok(()),
            Some(_) => Err(AdminCredentialError::InvalidConfiguration),
        }
    }
}

#[derive(Clone)]
enum AdminCredentialBackend {
    Memory(MemoryAdminCredentialStore),
    #[cfg(feature = "aws")]
    SecretsManager(aws_sdk_secretsmanager::Client),
}

impl AdminCredentialBackend {
    async fn fetch(
        &self,
        secret_ref: &str,
        _permits: Arc<Semaphore>,
    ) -> Result<LoadedSecretVersions, AdminCredentialError> {
        match self {
            Self::Memory(store) => {
                let versions = store
                    .documents
                    .read()
                    .expect("admin credential memory store lock")
                    .get(secret_ref)
                    .cloned()
                    .ok_or(AdminCredentialError::Removed)?;
                Ok(LoadedSecretVersions {
                    stages: SecretStageSnapshot::from_versions(&versions),
                    versions,
                })
            }
            #[cfg(feature = "aws")]
            Self::SecretsManager(client) => {
                let stages = self.stage_snapshot(secret_ref, _permits.clone()).await?;
                let (current, previous, validated, pending) = tokio::join!(
                    fetch_aws_secret_version_by_id_limited(
                        client,
                        secret_ref,
                        &stages.current_version_id,
                        _permits.clone()
                    ),
                    fetch_optional_aws_secret_version_by_id_limited(
                        client,
                        secret_ref,
                        stages.previous_version_id.as_deref(),
                        _permits.clone()
                    ),
                    fetch_optional_aws_secret_version_by_id_limited(
                        client,
                        secret_ref,
                        stages.validated_version_id.as_deref(),
                        _permits.clone()
                    ),
                    fetch_optional_aws_secret_version_by_id_limited(
                        client,
                        secret_ref,
                        stages.pending_version_id.as_deref(),
                        _permits.clone()
                    )
                );
                let current = current?;
                let previous = previous?;
                let validated = validated?;
                let pending = pending?;
                let observed = self.stage_snapshot(secret_ref, _permits).await?;
                if observed != stages {
                    return Err(AdminCredentialError::InvalidConfiguration);
                }
                Ok(LoadedSecretVersions {
                    stages,
                    versions: SecretVersions {
                        current,
                        previous,
                        validated,
                        pending,
                    },
                })
            }
        }
    }

    async fn stage_snapshot(
        &self,
        secret_ref: &str,
        _permits: Arc<Semaphore>,
    ) -> Result<SecretStageSnapshot, AdminCredentialError> {
        match self {
            Self::Memory(store) => {
                let documents = store
                    .documents
                    .read()
                    .expect("admin credential memory store lock");
                let versions = documents
                    .get(secret_ref)
                    .ok_or(AdminCredentialError::InvalidConfiguration)?;
                Ok(SecretStageSnapshot::from_versions(versions))
            }
            #[cfg(feature = "aws")]
            Self::SecretsManager(client) => {
                let _permit = _permits
                    .acquire_owned()
                    .await
                    .map_err(|_| AdminCredentialError::Unavailable)?;
                let output = client
                    .describe_secret()
                    .secret_id(secret_ref)
                    .send()
                    .await
                    .map_err(|error| {
                        if error
                            .as_service_error()
                            .is_some_and(|service| service.is_resource_not_found_exception())
                        {
                            AdminCredentialError::Removed
                        } else {
                            AdminCredentialError::Unavailable
                        }
                    })?;
                secret_stage_snapshot_from_description(&output)
            }
        }
    }

    async fn mark_validated(
        &self,
        checkpoint: &CredentialCheckpoint,
        now_floor: i64,
    ) -> Result<(), AdminCredentialError> {
        let stages = &checkpoint.stages;
        if stages
            .pending_version_id
            .as_deref()
            .is_some_and(|pending| pending != stages.current_version_id)
        {
            return Err(AdminCredentialError::InvalidConfiguration);
        }

        // AGENTAUTH_VALIDATED is the commit point. A marker left after another
        // worker committed is stale and can be removed without reopening the
        // deadline-bound transition.
        if stages.validated_version_id.as_deref() == Some(stages.current_version_id.as_str()) {
            if stages.pending_version_id.is_some() {
                self.clear_pending(&checkpoint.secret_ref, &stages.current_version_id)
                    .await?;
            }
            return self
                .ensure_stage_snapshot(&checkpoint.secret_ref, &stages.finalized())
                .await;
        }

        let validated_version_id = stages
            .validated_version_id
            .as_deref()
            .ok_or(AdminCredentialError::InvalidConfiguration)?;
        self.ensure_pending(
            &checkpoint.secret_ref,
            &stages.current_version_id,
            stages.pending_version_id.as_deref(),
        )
        .await?;
        self.ensure_stage_snapshot(&checkpoint.secret_ref, &stages.locked())
            .await?;

        if let Some(deadline) = checkpoint.rollback_deadline {
            if checkpoint_deadline_reached(now_floor, deadline, 2) {
                return Err(AdminCredentialError::InvalidConfiguration);
            }
        }

        self.commit_validated(
            &checkpoint.secret_ref,
            &stages.current_version_id,
            Some(validated_version_id),
        )
        .await?;
        self.ensure_stage_snapshot(&checkpoint.secret_ref, &stages.committed())
            .await?;
        self.clear_pending(&checkpoint.secret_ref, &stages.current_version_id)
            .await?;
        self.ensure_stage_snapshot(&checkpoint.secret_ref, &stages.finalized())
            .await
    }

    async fn ensure_stage_snapshot(
        &self,
        secret_ref: &str,
        expected: &SecretStageSnapshot,
    ) -> Result<(), AdminCredentialError> {
        let observed = self
            .stage_snapshot(
                secret_ref,
                Arc::new(Semaphore::new(MAX_ADMIN_CREDENTIAL_FETCH_CONCURRENCY)),
            )
            .await?;
        if observed == *expected {
            Ok(())
        } else {
            Err(AdminCredentialError::InvalidConfiguration)
        }
    }

    async fn commit_validated(
        &self,
        secret_ref: &str,
        current_version_id: &str,
        _validated_version_id: Option<&str>,
    ) -> Result<(), AdminCredentialError> {
        match self {
            Self::Memory(store) => {
                store.mark_validated(secret_ref, current_version_id, _validated_version_id)
            }
            #[cfg(feature = "aws")]
            Self::SecretsManager(client) => {
                let mut request = client
                    .update_secret_version_stage()
                    .secret_id(secret_ref)
                    .version_stage(ADMIN_CREDENTIAL_VALIDATED_STAGE)
                    .move_to_version_id(current_version_id);
                if let Some(previous) = _validated_version_id {
                    request = request.remove_from_version_id(previous);
                }
                if request.send().await.is_ok() {
                    return Ok(());
                }
                let validated = fetch_aws_secret_version(
                    client,
                    secret_ref,
                    Some(ADMIN_CREDENTIAL_VALIDATED_STAGE),
                )
                .await?;
                if validated
                    .as_ref()
                    .is_some_and(|document| document.version_id == current_version_id)
                {
                    Ok(())
                } else {
                    Err(AdminCredentialError::Unavailable)
                }
            }
        }
    }

    async fn ensure_pending(
        &self,
        secret_ref: &str,
        current_version_id: &str,
        pending_version_id: Option<&str>,
    ) -> Result<(), AdminCredentialError> {
        if pending_version_id == Some(current_version_id) {
            return Ok(());
        }
        match self {
            Self::Memory(store) => store.mark_pending(secret_ref, current_version_id),
            #[cfg(feature = "aws")]
            Self::SecretsManager(client) => {
                if client
                    .update_secret_version_stage()
                    .secret_id(secret_ref)
                    .version_stage(ADMIN_CREDENTIAL_PENDING_STAGE)
                    .move_to_version_id(current_version_id)
                    .send()
                    .await
                    .is_ok()
                {
                    return Ok(());
                }
                let pending = fetch_aws_secret_version(
                    client,
                    secret_ref,
                    Some(ADMIN_CREDENTIAL_PENDING_STAGE),
                )
                .await?;
                if pending
                    .as_ref()
                    .is_some_and(|document| document.version_id == current_version_id)
                {
                    Ok(())
                } else {
                    Err(AdminCredentialError::Unavailable)
                }
            }
        }
    }

    async fn clear_pending(
        &self,
        secret_ref: &str,
        current_version_id: &str,
    ) -> Result<(), AdminCredentialError> {
        match self {
            Self::Memory(store) => store.clear_pending(secret_ref, current_version_id),
            #[cfg(feature = "aws")]
            Self::SecretsManager(client) => {
                if client
                    .update_secret_version_stage()
                    .secret_id(secret_ref)
                    .version_stage(ADMIN_CREDENTIAL_PENDING_STAGE)
                    .remove_from_version_id(current_version_id)
                    .send()
                    .await
                    .is_ok()
                {
                    return Ok(());
                }
                let pending = fetch_aws_secret_version(
                    client,
                    secret_ref,
                    Some(ADMIN_CREDENTIAL_PENDING_STAGE),
                )
                .await?;
                if pending.is_none() {
                    Ok(())
                } else {
                    Err(AdminCredentialError::Unavailable)
                }
            }
        }
    }
}

#[cfg(any(feature = "aws", test))]
fn secret_stage_snapshot(
    version_ids_to_stages: &HashMap<String, Vec<String>>,
) -> Result<SecretStageSnapshot, AdminCredentialError> {
    fn version_for_stage(
        version_ids_to_stages: &HashMap<String, Vec<String>>,
        stage: &str,
    ) -> Result<Option<String>, AdminCredentialError> {
        let mut versions = version_ids_to_stages
            .iter()
            .filter(|(_, stages)| stages.iter().any(|candidate| candidate == stage))
            .map(|(version_id, _)| version_id.clone());
        let version = versions.next();
        if versions.next().is_some() {
            return Err(AdminCredentialError::InvalidConfiguration);
        }
        Ok(version)
    }

    Ok(SecretStageSnapshot {
        current_version_id: version_for_stage(version_ids_to_stages, "AWSCURRENT")?
            .ok_or(AdminCredentialError::InvalidConfiguration)?,
        previous_version_id: version_for_stage(version_ids_to_stages, "AWSPREVIOUS")?,
        validated_version_id: version_for_stage(
            version_ids_to_stages,
            ADMIN_CREDENTIAL_VALIDATED_STAGE,
        )?,
        pending_version_id: version_for_stage(
            version_ids_to_stages,
            ADMIN_CREDENTIAL_PENDING_STAGE,
        )?,
    })
}

#[cfg(feature = "aws")]
fn secret_stage_snapshot_from_description(
    output: &aws_sdk_secretsmanager::operation::describe_secret::DescribeSecretOutput,
) -> Result<SecretStageSnapshot, AdminCredentialError> {
    if output.deleted_date().is_some() {
        return Err(AdminCredentialError::Removed);
    }
    secret_stage_snapshot(
        output
            .version_ids_to_stages()
            .ok_or(AdminCredentialError::InvalidConfiguration)?,
    )
}

#[cfg(feature = "aws")]
async fn fetch_aws_secret_version_limited(
    client: &aws_sdk_secretsmanager::Client,
    secret_ref: &str,
    version_stage: Option<&str>,
    permits: Arc<Semaphore>,
) -> Result<Option<SecretDocument>, AdminCredentialError> {
    let _permit = permits
        .acquire_owned()
        .await
        .map_err(|_| AdminCredentialError::Unavailable)?;
    ensure_aws_secret_not_removed(client, secret_ref).await?;
    fetch_aws_secret_version(client, secret_ref, version_stage).await
}

#[cfg(feature = "aws")]
async fn ensure_aws_secret_not_removed(
    client: &aws_sdk_secretsmanager::Client,
    secret_ref: &str,
) -> Result<(), AdminCredentialError> {
    let output = client
        .describe_secret()
        .secret_id(secret_ref)
        .send()
        .await
        .map_err(|error| {
            if error
                .as_service_error()
                .is_some_and(|service| service.is_resource_not_found_exception())
            {
                AdminCredentialError::Removed
            } else {
                AdminCredentialError::Unavailable
            }
        })?;
    secret_description_not_removed(&output)
}

#[cfg(feature = "aws")]
fn secret_description_not_removed(
    output: &aws_sdk_secretsmanager::operation::describe_secret::DescribeSecretOutput,
) -> Result<(), AdminCredentialError> {
    if output.deleted_date().is_some() {
        Err(AdminCredentialError::Removed)
    } else {
        Ok(())
    }
}

#[cfg(feature = "aws")]
async fn fetch_aws_secret_version_by_id_limited(
    client: &aws_sdk_secretsmanager::Client,
    secret_ref: &str,
    version_id: &str,
    permits: Arc<Semaphore>,
) -> Result<SecretDocument, AdminCredentialError> {
    let _permit = permits
        .acquire_owned()
        .await
        .map_err(|_| AdminCredentialError::Unavailable)?;
    let output = client
        .get_secret_value()
        .secret_id(secret_ref)
        .version_id(version_id)
        .send()
        .await
        .map_err(|error| {
            if error
                .as_service_error()
                .is_some_and(|service| service.is_resource_not_found_exception())
            {
                AdminCredentialError::InvalidConfiguration
            } else {
                AdminCredentialError::Unavailable
            }
        })?;
    secret_document_from_output(output)
}

#[cfg(feature = "aws")]
async fn fetch_optional_aws_secret_version_by_id_limited(
    client: &aws_sdk_secretsmanager::Client,
    secret_ref: &str,
    version_id: Option<&str>,
    permits: Arc<Semaphore>,
) -> Result<Option<SecretDocument>, AdminCredentialError> {
    match version_id {
        Some(version_id) => {
            fetch_aws_secret_version_by_id_limited(client, secret_ref, version_id, permits)
                .await
                .map(Some)
        }
        None => Ok(None),
    }
}

#[cfg(feature = "aws")]
async fn fetch_aws_secret_version(
    client: &aws_sdk_secretsmanager::Client,
    secret_ref: &str,
    version_stage: Option<&str>,
) -> Result<Option<SecretDocument>, AdminCredentialError> {
    let mut request = client.get_secret_value().secret_id(secret_ref);
    if let Some(stage) = version_stage {
        request = request.version_stage(stage);
    }
    let output = match request.send().await {
        Ok(output) => output,
        Err(error)
            if version_stage.is_some()
                && error
                    .as_service_error()
                    .is_some_and(|service| service.is_resource_not_found_exception()) =>
        {
            return Ok(None);
        }
        Err(error)
            if error
                .as_service_error()
                .is_some_and(|service| service.is_resource_not_found_exception()) =>
        {
            return Err(AdminCredentialError::InvalidConfiguration);
        }
        Err(_) => return Err(AdminCredentialError::Unavailable),
    };
    secret_document_from_output(output).map(Some)
}

#[cfg(feature = "aws")]
fn secret_document_from_output(
    output: aws_sdk_secretsmanager::operation::get_secret_value::GetSecretValueOutput,
) -> Result<SecretDocument, AdminCredentialError> {
    let secret_string = output
        .secret_string()
        .map(str::to_owned)
        .ok_or(AdminCredentialError::InvalidConfiguration)?;
    let version_created_at = output
        .created_date()
        .map(|created| created.secs())
        .ok_or(AdminCredentialError::InvalidConfiguration)?;
    let version_id = output
        .version_id()
        .map(str::to_owned)
        .ok_or(AdminCredentialError::InvalidConfiguration)?;
    Ok(SecretDocument {
        secret_string,
        version_created_at,
        version_id,
    })
}

#[cfg(any(feature = "aws", test))]
struct PreparedAdminCredentialDocument {
    serialized: String,
    normalized: NormalizedSet,
}

#[cfg(any(feature = "aws", test))]
fn prepare_existing_admin_credential_document(
    owner: &AdminCredentialOwner,
    secret_string: &str,
    version_created_at: i64,
) -> Result<PreparedAdminCredentialDocument, AdminCredentialError> {
    let set = serde_json::from_str::<AdminCredentialSet>(secret_string)
        .map_err(|_| AdminCredentialError::InvalidConfiguration)?;
    let normalized = normalize_set(set.clone(), version_created_at, owner)?;
    let serialized =
        serde_json::to_string(&set).map_err(|_| AdminCredentialError::InvalidConfiguration)?;
    Ok(PreparedAdminCredentialDocument {
        serialized,
        normalized,
    })
}

#[cfg(any(feature = "aws", test))]
fn prepare_legacy_admin_credential_document(
    owner: &AdminCredentialOwner,
    credential_id: &str,
    legacy_bearer: &str,
    migrated_at: i64,
) -> Result<PreparedAdminCredentialDocument, AdminCredentialError> {
    let set = AdminCredentialSet::single(
        owner.clone(),
        AdminCredentialRecord {
            credential_id: credential_id.to_string(),
            secret: legacy_bearer.to_string(),
            created_at: None,
            not_before: None,
            expires_at: None,
            ttl_seconds: Some(90 * 24 * 60 * 60),
        },
    );
    let normalized = normalize_set(set.clone(), migrated_at, owner)?;
    let serialized =
        serde_json::to_string(&set).map_err(|_| AdminCredentialError::InvalidConfiguration)?;
    Ok(PreparedAdminCredentialDocument {
        serialized,
        normalized,
    })
}

fn is_admin_credential_document(secret_string: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(secret_string)
        .ok()
        .and_then(|value| {
            value
                .as_object()
                .and_then(|object| object.get("schema_version"))
                .and_then(serde_json::Value::as_u64)
        })
        == Some(u64::from(ADMIN_CREDENTIAL_SCHEMA_VERSION))
}

#[cfg(any(feature = "aws", test))]
fn prepare_admin_credential_target(
    owner: &AdminCredentialOwner,
    credential_id: &str,
    source: &SecretDocument,
    target: &SecretDocument,
    target_previous: Option<&SecretDocument>,
    target_validated: Option<&SecretDocument>,
    migrated_at: i64,
) -> Result<(PreparedAdminCredentialDocument, bool, bool), AdminCredentialError> {
    let target_is_document = is_admin_credential_document(&target.secret_string);
    if !target_is_document && (target_previous.is_some() || target_validated.is_some()) {
        return Err(AdminCredentialError::InvalidConfiguration);
    }
    if !target_is_document {
        return Ok((
            prepare_legacy_admin_credential_document(
                owner,
                credential_id,
                &source.secret_string,
                migrated_at,
            )?,
            true,
            true,
        ));
    }

    let prepared = prepare_existing_admin_credential_document(
        owner,
        &target.secret_string,
        target.version_created_at,
    )?;
    let Some(validated) = target_validated else {
        let expected = prepare_legacy_admin_credential_document(
            owner,
            credential_id,
            &source.secret_string,
            target.version_created_at,
        )?;
        if prepared.serialized != expected.serialized
            || target_previous.is_none_or(|previous| {
                previous.version_id == target.version_id
                    || is_admin_credential_document(&previous.secret_string)
            })
        {
            return Err(AdminCredentialError::InvalidConfiguration);
        }
        return Ok((prepared, false, true));
    };
    let current_is_validated = validated.version_id == target.version_id;
    if !current_is_validated {
        let validated = prepare_existing_admin_credential_document(
            owner,
            &validated.secret_string,
            validated.version_created_at,
        )?;
        validate_transition(&validated.normalized, &prepared.normalized, migrated_at)?;
    }
    if let Some(previous) = target_previous.filter(|previous| {
        previous.version_id != target.version_id
            && previous.version_id != validated.version_id
            && is_admin_credential_document(&previous.secret_string)
    }) {
        let previous = prepare_existing_admin_credential_document(
            owner,
            &previous.secret_string,
            previous.version_created_at,
        )?;
        if current_is_validated {
            validate_trusted_current_revision(&previous.normalized, &prepared.normalized)?;
        } else {
            validate_transition(&previous.normalized, &prepared.normalized, migrated_at)?;
        }
    }
    Ok((prepared, false, false))
}

#[cfg(any(feature = "aws", test))]
fn admin_migration_request_token(target_secret_arn: &str, target_created_at: i64) -> String {
    let mut digest = Sha256::new();
    digest.update(b"agent-auth:admin-credential-migration:v2\0");
    digest.update(target_secret_arn.as_bytes());
    digest.update(b"\0");
    digest.update(target_created_at.to_be_bytes());
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(feature = "aws")]
pub async fn migrate_legacy_admin_credentials(
    client: &aws_sdk_secretsmanager::Client,
    entries: &[AdminCredentialMigrationEntry],
    migrated_at: i64,
) -> Result<usize, AdminCredentialError> {
    if entries.is_empty() || migrated_at <= 0 {
        return Err(AdminCredentialError::InvalidConfiguration);
    }
    validate_admin_credential_migration_entries(entries)?;

    struct Loaded {
        target_secret_arn: String,
        expected_stages: SecretStageSnapshot,
        expected_current_version_id: String,
        validated_version_id: Option<String>,
        serialized: String,
        client_request_token: String,
        needs_write: bool,
        needs_validation: bool,
        normalized: NormalizedSet,
    }

    let mut loaded = Vec::with_capacity(entries.len());
    let permits = Arc::new(Semaphore::new(MAX_ADMIN_CREDENTIAL_FETCH_CONCURRENCY));
    let mut reads = JoinSet::new();
    for entry in entries.iter().cloned() {
        let client = client.clone();
        let permits = permits.clone();
        reads.spawn(async move {
            let backend = AdminCredentialBackend::SecretsManager(client.clone());
            let (source, target) = tokio::join!(
                fetch_aws_secret_version_limited(
                    &client,
                    &entry.source_secret_arn,
                    None,
                    permits.clone()
                ),
                backend.fetch(&entry.target_secret_arn, permits)
            );
            let Some(source) = migration_value_or_skip(source, entry.allow_removed)? else {
                return Ok::<_, AdminCredentialError>(None);
            };
            let source = source.ok_or(AdminCredentialError::InvalidConfiguration)?;
            let Some(target) = migration_value_or_skip(target, entry.allow_removed)? else {
                return Ok(None);
            };
            Ok(Some((entry, source, target)))
        });
    }
    while let Some(result) = reads.join_next().await {
        let Some((entry, source, target)) =
            result.map_err(|_| AdminCredentialError::Unavailable)??
        else {
            continue;
        };
        let LoadedSecretVersions {
            stages,
            versions:
                SecretVersions {
                    current: target,
                    previous: target_previous,
                    validated: target_validated,
                    pending: _,
                },
        } = target;
        if stages.pending_version_id.is_some() {
            return Err(AdminCredentialError::InvalidConfiguration);
        }
        let (prepared, needs_write, needs_validation) = prepare_admin_credential_target(
            &entry.owner,
            &entry.credential_id,
            &source,
            &target,
            target_previous.as_ref(),
            target_validated.as_ref(),
            migrated_at,
        )?;
        let client_request_token =
            admin_migration_request_token(&entry.target_secret_arn, target.version_created_at);
        loaded.push(Loaded {
            target_secret_arn: entry.target_secret_arn,
            expected_stages: stages,
            expected_current_version_id: target.version_id,
            validated_version_id: target_validated.map(|validated| validated.version_id),
            serialized: prepared.serialized,
            client_request_token,
            needs_write,
            needs_validation,
            normalized: prepared.normalized,
        });
    }
    validate_registry_uniqueness(loaded.iter().map(|item| &item.normalized))?;

    let migrated = loaded.iter().filter(|item| item.needs_write).count();
    let actions: Vec<_> = loaded
        .into_iter()
        .filter(|item| item.needs_write || item.needs_validation)
        .collect();
    let permits = Arc::new(Semaphore::new(MAX_ADMIN_CREDENTIAL_FETCH_CONCURRENCY));
    let mut tasks = JoinSet::new();
    for item in actions {
        let client = client.clone();
        let permits = permits.clone();
        tasks.spawn(async move {
            let _permit = permits
                .acquire_owned()
                .await
                .map_err(|_| AdminCredentialError::Unavailable)?;
            let backend = AdminCredentialBackend::SecretsManager(client.clone());
            backend
                .ensure_stage_snapshot(&item.target_secret_arn, &item.expected_stages)
                .await?;
            let candidate_version_id = if item.needs_write {
                let output = client
                    .put_secret_value()
                    .secret_id(&item.target_secret_arn)
                    .secret_string(item.serialized)
                    .client_request_token(item.client_request_token)
                    .version_stages(ADMIN_CREDENTIAL_MIGRATED_STAGE)
                    .send()
                    .await
                    .map_err(|_| AdminCredentialError::Unavailable)?;
                output
                    .version_id()
                    .map(str::to_owned)
                    .ok_or(AdminCredentialError::Unavailable)?
            } else {
                item.expected_current_version_id.clone()
            };

            if item.needs_write
                && client
                    .update_secret_version_stage()
                    .secret_id(&item.target_secret_arn)
                    .version_stage("AWSCURRENT")
                    .move_to_version_id(&candidate_version_id)
                    .remove_from_version_id(&item.expected_current_version_id)
                    .send()
                    .await
                    .is_err()
            {
                let current =
                    fetch_aws_secret_version(&client, &item.target_secret_arn, None).await?;
                if current.as_ref().map(|value| value.version_id.as_str())
                    != Some(candidate_version_id.as_str())
                {
                    return Err(AdminCredentialError::InvalidConfiguration);
                }
            }

            let mut request = client
                .update_secret_version_stage()
                .secret_id(&item.target_secret_arn)
                .version_stage(ADMIN_CREDENTIAL_VALIDATED_STAGE)
                .move_to_version_id(&candidate_version_id);
            if let Some(previous) = item.validated_version_id.as_deref() {
                request = request.remove_from_version_id(previous);
            }
            if request.send().await.is_err() {
                let validated = fetch_aws_secret_version(
                    &client,
                    &item.target_secret_arn,
                    Some(ADMIN_CREDENTIAL_VALIDATED_STAGE),
                )
                .await?;
                if validated.as_ref().map(|value| value.version_id.as_str())
                    != Some(candidate_version_id.as_str())
                {
                    return Err(AdminCredentialError::Unavailable);
                }
            }
            let mut expected_final = item.expected_stages;
            if item.needs_write {
                expected_final.previous_version_id =
                    Some(expected_final.current_version_id.clone());
                expected_final.current_version_id = candidate_version_id.clone();
            }
            expected_final.validated_version_id = Some(candidate_version_id);
            backend
                .ensure_stage_snapshot(&item.target_secret_arn, &expected_final)
                .await?;
            Ok::<_, AdminCredentialError>(())
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.map_err(|_| AdminCredentialError::Unavailable)??;
    }
    Ok(migrated)
}

#[cfg(feature = "aws")]
fn validate_admin_credential_migration_entries(
    entries: &[AdminCredentialMigrationEntry],
) -> Result<(), AdminCredentialError> {
    let mut source_secret_arns = HashSet::new();
    let mut target_secret_arns = HashSet::new();
    for entry in entries {
        validate_owner(&entry.owner)?;
        if entry.allow_removed && matches!(entry.owner, AdminCredentialOwner::Platform) {
            return Err(AdminCredentialError::InvalidConfiguration);
        }
        if entry.source_secret_arn.is_empty()
            || entry.target_secret_arn.is_empty()
            || entry.source_secret_arn == entry.target_secret_arn
            || !source_secret_arns.insert(entry.source_secret_arn.clone())
            || !target_secret_arns.insert(entry.target_secret_arn.clone())
        {
            return Err(AdminCredentialError::InvalidConfiguration);
        }
    }
    if source_secret_arns
        .iter()
        .any(|source| target_secret_arns.contains(source))
    {
        return Err(AdminCredentialError::InvalidConfiguration);
    }
    Ok(())
}

#[cfg(any(feature = "aws", test))]
fn migration_value_or_skip<T>(
    value: Result<T, AdminCredentialError>,
    allow_removed: bool,
) -> Result<Option<T>, AdminCredentialError> {
    match value {
        Ok(value) => Ok(Some(value)),
        Err(AdminCredentialError::Removed) if allow_removed => Ok(None),
        Err(error) => Err(error),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminCredentialError {
    InvalidConfiguration,
    Unavailable,
    Removed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdminCredentialSlot {
    Current,
    Next,
}

pub struct AdminCredentialMatch {
    pub credential_id: String,
    pub owner: AdminCredentialOwner,
    pub slot: AdminCredentialSlot,
    pub revision: u64,
}

struct NormalizedRecord {
    credential_id: String,
    secret: String,
    secret_sha256: String,
    created_at: i64,
    not_before: i64,
    expires_at: i64,
}

struct NormalizedSet {
    owner: AdminCredentialOwner,
    revision: u64,
    current: NormalizedRecord,
    next: Option<NormalizedRecord>,
    retire_current_at: Option<i64>,
    retired: Vec<AdminRetiredCredential>,
}

struct CredentialRegistry {
    sets: HashMap<AdminCredentialOwner, NormalizedSet>,
}

struct CachedRegistry {
    loaded_at: Instant,
    registry: CredentialRegistry,
}

#[derive(Default)]
struct CacheState {
    current: Option<CachedRegistry>,
    highest_revisions: HashMap<AdminCredentialOwner, u64>,
}

pub struct AdminCredentialResolver {
    platform_secret_ref: Option<String>,
    tenant_secret_refs: HashMap<String, String>,
    scim_tenant_secret_refs: HashMap<String, String>,
    backend: AdminCredentialBackend,
    cache_ttl: Duration,
    cache: Mutex<CacheState>,
    refresh: Mutex<()>,
}

impl AdminCredentialResolver {
    pub fn memory(
        platform_secret_ref: Option<String>,
        tenant_secret_refs: HashMap<String, String>,
        store: MemoryAdminCredentialStore,
        cache_ttl: Duration,
    ) -> Self {
        Self::memory_scoped(
            platform_secret_ref,
            tenant_secret_refs,
            HashMap::new(),
            store,
            cache_ttl,
        )
    }

    pub fn memory_scoped(
        platform_secret_ref: Option<String>,
        tenant_secret_refs: HashMap<String, String>,
        scim_tenant_secret_refs: HashMap<String, String>,
        store: MemoryAdminCredentialStore,
        cache_ttl: Duration,
    ) -> Self {
        Self {
            platform_secret_ref,
            tenant_secret_refs,
            scim_tenant_secret_refs,
            backend: AdminCredentialBackend::Memory(store),
            cache_ttl,
            cache: Mutex::new(CacheState::default()),
            refresh: Mutex::new(()),
        }
    }

    #[cfg(feature = "aws")]
    pub fn secrets_manager(
        config: &aws_config::SdkConfig,
        platform_secret_ref: Option<String>,
        tenant_secret_refs: HashMap<String, String>,
        scim_tenant_secret_refs: HashMap<String, String>,
        cache_ttl: Duration,
    ) -> Self {
        let timeout_config = aws_config::timeout::TimeoutConfig::builder()
            .operation_timeout(Duration::from_secs(
                ADMIN_CREDENTIAL_AWS_OPERATION_TIMEOUT_SECS,
            ))
            .build();
        let config = aws_sdk_secretsmanager::config::Builder::from(config)
            .timeout_config(timeout_config)
            .build();
        Self {
            platform_secret_ref,
            tenant_secret_refs,
            scim_tenant_secret_refs,
            backend: AdminCredentialBackend::SecretsManager(
                aws_sdk_secretsmanager::Client::from_conf(config),
            ),
            cache_ttl,
            cache: Mutex::new(CacheState::default()),
            refresh: Mutex::new(()),
        }
    }

    pub fn dev(secret: &str, now: i64) -> Self {
        let secret_ref = "memory:platform-admin".to_string();
        let scim_secret_ref = "memory:default-scim".to_string();
        let store = MemoryAdminCredentialStore::default();
        store.put_set(
            secret_ref.clone(),
            &AdminCredentialSet::single(
                AdminCredentialOwner::platform(),
                AdminCredentialRecord::explicit(
                    "dev-platform-admin",
                    secret,
                    now,
                    now,
                    now + 365 * 24 * 60 * 60,
                ),
            ),
            now,
        );
        store.put_set(
            scim_secret_ref.clone(),
            &AdminCredentialSet::single(
                AdminCredentialOwner::scim_tenant("default"),
                AdminCredentialRecord::explicit(
                    "dev-default-scim",
                    "dev-scim-token-not-for-prod",
                    now,
                    now,
                    now + 365 * 24 * 60 * 60,
                ),
            ),
            now,
        );
        Self::memory_scoped(
            Some(secret_ref),
            HashMap::new(),
            HashMap::from([("default".to_string(), scim_secret_ref)]),
            store,
            Duration::from_secs(DEFAULT_ADMIN_CREDENTIAL_CACHE_TTL_SECS),
        )
    }

    pub fn disabled() -> Self {
        Self::memory_scoped(
            None,
            HashMap::new(),
            HashMap::new(),
            MemoryAdminCredentialStore::default(),
            Duration::ZERO,
        )
    }

    pub fn platform_secret_ref(&self) -> Option<&str> {
        self.platform_secret_ref.as_deref()
    }

    pub fn tenant_secret_refs(&self) -> &HashMap<String, String> {
        &self.tenant_secret_refs
    }

    pub fn scim_tenant_secret_refs(&self) -> &HashMap<String, String> {
        &self.scim_tenant_secret_refs
    }

    pub async fn verify(
        &self,
        owner: &AdminCredentialOwner,
        presented: &str,
        now: i64,
    ) -> Result<Option<AdminCredentialMatch>, AdminCredentialError> {
        {
            let cache = self.cache.lock().await;
            if !self.cache_needs_refresh(&cache) {
                return cached_verify(&cache, owner, presented, now);
            }
        }

        let _refresh = self.refresh.lock().await;
        {
            let cache = self.cache.lock().await;
            if !self.cache_needs_refresh(&cache) {
                return cached_verify(&cache, owner, presented, now);
            }
        }

        let registry = self.load_registry(now).await?;
        let mut cache = self.cache.lock().await;
        for (loaded_owner, set) in &registry.sets {
            if cache
                .highest_revisions
                .get(loaded_owner)
                .is_some_and(|highest| set.revision < *highest)
            {
                return Err(AdminCredentialError::InvalidConfiguration);
            }
        }
        for (loaded_owner, set) in &registry.sets {
            cache
                .highest_revisions
                .entry(loaded_owner.clone())
                .and_modify(|highest| *highest = (*highest).max(set.revision))
                .or_insert(set.revision);
        }
        cache.current = Some(CachedRegistry {
            loaded_at: Instant::now(),
            registry,
        });
        cached_verify(&cache, owner, presented, now)
    }

    fn cache_needs_refresh(&self, cache: &CacheState) -> bool {
        cache
            .current
            .as_ref()
            .is_none_or(|cached| cached.loaded_at.elapsed() >= self.cache_ttl)
    }

    async fn ensure_stage_snapshots_stable(
        &self,
        checkpoints: &[CredentialCheckpoint],
        finalized: bool,
    ) -> Result<(), AdminCredentialError> {
        let permits = Arc::new(Semaphore::new(MAX_ADMIN_CREDENTIAL_FETCH_CONCURRENCY));
        let mut tasks = JoinSet::new();
        for checkpoint in checkpoints {
            let backend = self.backend.clone();
            let permits = permits.clone();
            let secret_ref = checkpoint.secret_ref.clone();
            let expected = if finalized {
                checkpoint.stages.finalized()
            } else {
                checkpoint.stages.clone()
            };
            tasks.spawn(async move {
                let observed = backend.stage_snapshot(&secret_ref, permits).await?;
                if observed == expected {
                    Ok::<_, AdminCredentialError>(())
                } else {
                    Err(AdminCredentialError::InvalidConfiguration)
                }
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.map_err(|_| AdminCredentialError::Unavailable)??;
        }
        Ok(())
    }

    async fn load_registry(&self, now: i64) -> Result<CredentialRegistry, AdminCredentialError> {
        let platform_ref = self
            .platform_secret_ref
            .as_deref()
            .ok_or(AdminCredentialError::InvalidConfiguration)?;
        let mut expected = Vec::with_capacity(
            1 + self.tenant_secret_refs.len() + self.scim_tenant_secret_refs.len(),
        );
        expected.push((AdminCredentialOwner::platform(), platform_ref.to_string()));
        let mut tenants: Vec<_> = self.tenant_secret_refs.iter().collect();
        tenants.sort_by(|left, right| left.0.cmp(right.0));
        expected.extend(tenants.into_iter().map(|(tenant, secret_ref)| {
            (AdminCredentialOwner::tenant(tenant), secret_ref.to_string())
        }));
        let mut scim_tenants: Vec<_> = self.scim_tenant_secret_refs.iter().collect();
        scim_tenants.sort_by(|left, right| left.0.cmp(right.0));
        expected.extend(scim_tenants.into_iter().map(|(tenant, secret_ref)| {
            (
                AdminCredentialOwner::scim_tenant(tenant),
                secret_ref.to_string(),
            )
        }));

        let permits = Arc::new(Semaphore::new(MAX_ADMIN_CREDENTIAL_FETCH_CONCURRENCY));
        let mut tasks = JoinSet::new();
        for (expected_owner, secret_ref) in expected {
            let backend = self.backend.clone();
            let permits = permits.clone();
            tasks.spawn(async move {
                let versions = backend.fetch(&secret_ref, permits).await;
                (expected_owner, secret_ref, versions)
            });
        }

        let mut sets = HashMap::new();
        let mut checkpoints = Vec::new();
        while let Some(result) = tasks.join_next().await {
            let (expected_owner, secret_ref, versions) =
                result.map_err(|_| AdminCredentialError::Unavailable)?;
            let versions = match versions {
                Ok(versions) => versions,
                Err(AdminCredentialError::Removed)
                    if !matches!(expected_owner, AdminCredentialOwner::Platform) =>
                {
                    continue;
                }
                Err(AdminCredentialError::Removed) => {
                    return Err(AdminCredentialError::InvalidConfiguration);
                }
                Err(error) => return Err(error),
            };
            let LoadedSecretVersions { stages, versions } = versions;
            let SecretVersions {
                current,
                previous,
                validated,
                pending: _,
            } = versions;
            let wire: AdminCredentialSet = serde_json::from_str(&current.secret_string)
                .map_err(|_| AdminCredentialError::InvalidConfiguration)?;
            let set = normalize_set(wire, current.version_created_at, &expected_owner)?;

            if stages
                .pending_version_id
                .as_deref()
                .is_some_and(|pending| pending != current.version_id)
            {
                return Err(AdminCredentialError::InvalidConfiguration);
            }
            let mut rollback_deadline = None;
            let current_is_validated = match validated {
                Some(validated) => {
                    let current_is_validated = validated.version_id == current.version_id;
                    if !current_is_validated {
                        let validated_wire: AdminCredentialSet =
                            serde_json::from_str(&validated.secret_string)
                                .map_err(|_| AdminCredentialError::InvalidConfiguration)?;
                        let validated_set = normalize_set(
                            validated_wire,
                            validated.version_created_at,
                            &expected_owner,
                        )?;
                        rollback_deadline =
                            transition_deadline(&validated_set, &set, rollback_deadline);
                        validate_transition(&validated_set, &set, now)?;
                    }
                    current_is_validated
                }
                None => return Err(AdminCredentialError::InvalidConfiguration),
            };

            if let Some(previous) = previous.filter(|previous| {
                previous.version_id != current.version_id
                    && Some(previous.version_id.as_str()) != stages.validated_version_id.as_deref()
                    && is_admin_credential_document(&previous.secret_string)
            }) {
                let previous_wire: AdminCredentialSet =
                    serde_json::from_str(&previous.secret_string)
                        .map_err(|_| AdminCredentialError::InvalidConfiguration)?;
                let previous_set =
                    normalize_set(previous_wire, previous.version_created_at, &expected_owner)?;
                if current_is_validated {
                    validate_trusted_current_revision(&previous_set, &set)?;
                } else {
                    rollback_deadline = transition_deadline(&previous_set, &set, rollback_deadline);
                    validate_transition(&previous_set, &set, now)?;
                }
            }
            checkpoints.push(CredentialCheckpoint {
                stages,
                rollback_deadline,
                secret_ref,
            });
            if sets.insert(expected_owner, set).is_some() {
                return Err(AdminCredentialError::InvalidConfiguration);
            }
        }
        validate_registry_uniqueness(sets.values())?;
        if sets.values().any(|set| !set.has_active_credential(now)) {
            return Err(AdminCredentialError::InvalidConfiguration);
        }
        self.ensure_stage_snapshots_stable(&checkpoints, false)
            .await?;

        let permits = Arc::new(Semaphore::new(MAX_ADMIN_CREDENTIAL_FETCH_CONCURRENCY));
        let mut checkpoint_tasks = JoinSet::new();
        for checkpoint in checkpoints.iter().cloned() {
            let backend = self.backend.clone();
            let permits = permits.clone();
            checkpoint_tasks.spawn(async move {
                let _permit = permits
                    .acquire_owned()
                    .await
                    .map_err(|_| AdminCredentialError::Unavailable)?;
                backend.mark_validated(&checkpoint, now).await
            });
        }
        while let Some(result) = checkpoint_tasks.join_next().await {
            result.map_err(|_| AdminCredentialError::Unavailable)??;
        }
        self.ensure_stage_snapshots_stable(&checkpoints, true)
            .await?;
        Ok(CredentialRegistry { sets })
    }
}

fn cached_verify(
    cache: &CacheState,
    owner: &AdminCredentialOwner,
    presented: &str,
    now: i64,
) -> Result<Option<AdminCredentialMatch>, AdminCredentialError> {
    let registry = &cache
        .current
        .as_ref()
        .ok_or(AdminCredentialError::InvalidConfiguration)?
        .registry;
    if registry
        .sets
        .values()
        .any(|set| !set.has_active_credential(now))
    {
        return Err(AdminCredentialError::InvalidConfiguration);
    }
    let set = registry
        .sets
        .get(owner)
        .ok_or(AdminCredentialError::InvalidConfiguration)?;
    Ok(set.verify(presented, now))
}

fn validate_registry_uniqueness<'a>(
    sets: impl IntoIterator<Item = &'a NormalizedSet>,
) -> Result<(), AdminCredentialError> {
    let mut credential_ids = HashSet::new();
    let mut credential_id_hashes = HashSet::new();
    let mut secret_values = HashSet::new();
    let mut secret_hashes = HashSet::new();
    let mut retired_ids = HashSet::new();
    let mut retired_id_hashes = HashSet::new();
    let mut retired_hashes = HashSet::new();

    for set in sets {
        for record in std::iter::once(&set.current).chain(set.next.iter()) {
            let credential_id_hash = secret_sha256(&record.credential_id);
            if record.credential_id == record.secret
                || secret_values.contains(&record.credential_id)
                || credential_ids.contains(&record.secret)
                || retired_ids.contains(&record.credential_id)
                || retired_ids.contains(&record.secret)
                || retired_hashes.contains(&credential_id_hash)
                || retired_hashes.contains(&record.secret_sha256)
                || !credential_ids.insert(record.credential_id.clone())
                || !credential_id_hashes.insert(credential_id_hash)
                || !secret_values.insert(record.secret.clone())
                || !secret_hashes.insert(record.secret_sha256.clone())
            {
                return Err(AdminCredentialError::InvalidConfiguration);
            }
        }
        for retired in &set.retired {
            let credential_id_hash = secret_sha256(&retired.credential_id);
            if credential_ids.contains(&retired.credential_id)
                || secret_values.contains(&retired.credential_id)
                || credential_id_hashes.contains(&retired.secret_sha256)
                || secret_hashes.contains(&retired.secret_sha256)
                || retired_hashes.contains(&credential_id_hash)
                || retired_id_hashes.contains(&retired.secret_sha256)
                || !retired_ids.insert(retired.credential_id.clone())
                || !retired_id_hashes.insert(credential_id_hash)
                || !retired_hashes.insert(retired.secret_sha256.clone())
            {
                return Err(AdminCredentialError::InvalidConfiguration);
            }
        }
    }
    Ok(())
}

impl NormalizedSet {
    fn current_is_active(&self, now: i64) -> bool {
        now >= self.current.not_before
            && now < self.current.expires_at
            && self
                .retire_current_at
                .is_none_or(|retire_current_at| now < retire_current_at)
    }

    fn next_is_active(&self, now: i64) -> bool {
        self.next
            .as_ref()
            .is_some_and(|next| now >= next.not_before && now < next.expires_at)
    }

    fn has_active_credential(&self, now: i64) -> bool {
        self.current_is_active(now) || self.next_is_active(now)
    }

    fn verify(&self, presented: &str, now: i64) -> Option<AdminCredentialMatch> {
        let current_active = self.current_is_active(now);
        let next_active = self.next_is_active(now);
        let current_matches = ct_secret_eq(presented, &self.current.secret);
        let next_matches = self
            .next
            .as_ref()
            .is_some_and(|next| ct_secret_eq(presented, &next.secret));

        if current_active && current_matches {
            Some(AdminCredentialMatch {
                credential_id: self.current.credential_id.clone(),
                owner: self.owner.clone(),
                slot: AdminCredentialSlot::Current,
                revision: self.revision,
            })
        } else if next_active && next_matches {
            Some(AdminCredentialMatch {
                credential_id: self
                    .next
                    .as_ref()
                    .expect("next_active implies next")
                    .credential_id
                    .clone(),
                owner: self.owner.clone(),
                slot: AdminCredentialSlot::Next,
                revision: self.revision,
            })
        } else {
            None
        }
    }
}

fn normalize_set(
    wire: AdminCredentialSet,
    version_created_at: i64,
    expected_owner: &AdminCredentialOwner,
) -> Result<NormalizedSet, AdminCredentialError> {
    if wire.schema_version != ADMIN_CREDENTIAL_SCHEMA_VERSION
        || wire.owner != *expected_owner
        || wire.usage != expected_owner.expected_usage()
        || wire.revision == 0
    {
        return Err(AdminCredentialError::InvalidConfiguration);
    }
    validate_owner(&wire.owner)?;
    let retired = normalize_retired(wire.retired)?;
    if retired
        .iter()
        .any(|record| record.retired_at > version_created_at)
    {
        return Err(AdminCredentialError::InvalidConfiguration);
    }
    let generated_initial = wire.revision == 1 && wire.next.is_none() && wire.rotation.is_none();
    let current = normalize_record(wire.current, version_created_at, generated_initial)?;
    let next = match wire.next {
        Some(record) => Some(normalize_record(record, version_created_at, false)?),
        None => None,
    };

    let retire_current_at = match (next.as_ref(), wire.rotation) {
        (None, None) => None,
        (Some(next), Some(rotation)) => {
            if rotation.overlap_starts_at != next.not_before
                || rotation.overlap_starts_at < current.not_before
                || rotation.overlap_starts_at >= rotation.cutover_at
                || rotation.cutover_at >= rotation.retire_current_at
                || rotation.retire_current_at > current.expires_at
                || rotation.retire_current_at >= next.expires_at
                || rotation.retire_current_at - rotation.overlap_starts_at
                    > MAX_ADMIN_ROTATION_OVERLAP_SECS
                || current.credential_id == next.credential_id
                || current.secret == next.secret
            {
                return Err(AdminCredentialError::InvalidConfiguration);
            }
            Some(rotation.retire_current_at)
        }
        _ => return Err(AdminCredentialError::InvalidConfiguration),
    };
    for record in std::iter::once(&current).chain(next.iter()) {
        if retired.iter().any(|retired| {
            retired.credential_id == record.credential_id
                || retired.secret_sha256 == record.secret_sha256
        }) {
            return Err(AdminCredentialError::InvalidConfiguration);
        }
    }

    Ok(NormalizedSet {
        owner: wire.owner,
        revision: wire.revision,
        current,
        next,
        retire_current_at,
        retired,
    })
}

fn normalize_retired(
    retired: Vec<AdminRetiredCredential>,
) -> Result<Vec<AdminRetiredCredential>, AdminCredentialError> {
    let mut ids = HashSet::new();
    let mut hashes = HashSet::new();
    for record in &retired {
        if !valid_credential_id(&record.credential_id)
            || record.retired_at <= 0
            || record.secret_sha256.len() != 64
            || !record
                .secret_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || secret_sha256(&record.credential_id) == record.secret_sha256
            || !ids.insert(record.credential_id.clone())
            || !hashes.insert(record.secret_sha256.clone())
        {
            return Err(AdminCredentialError::InvalidConfiguration);
        }
    }
    Ok(retired)
}

fn validate_transition(
    previous: &NormalizedSet,
    current: &NormalizedSet,
    transition_at: i64,
) -> Result<(), AdminCredentialError> {
    if current.revision <= previous.revision {
        return Err(AdminCredentialError::InvalidConfiguration);
    }
    for inherited in &previous.retired {
        if !current.retired.contains(inherited) {
            return Err(AdminCredentialError::InvalidConfiguration);
        }
    }

    let previous_current_remains = same_credential(&previous.current, &current.current);
    if current
        .next
        .as_ref()
        .is_some_and(|candidate| same_credential(&previous.current, candidate))
    {
        return Err(AdminCredentialError::InvalidConfiguration);
    }
    let current_must_retire = previous
        .retire_current_at
        .is_some_and(|retire_current_at| transition_at >= retire_current_at);
    if current_must_retire || !previous_current_remains {
        require_retired(&previous.current, current, transition_at)?;
    } else if !same_record(&previous.current, &current.current) {
        return Err(AdminCredentialError::InvalidConfiguration);
    }

    if let Some(previous_next) = &previous.next {
        let persisted = std::iter::once(&current.current)
            .chain(current.next.iter())
            .find(|candidate| same_credential(previous_next, candidate));
        match persisted {
            Some(candidate) if same_record(previous_next, candidate) => {
                if current
                    .next
                    .as_ref()
                    .is_some_and(|next| same_credential(previous_next, next))
                    && current.retire_current_at > previous.retire_current_at
                {
                    return Err(AdminCredentialError::InvalidConfiguration);
                }
            }
            Some(_) => return Err(AdminCredentialError::InvalidConfiguration),
            None => require_retired(previous_next, current, transition_at)?,
        }
    }
    Ok(())
}

fn transition_deadline(
    previous: &NormalizedSet,
    current: &NormalizedSet,
    existing: Option<i64>,
) -> Option<i64> {
    let deadline = previous
        .retire_current_at
        .filter(|_| same_credential(&previous.current, &current.current));
    match (existing, deadline) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
        (None, None) => None,
    }
}

fn transition_now(now_floor: i64) -> i64 {
    now_floor.max(crate::current_unix_secs())
}

fn checkpoint_deadline_reached(
    now_floor: i64,
    deadline: i64,
    remaining_stage_mutations: i64,
) -> bool {
    transition_now(now_floor)
        .saturating_add(ADMIN_CREDENTIAL_CHECKPOINT_SAFETY_SECS)
        .saturating_add(
            ADMIN_CREDENTIAL_STAGE_MUTATION_RESERVE_SECS.saturating_mul(remaining_stage_mutations),
        )
        >= deadline
}

fn validate_trusted_current_revision(
    previous: &NormalizedSet,
    current: &NormalizedSet,
) -> Result<(), AdminCredentialError> {
    if current.revision <= previous.revision {
        return Err(AdminCredentialError::InvalidConfiguration);
    }
    Ok(())
}

fn same_credential(left: &NormalizedRecord, right: &NormalizedRecord) -> bool {
    left.credential_id == right.credential_id && left.secret_sha256 == right.secret_sha256
}

fn same_record(left: &NormalizedRecord, right: &NormalizedRecord) -> bool {
    same_credential(left, right)
        && left.created_at == right.created_at
        && left.not_before == right.not_before
        && left.expires_at == right.expires_at
}

fn require_retired(
    record: &NormalizedRecord,
    current: &NormalizedSet,
    transition_at: i64,
) -> Result<(), AdminCredentialError> {
    let retired = current.retired.iter().find(|retired| {
        retired.credential_id == record.credential_id
            && retired.secret_sha256 == record.secret_sha256
    });
    if retired.is_none_or(|retired| retired.retired_at > transition_at) {
        return Err(AdminCredentialError::InvalidConfiguration);
    }
    Ok(())
}

fn normalize_record(
    wire: AdminCredentialRecord,
    version_created_at: i64,
    allow_generated_initial: bool,
) -> Result<NormalizedRecord, AdminCredentialError> {
    if !valid_credential_id(&wire.credential_id)
        || wire.secret.len() < MIN_ADMIN_CREDENTIAL_SECRET_BYTES
        || wire.secret.trim() != wire.secret
    {
        return Err(AdminCredentialError::InvalidConfiguration);
    }
    let (created_at, not_before, expires_at) = match (
        wire.created_at,
        wire.not_before,
        wire.expires_at,
        wire.ttl_seconds,
    ) {
        (Some(created_at), Some(not_before), Some(expires_at), None) => {
            (created_at, not_before, expires_at)
        }
        (None, None, None, Some(ttl_seconds))
            if allow_generated_initial
                && ttl_seconds > 0
                && ttl_seconds <= MAX_ADMIN_CREDENTIAL_LIFETIME_SECS =>
        {
            (
                version_created_at,
                version_created_at,
                version_created_at
                    .checked_add(ttl_seconds)
                    .ok_or(AdminCredentialError::InvalidConfiguration)?,
            )
        }
        _ => return Err(AdminCredentialError::InvalidConfiguration),
    };
    if created_at <= 0
        || created_at > not_before
        || not_before >= expires_at
        || expires_at - created_at > MAX_ADMIN_CREDENTIAL_LIFETIME_SECS
    {
        return Err(AdminCredentialError::InvalidConfiguration);
    }
    Ok(NormalizedRecord {
        credential_id: wire.credential_id,
        secret_sha256: secret_sha256(&wire.secret),
        secret: wire.secret,
        created_at,
        not_before,
        expires_at,
    })
}

pub fn secret_sha256(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_owner(owner: &AdminCredentialOwner) -> Result<(), AdminCredentialError> {
    match owner {
        AdminCredentialOwner::Platform => Ok(()),
        AdminCredentialOwner::Tenant { tenant_id }
        | AdminCredentialOwner::ScimTenant { tenant_id }
            if !tenant_id.is_empty()
                && tenant_id.len() <= 63
                && tenant_id.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                })
                && !tenant_id.starts_with('-')
                && !tenant_id.ends_with('-') =>
        {
            Ok(())
        }
        AdminCredentialOwner::Tenant { .. } | AdminCredentialOwner::ScimTenant { .. } => {
            Err(AdminCredentialError::InvalidConfiguration)
        }
    }
}

fn valid_credential_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn ct_secret_eq(presented: &str, expected: &str) -> bool {
    presented.len() == expected.len() && bool::from(presented.as_bytes().ct_eq(expected.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 2_000_000_000;
    const PLATFORM_REF: &str = "arn:platform";
    const T1_REF: &str = "arn:t1";

    fn record(id: &str, secret: &str, not_before: i64, expires_at: i64) -> AdminCredentialRecord {
        AdminCredentialRecord::explicit(id, secret, NOW - 100, not_before, expires_at)
    }

    fn retired(id: &str, secret: &str, retired_at: i64) -> AdminRetiredCredential {
        AdminRetiredCredential {
            credential_id: id.to_string(),
            secret_sha256: secret_sha256(secret),
            retired_at,
        }
    }

    fn secret_document(value: impl Into<String>, created_at: i64, id: &str) -> SecretDocument {
        SecretDocument {
            secret_string: value.into(),
            version_created_at: created_at,
            version_id: id.to_string(),
        }
    }

    fn resolver(
        platform: AdminCredentialSet,
        tenants: Vec<(&str, &str, AdminCredentialSet)>,
    ) -> AdminCredentialResolver {
        let store = MemoryAdminCredentialStore::default();
        store.put_set(PLATFORM_REF, &platform, NOW);
        let mut refs = HashMap::new();
        for (tenant, secret_ref, set) in tenants {
            refs.insert(tenant.to_string(), secret_ref.to_string());
            store.put_set(secret_ref, &set, NOW);
        }
        AdminCredentialResolver::memory(Some(PLATFORM_REF.to_string()), refs, store, Duration::ZERO)
    }

    #[test]
    fn checkpoint_reserves_finalize_time_before_safety_window() {
        assert!(!checkpoint_deadline_reached(NOW, NOW + 51, 2));
        assert!(checkpoint_deadline_reached(NOW, NOW + 50, 2));
        assert!(!checkpoint_deadline_reached(NOW, NOW + 41, 1));
        assert!(checkpoint_deadline_reached(NOW, NOW + 40, 1));
    }

    #[tokio::test]
    async fn current_and_next_overlap_then_current_retires() {
        let set = AdminCredentialSet::rotating(
            AdminCredentialOwner::platform(),
            2,
            record("platform-v1", "old-value-credential", NOW - 10, NOW + 300),
            record("platform-v2", "new-value-credential", NOW, NOW + 600),
            AdminCredentialRotation {
                overlap_starts_at: NOW,
                cutover_at: NOW + 100,
                retire_current_at: NOW + 200,
            },
        );
        let resolver = resolver(set, vec![]);
        let owner = AdminCredentialOwner::platform();

        assert!(resolver
            .verify(&owner, "old-value-credential", NOW + 50)
            .await
            .unwrap()
            .is_some());
        assert!(resolver
            .verify(&owner, "new-value-credential", NOW + 50)
            .await
            .unwrap()
            .is_some());
        assert!(resolver
            .verify(&owner, "old-value-credential", NOW + 200)
            .await
            .unwrap()
            .is_none());
        assert!(resolver
            .verify(&owner, "new-value-credential", NOW + 200)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn owner_without_an_active_value_invalidates_the_registry() {
        let set = AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            record("platform-v1", "active-secret-value", NOW + 10, NOW + 20),
        );
        let resolver = resolver(set, vec![]);
        let owner = AdminCredentialOwner::platform();
        assert!(matches!(
            resolver.verify(&owner, "active-secret-value", NOW).await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));
        assert!(matches!(
            resolver
                .verify(&owner, "active-secret-value", NOW + 20)
                .await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));
    }

    #[tokio::test]
    async fn cached_registry_fails_closed_when_any_owner_expires() {
        let store = MemoryAdminCredentialStore::default();
        store.put_set(
            PLATFORM_REF,
            &AdminCredentialSet::single(
                AdminCredentialOwner::platform(),
                record("platform-v1", "platform-secret-value", NOW, NOW + 10),
            ),
            NOW,
        );
        store.put_set(
            T1_REF,
            &AdminCredentialSet::single(
                AdminCredentialOwner::tenant("t1"),
                record("t1-v1", "tenant-secret-value", NOW, NOW + 100),
            ),
            NOW,
        );
        let resolver = AdminCredentialResolver::memory(
            Some(PLATFORM_REF.to_string()),
            HashMap::from([("t1".to_string(), T1_REF.to_string())]),
            store,
            Duration::from_secs(300),
        );
        let owner = AdminCredentialOwner::tenant("t1");

        assert!(resolver
            .verify(&owner, "tenant-secret-value", NOW + 1)
            .await
            .unwrap()
            .is_some());
        assert!(matches!(
            resolver
                .verify(&owner, "tenant-secret-value", NOW + 10)
                .await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));
    }

    #[tokio::test]
    async fn expired_cache_never_serves_stale_registry_when_backend_disappears() {
        let owner = AdminCredentialOwner::platform();
        let store = MemoryAdminCredentialStore::default();
        store.put_set(
            PLATFORM_REF,
            &AdminCredentialSet::single(
                owner.clone(),
                record("platform-v1", "platform-secret-value", NOW, NOW + 100),
            ),
            NOW,
        );
        let resolver = AdminCredentialResolver::memory(
            Some(PLATFORM_REF.to_string()),
            HashMap::new(),
            store.clone(),
            Duration::from_millis(1),
        );
        assert!(resolver
            .verify(&owner, "platform-secret-value", NOW)
            .await
            .unwrap()
            .is_some());

        store.remove(PLATFORM_REF);
        tokio::time::sleep(Duration::from_millis(2)).await;
        assert!(matches!(
            resolver.verify(&owner, "platform-secret-value", NOW).await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));
    }

    #[tokio::test]
    async fn removed_tenant_is_excluded_without_disabling_platform_credentials() {
        let platform_owner = AdminCredentialOwner::platform();
        let tenant_owner = AdminCredentialOwner::tenant("t1");
        let store = MemoryAdminCredentialStore::default();
        store.put_set(
            PLATFORM_REF,
            &AdminCredentialSet::single(
                platform_owner.clone(),
                record("platform-v1", "platform-secret-value", NOW, NOW + 100),
            ),
            NOW,
        );
        store.put_set(
            T1_REF,
            &AdminCredentialSet::single(
                tenant_owner.clone(),
                record("t1-v1", "tenant-secret-value", NOW, NOW + 100),
            ),
            NOW,
        );
        store.remove(T1_REF);
        let resolver = AdminCredentialResolver::memory(
            Some(PLATFORM_REF.to_string()),
            HashMap::from([("t1".to_string(), T1_REF.to_string())]),
            store,
            Duration::ZERO,
        );

        assert!(resolver
            .verify(&platform_owner, "platform-secret-value", NOW)
            .await
            .unwrap()
            .is_some());
        assert!(matches!(
            resolver
                .verify(&tenant_owner, "tenant-secret-value", NOW)
                .await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));
    }

    #[cfg(feature = "aws")]
    #[test]
    fn deleted_secret_description_is_classified_as_removed() {
        let output =
            aws_sdk_secretsmanager::operation::describe_secret::DescribeSecretOutput::builder()
                .deleted_date(aws_sdk_secretsmanager::primitives::DateTime::from_secs(NOW))
                .build();

        assert_eq!(
            secret_description_not_removed(&output),
            Err(AdminCredentialError::Removed)
        );
        assert_eq!(
            secret_stage_snapshot_from_description(&output),
            Err(AdminCredentialError::Removed)
        );
    }

    #[cfg(feature = "aws")]
    #[test]
    fn active_secret_description_is_not_removed() {
        let output =
            aws_sdk_secretsmanager::operation::describe_secret::DescribeSecretOutput::builder()
                .build();

        assert_eq!(secret_description_not_removed(&output), Ok(()));
    }

    #[test]
    fn migration_only_skips_explicitly_allowed_removed_owners() {
        assert_eq!(
            migration_value_or_skip::<u8>(Err(AdminCredentialError::Removed), false),
            Err(AdminCredentialError::Removed)
        );
        assert_eq!(
            migration_value_or_skip::<u8>(Err(AdminCredentialError::Removed), true),
            Ok(None)
        );
        assert_eq!(
            migration_value_or_skip::<u8>(Err(AdminCredentialError::Unavailable), true),
            Err(AdminCredentialError::Unavailable)
        );
        assert_eq!(migration_value_or_skip(Ok(7_u8), true), Ok(Some(7)));
    }

    #[cfg(feature = "aws")]
    #[test]
    fn migration_allow_removed_is_tenant_only_and_pascal_case() {
        let tenant_entry: AdminCredentialMigrationEntry =
            serde_json::from_value(serde_json::json!({
                "SourceSecretArn": "arn:source:t1",
                "TargetSecretArn": "arn:target:t1",
                "Owner": {"kind": "tenant", "tenant_id": "t1"},
                "CredentialId": "t1-bootstrap-v1",
                "AllowRemoved": "true"
            }))
            .unwrap();
        assert!(tenant_entry.allow_removed);
        assert_eq!(
            validate_admin_credential_migration_entries(&[tenant_entry]),
            Ok(())
        );

        let platform_entry: AdminCredentialMigrationEntry =
            serde_json::from_value(serde_json::json!({
                "SourceSecretArn": "arn:source:platform",
                "TargetSecretArn": "arn:target:platform",
                "Owner": {"kind": "platform"},
                "CredentialId": "platform-bootstrap-v1",
                "AllowRemoved": true
            }))
            .unwrap();
        assert_eq!(
            validate_admin_credential_migration_entries(&[platform_entry]),
            Err(AdminCredentialError::InvalidConfiguration)
        );

        let false_entry: AdminCredentialMigrationEntry =
            serde_json::from_value(serde_json::json!({
                "SourceSecretArn": "arn:source:t3",
                "TargetSecretArn": "arn:target:t3",
                "Owner": {"kind": "tenant", "tenant_id": "t3"},
                "CredentialId": "t3-bootstrap-v1",
                "AllowRemoved": "false"
            }))
            .unwrap();
        assert!(!false_entry.allow_removed);

        let invalid = serde_json::from_value::<AdminCredentialMigrationEntry>(serde_json::json!({
            "SourceSecretArn": "arn:source:t3",
            "TargetSecretArn": "arn:target:t3",
            "Owner": {"kind": "tenant", "tenant_id": "t3"},
            "CredentialId": "t3-bootstrap-v1",
            "AllowRemoved": "1"
        }));
        assert!(invalid.is_err());
    }

    #[tokio::test]
    async fn registry_snapshot_rejects_a_changed_owner_version() {
        let owner = AdminCredentialOwner::platform();
        let store = MemoryAdminCredentialStore::default();
        store.put_set(
            PLATFORM_REF,
            &AdminCredentialSet::single(
                owner.clone(),
                record("platform-v1", "platform-secret-value", NOW, NOW + 100),
            ),
            NOW,
        );
        let expected_stages = store
            .documents
            .read()
            .unwrap()
            .get(PLATFORM_REF)
            .map(SecretStageSnapshot::from_versions)
            .unwrap();
        let resolver = AdminCredentialResolver::memory(
            Some(PLATFORM_REF.to_string()),
            HashMap::new(),
            store.clone(),
            Duration::ZERO,
        );
        let mut changed = AdminCredentialSet::single(
            owner,
            record("platform-v2", "replacement-secret", NOW, NOW + 100),
        );
        changed.revision = 2;
        changed
            .retired
            .push(retired("platform-v1", "platform-secret-value", NOW));
        store.put_set(PLATFORM_REF, &changed, NOW);

        assert_eq!(
            resolver
                .ensure_stage_snapshots_stable(
                    &[CredentialCheckpoint {
                        stages: expected_stages,
                        rollback_deadline: None,
                        secret_ref: PLATFORM_REF.to_string(),
                    }],
                    false,
                )
                .await,
            Err(AdminCredentialError::InvalidConfiguration)
        );
    }

    #[tokio::test]
    async fn stale_checkpoint_cannot_overwrite_a_newer_validated_stage_after_aba() {
        let owner = AdminCredentialOwner::platform();
        let store = MemoryAdminCredentialStore::default();
        store.put_set(
            PLATFORM_REF,
            &AdminCredentialSet::single(
                owner.clone(),
                record("platform-v1", "platform-secret-value", NOW, NOW + 100),
            ),
            NOW,
        );
        let mut second = AdminCredentialSet::single(
            owner.clone(),
            record("platform-v2", "replacement-secret", NOW, NOW + 200),
        );
        second.revision = 2;
        second
            .retired
            .push(retired("platform-v1", "platform-secret-value", NOW));
        store.put_set(PLATFORM_REF, &second, NOW + 1);
        let stale_stages = {
            let documents = store.documents.read().unwrap();
            SecretStageSnapshot::from_versions(documents.get(PLATFORM_REF).unwrap())
        };

        let mut third = AdminCredentialSet::single(
            owner,
            record("platform-v3", "third-secret-value", NOW, NOW + 300),
        );
        third.revision = 3;
        third
            .retired
            .push(retired("platform-v1", "platform-secret-value", NOW));
        third
            .retired
            .push(retired("platform-v2", "replacement-secret", NOW + 1));
        store.put_set(PLATFORM_REF, &third, NOW + 2);
        let (third_version, old_validated) = {
            let documents = store.documents.read().unwrap();
            let versions = documents.get(PLATFORM_REF).unwrap();
            (
                versions.current.version_id.clone(),
                versions.validated.as_ref().unwrap().version_id.clone(),
            )
        };
        store.mark_pending(PLATFORM_REF, &third_version).unwrap();
        store
            .mark_validated(PLATFORM_REF, &third_version, Some(&old_validated))
            .unwrap();
        store.clear_pending(PLATFORM_REF, &third_version).unwrap();

        let third_validated = {
            let mut documents = store.documents.write().unwrap();
            let versions = documents.get_mut(PLATFORM_REF).unwrap();
            let third_document = versions.current.clone();
            let second_document = versions.previous.take().unwrap();
            versions.current = second_document;
            versions.previous = Some(third_document);
            versions.validated.as_ref().unwrap().version_id.clone()
        };
        assert_eq!(
            stale_stages.current_version_id,
            store
                .documents
                .read()
                .unwrap()
                .get(PLATFORM_REF)
                .unwrap()
                .current
                .version_id
        );

        let backend = AdminCredentialBackend::Memory(store.clone());
        assert_eq!(
            backend
                .mark_validated(
                    &CredentialCheckpoint {
                        stages: stale_stages,
                        rollback_deadline: None,
                        secret_ref: PLATFORM_REF.to_string(),
                    },
                    NOW + 3,
                )
                .await,
            Err(AdminCredentialError::InvalidConfiguration)
        );
        let documents = store.documents.read().unwrap();
        let versions = documents.get(PLATFORM_REF).unwrap();
        assert_eq!(
            versions
                .validated
                .as_ref()
                .map(|document| document.version_id.as_str()),
            Some(third_validated.as_str())
        );
        assert_eq!(
            versions
                .pending
                .as_ref()
                .map(|document| document.version_id.as_str()),
            Some(versions.current.version_id.as_str())
        );
    }

    #[test]
    fn stage_snapshot_rejects_duplicate_stage_assignments() {
        let stages = HashMap::from([
            ("version-a".to_string(), vec!["AWSCURRENT".to_string()]),
            ("version-b".to_string(), vec!["AWSCURRENT".to_string()]),
        ]);
        assert_eq!(
            secret_stage_snapshot(&stages),
            Err(AdminCredentialError::InvalidConfiguration)
        );
    }

    #[tokio::test]
    async fn duplicate_or_cross_tenant_documents_fail_closed() {
        let platform = AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            record("platform-v1", "shared-admin-secret", NOW, NOW + 100),
        );
        let duplicate = AdminCredentialSet::single(
            AdminCredentialOwner::tenant("t1"),
            record("t1-v1", "shared-admin-secret", NOW, NOW + 100),
        );
        let duplicate_resolver = resolver(platform.clone(), vec![("t1", T1_REF, duplicate)]);
        assert!(matches!(
            duplicate_resolver
                .verify(
                    &AdminCredentialOwner::platform(),
                    "shared-admin-secret",
                    NOW
                )
                .await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));

        let wrong_owner = AdminCredentialSet::single(
            AdminCredentialOwner::tenant("t2"),
            record("t2-v1", "tenant-secret-value", NOW, NOW + 100),
        );
        let wrong_owner_resolver = resolver(platform, vec![("t1", T1_REF, wrong_owner)]);
        assert!(matches!(
            wrong_owner_resolver
                .verify(
                    &AdminCredentialOwner::tenant("t1"),
                    "tenant-secret-value",
                    NOW
                )
                .await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));
    }

    #[tokio::test]
    async fn warm_cache_refreshes_and_rejects_revision_regression() {
        let store = MemoryAdminCredentialStore::default();
        let v1 = AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            record("platform-v1", "old-value-credential", NOW, NOW + 100),
        );
        store.put_set(PLATFORM_REF, &v1, NOW);
        let resolver = AdminCredentialResolver::memory(
            Some(PLATFORM_REF.to_string()),
            HashMap::new(),
            store.clone(),
            Duration::ZERO,
        );
        let owner = AdminCredentialOwner::platform();
        assert!(resolver
            .verify(&owner, "old-value-credential", NOW)
            .await
            .unwrap()
            .is_some());

        let mut v2 = AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            record("platform-v2", "new-value-credential", NOW, NOW + 100),
        );
        v2.revision = 2;
        v2.retired
            .push(retired("platform-v1", "old-value-credential", NOW + 1));
        store.put_set(PLATFORM_REF, &v2, NOW + 1);
        assert!(resolver
            .verify(&owner, "old-value-credential", NOW + 1)
            .await
            .unwrap()
            .is_none());
        assert!(resolver
            .verify(&owner, "new-value-credential", NOW + 1)
            .await
            .unwrap()
            .is_some());

        store.put_set(PLATFORM_REF, &v1, NOW + 2);
        assert!(matches!(
            resolver
                .verify(&owner, "old-value-credential", NOW + 2)
                .await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));
    }

    #[tokio::test]
    async fn higher_revision_can_roll_back_to_current_before_retirement() {
        let store = MemoryAdminCredentialStore::default();
        let rotating = AdminCredentialSet::rotating(
            AdminCredentialOwner::platform(),
            2,
            record("platform-v1", "old-value-credential", NOW - 10, NOW + 300),
            record("platform-v2", "new-value-credential", NOW, NOW + 600),
            AdminCredentialRotation {
                overlap_starts_at: NOW,
                cutover_at: NOW + 100,
                retire_current_at: NOW + 200,
            },
        );
        store.put_set(PLATFORM_REF, &rotating, NOW);
        let resolver = AdminCredentialResolver::memory(
            Some(PLATFORM_REF.to_string()),
            HashMap::new(),
            store.clone(),
            Duration::ZERO,
        );
        let owner = AdminCredentialOwner::platform();
        assert!(resolver
            .verify(&owner, "new-value-credential", NOW + 50)
            .await
            .unwrap()
            .is_some());

        let mut rollback = AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            record("platform-v1", "old-value-credential", NOW - 10, NOW + 300),
        );
        rollback.revision = 3;
        rollback
            .retired
            .push(retired("platform-v2", "new-value-credential", NOW + 50));
        store.put_set(PLATFORM_REF, &rollback, NOW + 50);
        assert!(resolver
            .verify(&owner, "old-value-credential", NOW + 50)
            .await
            .unwrap()
            .is_some());
        assert!(resolver
            .verify(&owner, "new-value-credential", NOW + 50)
            .await
            .unwrap()
            .is_none());
        assert!(resolver
            .verify(&owner, "old-value-credential", NOW + 250)
            .await
            .unwrap()
            .is_some());
        assert!(resolver
            .verify(&owner, "new-value-credential", NOW + 250)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn rollback_must_be_validated_before_retirement_not_only_precreated() {
        let store = MemoryAdminCredentialStore::default();
        let rotating = AdminCredentialSet::rotating(
            AdminCredentialOwner::platform(),
            2,
            record("platform-v1", "old-value-credential", NOW - 10, NOW + 300),
            record("platform-v2", "new-value-credential", NOW, NOW + 600),
            AdminCredentialRotation {
                overlap_starts_at: NOW,
                cutover_at: NOW + 100,
                retire_current_at: NOW + 200,
            },
        );
        store.put_set(PLATFORM_REF, &rotating, NOW);

        let mut rollback = AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            record("platform-v1", "old-value-credential", NOW - 10, NOW + 300),
        );
        rollback.revision = 3;
        rollback
            .retired
            .push(retired("platform-v2", "new-value-credential", NOW + 50));
        store.put_set(PLATFORM_REF, &rollback, NOW + 50);

        let cold = AdminCredentialResolver::memory(
            Some(PLATFORM_REF.to_string()),
            HashMap::new(),
            store,
            Duration::ZERO,
        );
        assert!(matches!(
            cold.verify(
                &AdminCredentialOwner::platform(),
                "old-value-credential",
                NOW + 250
            )
            .await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));
    }

    #[tokio::test]
    async fn checkpoint_does_not_trust_rollback_in_retirement_safety_window() {
        let owner = AdminCredentialOwner::platform();
        let store = MemoryAdminCredentialStore::default();
        let rotating = AdminCredentialSet::rotating(
            owner.clone(),
            2,
            record("platform-v1", "old-value-credential", NOW - 10, NOW + 300),
            record("platform-v2", "new-value-credential", NOW, NOW + 600),
            AdminCredentialRotation {
                overlap_starts_at: NOW,
                cutover_at: NOW + 50,
                retire_current_at: NOW + 100,
            },
        );
        store.put_set(PLATFORM_REF, &rotating, NOW);
        let mut rollback = AdminCredentialSet::single(
            owner,
            record("platform-v1", "old-value-credential", NOW - 10, NOW + 300),
        );
        rollback.revision = 3;
        rollback
            .retired
            .push(retired("platform-v2", "new-value-credential", NOW + 50));
        store.put_set(PLATFORM_REF, &rollback, NOW + 50);

        let stages = {
            let documents = store
                .documents
                .read()
                .expect("admin credential memory store lock");
            let versions = documents.get(PLATFORM_REF).expect("platform versions");
            SecretStageSnapshot::from_versions(versions)
        };
        let current_version = stages.current_version_id.clone();
        let validated_version = stages
            .validated_version_id
            .clone()
            .expect("validated rotation");
        let backend = AdminCredentialBackend::Memory(store.clone());
        assert_eq!(
            backend
                .mark_validated(
                    &CredentialCheckpoint {
                        stages,
                        rollback_deadline: Some(NOW + 100),
                        secret_ref: PLATFORM_REF.to_string(),
                    },
                    NOW + 90,
                )
                .await,
            Err(AdminCredentialError::InvalidConfiguration)
        );
        let documents = store
            .documents
            .read()
            .expect("admin credential memory store lock");
        assert_eq!(
            documents
                .get(PLATFORM_REF)
                .and_then(|versions| versions.validated.as_ref())
                .map(|document| document.version_id.as_str()),
            Some(validated_version.as_str())
        );
        assert_eq!(
            documents
                .get(PLATFORM_REF)
                .and_then(|versions| versions.pending.as_ref())
                .map(|document| document.version_id.as_str()),
            Some(current_version.as_str())
        );
    }

    #[tokio::test]
    async fn precommit_crash_stays_fail_closed_after_retirement() {
        let owner = AdminCredentialOwner::platform();
        let store = MemoryAdminCredentialStore::default();
        let rotating = AdminCredentialSet::rotating(
            owner.clone(),
            2,
            record("platform-v1", "old-value-credential", NOW - 10, NOW + 300),
            record("platform-v2", "new-value-credential", NOW, NOW + 600),
            AdminCredentialRotation {
                overlap_starts_at: NOW,
                cutover_at: NOW + 50,
                retire_current_at: NOW + 100,
            },
        );
        store.put_set(PLATFORM_REF, &rotating, NOW);
        let mut rollback = AdminCredentialSet::single(
            owner.clone(),
            record("platform-v1", "old-value-credential", NOW - 10, NOW + 300),
        );
        rollback.revision = 3;
        rollback
            .retired
            .push(retired("platform-v2", "new-value-credential", NOW + 50));
        store.put_set(PLATFORM_REF, &rollback, NOW + 50);
        let (rollback_version, trusted_version) = {
            let documents = store.documents.read().unwrap();
            let versions = documents.get(PLATFORM_REF).unwrap();
            (
                versions.current.version_id.clone(),
                versions.validated.as_ref().unwrap().version_id.clone(),
            )
        };
        store.mark_pending(PLATFORM_REF, &rollback_version).unwrap();

        let cold = AdminCredentialResolver::memory(
            Some(PLATFORM_REF.to_string()),
            HashMap::new(),
            store.clone(),
            Duration::ZERO,
        );
        assert!(matches!(
            cold.verify(&owner, "old-value-credential", NOW + 101).await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));

        let documents = store.documents.read().unwrap();
        let versions = documents.get(PLATFORM_REF).unwrap();
        assert_eq!(
            versions
                .validated
                .as_ref()
                .map(|value| value.version_id.as_str()),
            Some(trusted_version.as_str())
        );
        assert_eq!(
            versions
                .pending
                .as_ref()
                .map(|value| value.version_id.as_str()),
            Some(rollback_version.as_str())
        );
    }

    #[tokio::test]
    async fn committed_checkpoint_cleans_stale_pending_after_retirement() {
        let owner = AdminCredentialOwner::platform();
        let store = MemoryAdminCredentialStore::default();
        let rotating = AdminCredentialSet::rotating(
            owner.clone(),
            2,
            record("platform-v1", "old-value-credential", NOW - 10, NOW + 300),
            record("platform-v2", "new-value-credential", NOW, NOW + 600),
            AdminCredentialRotation {
                overlap_starts_at: NOW,
                cutover_at: NOW + 50,
                retire_current_at: NOW + 100,
            },
        );
        store.put_set(PLATFORM_REF, &rotating, NOW);
        let mut rollback = AdminCredentialSet::single(
            owner.clone(),
            record("platform-v1", "old-value-credential", NOW - 10, NOW + 300),
        );
        rollback.revision = 3;
        rollback
            .retired
            .push(retired("platform-v2", "new-value-credential", NOW + 50));
        store.put_set(PLATFORM_REF, &rollback, NOW + 50);
        let (rollback_version, validated_version) = {
            let documents = store.documents.read().unwrap();
            let versions = documents.get(PLATFORM_REF).unwrap();
            (
                versions.current.version_id.clone(),
                versions
                    .validated
                    .as_ref()
                    .expect("validated rotation")
                    .version_id
                    .clone(),
            )
        };
        store.mark_pending(PLATFORM_REF, &rollback_version).unwrap();
        store
            .mark_validated(PLATFORM_REF, &rollback_version, Some(&validated_version))
            .unwrap();

        let cold = AdminCredentialResolver::memory(
            Some(PLATFORM_REF.to_string()),
            HashMap::new(),
            store.clone(),
            Duration::ZERO,
        );
        assert!(cold
            .verify(&owner, "old-value-credential", NOW + 101)
            .await
            .unwrap()
            .is_some());

        let documents = store.documents.read().unwrap();
        let versions = documents.get(PLATFORM_REF).unwrap();
        assert_eq!(
            versions
                .validated
                .as_ref()
                .map(|value| value.version_id.as_str()),
            Some(rollback_version.as_str())
        );
        assert!(versions.pending.is_none());
    }

    #[tokio::test]
    async fn active_record_times_and_current_slot_are_immutable() {
        let owner = AdminCredentialOwner::platform();
        let original = AdminCredentialSet::single(
            owner.clone(),
            record("platform-v1", "stable-admin-secret", NOW, NOW + 300),
        );
        let store = MemoryAdminCredentialStore::default();
        store.put_set(PLATFORM_REF, &original, NOW);
        let resolver = AdminCredentialResolver::memory(
            Some(PLATFORM_REF.to_string()),
            HashMap::new(),
            store.clone(),
            Duration::ZERO,
        );
        assert!(resolver
            .verify(&owner, "stable-admin-secret", NOW)
            .await
            .unwrap()
            .is_some());

        let mut extended = AdminCredentialSet::single(
            owner.clone(),
            AdminCredentialRecord::explicit(
                "platform-v1",
                "stable-admin-secret",
                NOW,
                NOW,
                NOW + 600,
            ),
        );
        extended.revision = 2;
        store.put_set(PLATFORM_REF, &extended, NOW + 1);
        assert!(matches!(
            resolver
                .verify(&owner, "stable-admin-secret", NOW + 1)
                .await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));

        let store = MemoryAdminCredentialStore::default();
        store.put_set(PLATFORM_REF, &original, NOW);
        let moved_to_next = AdminCredentialSet::rotating(
            owner.clone(),
            2,
            record("platform-v2", "replacement-admin-secret", NOW, NOW + 300),
            record("platform-v1", "stable-admin-secret", NOW, NOW + 300),
            AdminCredentialRotation {
                overlap_starts_at: NOW,
                cutover_at: NOW + 100,
                retire_current_at: NOW + 200,
            },
        );
        store.put_set(PLATFORM_REF, &moved_to_next, NOW + 1);
        let cold = AdminCredentialResolver::memory(
            Some(PLATFORM_REF.to_string()),
            HashMap::new(),
            store,
            Duration::ZERO,
        );
        assert!(matches!(
            cold.verify(&owner, "stable-admin-secret", NOW + 1).await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));

        let store = MemoryAdminCredentialStore::default();
        let rotating = AdminCredentialSet::rotating(
            owner.clone(),
            2,
            record("platform-v1", "stable-admin-secret", NOW, NOW + 300),
            record("platform-v2", "replacement-admin-secret", NOW, NOW + 600),
            AdminCredentialRotation {
                overlap_starts_at: NOW,
                cutover_at: NOW + 100,
                retire_current_at: NOW + 200,
            },
        );
        store.put_set(PLATFORM_REF, &rotating, NOW);
        let resolver = AdminCredentialResolver::memory(
            Some(PLATFORM_REF.to_string()),
            HashMap::new(),
            store.clone(),
            Duration::ZERO,
        );
        assert!(resolver
            .verify(&owner, "stable-admin-secret", NOW)
            .await
            .unwrap()
            .is_some());
        let mut extended_rotation = rotating;
        extended_rotation.revision = 3;
        extended_rotation
            .rotation
            .as_mut()
            .expect("rotating set")
            .retire_current_at = NOW + 250;
        store.put_set(PLATFORM_REF, &extended_rotation, NOW + 1);
        assert!(matches!(
            resolver
                .verify(&owner, "stable-admin-secret", NOW + 1)
                .await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));
    }

    #[tokio::test]
    async fn future_retirement_and_short_secrets_fail_closed() {
        let owner = AdminCredentialOwner::platform();
        let mut future_retirement = AdminCredentialSet::single(
            owner.clone(),
            record("platform-v2", "current-admin-secret", NOW, NOW + 300),
        );
        future_retirement.revision = 2;
        future_retirement
            .retired
            .push(retired("platform-v1", "retired-admin-secret", NOW + 1));
        let future_resolver = resolver(future_retirement, vec![]);
        assert!(matches!(
            future_resolver
                .verify(&owner, "current-admin-secret", NOW + 1)
                .await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));

        let short = AdminCredentialSet::single(
            owner.clone(),
            record("platform-v1", "too-short", NOW, NOW + 300),
        );
        let resolver = resolver(short, vec![]);
        assert!(matches!(
            resolver.verify(&owner, "too-short", NOW).await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));
    }

    #[tokio::test]
    async fn cold_runtime_rejects_lower_or_changed_equal_revision() {
        let store = MemoryAdminCredentialStore::default();
        let v1 = AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            record("platform-v1", "old-value-credential", NOW, NOW + 300),
        );
        store.put_set(PLATFORM_REF, &v1, NOW);
        let mut v2 = AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            record("platform-v2", "new-value-credential", NOW, NOW + 300),
        );
        v2.revision = 2;
        v2.retired
            .push(retired("platform-v1", "old-value-credential", NOW + 1));
        store.put_set(PLATFORM_REF, &v2, NOW + 1);

        store.put_set(PLATFORM_REF, &v1, NOW + 2);
        let cold = AdminCredentialResolver::memory(
            Some(PLATFORM_REF.to_string()),
            HashMap::new(),
            store.clone(),
            Duration::ZERO,
        );
        assert!(matches!(
            cold.verify(
                &AdminCredentialOwner::platform(),
                "old-value-credential",
                NOW + 2
            )
            .await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));

        let mut changed_v1 = v1;
        changed_v1.current.secret = "changed-at-same-revision".to_string();
        store.put_set(PLATFORM_REF, &changed_v1, NOW + 3);
        let cold = AdminCredentialResolver::memory(
            Some(PLATFORM_REF.to_string()),
            HashMap::new(),
            store,
            Duration::ZERO,
        );
        assert!(matches!(
            cold.verify(
                &AdminCredentialOwner::platform(),
                "changed-at-same-revision",
                NOW + 3
            )
            .await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));
    }

    #[tokio::test]
    async fn retired_value_cannot_return_at_a_higher_revision() {
        let store = MemoryAdminCredentialStore::default();
        let mut v2 = AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            record("platform-v2", "new-value-credential", NOW, NOW + 300),
        );
        v2.revision = 2;
        v2.retired
            .push(retired("platform-v1", "old-value-credential", NOW - 1));
        store.put_set(PLATFORM_REF, &v2, NOW);

        let mut resurrected = AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            record("platform-v1", "old-value-credential", NOW, NOW + 300),
        );
        resurrected.revision = 3;
        resurrected.retired = v2.retired;
        store.put_set(PLATFORM_REF, &resurrected, NOW + 1);
        let cold = AdminCredentialResolver::memory(
            Some(PLATFORM_REF.to_string()),
            HashMap::new(),
            store,
            Duration::ZERO,
        );
        assert!(matches!(
            cold.verify(
                &AdminCredentialOwner::platform(),
                "old-value-credential",
                NOW + 1
            )
            .await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));
    }

    #[tokio::test]
    async fn credential_ids_cannot_equal_any_secret_value() {
        let platform = AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            record(
                "platform-secret-value",
                "platform-secret-value",
                NOW,
                NOW + 100,
            ),
        );
        let platform_resolver = resolver(platform, vec![]);
        assert!(matches!(
            platform_resolver
                .verify(
                    &AdminCredentialOwner::platform(),
                    "platform-secret-value",
                    NOW
                )
                .await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));

        let platform = AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            record(
                "tenant-secret-value",
                "platform-secret-value",
                NOW,
                NOW + 100,
            ),
        );
        let tenant = AdminCredentialSet::single(
            AdminCredentialOwner::tenant("t1"),
            record("tenant-v1", "tenant-secret-value", NOW, NOW + 100),
        );
        let tenant_resolver = resolver(platform, vec![("t1", T1_REF, tenant)]);
        assert!(matches!(
            tenant_resolver
                .verify(
                    &AdminCredentialOwner::tenant("t1"),
                    "tenant-secret-value",
                    NOW
                )
                .await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));

        let mut retired_leak = AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            record("platform-v2", "platform-new-secret", NOW, NOW + 100),
        );
        retired_leak.revision = 2;
        retired_leak.retired.push(retired(
            "retired-secret-value",
            "retired-secret-value",
            NOW - 1,
        ));
        let retired_resolver = resolver(retired_leak, vec![]);
        assert!(matches!(
            retired_resolver
                .verify(
                    &AdminCredentialOwner::platform(),
                    "platform-new-secret",
                    NOW
                )
                .await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));
    }

    #[test]
    fn legacy_migration_starts_lifetime_at_migration_time() {
        let prepared = prepare_legacy_admin_credential_document(
            &AdminCredentialOwner::platform(),
            "platform-bootstrap-v1",
            "legacy-admin-secret",
            NOW,
        )
        .unwrap();
        assert_eq!(prepared.normalized.current.not_before, NOW);
        assert_eq!(
            prepared.normalized.current.expires_at,
            NOW + 90 * 24 * 60 * 60
        );

        let migrated: AdminCredentialSet = serde_json::from_str(&prepared.serialized).unwrap();
        assert_eq!(migrated.current.created_at, None);
        assert_eq!(migrated.current.not_before, None);
        assert_eq!(migrated.current.expires_at, None);
        assert_eq!(migrated.current.ttl_seconds, Some(90 * 24 * 60 * 60));
    }

    #[test]
    fn source_to_target_migration_is_copy_only_and_idempotent() {
        let source = secret_document(
            "legacy-admin-secret",
            NOW - 10 * 365 * 24 * 60 * 60,
            "source-v1",
        );
        let placeholder = secret_document(
            "generated-target-placeholder",
            NOW - 180 * 24 * 60 * 60,
            "target-placeholder",
        );
        let (prepared, needs_write, needs_validation) = prepare_admin_credential_target(
            &AdminCredentialOwner::platform(),
            "platform-bootstrap-v1",
            &source,
            &placeholder,
            None,
            None,
            NOW,
        )
        .unwrap();
        assert!(needs_write);
        assert!(needs_validation);
        assert_eq!(source.secret_string, "legacy-admin-secret");
        let first_serialized = prepared.serialized.clone();
        let (concurrent_retry, needs_write, needs_validation) = prepare_admin_credential_target(
            &AdminCredentialOwner::platform(),
            "platform-bootstrap-v1",
            &source,
            &placeholder,
            None,
            None,
            NOW + 30,
        )
        .unwrap();
        assert!(needs_write);
        assert!(needs_validation);
        assert_eq!(concurrent_retry.serialized, first_serialized);

        let target = secret_document(prepared.serialized, NOW, "target-v1");
        let (interrupted, needs_write, needs_validation) = prepare_admin_credential_target(
            &AdminCredentialOwner::platform(),
            "platform-bootstrap-v1",
            &source,
            &target,
            Some(&placeholder),
            None,
            NOW + 1,
        )
        .unwrap();
        assert!(!needs_write);
        assert!(needs_validation);
        assert_eq!(interrupted.serialized, first_serialized);

        let (prepared, needs_write, needs_validation) = prepare_admin_credential_target(
            &AdminCredentialOwner::platform(),
            "platform-bootstrap-v1",
            &source,
            &target,
            Some(&placeholder),
            Some(&target),
            NOW + 1,
        )
        .unwrap();
        assert!(!needs_write);
        assert!(!needs_validation);
        assert_eq!(prepared.normalized.current.secret, "legacy-admin-secret");
        assert_eq!(prepared.serialized, first_serialized);
        assert_eq!(
            admin_migration_request_token("arn:target", placeholder.version_created_at),
            admin_migration_request_token("arn:target", placeholder.version_created_at)
        );
        assert_ne!(
            admin_migration_request_token("arn:target", placeholder.version_created_at),
            admin_migration_request_token("arn:target", placeholder.version_created_at + 1)
        );
    }

    #[test]
    fn legacy_source_is_always_wrapped_as_an_opaque_bearer() {
        let json_bearer = serde_json::to_string(&AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            record("nested-v1", "nested-admin-secret", NOW, NOW + 300),
        ))
        .unwrap();
        let source = secret_document(&json_bearer, NOW - 100, "source-v1");
        let target = secret_document("generated-placeholder", NOW, "target-placeholder");

        let (prepared, needs_write, needs_validation) = prepare_admin_credential_target(
            &AdminCredentialOwner::platform(),
            "platform-bootstrap-v1",
            &source,
            &target,
            None,
            None,
            NOW + 10,
        )
        .unwrap();

        assert!(needs_write);
        assert!(needs_validation);
        assert_eq!(prepared.normalized.current.secret, json_bearer);
        let migrated: AdminCredentialSet = serde_json::from_str(&prepared.serialized).unwrap();
        assert_eq!(migrated.current.secret, source.secret_string);
    }

    #[test]
    fn migrated_target_cannot_be_reset_to_a_raw_value() {
        let source = secret_document("legacy-admin-secret", NOW - 100, "source-v1");
        let target = secret_document("raw-reset", NOW + 1, "target-v2");
        let previous = secret_document(
            serde_json::to_string(&AdminCredentialSet::single(
                AdminCredentialOwner::platform(),
                record("platform-v1", "legacy-admin-secret", NOW, NOW + 300),
            ))
            .unwrap(),
            NOW,
            "target-v1",
        );
        assert!(matches!(
            prepare_admin_credential_target(
                &AdminCredentialOwner::platform(),
                "platform-bootstrap-v1",
                &source,
                &target,
                Some(&previous),
                Some(&previous),
                NOW + 1,
            ),
            Err(AdminCredentialError::InvalidConfiguration)
        ));
    }

    #[test]
    fn migration_rejects_target_revision_rollback() {
        let source = secret_document("legacy-admin-secret", NOW - 100, "source-v1");
        let mut v2 = AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            record("platform-v2", "new-admin-secret", NOW, NOW + 300),
        );
        v2.revision = 2;
        v2.retired
            .push(retired("platform-v1", "legacy-admin-secret", NOW));
        let current = AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            record("platform-v1", "legacy-admin-secret", NOW, NOW + 300),
        );
        let target = secret_document(
            serde_json::to_string(&current).unwrap(),
            NOW + 1,
            "target-v1",
        );
        let previous = secret_document(serde_json::to_string(&v2).unwrap(), NOW, "target-v2");
        assert!(matches!(
            prepare_admin_credential_target(
                &AdminCredentialOwner::platform(),
                "platform-bootstrap-v1",
                &source,
                &target,
                Some(&previous),
                Some(&previous),
                NOW + 1,
            ),
            Err(AdminCredentialError::InvalidConfiguration)
        ));
    }

    #[test]
    fn migration_rejects_precreated_rollback_after_retirement() {
        let source = secret_document("legacy-admin-secret", NOW - 100, "source-v1");
        let rotating = AdminCredentialSet::rotating(
            AdminCredentialOwner::platform(),
            2,
            record("platform-v1", "old-value-credential", NOW - 10, NOW + 300),
            record("platform-v2", "new-value-credential", NOW, NOW + 600),
            AdminCredentialRotation {
                overlap_starts_at: NOW,
                cutover_at: NOW + 100,
                retire_current_at: NOW + 200,
            },
        );
        let mut rollback = AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            record("platform-v1", "old-value-credential", NOW - 10, NOW + 300),
        );
        rollback.revision = 3;
        rollback
            .retired
            .push(retired("platform-v2", "new-value-credential", NOW + 50));

        let target = secret_document(
            serde_json::to_string(&rollback).unwrap(),
            NOW + 50,
            "target-v3",
        );
        let validated =
            secret_document(serde_json::to_string(&rotating).unwrap(), NOW, "target-v2");
        assert!(matches!(
            prepare_admin_credential_target(
                &AdminCredentialOwner::platform(),
                "platform-bootstrap-v1",
                &source,
                &target,
                Some(&validated),
                Some(&validated),
                NOW + 250,
            ),
            Err(AdminCredentialError::InvalidConfiguration)
        ));
    }

    #[tokio::test]
    async fn retired_values_cannot_move_to_another_owner() {
        let mut platform = AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            record("platform-v2", "platform-new-secret", NOW, NOW + 300),
        );
        platform.revision = 2;
        platform
            .retired
            .push(retired("platform-v1", "retired-admin-value", NOW - 1));
        let tenant = AdminCredentialSet::single(
            AdminCredentialOwner::tenant("t1"),
            record("t1-v1", "retired-admin-value", NOW, NOW + 300),
        );
        let resolver = resolver(platform, vec![("t1", T1_REF, tenant)]);

        assert!(matches!(
            resolver
                .verify(
                    &AdminCredentialOwner::tenant("t1"),
                    "retired-admin-value",
                    NOW
                )
                .await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));
    }

    #[tokio::test]
    async fn validated_stage_blocks_resurrection_across_multiple_invalid_versions() {
        let store = MemoryAdminCredentialStore::default();
        let mut trusted = AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            record("platform-v2", "trusted-current-secret", NOW, NOW + 500),
        );
        trusted.revision = 2;
        trusted
            .retired
            .push(retired("platform-v1", "retired-admin-value", NOW - 1));
        store.put_set(PLATFORM_REF, &trusted, NOW);
        let resolver = AdminCredentialResolver::memory(
            Some(PLATFORM_REF.to_string()),
            HashMap::new(),
            store.clone(),
            Duration::ZERO,
        );
        assert!(resolver
            .verify(
                &AdminCredentialOwner::platform(),
                "trusted-current-secret",
                NOW
            )
            .await
            .unwrap()
            .is_some());

        let mut invalid_v3 = AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            record("platform-v3", "invalid-intermediate", NOW, NOW + 500),
        );
        invalid_v3.revision = 3;
        store.put_set(PLATFORM_REF, &invalid_v3, NOW + 1);
        assert!(matches!(
            resolver
                .verify(
                    &AdminCredentialOwner::platform(),
                    "invalid-intermediate",
                    NOW + 1
                )
                .await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));

        let mut invalid_v4 = AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            record("platform-v1", "retired-admin-value", NOW, NOW + 500),
        );
        invalid_v4.revision = 4;
        store.put_set(PLATFORM_REF, &invalid_v4, NOW + 2);
        let cold = AdminCredentialResolver::memory(
            Some(PLATFORM_REF.to_string()),
            HashMap::new(),
            store,
            Duration::ZERO,
        );
        assert!(matches!(
            cold.verify(
                &AdminCredentialOwner::platform(),
                "retired-admin-value",
                NOW + 2
            )
            .await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));
    }

    #[tokio::test]
    async fn missing_validated_stage_fails_closed_even_for_revision_one() {
        let store = MemoryAdminCredentialStore::default();
        store.put_set(
            PLATFORM_REF,
            &AdminCredentialSet::single(
                AdminCredentialOwner::platform(),
                record("platform-v1", "bootstrap-admin-value", NOW, NOW + 500),
            ),
            NOW,
        );
        store
            .documents
            .write()
            .unwrap()
            .get_mut(PLATFORM_REF)
            .unwrap()
            .validated = None;
        let resolver = AdminCredentialResolver::memory(
            Some(PLATFORM_REF.to_string()),
            HashMap::new(),
            store,
            Duration::ZERO,
        );

        assert!(matches!(
            resolver
                .verify(
                    &AdminCredentialOwner::platform(),
                    "bootstrap-admin-value",
                    NOW
                )
                .await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));
    }

    #[test]
    fn credential_ids_cannot_equal_retired_secrets_in_any_iteration_order() {
        let mut platform = AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            record("platform-v2", "platform-new-secret", NOW, NOW + 300),
        );
        platform.revision = 2;
        platform
            .retired
            .push(retired("platform-v1", "retired-admin-value", NOW - 1));
        let tenant = AdminCredentialSet::single(
            AdminCredentialOwner::tenant("t1"),
            record("retired-admin-value", "tenant-new-secret", NOW, NOW + 300),
        );
        let platform = normalize_set(platform, NOW, &AdminCredentialOwner::platform()).unwrap();
        let tenant = normalize_set(tenant, NOW, &AdminCredentialOwner::tenant("t1")).unwrap();

        assert!(matches!(
            validate_registry_uniqueness([&platform, &tenant]),
            Err(AdminCredentialError::InvalidConfiguration)
        ));
        assert!(matches!(
            validate_registry_uniqueness([&tenant, &platform]),
            Err(AdminCredentialError::InvalidConfiguration)
        ));
    }
}
