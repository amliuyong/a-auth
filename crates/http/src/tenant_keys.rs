//! Runtime tenant-key registry and immutable signer resolution.
//!
//! SaaS requests resolve one complete EC/RSA snapshot from the authoritative
//! registry. Self-hosted deployments keep the existing stack-scoped signer.

use std::{collections::HashMap, future::Future, sync::Arc};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use agent_auth_infra_core::{TenantKeyRecord, TenantKeySnapshot};
use axum::{http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{adapters::memory::MemorySigner, ports::StoreError, state::SignerImpl};

pub trait TenantKeyRegistry: Send + Sync {
    fn get(
        &self,
        tenant_id: &str,
    ) -> impl Future<Output = Result<Option<TenantKeyRecord>, StoreError>> + Send;

    fn create(
        &self,
        record: TenantKeyRecord,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    fn compare_and_swap(
        &self,
        expected_revision: u64,
        record: TenantKeyRecord,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
}

#[derive(Clone, Default)]
pub struct MemoryTenantKeyRegistry {
    records: Arc<Mutex<HashMap<String, TenantKeyRecord>>>,
    #[cfg(test)]
    compare_and_swap_failures: Arc<AtomicUsize>,
}

#[cfg(test)]
impl MemoryTenantKeyRegistry {
    pub(crate) fn fail_next_compare_and_swaps(&self, count: usize) {
        self.compare_and_swap_failures
            .store(count, Ordering::SeqCst);
    }
}

impl TenantKeyRegistry for MemoryTenantKeyRegistry {
    async fn get(&self, tenant_id: &str) -> Result<Option<TenantKeyRecord>, StoreError> {
        Ok(self.records.lock().await.get(tenant_id).cloned())
    }

    async fn create(&self, record: TenantKeyRecord) -> Result<bool, StoreError> {
        let mut records = self.records.lock().await;
        if records.contains_key(&record.tenant_id) {
            return Ok(false);
        }
        records.insert(record.tenant_id.clone(), record);
        Ok(true)
    }

    async fn compare_and_swap(
        &self,
        expected_revision: u64,
        record: TenantKeyRecord,
    ) -> Result<bool, StoreError> {
        #[cfg(test)]
        if self
            .compare_and_swap_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Ok(false);
        }
        let mut records = self.records.lock().await;
        let Some(current) = records.get(&record.tenant_id) else {
            return Ok(false);
        };
        if current.revision != expected_revision {
            return Ok(false);
        }
        records.insert(record.tenant_id.clone(), record);
        Ok(true)
    }
}

#[derive(Clone)]
pub enum TenantKeyRegistryImpl {
    Memory(MemoryTenantKeyRegistry),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoTenantKeyRegistry),
}

impl TenantKeyRegistry for TenantKeyRegistryImpl {
    async fn get(&self, tenant_id: &str) -> Result<Option<TenantKeyRecord>, StoreError> {
        match self {
            Self::Memory(registry) => registry.get(tenant_id).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(registry) => registry.get(tenant_id).await,
        }
    }

    async fn create(&self, record: TenantKeyRecord) -> Result<bool, StoreError> {
        match self {
            Self::Memory(registry) => registry.create(record).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(registry) => registry.create(record).await,
        }
    }

    async fn compare_and_swap(
        &self,
        expected_revision: u64,
        record: TenantKeyRecord,
    ) -> Result<bool, StoreError> {
        match self {
            Self::Memory(registry) => registry.compare_and_swap(expected_revision, record).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(registry) => registry.compare_and_swap(expected_revision, record).await,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantKeyCommandAction {
    Ensure,
    Rotate,
    Activate,
    Rollback,
    Retire,
    EmergencyRevoke,
    Offboard,
    Reconcile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantKeyGovernanceDispatchPermit {
    pub job_id: String,
    pub tenant_revision: u64,
    pub action_id: String,
    pub action_revision: u64,
    pub claim_token_digest: String,
    pub claim_deadline: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantKeyCommand {
    pub tenant_id: String,
    pub action: TenantKeyCommandAction,
    pub operation_id: String,
    pub requested_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_dispatch: Option<TenantKeyGovernanceDispatchPermit>,
}

pub trait TenantKeyCommandSink: Send + Sync {
    fn send(
        &self,
        command: TenantKeyCommand,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

#[derive(Clone, Default)]
pub struct MemoryTenantKeyCommandSink {
    commands: Arc<Mutex<Vec<TenantKeyCommand>>>,
}

impl MemoryTenantKeyCommandSink {
    pub async fn commands(&self) -> Vec<TenantKeyCommand> {
        self.commands.lock().await.clone()
    }
}

impl TenantKeyCommandSink for MemoryTenantKeyCommandSink {
    async fn send(&self, command: TenantKeyCommand) -> Result<(), StoreError> {
        self.commands.lock().await.push(command);
        Ok(())
    }
}

#[derive(Clone)]
pub enum TenantKeyCommandSinkImpl {
    Memory(MemoryTenantKeyCommandSink),
    Disabled,
    #[cfg(feature = "aws")]
    Sqs(crate::adapters::aws::SqsTenantKeyCommandSink),
}

impl TenantKeyCommandSink for TenantKeyCommandSinkImpl {
    async fn send(&self, command: TenantKeyCommand) -> Result<(), StoreError> {
        match self {
            Self::Memory(sink) => sink.send(command).await,
            Self::Disabled => Err(StoreError::Transient(
                "tenant key lifecycle commands are disabled in this runtime".to_string(),
            )),
            #[cfg(feature = "aws")]
            Self::Sqs(sink) => sink.send(command).await,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantSignerResolveError {
    UnknownTenant,
    NotReady,
    RegistryUnavailable,
    InvalidSnapshot,
    SigningBackendUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantKeyOffboardingStatus {
    NotTenantManaged,
    NotStarted,
    Dispatched,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantKeyDeletionVerification {
    Complete,
    PendingUntil(i64),
    Incomplete,
}

#[derive(Clone)]
enum TenantSigningBackend {
    Shared(Arc<SignerImpl>),
    Memory {
        signers: Arc<Mutex<HashMap<String, MemorySigner>>>,
    },
    #[cfg(feature = "aws")]
    Kms(aws_sdk_kms::Client),
}

#[derive(Clone)]
pub struct TenantKeyService {
    registry: Arc<TenantKeyRegistryImpl>,
    command_sink: Arc<TenantKeyCommandSinkImpl>,
    backend: TenantSigningBackend,
    region: crate::region::RegionRuntime,
}

impl TenantKeyService {
    pub fn shared(signer: Arc<SignerImpl>) -> Self {
        Self {
            registry: Arc::new(TenantKeyRegistryImpl::Memory(
                MemoryTenantKeyRegistry::default(),
            )),
            command_sink: Arc::new(TenantKeyCommandSinkImpl::Memory(
                MemoryTenantKeyCommandSink::default(),
            )),
            backend: TenantSigningBackend::Shared(signer),
            region: crate::region::RegionRuntime::single_region(),
        }
    }

    pub fn memory() -> Self {
        Self {
            registry: Arc::new(TenantKeyRegistryImpl::Memory(
                MemoryTenantKeyRegistry::default(),
            )),
            command_sink: Arc::new(TenantKeyCommandSinkImpl::Memory(
                MemoryTenantKeyCommandSink::default(),
            )),
            backend: TenantSigningBackend::Memory {
                signers: Arc::new(Mutex::new(HashMap::new())),
            },
            region: crate::region::RegionRuntime::single_region(),
        }
    }

    #[cfg(feature = "aws")]
    pub fn dynamo(
        registry: crate::adapters::aws::DynamoTenantKeyRegistry,
        command_sink: crate::adapters::aws::SqsTenantKeyCommandSink,
        kms: aws_sdk_kms::Client,
    ) -> Self {
        Self {
            registry: Arc::new(TenantKeyRegistryImpl::Dynamo(registry)),
            command_sink: Arc::new(TenantKeyCommandSinkImpl::Sqs(command_sink)),
            backend: TenantSigningBackend::Kms(kms),
            region: crate::region::RegionRuntime::single_region(),
        }
    }

    #[cfg(feature = "aws")]
    pub fn dynamo_readonly(
        registry: crate::adapters::aws::DynamoTenantKeyRegistry,
        kms: aws_sdk_kms::Client,
    ) -> Self {
        Self {
            registry: Arc::new(TenantKeyRegistryImpl::Dynamo(registry)),
            command_sink: Arc::new(TenantKeyCommandSinkImpl::Disabled),
            backend: TenantSigningBackend::Kms(kms),
            region: crate::region::RegionRuntime::single_region(),
        }
    }

    pub fn with_region(mut self, region: crate::region::RegionRuntime) -> Self {
        self.region = region;
        self
    }

    pub fn registry(&self) -> &TenantKeyRegistryImpl {
        &self.registry
    }

    pub fn command_sink(&self) -> &TenantKeyCommandSinkImpl {
        &self.command_sink
    }

    /// Read the durable registry outcome without dispatching another command.
    pub async fn inspect_offboarding(
        &self,
        tenant_id: &str,
        operation_id: &str,
    ) -> Result<TenantKeyOffboardingStatus, StoreError> {
        if matches!(self.backend, TenantSigningBackend::Shared(_)) {
            return Ok(TenantKeyOffboardingStatus::NotTenantManaged);
        }
        let Some(record) = self.registry.get(tenant_id).await? else {
            return Ok(TenantKeyOffboardingStatus::NotStarted);
        };
        match record.lifecycle {
            agent_auth_infra_core::TenantKeyLifecycle::Offboarded => {
                if record.offboarding_operation_id.as_deref() == Some(operation_id) {
                    Ok(TenantKeyOffboardingStatus::Complete)
                } else {
                    Err(StoreError::Permanent(
                        "tenant key registry is offboarded by another operation".into(),
                    ))
                }
            }
            agent_auth_infra_core::TenantKeyLifecycle::Offboarding => {
                if record.offboarding_operation_id.as_deref() == Some(operation_id) {
                    Ok(TenantKeyOffboardingStatus::Dispatched)
                } else {
                    Err(StoreError::Permanent(
                        "tenant key registry is offboarding under another operation".into(),
                    ))
                }
            }
            _ => Ok(TenantKeyOffboardingStatus::NotStarted),
        }
    }

    /// Revoke data-plane signing authority with a registry CAS before
    /// dispatching external KMS cleanup. Repeated calls resume the same
    /// operation and never create a second logical deletion.
    pub async fn begin_offboarding(
        &self,
        tenant_id: &str,
        operation_id: &str,
        now: i64,
        governance_dispatch: TenantKeyGovernanceDispatchPermit,
    ) -> Result<TenantKeyOffboardingStatus, StoreError> {
        if matches!(self.backend, TenantSigningBackend::Shared(_)) {
            return Ok(TenantKeyOffboardingStatus::NotTenantManaged);
        }

        let mut record = match self.registry.get(tenant_id).await? {
            Some(record) => record,
            None => {
                let mut record = TenantKeyRecord::begin_onboarding(tenant_id, operation_id, now)
                    .map_err(|_| {
                        StoreError::Permanent("invalid tenant key offboarding identity".into())
                    })?;
                record.begin_offboarding(operation_id, now).map_err(|_| {
                    StoreError::Permanent("tenant key offboarding transition failed".into())
                })?;
                if !self.registry.create(record.clone()).await? {
                    self.registry.get(tenant_id).await?.ok_or_else(|| {
                        StoreError::Transient(
                            "tenant key offboarding registry create conflicted".into(),
                        )
                    })?
                } else {
                    record
                }
            }
        };

        if record.lifecycle == agent_auth_infra_core::TenantKeyLifecycle::Offboarded {
            return if record.offboarding_operation_id.as_deref() == Some(operation_id) {
                Ok(TenantKeyOffboardingStatus::Complete)
            } else {
                Err(StoreError::Permanent(
                    "tenant key registry is offboarded by another operation".into(),
                ))
            };
        }
        if record.lifecycle != agent_auth_infra_core::TenantKeyLifecycle::Offboarding {
            let expected_revision = record.revision;
            record.begin_offboarding(operation_id, now).map_err(|_| {
                StoreError::Permanent("tenant key offboarding transition failed".into())
            })?;
            if !self
                .registry
                .compare_and_swap(expected_revision, record.clone())
                .await?
            {
                return Err(StoreError::Transient(
                    "tenant key offboarding registry CAS conflicted".into(),
                ));
            }
        } else if record.offboarding_operation_id.as_deref() != Some(operation_id) {
            return Err(StoreError::Permanent(
                "tenant key registry is offboarding under another operation".into(),
            ));
        }

        self.command_sink
            .send(TenantKeyCommand {
                tenant_id: tenant_id.to_string(),
                action: TenantKeyCommandAction::Offboard,
                operation_id: operation_id.to_string(),
                requested_at: now,
                governance_dispatch: Some(governance_dispatch),
            })
            .await?;
        Ok(TenantKeyOffboardingStatus::Dispatched)
    }

    pub async fn verify_offboarding_deletion(
        &self,
        tenant_id: &str,
        operation_id: &str,
    ) -> Result<TenantKeyDeletionVerification, StoreError> {
        if matches!(self.backend, TenantSigningBackend::Shared(_)) {
            return Ok(TenantKeyDeletionVerification::Incomplete);
        }
        let Some(record) = self.registry.get(tenant_id).await? else {
            return Ok(TenantKeyDeletionVerification::Incomplete);
        };
        if record.lifecycle != agent_auth_infra_core::TenantKeyLifecycle::Offboarded
            || record.offboarding_operation_id.as_deref() != Some(operation_id)
            || !record.pending_deletion_arns.is_empty()
        {
            return Ok(TenantKeyDeletionVerification::Incomplete);
        }
        match &self.backend {
            TenantSigningBackend::Memory { .. } => Ok(TenantKeyDeletionVerification::Complete),
            TenantSigningBackend::Shared(_) => Ok(TenantKeyDeletionVerification::Incomplete),
            #[cfg(feature = "aws")]
            TenantSigningBackend::Kms(kms) => {
                use aws_sdk_kms::error::ProvideErrorMetadata;

                let mut pending_until: Option<i64> = None;
                for key_arn in &record.scheduled_deletion_arns {
                    match kms.describe_key().key_id(key_arn).send().await {
                        Ok(output) => {
                            let Some(metadata) = output.key_metadata() else {
                                return Err(StoreError::Permanent(
                                    "KMS DescribeKey returned no metadata".into(),
                                ));
                            };
                            let deletion_at = metadata.deletion_date().map(|date| date.secs());
                            if !matches!(
                                metadata.key_state(),
                                Some(
                                    aws_sdk_kms::types::KeyState::PendingDeletion
                                        | aws_sdk_kms::types::KeyState::PendingReplicaDeletion
                                )
                            ) || deletion_at.is_none()
                            {
                                return Ok(TenantKeyDeletionVerification::Incomplete);
                            }
                            pending_until = Some(
                                pending_until
                                    .unwrap_or_default()
                                    .max(deletion_at.unwrap_or_default()),
                            );
                        }
                        Err(error)
                            if error.code().is_some_and(|code| code.contains("NotFound")) => {}
                        Err(error) => {
                            return Err(StoreError::Transient(format!(
                                "KMS deletion verification failed: {}",
                                error.code().unwrap_or("unknown")
                            )))
                        }
                    }
                }
                Ok(pending_until.map_or(
                    TenantKeyDeletionVerification::Complete,
                    TenantKeyDeletionVerification::PendingUntil,
                ))
            }
        }
    }

    pub async fn install_memory_signer(&self, key_arn: &str, signer: MemorySigner) {
        if let TenantSigningBackend::Memory { signers } = &self.backend {
            signers.lock().await.insert(key_arn.to_string(), signer);
        }
    }

    pub fn resolve<'a>(
        &'a self,
        tenant_id: &'a str,
    ) -> impl Future<Output = Result<Arc<SignerImpl>, TenantSignerResolveError>> + Send + 'a {
        // Self-hosted/shared signing is synchronous. Only construct the boxed
        // registry/KMS resolver when a tenant-managed backend actually needs it.
        let shared = match &self.backend {
            TenantSigningBackend::Shared(signer) => Some(signer.clone()),
            TenantSigningBackend::Memory { .. } => None,
            #[cfg(feature = "aws")]
            TenantSigningBackend::Kms(_) => None,
        };
        async move {
            if let Some(signer) = shared {
                return Ok(signer);
            }
            Box::pin(self.resolve_managed(tenant_id)).await
        }
    }

    async fn resolve_managed(
        &self,
        tenant_id: &str,
    ) -> Result<Arc<SignerImpl>, TenantSignerResolveError> {
        let record = self
            .registry
            .get(tenant_id)
            .await
            .map_err(|_| TenantSignerResolveError::RegistryUnavailable)?
            .ok_or(TenantSignerResolveError::UnknownTenant)?;
        let snapshot = record
            .ready_snapshot()
            .map_err(|_| TenantSignerResolveError::NotReady)?
            .clone();
        self.signer_from_snapshot(snapshot).await
    }

    async fn signer_from_snapshot(
        &self,
        snapshot: TenantKeySnapshot,
    ) -> Result<Arc<SignerImpl>, TenantSignerResolveError> {
        snapshot
            .validate()
            .map_err(|_| TenantSignerResolveError::InvalidSnapshot)?;
        match &self.backend {
            TenantSigningBackend::Shared(signer) => Ok(signer.clone()),
            TenantSigningBackend::Memory { signers } => {
                let signer = signers
                    .lock()
                    .await
                    .get(&snapshot.ec.active.key_arn)
                    .cloned()
                    .ok_or(TenantSignerResolveError::SigningBackendUnavailable)?
                    .with_tenant_snapshot(&snapshot)
                    .map_err(|_| TenantSignerResolveError::InvalidSnapshot)?;
                Ok(Arc::new(SignerImpl::Memory(signer)))
            }
            #[cfg(feature = "aws")]
            TenantSigningBackend::Kms(kms) => {
                let mut snapshot = snapshot;
                for key in &mut snapshot.ec.published {
                    key.key_arn = self
                        .region
                        .local_kms_key_arn(&key.key_arn)
                        .map_err(|_| TenantSignerResolveError::SigningBackendUnavailable)?;
                }
                for key in &mut snapshot.rsa.published {
                    key.key_arn = self
                        .region
                        .local_kms_key_arn(&key.key_arn)
                        .map_err(|_| TenantSignerResolveError::SigningBackendUnavailable)?;
                }
                snapshot.ec.active.key_arn = self
                    .region
                    .local_kms_key_arn(&snapshot.ec.active.key_arn)
                    .map_err(|_| TenantSignerResolveError::SigningBackendUnavailable)?;
                snapshot.rsa.active.key_arn = self
                    .region
                    .local_kms_key_arn(&snapshot.rsa.active.key_arn)
                    .map_err(|_| TenantSignerResolveError::SigningBackendUnavailable)?;
                let signer =
                    crate::adapters::aws::KmsSigner::from_tenant_snapshot(kms.clone(), &snapshot)
                        .map_err(|_| TenantSignerResolveError::InvalidSnapshot)?;
                Ok(Arc::new(SignerImpl::Kms(signer)))
            }
        }
    }
}

pub async fn signer_or_503(
    state: &crate::state::AppState,
    tenant_id: &str,
) -> Result<Arc<SignerImpl>, axum::response::Response> {
    state.tenant_keys.resolve(tenant_id).await.map_err(|error| {
        eprintln!(
            "TENANT_KEY_RESOLUTION_ERROR tenant={} class={error:?}",
            tenant_id
        );
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "error": "temporarily_unavailable",
                "error_description": "Tenant signing keys are unavailable"
            })),
        )
            .into_response()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::Signer;
    use agent_auth_infra_core::{EcPublicJwk, RsaPublicJwk, TenantKeyAlgorithm, TenantKeyRecord};

    async fn ready_record(
        registry: &MemoryTenantKeyRegistry,
        tenant: &str,
        operation: &str,
        signer: &MemorySigner,
    ) -> TenantKeyRecord {
        let mut record = TenantKeyRecord::begin_onboarding(tenant, operation, 1).unwrap();
        let ec = signer.public_jwks().await.unwrap().remove(0);
        let rsa = signer.public_rsa_jwks().await.unwrap().remove(0);
        record
            .record_created_key(
                operation,
                TenantKeyAlgorithm::Es256,
                format!("arn:{tenant}:ec"),
                2,
            )
            .unwrap();
        record
            .record_verified_ec(
                operation,
                EcPublicJwk {
                    x: ec.x,
                    y: ec.y,
                    kid: ec.kid,
                },
                3,
            )
            .unwrap();
        record
            .record_created_key(
                operation,
                TenantKeyAlgorithm::Rs256,
                format!("arn:{tenant}:rsa"),
                4,
            )
            .unwrap();
        record
            .record_verified_rsa(
                operation,
                RsaPublicJwk {
                    n: rsa.n,
                    e: rsa.e,
                    kid: rsa.kid,
                },
                5,
            )
            .unwrap();
        record.publish_candidate(operation, 6).unwrap();
        assert!(registry.create(record.clone()).await.unwrap());
        record
    }

    #[tokio::test]
    async fn memory_resolver_isolates_tenant_keysets() {
        let service = TenantKeyService::memory();
        #[cfg(not(feature = "aws"))]
        let TenantKeyRegistryImpl::Memory(registry) = service.registry();
        #[cfg(feature = "aws")]
        let registry = match service.registry() {
            TenantKeyRegistryImpl::Memory(registry) => registry,
            TenantKeyRegistryImpl::Dynamo(_) => panic!("memory registry"),
        };
        let signer_a = MemorySigner::from_seed([31; 32]);
        let signer_b = MemorySigner::from_seed([32; 32]);
        ready_record(registry, "t1", "op-a", &signer_a).await;
        ready_record(registry, "t2", "op-b", &signer_b).await;
        service.install_memory_signer("arn:t1:ec", signer_a).await;
        service.install_memory_signer("arn:t2:ec", signer_b).await;

        let t1 = service.resolve("t1").await.unwrap();
        let t2 = service.resolve("t2").await.unwrap();
        assert_ne!(
            t1.active_kid().await.unwrap(),
            t2.active_kid().await.unwrap()
        );
        assert_ne!(
            t1.active_rsa_kid().await.unwrap(),
            t2.active_rsa_kid().await.unwrap()
        );
        assert!(matches!(
            service.resolve("unknown").await,
            Err(TenantSignerResolveError::UnknownTenant)
        ));
    }

    #[tokio::test]
    async fn disabled_command_sink_fails_closed() {
        let result = TenantKeyCommandSinkImpl::Disabled
            .send(TenantKeyCommand {
                tenant_id: "t1".to_string(),
                action: TenantKeyCommandAction::Rotate,
                operation_id: "failover-freeze".to_string(),
                requested_at: 1,
                governance_dispatch: None,
            })
            .await;
        assert!(matches!(result, Err(StoreError::Transient(_))));
    }

    #[tokio::test]
    async fn offboarding_disables_resolution_before_dispatch() {
        let service = TenantKeyService::memory();
        #[cfg(not(feature = "aws"))]
        let TenantKeyRegistryImpl::Memory(registry) = service.registry();
        #[cfg(feature = "aws")]
        let registry = match service.registry() {
            TenantKeyRegistryImpl::Memory(registry) => registry,
            TenantKeyRegistryImpl::Dynamo(_) => panic!("memory registry"),
        };
        let signer = MemorySigner::from_seed([33; 32]);
        ready_record(registry, "t1", "onboard-1", &signer).await;
        service.install_memory_signer("arn:t1:ec", signer).await;
        assert!(service.resolve("t1").await.is_ok());

        assert_eq!(
            service
                .begin_offboarding(
                    "t1",
                    "offboard-1",
                    100,
                    TenantKeyGovernanceDispatchPermit {
                        job_id: "job-1".into(),
                        tenant_revision: 1,
                        action_id: "action-1".into(),
                        action_revision: 2,
                        claim_token_digest: "claim-1".into(),
                        claim_deadline: 200,
                    },
                )
                .await
                .unwrap(),
            TenantKeyOffboardingStatus::Dispatched
        );
        assert!(matches!(
            service.resolve("t1").await,
            Err(TenantSignerResolveError::NotReady)
        ));
        let record = registry.get("t1").await.unwrap().unwrap();
        assert_eq!(
            record.lifecycle,
            agent_auth_infra_core::TenantKeyLifecycle::Offboarding
        );

        #[cfg(not(feature = "aws"))]
        let TenantKeyCommandSinkImpl::Memory(sink) = service.command_sink() else {
            panic!("memory sink")
        };
        #[cfg(feature = "aws")]
        let sink = match service.command_sink() {
            TenantKeyCommandSinkImpl::Memory(sink) => sink,
            TenantKeyCommandSinkImpl::Disabled | TenantKeyCommandSinkImpl::Sqs(_) => {
                panic!("memory sink")
            }
        };
        let commands = sink.commands().await;
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].action, TenantKeyCommandAction::Offboard);
        assert_eq!(
            commands[0].governance_dispatch,
            Some(TenantKeyGovernanceDispatchPermit {
                job_id: "job-1".into(),
                tenant_revision: 1,
                action_id: "action-1".into(),
                action_revision: 2,
                claim_token_digest: "claim-1".into(),
                claim_deadline: 200,
            })
        );
    }
}
