//! Idempotent tenant EC/RSA provisioning orchestration.
//!
//! External key creation is recorded by CAS before probing. A complete
//! generation is published only after both algorithms pass GetPublicKey,
//! signature, and local verification through the backend contract.

use std::future::Future;

use agent_auth_infra_core::{
    EcPublicJwk, RsaPublicJwk, TenantKeyAlgorithm, TenantKeyCompletionOutcome, TenantKeyLifecycle,
    TenantKeyRecord, TenantKeyStateError, DEFAULT_CLOCK_SKEW_SECS,
};

use crate::{
    ports::StoreError,
    tenant_keys::{
        TenantKeyCommand, TenantKeyCommandAction, TenantKeyRegistry, TenantKeyRegistryImpl,
    },
};

pub const PUBLISH_AHEAD_SECS: i64 = 600;
pub const PUBLISHING_TIMEOUT_SECS: i64 = 3_600;
pub const TOKEN_OVERLAP_SECS: i64 = crate::ssf::SSF_MAX_RETRY_AGE_SECS + DEFAULT_CLOCK_SKEW_SECS;
pub const KMS_READINESS_PROPAGATION_SECS: i64 = 300;

fn kms_readiness_is_pending(created_at: i64, now: i64) -> bool {
    now.checked_sub(created_at)
        .is_some_and(|age| (0..KMS_READINESS_PROPAGATION_SECS).contains(&age))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisioningBackendError {
    Transient(String),
    ReadinessPending(String),
    ReplicaReadinessPending(String),
    Permanent(String),
    DuplicateKeys {
        message: String,
        key_arns: Vec<String>,
    },
}

pub trait TenantKeyProvisioningBackend: Send + Sync {
    fn find_managed_keys(
        &self,
        tenant_id: &str,
    ) -> impl Future<Output = Result<Vec<String>, ProvisioningBackendError>> + Send;

    fn find_created_keys(
        &self,
        tenant_id: &str,
        operation_id: &str,
        generation: u64,
        algorithm: TenantKeyAlgorithm,
    ) -> impl Future<Output = Result<Vec<String>, ProvisioningBackendError>> + Send;

    fn create_key(
        &self,
        tenant_id: &str,
        operation_id: &str,
        generation: u64,
        algorithm: TenantKeyAlgorithm,
    ) -> impl Future<Output = Result<String, ProvisioningBackendError>> + Send;

    /// Implementations return only after a real signature over a fixed
    /// challenge has been verified locally with this public key.
    fn probe_ec(
        &self,
        key_arn: &str,
    ) -> impl Future<Output = Result<EcPublicJwk, ProvisioningBackendError>> + Send;

    fn probe_rsa(
        &self,
        key_arn: &str,
    ) -> impl Future<Output = Result<RsaPublicJwk, ProvisioningBackendError>> + Send;

    fn schedule_deletion(
        &self,
        key_arn: &str,
    ) -> impl Future<Output = Result<(), ProvisioningBackendError>> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisioningError {
    Busy,
    InvalidState,
    Registry(StoreError),
    BackendTransient(String),
    BackendPermanent(String),
}

impl From<StoreError> for ProvisioningError {
    fn from(error: StoreError) -> Self {
        Self::Registry(error)
    }
}

impl From<TenantKeyStateError> for ProvisioningError {
    fn from(_: TenantKeyStateError) -> Self {
        Self::InvalidState
    }
}

pub async fn execute_command<B: TenantKeyProvisioningBackend>(
    registry: &TenantKeyRegistryImpl,
    backend: &B,
    command: &TenantKeyCommand,
    now: i64,
) -> Result<Option<TenantKeyRecord>, ProvisioningError> {
    let publish_now = crate::current_unix_secs;
    let record = match command.action {
        TenantKeyCommandAction::Ensure => Some(
            ensure_tenant_with_publish_clock(
                registry,
                backend,
                &command.tenant_id,
                &command.operation_id,
                now,
                &publish_now,
            )
            .await?,
        ),
        TenantKeyCommandAction::Rotate => Some(
            rotate_tenant_with_publish_clock(
                registry,
                backend,
                &command.tenant_id,
                &command.operation_id,
                now,
                &publish_now,
            )
            .await?,
        ),
        TenantKeyCommandAction::Activate => {
            Some(activate_tenant(registry, &command.tenant_id, &command.operation_id, now).await?)
        }
        TenantKeyCommandAction::Rollback => Some(
            rollback_tenant(
                registry,
                backend,
                &command.tenant_id,
                &command.operation_id,
                now,
            )
            .await?,
        ),
        TenantKeyCommandAction::Retire => Some(
            retire_tenant(
                registry,
                backend,
                &command.tenant_id,
                &command.operation_id,
                now,
            )
            .await?,
        ),
        TenantKeyCommandAction::EmergencyRevoke => Some(
            emergency_revoke_tenant(
                registry,
                backend,
                &command.tenant_id,
                &command.operation_id,
                now,
            )
            .await?,
        ),
        TenantKeyCommandAction::Offboard => Some(
            offboard_tenant(
                registry,
                backend,
                &command.tenant_id,
                &command.operation_id,
                now,
            )
            .await?,
        ),
        TenantKeyCommandAction::Reconcile => {
            let current = registry.get(&command.tenant_id).await?;
            if current
                .as_ref()
                .is_some_and(|record| record.lifecycle == TenantKeyLifecycle::Offboarding)
            {
                // A scheduled reconciliation command has no governance claim
                // and therefore may not resume irreversible offboarding.
                current
            } else if current
                .as_ref()
                .is_some_and(|record| record.lifecycle == TenantKeyLifecycle::Offboarded)
            {
                current
            } else if current.is_none() {
                Some(
                    ensure_tenant_with_publish_clock(
                        registry,
                        backend,
                        &command.tenant_id,
                        &command.operation_id,
                        now,
                        &publish_now,
                    )
                    .await?,
                )
            } else {
                reconcile_tenant_with_publish_clock(
                    registry,
                    backend,
                    &command.tenant_id,
                    now,
                    &publish_now,
                )
                .await?
            }
        }
    };
    Ok(record)
}

pub async fn offboard_tenant<B: TenantKeyProvisioningBackend>(
    registry: &TenantKeyRegistryImpl,
    backend: &B,
    tenant_id: &str,
    operation_id: &str,
    now: i64,
) -> Result<TenantKeyRecord, ProvisioningError> {
    let mut record = match registry.get(tenant_id).await? {
        Some(record) => record,
        None => {
            let mut record = TenantKeyRecord::begin_onboarding(tenant_id, operation_id, now)?;
            record.begin_offboarding(operation_id, now)?;
            if registry.create(record.clone()).await? {
                record
            } else {
                registry
                    .get(tenant_id)
                    .await?
                    .ok_or(ProvisioningError::Busy)?
            }
        }
    };

    if record.lifecycle == TenantKeyLifecycle::Offboarded {
        return if record.offboarding_operation_id.as_deref() == Some(operation_id) {
            Ok(record)
        } else {
            Err(ProvisioningError::InvalidState)
        };
    }
    if record.lifecycle != TenantKeyLifecycle::Offboarding {
        let expected = record.revision;
        record.begin_offboarding(operation_id, now)?;
        if !registry.compare_and_swap(expected, record.clone()).await? {
            return Err(ProvisioningError::Busy);
        }
    } else if record.offboarding_operation_id.as_deref() != Some(operation_id) {
        return Err(ProvisioningError::InvalidState);
    }

    let discovered = match backend.find_managed_keys(tenant_id).await {
        Ok(keys) => keys,
        Err(ProvisioningBackendError::Transient(message))
        | Err(ProvisioningBackendError::ReadinessPending(message))
        | Err(ProvisioningBackendError::ReplicaReadinessPending(message)) => {
            return Err(ProvisioningError::BackendTransient(message))
        }
        Err(ProvisioningBackendError::Permanent(message))
        | Err(ProvisioningBackendError::DuplicateKeys { message, .. }) => {
            return Err(ProvisioningError::BackendPermanent(message))
        }
    };
    let expected = record.revision;
    for key_arn in discovered {
        if !record.tracks_key_arn(&key_arn) {
            record.track_pending_deletion(key_arn, now)?;
        }
    }
    if record.revision != expected && !registry.compare_and_swap(expected, record.clone()).await? {
        return Err(ProvisioningError::Busy);
    }

    if !record.pending_deletion_arns.is_empty() {
        schedule_key_deletions(
            backend,
            record.pending_deletion_arns.iter().map(String::as_str),
        )
        .await?;
        let expected = record.revision;
        record.mark_pending_deletions_complete(now)?;
        if !registry.compare_and_swap(expected, record.clone()).await? {
            return Err(ProvisioningError::Busy);
        }
    }

    let expected = record.revision;
    record.finish_offboarding(operation_id, now)?;
    if record.revision != expected && !registry.compare_and_swap(expected, record.clone()).await? {
        return Err(ProvisioningError::Busy);
    }
    Ok(record)
}

pub async fn ensure_tenant<B: TenantKeyProvisioningBackend>(
    registry: &TenantKeyRegistryImpl,
    backend: &B,
    tenant_id: &str,
    requested_operation_id: &str,
    now: i64,
) -> Result<TenantKeyRecord, ProvisioningError> {
    ensure_tenant_with_publish_clock(
        registry,
        backend,
        tenant_id,
        requested_operation_id,
        now,
        &|| now,
    )
    .await
}

async fn ensure_tenant_with_publish_clock<B: TenantKeyProvisioningBackend>(
    registry: &TenantKeyRegistryImpl,
    backend: &B,
    tenant_id: &str,
    requested_operation_id: &str,
    now: i64,
    publish_now: &(dyn Fn() -> i64 + Sync),
) -> Result<TenantKeyRecord, ProvisioningError> {
    let mut current = registry.get(tenant_id).await?;
    if let Some(record) = current
        .as_ref()
        .filter(|record| {
            record
                .last_failure
                .as_ref()
                .is_some_and(|failure| failure.cleanup_pending)
        })
        .cloned()
    {
        current = Some(compensate_failure(registry, backend, record, now).await?);
    }
    let record = match current {
        None => {
            let record = TenantKeyRecord::begin_onboarding(tenant_id, requested_operation_id, now)?;
            if !registry.create(record.clone()).await? {
                registry
                    .get(tenant_id)
                    .await?
                    .ok_or(ProvisioningError::Busy)?
            } else {
                record
            }
        }
        Some(mut record)
            if record.lifecycle == TenantKeyLifecycle::Failed
                && record
                    .last_failure
                    .as_ref()
                    .is_some_and(|failure| !failure.cleanup_pending) =>
        {
            if let Some(failure) = record
                .last_failure
                .as_ref()
                .filter(|failure| failure.operation_id == requested_operation_id)
            {
                return Err(ProvisioningError::BackendPermanent(
                    failure.error_class.clone(),
                ));
            }
            let expected = record.revision;
            record.retry_onboarding(requested_operation_id, now)?;
            if !registry.compare_and_swap(expected, record.clone()).await? {
                return Err(ProvisioningError::Busy);
            }
            record
        }
        Some(record) => record,
    };

    if record.lifecycle == TenantKeyLifecycle::Ready && record.operation.is_none() {
        return Ok(record);
    }
    if record.lifecycle != TenantKeyLifecycle::Provisioning {
        return Err(ProvisioningError::InvalidState);
    }
    let operation = record
        .operation
        .as_ref()
        .ok_or(ProvisioningError::InvalidState)?;
    if operation.kind != agent_auth_infra_core::TenantKeyOperationKind::Onboard {
        return Err(ProvisioningError::InvalidState);
    }
    if operation.operation_id != requested_operation_id {
        return Err(ProvisioningError::Busy);
    }
    provision_current(registry, backend, tenant_id, now, publish_now).await
}

pub async fn rotate_tenant<B: TenantKeyProvisioningBackend>(
    registry: &TenantKeyRegistryImpl,
    backend: &B,
    tenant_id: &str,
    requested_operation_id: &str,
    now: i64,
) -> Result<TenantKeyRecord, ProvisioningError> {
    rotate_tenant_with_publish_clock(
        registry,
        backend,
        tenant_id,
        requested_operation_id,
        now,
        &|| now,
    )
    .await
}

async fn rotate_tenant_with_publish_clock<B: TenantKeyProvisioningBackend>(
    registry: &TenantKeyRegistryImpl,
    backend: &B,
    tenant_id: &str,
    requested_operation_id: &str,
    now: i64,
    publish_now: &(dyn Fn() -> i64 + Sync),
) -> Result<TenantKeyRecord, ProvisioningError> {
    let mut record = registry
        .get(tenant_id)
        .await?
        .ok_or(ProvisioningError::InvalidState)?;
    if record.lifecycle == TenantKeyLifecycle::Ready && record.operation.is_none() {
        if !record.pending_deletion_arns.is_empty() {
            record = cleanup_pending_deletions(registry, backend, record, now).await?;
        }
        if record
            .last_failure
            .as_ref()
            .is_some_and(|failure| failure.cleanup_pending)
        {
            record = compensate_failure(registry, backend, record, now).await?;
        }
        if let Some(failure) = record
            .last_failure
            .as_ref()
            .filter(|failure| failure.operation_id == requested_operation_id)
        {
            return Err(ProvisioningError::BackendPermanent(
                failure.error_class.clone(),
            ));
        }
        if record.last_completed_operation_id.as_deref() == Some(requested_operation_id) {
            return Ok(record);
        }
        let expected = record.revision;
        record.begin_rotation(requested_operation_id, now)?;
        if !registry.compare_and_swap(expected, record.clone()).await? {
            return Err(ProvisioningError::Busy);
        }
    } else {
        let operation = record
            .operation
            .as_ref()
            .ok_or(ProvisioningError::InvalidState)?;
        if operation.kind != agent_auth_infra_core::TenantKeyOperationKind::Rotate {
            return Err(ProvisioningError::InvalidState);
        }
        if operation.operation_id != requested_operation_id {
            return Err(ProvisioningError::Busy);
        }
        if record.lifecycle != TenantKeyLifecycle::Provisioning {
            return Ok(record);
        }
    }
    provision_current(registry, backend, tenant_id, now, publish_now).await
}

pub async fn activate_tenant(
    registry: &TenantKeyRegistryImpl,
    tenant_id: &str,
    operation_id: &str,
    now: i64,
) -> Result<TenantKeyRecord, ProvisioningError> {
    let mut record = registry
        .get(tenant_id)
        .await?
        .ok_or(ProvisioningError::InvalidState)?;
    if record.lifecycle == TenantKeyLifecycle::ActiveOverlap
        && record
            .operation
            .as_ref()
            .is_some_and(|operation| operation.operation_id == operation_id)
    {
        return Ok(record);
    }
    let published_at = record
        .served_snapshot
        .as_ref()
        .map(|snapshot| snapshot.committed_at)
        .ok_or(ProvisioningError::InvalidState)?;
    if now < published_at + PUBLISH_AHEAD_SECS {
        return Err(ProvisioningError::Busy);
    }
    let expected = record.revision;
    record.activate_candidate(operation_id, now, now + TOKEN_OVERLAP_SECS)?;
    if !registry.compare_and_swap(expected, record.clone()).await? {
        return Err(ProvisioningError::Busy);
    }
    Ok(record)
}

pub async fn rollback_tenant<B: TenantKeyProvisioningBackend>(
    registry: &TenantKeyRegistryImpl,
    backend: &B,
    tenant_id: &str,
    operation_id: &str,
    now: i64,
) -> Result<TenantKeyRecord, ProvisioningError> {
    let mut record = registry
        .get(tenant_id)
        .await?
        .ok_or(ProvisioningError::InvalidState)?;
    if (record.lifecycle == TenantKeyLifecycle::RollbackOverlap
        && record
            .operation
            .as_ref()
            .is_some_and(|operation| operation.operation_id == operation_id))
        || (record.lifecycle == TenantKeyLifecycle::Ready
            && record.last_completed_operation_id.as_deref() == Some(operation_id)
            && matches!(
                record.last_completed_outcome,
                Some(
                    TenantKeyCompletionOutcome::RolledBack
                        | TenantKeyCompletionOutcome::RetiredRollback
                )
            ))
    {
        return if record.pending_deletion_arns.is_empty() {
            Ok(record)
        } else {
            cleanup_pending_deletions(registry, backend, record, now).await
        };
    }
    let expected = record.revision;
    record.rollback(operation_id, now, now + TOKEN_OVERLAP_SECS)?;
    if !registry.compare_and_swap(expected, record.clone()).await? {
        return Err(ProvisioningError::Busy);
    }
    if record.pending_deletion_arns.is_empty() {
        Ok(record)
    } else {
        cleanup_pending_deletions(registry, backend, record, now).await
    }
}

pub async fn retire_tenant<B: TenantKeyProvisioningBackend>(
    registry: &TenantKeyRegistryImpl,
    backend: &B,
    tenant_id: &str,
    operation_id: &str,
    now: i64,
) -> Result<TenantKeyRecord, ProvisioningError> {
    let mut record = registry
        .get(tenant_id)
        .await?
        .ok_or(ProvisioningError::InvalidState)?;
    if record.lifecycle == TenantKeyLifecycle::Ready
        && record.last_completed_operation_id.as_deref() == Some(operation_id)
    {
        return if record.pending_deletion_arns.is_empty() {
            Ok(record)
        } else {
            cleanup_pending_deletions(registry, backend, record, now).await
        };
    }
    let expected = record.revision;
    record.retire(operation_id, now)?;
    if !registry.compare_and_swap(expected, record.clone()).await? {
        return Err(ProvisioningError::Busy);
    }
    cleanup_pending_deletions(registry, backend, record, now).await
}

pub async fn emergency_revoke_tenant<B: TenantKeyProvisioningBackend>(
    registry: &TenantKeyRegistryImpl,
    backend: &B,
    tenant_id: &str,
    operation_id: &str,
    now: i64,
) -> Result<TenantKeyRecord, ProvisioningError> {
    let mut record = registry
        .get(tenant_id)
        .await?
        .ok_or(ProvisioningError::InvalidState)?;
    if record.lifecycle == TenantKeyLifecycle::Ready
        && record.last_completed_operation_id.as_deref() == Some(operation_id)
        && record.last_emergency_revoke_operation_id.as_deref() == Some(operation_id)
    {
        return if record.pending_deletion_arns.is_empty() {
            Ok(record)
        } else {
            cleanup_pending_deletions(registry, backend, record, now).await
        };
    }
    let expected = record.revision;
    record.emergency_revoke(operation_id, now)?;
    if !registry.compare_and_swap(expected, record.clone()).await? {
        return Err(ProvisioningError::Busy);
    }
    cleanup_pending_deletions(registry, backend, record, now).await
}

pub async fn reconcile_tenant<B: TenantKeyProvisioningBackend>(
    registry: &TenantKeyRegistryImpl,
    backend: &B,
    tenant_id: &str,
    now: i64,
) -> Result<Option<TenantKeyRecord>, ProvisioningError> {
    reconcile_tenant_with_publish_clock(registry, backend, tenant_id, now, &|| now).await
}

async fn reconcile_tenant_with_publish_clock<B: TenantKeyProvisioningBackend>(
    registry: &TenantKeyRegistryImpl,
    backend: &B,
    tenant_id: &str,
    now: i64,
    publish_now: &(dyn Fn() -> i64 + Sync),
) -> Result<Option<TenantKeyRecord>, ProvisioningError> {
    let Some(record) = registry.get(tenant_id).await? else {
        return Ok(None);
    };
    if matches!(
        record.lifecycle,
        TenantKeyLifecycle::Offboarding | TenantKeyLifecycle::Offboarded
    ) {
        // Scheduled reconciliation carries no destructive governance claim.
        // Only an Offboard command may resume provider-side key deletion.
        return Ok(Some(record));
    }
    if !record.pending_deletion_arns.is_empty() {
        return cleanup_pending_deletions(registry, backend, record, now)
            .await
            .map(Some);
    }
    if record
        .last_failure
        .as_ref()
        .is_some_and(|failure| failure.cleanup_pending)
    {
        return compensate_failure(registry, backend, record, now)
            .await
            .map(Some);
    }
    if record.lifecycle == TenantKeyLifecycle::Provisioning && record.operation.is_some() {
        return provision_current(registry, backend, tenant_id, now, publish_now)
            .await
            .map(Some);
    }
    if record.lifecycle == TenantKeyLifecycle::Publishing
        && record
            .served_snapshot
            .as_ref()
            .is_some_and(|snapshot| now >= snapshot.committed_at + PUBLISHING_TIMEOUT_SECS)
    {
        return rollback_observed_publishing(registry, backend, record, now)
            .await
            .map(Some);
    }
    if matches!(
        record.lifecycle,
        TenantKeyLifecycle::ActiveOverlap | TenantKeyLifecycle::RollbackOverlap
    ) && record
        .operation
        .as_ref()
        .and_then(|operation| operation.retire_after)
        .is_some_and(|deadline| now >= deadline)
    {
        let operation_id = record
            .operation
            .as_ref()
            .expect("checked")
            .operation_id
            .clone();
        return retire_tenant(registry, backend, tenant_id, &operation_id, now)
            .await
            .map(Some);
    }
    reconcile_discovered_orphans(registry, backend, tenant_id, now)
        .await
        .map(Some)
}

async fn rollback_observed_publishing<B: TenantKeyProvisioningBackend>(
    registry: &TenantKeyRegistryImpl,
    backend: &B,
    mut record: TenantKeyRecord,
    now: i64,
) -> Result<TenantKeyRecord, ProvisioningError> {
    if record.lifecycle != TenantKeyLifecycle::Publishing {
        return Err(ProvisioningError::InvalidState);
    }
    let operation_id = record
        .operation
        .as_ref()
        .ok_or(ProvisioningError::InvalidState)?
        .operation_id
        .clone();
    let expected = record.revision;
    record.rollback(&operation_id, now, now + TOKEN_OVERLAP_SECS)?;
    if !registry.compare_and_swap(expected, record.clone()).await? {
        return Err(ProvisioningError::Busy);
    }
    cleanup_pending_deletions(registry, backend, record, now).await
}

async fn schedule_key_deletions<'a, B, I>(backend: &B, key_arns: I) -> Result<(), ProvisioningError>
where
    B: TenantKeyProvisioningBackend,
    I: IntoIterator<Item = &'a str>,
{
    for key_arn in key_arns {
        match backend.schedule_deletion(key_arn).await {
            Ok(()) => {}
            Err(ProvisioningBackendError::Transient(message)) => {
                return Err(ProvisioningError::BackendTransient(message))
            }
            Err(ProvisioningBackendError::ReadinessPending(message)) => {
                return Err(ProvisioningError::BackendTransient(message))
            }
            Err(ProvisioningBackendError::ReplicaReadinessPending(message)) => {
                return Err(ProvisioningError::BackendTransient(message))
            }
            Err(ProvisioningBackendError::Permanent(message)) => {
                return Err(ProvisioningError::BackendPermanent(message))
            }
            Err(ProvisioningBackendError::DuplicateKeys { message, .. }) => {
                return Err(ProvisioningError::BackendPermanent(message))
            }
        }
    }
    Ok(())
}

async fn cleanup_pending_deletions<B: TenantKeyProvisioningBackend>(
    registry: &TenantKeyRegistryImpl,
    backend: &B,
    mut record: TenantKeyRecord,
    now: i64,
) -> Result<TenantKeyRecord, ProvisioningError> {
    schedule_key_deletions(
        backend,
        record.pending_deletion_arns.iter().map(String::as_str),
    )
    .await?;
    let expected = record.revision;
    record.mark_pending_deletions_complete(now)?;
    if !registry.compare_and_swap(expected, record.clone()).await? {
        return Err(ProvisioningError::Busy);
    }
    Ok(record)
}

async fn provision_current<B: TenantKeyProvisioningBackend>(
    registry: &TenantKeyRegistryImpl,
    backend: &B,
    tenant_id: &str,
    now: i64,
    publish_now: &(dyn Fn() -> i64 + Sync),
) -> Result<TenantKeyRecord, ProvisioningError> {
    let mut record = registry
        .get(tenant_id)
        .await?
        .ok_or(ProvisioningError::InvalidState)?;
    let operation_id = record
        .operation
        .as_ref()
        .ok_or(ProvisioningError::InvalidState)?
        .operation_id
        .clone();
    let generation = record
        .operation
        .as_ref()
        .expect("checked")
        .candidate
        .generation;

    if record
        .operation
        .as_ref()
        .expect("checked")
        .candidate
        .ec
        .is_none()
    {
        let key_arn = match find_or_create_key(
            backend,
            tenant_id,
            &operation_id,
            generation,
            TenantKeyAlgorithm::Es256,
        )
        .await
        {
            Ok(key_arn) => key_arn,
            Err(error) => {
                return handle_backend_error(registry, backend, record, &operation_id, error, now)
                    .await
            }
        };
        let expected = record.revision;
        record.record_created_key(
            &operation_id,
            TenantKeyAlgorithm::Es256,
            key_arn.clone(),
            now,
        )?;
        if !registry.compare_and_swap(expected, record.clone()).await? {
            handle_cas_losing_key(registry, backend, tenant_id, &key_arn, now).await?;
            return Err(ProvisioningError::Busy);
        }
    }

    record = registry
        .get(tenant_id)
        .await?
        .ok_or(ProvisioningError::InvalidState)?;
    let ec = record
        .operation
        .as_ref()
        .and_then(|operation| operation.candidate.ec.as_ref())
        .ok_or(ProvisioningError::InvalidState)?;
    cleanup_unrecorded_created_keys(
        registry,
        backend,
        tenant_id,
        &operation_id,
        generation,
        TenantKeyAlgorithm::Es256,
        &ec.key_arn,
        now,
    )
    .await?;
    if ec.verified_at.is_none() {
        let jwk = match backend.probe_ec(&ec.key_arn).await {
            Ok(jwk) => jwk,
            Err(error) => {
                return handle_backend_error(registry, backend, record, &operation_id, error, now)
                    .await
            }
        };
        let expected = record.revision;
        record.record_verified_ec(&operation_id, jwk, now)?;
        if !registry.compare_and_swap(expected, record.clone()).await? {
            return Err(ProvisioningError::Busy);
        }
    }

    record = registry
        .get(tenant_id)
        .await?
        .ok_or(ProvisioningError::InvalidState)?;
    if record
        .operation
        .as_ref()
        .expect("operation retained")
        .candidate
        .rsa
        .is_none()
    {
        let key_arn = match find_or_create_key(
            backend,
            tenant_id,
            &operation_id,
            generation,
            TenantKeyAlgorithm::Rs256,
        )
        .await
        {
            Ok(key_arn) => key_arn,
            Err(error) => {
                return handle_backend_error(registry, backend, record, &operation_id, error, now)
                    .await
            }
        };
        let expected = record.revision;
        record.record_created_key(
            &operation_id,
            TenantKeyAlgorithm::Rs256,
            key_arn.clone(),
            now,
        )?;
        if !registry.compare_and_swap(expected, record.clone()).await? {
            handle_cas_losing_key(registry, backend, tenant_id, &key_arn, now).await?;
            return Err(ProvisioningError::Busy);
        }
    }

    record = registry
        .get(tenant_id)
        .await?
        .ok_or(ProvisioningError::InvalidState)?;
    let rsa = record
        .operation
        .as_ref()
        .and_then(|operation| operation.candidate.rsa.as_ref())
        .ok_or(ProvisioningError::InvalidState)?;
    cleanup_unrecorded_created_keys(
        registry,
        backend,
        tenant_id,
        &operation_id,
        generation,
        TenantKeyAlgorithm::Rs256,
        &rsa.key_arn,
        now,
    )
    .await?;
    if rsa.verified_at.is_none() {
        let jwk = match backend.probe_rsa(&rsa.key_arn).await {
            Ok(jwk) => jwk,
            Err(error) => {
                return handle_backend_error(registry, backend, record, &operation_id, error, now)
                    .await
            }
        };
        let expected = record.revision;
        record.record_verified_rsa(&operation_id, jwk, now)?;
        if !registry.compare_and_swap(expected, record.clone()).await? {
            return Err(ProvisioningError::Busy);
        }
    }

    record = registry
        .get(tenant_id)
        .await?
        .ok_or(ProvisioningError::InvalidState)?;
    let expected = record.revision;
    record.publish_candidate(&operation_id, publish_now().max(now))?;
    if !registry.compare_and_swap(expected, record.clone()).await? {
        return Err(ProvisioningError::Busy);
    }
    Ok(record)
}

async fn find_or_create_key<B: TenantKeyProvisioningBackend>(
    backend: &B,
    tenant_id: &str,
    operation_id: &str,
    generation: u64,
    algorithm: TenantKeyAlgorithm,
) -> Result<String, ProvisioningBackendError> {
    let mut discovered = backend
        .find_created_keys(tenant_id, operation_id, generation, algorithm)
        .await?;
    discovered.sort();
    match discovered.as_slice() {
        [] => {}
        [key_arn] => return Ok(key_arn.clone()),
        _ => {
            return Err(ProvisioningBackendError::DuplicateKeys {
                message: format!(
                    "multiple KMS keys match tenant={tenant_id} operation={operation_id} generation={generation} algorithm={algorithm:?}"
                ),
                key_arns: discovered,
            })
        }
    }
    backend
        .create_key(tenant_id, operation_id, generation, algorithm)
        .await
}

async fn handle_cas_losing_key<B: TenantKeyProvisioningBackend>(
    registry: &TenantKeyRegistryImpl,
    backend: &B,
    tenant_id: &str,
    key_arn: &str,
    now: i64,
) -> Result<(), ProvisioningError> {
    loop {
        let mut winner = registry
            .get(tenant_id)
            .await?
            .ok_or(ProvisioningError::InvalidState)?;
        if winner.references_key_arn(key_arn) {
            return Ok(());
        }
        if winner
            .scheduled_deletion_arns
            .iter()
            .any(|scheduled| scheduled == key_arn)
        {
            return Ok(());
        }
        if winner
            .pending_deletion_arns
            .iter()
            .any(|pending| pending == key_arn)
        {
            return cleanup_pending_deletions(registry, backend, winner, now)
                .await
                .map(|_| ());
        }
        let expected = winner.revision;
        winner.track_pending_deletion(key_arn, now)?;
        if registry.compare_and_swap(expected, winner.clone()).await? {
            return cleanup_pending_deletions(registry, backend, winner, now)
                .await
                .map(|_| ());
        }
    }
}

async fn reconcile_discovered_orphans<B: TenantKeyProvisioningBackend>(
    registry: &TenantKeyRegistryImpl,
    backend: &B,
    tenant_id: &str,
    now: i64,
) -> Result<TenantKeyRecord, ProvisioningError> {
    let discovered = match backend.find_managed_keys(tenant_id).await {
        Ok(discovered) => discovered,
        Err(ProvisioningBackendError::Transient(message)) => {
            return Err(ProvisioningError::BackendTransient(message))
        }
        Err(ProvisioningBackendError::ReadinessPending(message)) => {
            return Err(ProvisioningError::BackendTransient(message))
        }
        Err(ProvisioningBackendError::ReplicaReadinessPending(message)) => {
            return Err(ProvisioningError::BackendTransient(message))
        }
        Err(ProvisioningBackendError::Permanent(message)) => {
            return Err(ProvisioningError::BackendPermanent(message))
        }
        Err(ProvisioningBackendError::DuplicateKeys { message, .. }) => {
            return Err(ProvisioningError::BackendPermanent(message))
        }
    };
    persist_discovered_orphans(registry, backend, tenant_id, &discovered, now, false).await
}

async fn persist_discovered_orphans<B: TenantKeyProvisioningBackend>(
    registry: &TenantKeyRegistryImpl,
    backend: &B,
    tenant_id: &str,
    discovered: &[String],
    now: i64,
    allow_during_provisioning: bool,
) -> Result<TenantKeyRecord, ProvisioningError> {
    loop {
        let mut current = registry
            .get(tenant_id)
            .await?
            .ok_or(ProvisioningError::InvalidState)?;
        // A sweep may have started from a Ready snapshot just before a
        // rotation created its first key. Provisioning owns orphan adoption
        // until its candidate CAS completes.
        if !allow_during_provisioning && current.lifecycle == TenantKeyLifecycle::Provisioning {
            return Ok(current);
        }
        let expected = current.revision;
        for key_arn in discovered {
            if !current.tracks_key_arn(key_arn) {
                current.track_pending_deletion(key_arn, now)?;
            }
        }
        if current.revision == expected {
            return Ok(current);
        }
        if registry.compare_and_swap(expected, current.clone()).await? {
            return cleanup_pending_deletions(registry, backend, current, now).await;
        }
    }
}

async fn cleanup_unrecorded_created_keys<B: TenantKeyProvisioningBackend>(
    registry: &TenantKeyRegistryImpl,
    backend: &B,
    tenant_id: &str,
    operation_id: &str,
    generation: u64,
    algorithm: TenantKeyAlgorithm,
    recorded_arn: &str,
    now: i64,
) -> Result<(), ProvisioningError> {
    let discovered = match backend
        .find_created_keys(tenant_id, operation_id, generation, algorithm)
        .await
    {
        Ok(discovered) => discovered,
        Err(ProvisioningBackendError::Transient(message)) => {
            return Err(ProvisioningError::BackendTransient(message))
        }
        Err(ProvisioningBackendError::ReadinessPending(message)) => {
            return Err(ProvisioningError::BackendTransient(message))
        }
        Err(ProvisioningBackendError::ReplicaReadinessPending(message)) => {
            return Err(ProvisioningError::BackendTransient(message))
        }
        Err(ProvisioningBackendError::Permanent(message)) => {
            return Err(ProvisioningError::BackendPermanent(message))
        }
        Err(ProvisioningBackendError::DuplicateKeys { message, .. }) => {
            return Err(ProvisioningError::BackendPermanent(message))
        }
    };
    let unrecorded: Vec<String> = discovered
        .into_iter()
        .filter(|key_arn| key_arn != recorded_arn)
        .collect();
    persist_discovered_orphans(registry, backend, tenant_id, &unrecorded, now, true)
        .await
        .map(|_| ())
}

async fn handle_backend_error<B: TenantKeyProvisioningBackend>(
    registry: &TenantKeyRegistryImpl,
    backend: &B,
    record: TenantKeyRecord,
    operation_id: &str,
    error: ProvisioningBackendError,
    now: i64,
) -> Result<TenantKeyRecord, ProvisioningError> {
    let (message, cleanup_arns) = match error {
        ProvisioningBackendError::Transient(message) => {
            return Err(ProvisioningError::BackendTransient(message))
        }
        ProvisioningBackendError::ReadinessPending(message) => {
            let created_at = record
                .operation
                .as_ref()
                .and_then(|operation| {
                    operation
                        .candidate
                        .ec
                        .as_ref()
                        .filter(|key| key.verified_at.is_none())
                        .map(|key| key.created_at)
                        .or_else(|| {
                            operation
                                .candidate
                                .rsa
                                .as_ref()
                                .filter(|key| key.verified_at.is_none())
                                .map(|key| key.created_at)
                        })
                })
                .ok_or(ProvisioningError::InvalidState)?;
            if kms_readiness_is_pending(created_at, now) {
                return Err(ProvisioningError::BackendTransient(message));
            }
            (
                format!(
                    "{message} after {KMS_READINESS_PROPAGATION_SECS}s KMS readiness propagation window"
                ),
                Vec::new(),
            )
        }
        ProvisioningBackendError::ReplicaReadinessPending(message) => {
            let (algorithm, started_at) = record
                .operation
                .as_ref()
                .and_then(|operation| {
                    operation
                        .candidate
                        .ec
                        .as_ref()
                        .filter(|key| key.verified_at.is_none())
                        .map(|key| (TenantKeyAlgorithm::Es256, key.replica_readiness_started_at))
                        .or_else(|| {
                            operation
                                .candidate
                                .rsa
                                .as_ref()
                                .filter(|key| key.verified_at.is_none())
                                .map(|key| {
                                    (TenantKeyAlgorithm::Rs256, key.replica_readiness_started_at)
                                })
                        })
                })
                .ok_or(ProvisioningError::InvalidState)?;
            let Some(started_at) = started_at else {
                let expected = record.revision;
                let mut pending = record;
                pending.record_replica_readiness_started(operation_id, algorithm, now)?;
                if !registry.compare_and_swap(expected, pending).await? {
                    return Err(ProvisioningError::Busy);
                }
                return Err(ProvisioningError::BackendTransient(message));
            };
            if kms_readiness_is_pending(started_at, now) {
                return Err(ProvisioningError::BackendTransient(message));
            }
            (
                format!(
                    "{message} after {KMS_READINESS_PROPAGATION_SECS}s KMS replica readiness propagation window"
                ),
                Vec::new(),
            )
        }
        ProvisioningBackendError::Permanent(message) => (message, Vec::new()),
        ProvisioningBackendError::DuplicateKeys { message, key_arns } => (message, key_arns),
    };
    let expected = record.revision;
    let mut failed = record;
    failed.fail_operation_with_cleanup(operation_id, message.clone(), cleanup_arns, now)?;
    if !registry.compare_and_swap(expected, failed.clone()).await? {
        return Err(ProvisioningError::Busy);
    }
    if failed
        .last_failure
        .as_ref()
        .is_none_or(|failure| !failure.cleanup_pending)
    {
        return Err(ProvisioningError::BackendPermanent(message));
    }
    match compensate_failure(registry, backend, failed, now).await {
        Ok(_) | Err(ProvisioningError::BackendTransient(_)) => {
            Err(ProvisioningError::BackendPermanent(message))
        }
        Err(other) => Err(other),
    }
}

async fn compensate_failure<B: TenantKeyProvisioningBackend>(
    registry: &TenantKeyRegistryImpl,
    backend: &B,
    mut record: TenantKeyRecord,
    now: i64,
) -> Result<TenantKeyRecord, ProvisioningError> {
    let failure = record
        .last_failure
        .as_ref()
        .filter(|failure| failure.cleanup_pending)
        .ok_or(ProvisioningError::InvalidState)?
        .clone();
    let fallback_arns = [
        failure
            .candidate
            .ec
            .as_ref()
            .map(|key| key.key_arn.as_str()),
        failure
            .candidate
            .rsa
            .as_ref()
            .map(|key| key.key_arn.as_str()),
    ];
    let cleanup_arns: Vec<&str> = if failure.cleanup_arns.is_empty() {
        fallback_arns.into_iter().flatten().collect()
    } else {
        failure.cleanup_arns.iter().map(String::as_str).collect()
    };
    for key_arn in cleanup_arns {
        match backend.schedule_deletion(key_arn).await {
            Ok(()) => {}
            Err(ProvisioningBackendError::Transient(message)) => {
                return Err(ProvisioningError::BackendTransient(message))
            }
            Err(ProvisioningBackendError::ReadinessPending(message)) => {
                return Err(ProvisioningError::BackendTransient(message))
            }
            Err(ProvisioningBackendError::ReplicaReadinessPending(message)) => {
                return Err(ProvisioningError::BackendTransient(message))
            }
            Err(ProvisioningBackendError::Permanent(message)) => {
                return Err(ProvisioningError::BackendPermanent(message))
            }
            Err(ProvisioningBackendError::DuplicateKeys { message, .. }) => {
                return Err(ProvisioningError::BackendPermanent(message))
            }
        }
    }
    let expected = record.revision;
    record.mark_cleanup_complete(now)?;
    if !registry.compare_and_swap(expected, record.clone()).await? {
        return Err(ProvisioningError::Busy);
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenant_keys::{MemoryTenantKeyRegistry, TenantKeyRegistryImpl};
    use std::sync::{atomic::AtomicI64, atomic::Ordering, Arc};
    use tokio::sync::Mutex;

    #[derive(Clone, Default)]
    struct FakeBackend {
        deleted: Arc<Mutex<Vec<String>>>,
        fail_rsa_create: Arc<Mutex<bool>>,
        discovered_ec: Arc<Mutex<Vec<String>>>,
        discovered_rsa: Arc<Mutex<Vec<String>>>,
        created: Arc<Mutex<usize>>,
        fail_delete: Arc<Mutex<bool>>,
        probe_ec_error: Arc<Mutex<Option<ProvisioningBackendError>>>,
        probe_rsa_error: Arc<Mutex<Option<ProvisioningBackendError>>>,
    }

    impl TenantKeyProvisioningBackend for FakeBackend {
        async fn find_managed_keys(
            &self,
            _tenant_id: &str,
        ) -> Result<Vec<String>, ProvisioningBackendError> {
            let mut keys = self.discovered_ec.lock().await.clone();
            keys.extend(self.discovered_rsa.lock().await.clone());
            Ok(keys)
        }

        async fn find_created_keys(
            &self,
            _tenant_id: &str,
            _operation_id: &str,
            _generation: u64,
            algorithm: TenantKeyAlgorithm,
        ) -> Result<Vec<String>, ProvisioningBackendError> {
            Ok(match algorithm {
                TenantKeyAlgorithm::Es256 => self.discovered_ec.lock().await.clone(),
                TenantKeyAlgorithm::Rs256 => self.discovered_rsa.lock().await.clone(),
            })
        }

        async fn create_key(
            &self,
            tenant_id: &str,
            operation_id: &str,
            generation: u64,
            algorithm: TenantKeyAlgorithm,
        ) -> Result<String, ProvisioningBackendError> {
            if algorithm == TenantKeyAlgorithm::Rs256 && *self.fail_rsa_create.lock().await {
                return Err(ProvisioningBackendError::Permanent(
                    "injected_rsa_create_failure".to_string(),
                ));
            }
            *self.created.lock().await += 1;
            Ok(format!(
                "arn:{tenant_id}:{operation_id}:{generation}:{algorithm:?}"
            ))
        }

        async fn probe_ec(&self, key_arn: &str) -> Result<EcPublicJwk, ProvisioningBackendError> {
            if let Some(error) = self.probe_ec_error.lock().await.clone() {
                return Err(error);
            }
            Ok(EcPublicJwk {
                x: format!("x-{key_arn}"),
                y: format!("y-{key_arn}"),
                kid: format!("ec-{}", key_arn.replace(':', "-")),
            })
        }

        async fn probe_rsa(&self, key_arn: &str) -> Result<RsaPublicJwk, ProvisioningBackendError> {
            if let Some(error) = self.probe_rsa_error.lock().await.clone() {
                return Err(error);
            }
            Ok(RsaPublicJwk {
                n: format!("n-{key_arn}"),
                e: "AQAB".to_string(),
                kid: format!("rsa-{}", key_arn.replace(':', "-")),
            })
        }

        async fn schedule_deletion(&self, key_arn: &str) -> Result<(), ProvisioningBackendError> {
            if *self.fail_delete.lock().await {
                return Err(ProvisioningBackendError::Transient(
                    "injected_delete_failure".to_string(),
                ));
            }
            self.deleted.lock().await.push(key_arn.to_string());
            Ok(())
        }
    }

    fn registry() -> TenantKeyRegistryImpl {
        TenantKeyRegistryImpl::Memory(MemoryTenantKeyRegistry::default())
    }

    #[tokio::test]
    async fn scheduled_reconcile_ensures_missing_tenant() {
        let registry = registry();
        let command = TenantKeyCommand {
            tenant_id: "t1".to_string(),
            action: TenantKeyCommandAction::Reconcile,
            operation_id: "onboard-t1-v1".to_string(),
            requested_at: 100,
            governance_dispatch: None,
        };

        let record = execute_command(&registry, &FakeBackend::default(), &command, 100)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(record.lifecycle, TenantKeyLifecycle::Ready);
        assert_eq!(
            record.last_completed_operation_id.as_deref(),
            Some("onboard-t1-v1")
        );
    }

    #[tokio::test]
    async fn ensure_commits_only_after_both_probes() {
        let registry = registry();
        let record = ensure_tenant(&registry, &FakeBackend::default(), "t1", "op-1", 100)
            .await
            .unwrap();
        assert_eq!(record.lifecycle, TenantKeyLifecycle::Ready);
        let snapshot = record.ready_snapshot().unwrap();
        assert_eq!(snapshot.ec.active.generation, 1);
        assert_eq!(snapshot.rsa.active.generation, 1);
    }

    #[tokio::test]
    async fn retry_adopts_tagged_keys_created_before_registry_commit() {
        let registry = registry();
        let backend = FakeBackend::default();
        backend
            .discovered_ec
            .lock()
            .await
            .push("arn:recovered:ec".to_string());
        backend
            .discovered_rsa
            .lock()
            .await
            .push("arn:recovered:rsa".to_string());
        let record = ensure_tenant(&registry, &backend, "t1", "op-1", 100)
            .await
            .unwrap();
        let snapshot = record.ready_snapshot().unwrap();
        assert_eq!(snapshot.ec.active.key_arn, "arn:recovered:ec");
        assert_eq!(snapshot.rsa.active.key_arn, "arn:recovered:rsa");
        assert_eq!(*backend.created.lock().await, 0);
    }

    #[tokio::test]
    async fn kms_not_found_readiness_is_bounded_before_permanent_failure() {
        let registry = registry();
        let backend = FakeBackend::default();
        *backend.probe_ec_error.lock().await = Some(ProvisioningBackendError::ReadinessPending(
            "NotFoundException: replica not propagated".to_string(),
        ));

        assert!(matches!(
            ensure_tenant(&registry, &backend, "t1", "op-1", 100).await,
            Err(ProvisioningError::BackendTransient(_))
        ));
        assert!(matches!(
            ensure_tenant(
                &registry,
                &backend,
                "t1",
                "op-1",
                100 + KMS_READINESS_PROPAGATION_SECS - 1,
            )
            .await,
            Err(ProvisioningError::BackendTransient(_))
        ));

        let error = ensure_tenant(
            &registry,
            &backend,
            "t1",
            "op-1",
            100 + KMS_READINESS_PROPAGATION_SECS,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, ProvisioningError::BackendPermanent(_)));
        let failed = registry.get("t1").await.unwrap().unwrap();
        assert_eq!(failed.lifecycle, TenantKeyLifecycle::Failed);
        assert!(!failed.last_failure.as_ref().unwrap().cleanup_pending);
        assert_eq!(backend.deleted.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn replica_readiness_gets_a_separate_bounded_window() {
        let registry = registry();
        let backend = FakeBackend::default();
        *backend.probe_ec_error.lock().await = Some(ProvisioningBackendError::ReadinessPending(
            "NotFoundException: primary not propagated".to_string(),
        ));
        assert!(matches!(
            ensure_tenant(&registry, &backend, "t1", "op-1", 100).await,
            Err(ProvisioningError::BackendTransient(_))
        ));
        let primary_pending = registry.get("t1").await.unwrap().unwrap();
        assert_eq!(primary_pending.lifecycle, TenantKeyLifecycle::Provisioning);
        assert!(primary_pending.served_snapshot.is_none());
        assert!(primary_pending.ready_snapshot().is_err());

        *backend.probe_ec_error.lock().await =
            Some(ProvisioningBackendError::ReplicaReadinessPending(
                "NotFoundException: replica not propagated".to_string(),
            ));

        let near_primary_deadline = 100 + KMS_READINESS_PROPAGATION_SECS - 1;
        assert!(matches!(
            ensure_tenant(&registry, &backend, "t1", "op-1", near_primary_deadline).await,
            Err(ProvisioningError::BackendTransient(_))
        ));
        let pending = registry.get("t1").await.unwrap().unwrap();
        assert_eq!(
            pending
                .operation
                .as_ref()
                .unwrap()
                .candidate
                .ec
                .as_ref()
                .unwrap()
                .replica_readiness_started_at,
            Some(near_primary_deadline)
        );
        assert_eq!(pending.lifecycle, TenantKeyLifecycle::Provisioning);
        assert!(pending.served_snapshot.is_none());
        assert!(pending.ready_snapshot().is_err());

        assert!(matches!(
            ensure_tenant(
                &registry,
                &backend,
                "t1",
                "op-1",
                near_primary_deadline + KMS_READINESS_PROPAGATION_SECS - 1,
            )
            .await,
            Err(ProvisioningError::BackendTransient(_))
        ));
        let error = ensure_tenant(
            &registry,
            &backend,
            "t1",
            "op-1",
            near_primary_deadline + KMS_READINESS_PROPAGATION_SECS,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, ProvisioningError::BackendPermanent(_)));
        assert_eq!(backend.deleted.lock().await.len(), 1);
        let failed = registry.get("t1").await.unwrap().unwrap();
        assert_eq!(failed.lifecycle, TenantKeyLifecycle::Failed);
        assert!(failed.served_snapshot.is_none());
        assert!(failed.ready_snapshot().is_err());

        let rotation_registry = self::registry();
        let rotation_backend = FakeBackend::default();
        let old = ensure_tenant(&rotation_registry, &rotation_backend, "t2", "op-1", 100)
            .await
            .unwrap()
            .ready_snapshot()
            .unwrap()
            .clone();
        *rotation_backend.probe_ec_error.lock().await =
            Some(ProvisioningBackendError::ReplicaReadinessPending(
                "NotFoundException: replica not propagated".to_string(),
            ));
        assert!(matches!(
            rotate_tenant(&rotation_registry, &rotation_backend, "t2", "op-2", 200,).await,
            Err(ProvisioningError::BackendTransient(_))
        ));
        let rotation_pending = rotation_registry.get("t2").await.unwrap().unwrap();
        assert_eq!(rotation_pending.lifecycle, TenantKeyLifecycle::Provisioning);
        assert_eq!(rotation_pending.served_snapshot.as_ref(), Some(&old));
        assert_eq!(rotation_pending.ready_snapshot().unwrap(), &old);
        let candidate = &rotation_pending.operation.as_ref().unwrap().candidate;
        assert_eq!(candidate.generation, old.generation + 1);
        assert!(candidate.ec.as_ref().unwrap().verified_at.is_none());
    }

    #[test]
    fn kms_readiness_window_fails_closed_on_clock_regression_or_overflow() {
        assert!(kms_readiness_is_pending(100, 100));
        assert!(kms_readiness_is_pending(
            100,
            100 + KMS_READINESS_PROPAGATION_SECS - 1
        ));
        assert!(!kms_readiness_is_pending(
            100,
            100 + KMS_READINESS_PROPAGATION_SECS
        ));
        assert!(!kms_readiness_is_pending(100, 99));
        assert!(kms_readiness_is_pending(i64::MAX - 100, i64::MAX));
        assert!(!kms_readiness_is_pending(i64::MIN, i64::MAX));
    }

    #[tokio::test]
    async fn rsa_kms_readiness_expiry_compensates_the_complete_candidate() {
        let registry = registry();
        let backend = FakeBackend::default();
        *backend.probe_rsa_error.lock().await = Some(ProvisioningBackendError::ReadinessPending(
            "AccessDeniedException: tag authorization pending".to_string(),
        ));

        assert!(matches!(
            ensure_tenant(&registry, &backend, "t1", "op-1", 100).await,
            Err(ProvisioningError::BackendTransient(_))
        ));
        let provisioning = registry.get("t1").await.unwrap().unwrap();
        let candidate = &provisioning.operation.as_ref().unwrap().candidate;
        assert!(candidate.ec.as_ref().unwrap().verified_at.is_some());
        assert!(candidate.rsa.as_ref().unwrap().verified_at.is_none());

        assert!(matches!(
            ensure_tenant(
                &registry,
                &backend,
                "t1",
                "op-1",
                100 + KMS_READINESS_PROPAGATION_SECS - 1,
            )
            .await,
            Err(ProvisioningError::BackendTransient(_))
        ));
        let error = ensure_tenant(
            &registry,
            &backend,
            "t1",
            "op-1",
            100 + KMS_READINESS_PROPAGATION_SECS,
        )
        .await
        .unwrap_err();

        assert!(matches!(error, ProvisioningError::BackendPermanent(_)));
        let failed = registry.get("t1").await.unwrap().unwrap();
        assert_eq!(failed.lifecycle, TenantKeyLifecycle::Failed);
        assert!(!failed.last_failure.as_ref().unwrap().cleanup_pending);
        assert_eq!(backend.deleted.lock().await.len(), 2);
    }

    #[tokio::test]
    async fn duplicate_uncommitted_keys_fail_closed() {
        let registry = registry();
        let backend = FakeBackend::default();
        *backend.discovered_ec.lock().await = vec![
            "arn:duplicate:ec:1".to_string(),
            "arn:duplicate:ec:2".to_string(),
        ];

        let error = ensure_tenant(&registry, &backend, "t1", "op-1", 100)
            .await
            .unwrap_err();

        assert!(matches!(error, ProvisioningError::BackendPermanent(_)));
        assert_eq!(backend.deleted.lock().await.len(), 2);
        let failed = registry.get("t1").await.unwrap().unwrap();
        assert_eq!(failed.lifecycle, TenantKeyLifecycle::Failed);
        let failure = failed.last_failure.as_ref().unwrap();
        assert!(failure.error_class.contains("multiple KMS keys"));
        assert_eq!(failure.cleanup_arns.len(), 2);
        assert!(!failure.cleanup_pending);
    }

    #[tokio::test]
    async fn recorded_key_cleanup_removes_only_cas_losing_orphans() {
        let registry = registry();
        let backend = FakeBackend::default();
        *backend.discovered_ec.lock().await = vec![
            "arn:recorded:ec".to_string(),
            "arn:cas-loser:ec".to_string(),
        ];
        let mut record = TenantKeyRecord::begin_onboarding("t1", "op-1", 100).unwrap();
        record
            .record_created_key("op-1", TenantKeyAlgorithm::Es256, "arn:recorded:ec", 101)
            .unwrap();
        assert!(registry.create(record).await.unwrap());

        cleanup_unrecorded_created_keys(
            &registry,
            &backend,
            "t1",
            "op-1",
            1,
            TenantKeyAlgorithm::Es256,
            "arn:recorded:ec",
            102,
        )
        .await
        .unwrap();

        assert_eq!(
            backend.deleted.lock().await.as_slice(),
            ["arn:cas-loser:ec"]
        );
        assert_eq!(
            registry
                .get("t1")
                .await
                .unwrap()
                .unwrap()
                .scheduled_deletion_arns,
            ["arn:cas-loser:ec"]
        );
    }

    #[tokio::test]
    async fn cas_loser_never_deletes_the_winners_adopted_key() {
        let memory_registry = MemoryTenantKeyRegistry::default();
        let registry = TenantKeyRegistryImpl::Memory(memory_registry.clone());
        let backend = FakeBackend::default();
        let mut record = TenantKeyRecord::begin_onboarding("t1", "op-1", 100).unwrap();
        record
            .record_created_key("op-1", TenantKeyAlgorithm::Es256, "arn:adopted:ec", 101)
            .unwrap();
        assert!(registry.create(record).await.unwrap());

        handle_cas_losing_key(&registry, &backend, "t1", "arn:adopted:ec", 102)
            .await
            .unwrap();
        assert!(backend.deleted.lock().await.is_empty());

        memory_registry.fail_next_compare_and_swaps(1);
        handle_cas_losing_key(&registry, &backend, "t1", "arn:cas-loser:ec", 103)
            .await
            .unwrap();
        assert_eq!(
            backend.deleted.lock().await.as_slice(),
            ["arn:cas-loser:ec"]
        );
        assert!(registry
            .get("t1")
            .await
            .unwrap()
            .unwrap()
            .pending_deletion_arns
            .is_empty());
        assert_eq!(
            registry
                .get("t1")
                .await
                .unwrap()
                .unwrap()
                .scheduled_deletion_arns,
            ["arn:cas-loser:ec"]
        );
    }

    #[tokio::test]
    async fn reconcile_persists_and_deletes_late_visible_orphans() {
        let registry = registry();
        let backend = FakeBackend::default();
        ensure_tenant(&registry, &backend, "t1", "op-1", 100)
            .await
            .unwrap();
        backend
            .discovered_ec
            .lock()
            .await
            .push("arn:late-visible:ec".to_string());

        let reconciled = reconcile_tenant(&registry, &backend, "t1", 200)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(reconciled.scheduled_deletion_arns, ["arn:late-visible:ec"]);
        assert_eq!(
            backend.deleted.lock().await.as_slice(),
            ["arn:late-visible:ec"]
        );
        reconcile_tenant(&registry, &backend, "t1", 201)
            .await
            .unwrap();
        assert_eq!(backend.deleted.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn stale_ready_sweep_never_deletes_an_uncommitted_candidate() {
        let registry = registry();
        let backend = FakeBackend::default();
        let record = TenantKeyRecord::begin_onboarding("t1", "op-1", 100).unwrap();
        assert!(registry.create(record).await.unwrap());
        backend
            .discovered_ec
            .lock()
            .await
            .push("arn:uncommitted:ec".to_string());

        let current = reconcile_discovered_orphans(&registry, &backend, "t1", 101)
            .await
            .unwrap();

        assert_eq!(current.lifecycle, TenantKeyLifecycle::Provisioning);
        assert!(current.pending_deletion_arns.is_empty());
        assert!(backend.deleted.lock().await.is_empty());
    }

    #[tokio::test]
    async fn permanent_partial_failure_is_compensated_and_not_ready() {
        let registry = registry();
        let backend = FakeBackend::default();
        *backend.fail_rsa_create.lock().await = true;
        let error = ensure_tenant(&registry, &backend, "t1", "op-1", 100)
            .await
            .unwrap_err();
        assert!(matches!(error, ProvisioningError::BackendPermanent(_)));
        let record = registry.get("t1").await.unwrap().unwrap();
        assert_eq!(record.lifecycle, TenantKeyLifecycle::Failed);
        assert!(record.ready_snapshot().is_err());
        assert!(!record.last_failure.as_ref().unwrap().cleanup_pending);
        assert_eq!(backend.deleted.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn rotation_keeps_old_active_until_explicit_activation() {
        let registry = registry();
        let backend = FakeBackend::default();
        let old = ensure_tenant(&registry, &backend, "t1", "op-1", 100)
            .await
            .unwrap()
            .ready_snapshot()
            .unwrap()
            .clone();
        let publishing = rotate_tenant(&registry, &backend, "t1", "op-2", 200)
            .await
            .unwrap();
        let snapshot = publishing.ready_snapshot().unwrap();
        assert_eq!(publishing.lifecycle, TenantKeyLifecycle::Publishing);
        assert_eq!(snapshot.ec.active.key_arn, old.ec.active.key_arn);
        assert_eq!(snapshot.rsa.active.key_arn, old.rsa.active.key_arn);
        assert_eq!(snapshot.ec.published.len(), 2);
        assert_eq!(snapshot.rsa.published.len(), 2);
        assert_eq!(
            activate_tenant(&registry, "t1", "op-2", 799).await,
            Err(ProvisioningError::Busy)
        );
        let active = activate_tenant(&registry, "t1", "op-2", 800).await.unwrap();
        assert_eq!(active.lifecycle, TenantKeyLifecycle::ActiveOverlap);
        assert_eq!(active.ready_snapshot().unwrap().generation, 2);
    }

    #[tokio::test]
    async fn publish_ahead_starts_after_provisioning_finishes() {
        let registry = registry();
        let backend = FakeBackend::default();
        ensure_tenant(&registry, &backend, "t1", "op-1", 100)
            .await
            .unwrap();
        let clock = AtomicI64::new(250);

        let publishing =
            rotate_tenant_with_publish_clock(&registry, &backend, "t1", "op-2", 200, &|| {
                clock.load(Ordering::Relaxed)
            })
            .await
            .unwrap();

        assert_eq!(
            publishing.served_snapshot.as_ref().unwrap().committed_at,
            250
        );
        assert_eq!(
            activate_tenant(&registry, "t1", "op-2", 849).await,
            Err(ProvisioningError::Busy)
        );
        activate_tenant(&registry, "t1", "op-2", 850).await.unwrap();
    }

    #[tokio::test]
    async fn graceful_rotation_enforces_publish_ahead_and_full_retirement_window() {
        let maximum_artifact_lifetime = crate::token::ACCESS_TTL
            .max(crate::token::ID_TOKEN_TTL_SECS)
            .max(crate::ssf::SSF_MAX_RETRY_AGE_SECS);
        assert!(
            PUBLISH_AHEAD_SECS >= i64::from(crate::jwks::JWKS_MAX_AGE_SECS),
            "new keys must be published for at least one frozen JWKS cache lifetime"
        );
        assert_eq!(
            TOKEN_OVERLAP_SECS,
            maximum_artifact_lifetime + DEFAULT_CLOCK_SKEW_SECS,
            "retirement must preserve the longest token or immutable SET retry lifetime plus skew"
        );

        let registry = registry();
        let backend = FakeBackend::default();
        let old = ensure_tenant(&registry, &backend, "t1", "op-1", 100)
            .await
            .unwrap()
            .ready_snapshot()
            .unwrap()
            .clone();
        let publish_clock = AtomicI64::new(250);
        let publishing =
            rotate_tenant_with_publish_clock(&registry, &backend, "t1", "op-2", 200, &|| {
                publish_clock.load(Ordering::Relaxed)
            })
            .await
            .unwrap();
        assert_eq!(publishing.lifecycle, TenantKeyLifecycle::Publishing);
        assert_eq!(publishing.ready_snapshot().unwrap().ec.published.len(), 2);
        assert_eq!(publishing.ready_snapshot().unwrap().rsa.published.len(), 2);

        let activation_time = 250 + PUBLISH_AHEAD_SECS;
        assert_eq!(
            activate_tenant(&registry, "t1", "op-2", activation_time - 1).await,
            Err(ProvisioningError::Busy)
        );
        let active = activate_tenant(&registry, "t1", "op-2", activation_time)
            .await
            .unwrap();
        let retirement_time = activation_time + TOKEN_OVERLAP_SECS;
        assert_eq!(active.lifecycle, TenantKeyLifecycle::ActiveOverlap);
        assert_eq!(
            active
                .operation
                .as_ref()
                .and_then(|operation| operation.retire_after),
            Some(retirement_time)
        );
        assert_eq!(active.ready_snapshot().unwrap().generation, 2);
        assert_eq!(active.ready_snapshot().unwrap().ec.published.len(), 2);
        assert_eq!(active.ready_snapshot().unwrap().rsa.published.len(), 2);

        let before_retirement = reconcile_tenant(&registry, &backend, "t1", retirement_time - 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            before_retirement.lifecycle,
            TenantKeyLifecycle::ActiveOverlap
        );
        assert_eq!(
            before_retirement
                .ready_snapshot()
                .unwrap()
                .ec
                .published
                .len(),
            2
        );
        assert_eq!(
            before_retirement
                .ready_snapshot()
                .unwrap()
                .rsa
                .published
                .len(),
            2
        );
        assert!(backend.deleted.lock().await.is_empty());

        let retired = reconcile_tenant(&registry, &backend, "t1", retirement_time)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retired.lifecycle, TenantKeyLifecycle::Ready);
        assert_eq!(retired.ready_snapshot().unwrap().generation, 2);
        assert_eq!(retired.ready_snapshot().unwrap().ec.published.len(), 1);
        assert_eq!(retired.ready_snapshot().unwrap().rsa.published.len(), 1);
        let mut deleted = backend.deleted.lock().await.clone();
        deleted.sort();
        let mut expected_deleted = vec![
            old.ec.active.key_arn.clone(),
            old.rsa.active.key_arn.clone(),
        ];
        expected_deleted.sort();
        assert_eq!(deleted, expected_deleted);
    }

    #[tokio::test]
    async fn emergency_revoke_command_skips_graceful_windows_and_is_idempotent() {
        let registry = registry();
        let backend = FakeBackend::default();
        let old = ensure_tenant(&registry, &backend, "t1", "op-1", 100)
            .await
            .unwrap()
            .ready_snapshot()
            .unwrap()
            .clone();
        let publishing = rotate_tenant(&registry, &backend, "t1", "op-2", 200)
            .await
            .unwrap();
        assert_eq!(publishing.lifecycle, TenantKeyLifecycle::Publishing);
        assert_eq!(publishing.ready_snapshot().unwrap().generation, 1);

        let command = TenantKeyCommand {
            tenant_id: "t1".to_string(),
            action: TenantKeyCommandAction::EmergencyRevoke,
            operation_id: "op-2".to_string(),
            requested_at: 201,
            governance_dispatch: None,
        };
        let emergency = execute_command(&registry, &backend, &command, 201)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(emergency.lifecycle, TenantKeyLifecycle::Ready);
        assert_eq!(emergency.ready_snapshot().unwrap().generation, 2);
        assert_eq!(emergency.ready_snapshot().unwrap().ec.published.len(), 1);
        assert_eq!(emergency.ready_snapshot().unwrap().rsa.published.len(), 1);
        assert_eq!(
            emergency.last_emergency_revoke_operation_id.as_deref(),
            Some("op-2")
        );
        assert_eq!(emergency.last_completed_outcome, None);
        assert!(emergency.operation.is_none());
        assert!(emergency.pending_deletion_arns.is_empty());

        let mut deleted = backend.deleted.lock().await.clone();
        deleted.sort();
        let mut expected_deleted = vec![
            old.ec.active.key_arn.clone(),
            old.rsa.active.key_arn.clone(),
        ];
        expected_deleted.sort();
        assert_eq!(deleted, expected_deleted);

        let repeated = execute_command(&registry, &backend, &command, 202)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            repeated.last_emergency_revoke_operation_id.as_deref(),
            Some("op-2")
        );
        assert_eq!(backend.deleted.lock().await.len(), 2);
    }

    #[tokio::test]
    async fn repeated_rotate_does_not_republish_or_regress_active_overlap() {
        let registry = registry();
        let backend = FakeBackend::default();
        ensure_tenant(&registry, &backend, "t1", "op-1", 100)
            .await
            .unwrap();
        let publishing = rotate_tenant(&registry, &backend, "t1", "op-2", 200)
            .await
            .unwrap();

        let repeated = rotate_tenant(&registry, &backend, "t1", "op-2", 300)
            .await
            .unwrap();
        assert_eq!(repeated, publishing);
        let active = activate_tenant(&registry, "t1", "op-2", 800).await.unwrap();

        let repeated = rotate_tenant(&registry, &backend, "t1", "op-2", 900)
            .await
            .unwrap();
        assert_eq!(repeated, active);
        assert_eq!(repeated.lifecycle, TenantKeyLifecycle::ActiveOverlap);
        assert_eq!(repeated.ready_snapshot().unwrap().generation, 2);
    }

    #[tokio::test]
    async fn abandoned_publishing_rotation_rolls_back_after_timeout() {
        let registry = registry();
        let backend = FakeBackend::default();
        ensure_tenant(&registry, &backend, "t1", "op-1", 100)
            .await
            .unwrap();
        rotate_tenant(&registry, &backend, "t1", "op-2", 200)
            .await
            .unwrap();

        let waiting =
            reconcile_tenant(&registry, &backend, "t1", 200 + PUBLISHING_TIMEOUT_SECS - 1)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(waiting.lifecycle, TenantKeyLifecycle::Publishing);

        let rolled_back =
            reconcile_tenant(&registry, &backend, "t1", 200 + PUBLISHING_TIMEOUT_SECS)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(rolled_back.lifecycle, TenantKeyLifecycle::Ready);
        assert_eq!(rolled_back.ready_snapshot().unwrap().generation, 1);
        assert_eq!(backend.deleted.lock().await.len(), 2);
    }

    #[tokio::test]
    async fn abandoned_publishing_rollback_cannot_undo_concurrent_activation() {
        let registry = registry();
        let backend = FakeBackend::default();
        ensure_tenant(&registry, &backend, "t1", "op-1", 100)
            .await
            .unwrap();
        rotate_tenant(&registry, &backend, "t1", "op-2", 200)
            .await
            .unwrap();
        let stale_publishing = registry.get("t1").await.unwrap().unwrap();
        activate_tenant(&registry, "t1", "op-2", 800).await.unwrap();

        assert!(matches!(
            rollback_observed_publishing(
                &registry,
                &backend,
                stale_publishing,
                200 + PUBLISHING_TIMEOUT_SECS,
            )
            .await,
            Err(ProvisioningError::Busy)
        ));
        let active = registry.get("t1").await.unwrap().unwrap();
        assert_eq!(active.lifecycle, TenantKeyLifecycle::ActiveOverlap);
        assert_eq!(active.ready_snapshot().unwrap().generation, 2);
        assert!(backend.deleted.lock().await.is_empty());
    }

    #[tokio::test]
    async fn failed_rotation_retry_reports_failure_and_blocks_new_work_until_cleanup() {
        let registry = registry();
        let backend = FakeBackend::default();
        ensure_tenant(&registry, &backend, "t1", "op-1", 100)
            .await
            .unwrap();
        *backend.fail_rsa_create.lock().await = true;
        *backend.fail_delete.lock().await = true;

        assert!(matches!(
            rotate_tenant(&registry, &backend, "t1", "op-2", 200).await,
            Err(ProvisioningError::BackendPermanent(_))
        ));
        assert!(matches!(
            rotate_tenant(&registry, &backend, "t1", "op-3", 201).await,
            Err(ProvisioningError::BackendTransient(_))
        ));

        *backend.fail_delete.lock().await = false;
        assert!(matches!(
            rotate_tenant(&registry, &backend, "t1", "op-2", 202).await,
            Err(ProvisioningError::BackendPermanent(_))
        ));
        let record = registry.get("t1").await.unwrap().unwrap();
        assert_eq!(record.lifecycle, TenantKeyLifecycle::Ready);
        assert_eq!(record.last_completed_operation_id.as_deref(), Some("op-1"));
        assert!(!record.last_failure.as_ref().unwrap().cleanup_pending);
    }

    #[tokio::test]
    async fn rollback_before_activation_deletes_candidate_pair_once() {
        let registry = registry();
        let backend = FakeBackend::default();
        ensure_tenant(&registry, &backend, "t1", "op-1", 100)
            .await
            .unwrap();
        rotate_tenant(&registry, &backend, "t1", "op-2", 200)
            .await
            .unwrap();

        let rolled_back = rollback_tenant(&registry, &backend, "t1", "op-2", 201)
            .await
            .unwrap();
        assert_eq!(rolled_back.lifecycle, TenantKeyLifecycle::Ready);
        assert_eq!(rolled_back.ready_snapshot().unwrap().generation, 1);
        assert_eq!(backend.deleted.lock().await.len(), 2);

        rollback_tenant(&registry, &backend, "t1", "op-2", 202)
            .await
            .unwrap();
        assert_eq!(backend.deleted.lock().await.len(), 2);
    }

    #[tokio::test]
    async fn rollback_commits_safe_snapshot_before_retryable_key_cleanup() {
        let registry = registry();
        let backend = FakeBackend::default();
        ensure_tenant(&registry, &backend, "t1", "op-1", 100)
            .await
            .unwrap();
        rotate_tenant(&registry, &backend, "t1", "op-2", 200)
            .await
            .unwrap();
        *backend.fail_delete.lock().await = true;

        assert!(matches!(
            rollback_tenant(&registry, &backend, "t1", "op-2", 201).await,
            Err(ProvisioningError::BackendTransient(_))
        ));
        let safe = registry.get("t1").await.unwrap().unwrap();
        assert_eq!(safe.lifecycle, TenantKeyLifecycle::Ready);
        assert_eq!(safe.ready_snapshot().unwrap().generation, 1);
        assert_eq!(safe.pending_deletion_arns.len(), 2);

        *backend.fail_delete.lock().await = false;
        let reconciled = reconcile_tenant(&registry, &backend, "t1", 202)
            .await
            .unwrap()
            .unwrap();
        assert!(reconciled.pending_deletion_arns.is_empty());
        assert_eq!(backend.deleted.lock().await.len(), 2);
    }

    #[tokio::test]
    async fn activated_rotation_can_rollback_then_retires_candidate_pair() {
        let registry = registry();
        let backend = FakeBackend::default();
        ensure_tenant(&registry, &backend, "t1", "op-1", 100)
            .await
            .unwrap();
        rotate_tenant(&registry, &backend, "t1", "op-2", 200)
            .await
            .unwrap();
        activate_tenant(&registry, "t1", "op-2", 800).await.unwrap();
        let overlap = rollback_tenant(&registry, &backend, "t1", "op-2", 801)
            .await
            .unwrap();
        assert_eq!(overlap.lifecycle, TenantKeyLifecycle::RollbackOverlap);
        assert!(backend.deleted.lock().await.is_empty());

        let retired = reconcile_tenant(&registry, &backend, "t1", 801 + TOKEN_OVERLAP_SECS)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retired.lifecycle, TenantKeyLifecycle::Ready);
        assert_eq!(retired.ready_snapshot().unwrap().generation, 1);
        assert_eq!(backend.deleted.lock().await.len(), 2);

        let repeated = rollback_tenant(
            &registry,
            &backend,
            "t1",
            "op-2",
            801 + TOKEN_OVERLAP_SECS + 1,
        )
        .await
        .unwrap();
        assert_eq!(repeated.ready_snapshot().unwrap().generation, 1);
    }

    #[tokio::test]
    async fn forward_retirement_is_not_misreported_as_an_idempotent_rollback() {
        let registry = registry();
        let backend = FakeBackend::default();
        ensure_tenant(&registry, &backend, "t1", "op-1", 100)
            .await
            .unwrap();
        rotate_tenant(&registry, &backend, "t1", "op-2", 200)
            .await
            .unwrap();
        activate_tenant(&registry, "t1", "op-2", 800).await.unwrap();
        let retired = reconcile_tenant(&registry, &backend, "t1", 800 + TOKEN_OVERLAP_SECS)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retired.ready_snapshot().unwrap().generation, 2);
        assert_eq!(
            retired.last_completed_outcome,
            Some(TenantKeyCompletionOutcome::RetiredForward)
        );

        assert!(matches!(
            rollback_tenant(
                &registry,
                &backend,
                "t1",
                "op-2",
                800 + TOKEN_OVERLAP_SECS + 1,
            )
            .await,
            Err(ProvisioningError::InvalidState)
        ));
        let current = registry.get("t1").await.unwrap().unwrap();
        assert_eq!(current.ready_snapshot().unwrap().generation, 2);

        let mut legacy_json = serde_json::to_value(retired).unwrap();
        legacy_json
            .as_object_mut()
            .unwrap()
            .remove("last_completed_outcome");
        let legacy_record: TenantKeyRecord = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(legacy_record.last_completed_outcome, None);
        let legacy_registry = TenantKeyRegistryImpl::Memory(MemoryTenantKeyRegistry::default());
        assert!(legacy_registry.create(legacy_record).await.unwrap());
        assert!(matches!(
            rollback_tenant(
                &legacy_registry,
                &FakeBackend::default(),
                "t1",
                "op-2",
                800 + TOKEN_OVERLAP_SECS + 1,
            )
            .await,
            Err(ProvisioningError::InvalidState)
        ));
    }

    #[tokio::test]
    async fn completed_rotation_command_is_idempotent_after_retirement() {
        let registry = registry();
        let backend = FakeBackend::default();
        ensure_tenant(&registry, &backend, "t1", "op-1", 100)
            .await
            .unwrap();
        rotate_tenant(&registry, &backend, "t1", "op-2", 200)
            .await
            .unwrap();
        activate_tenant(&registry, "t1", "op-2", 800).await.unwrap();
        let retired = reconcile_tenant(&registry, &backend, "t1", 800 + TOKEN_OVERLAP_SECS)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retired.ready_snapshot().unwrap().generation, 2);
        assert_eq!(backend.deleted.lock().await.len(), 2);

        let repeated = rotate_tenant(&registry, &backend, "t1", "op-2", 2_000)
            .await
            .unwrap();
        assert_eq!(repeated.ready_snapshot().unwrap().generation, 2);
        assert!(repeated.operation.is_none());
        assert_eq!(backend.deleted.lock().await.len(), 2);
    }

    #[tokio::test]
    async fn offboarding_revokes_snapshot_before_retryable_kms_cleanup() {
        let registry = registry();
        let backend = FakeBackend::default();
        ensure_tenant(&registry, &backend, "t1", "op-1", 100)
            .await
            .unwrap();
        backend
            .discovered_ec
            .lock()
            .await
            .push("arn:orphan:ec".to_string());
        *backend.fail_delete.lock().await = true;

        assert!(matches!(
            offboard_tenant(&registry, &backend, "t1", "offboard-1", 200).await,
            Err(ProvisioningError::BackendTransient(_))
        ));
        let disabled = registry.get("t1").await.unwrap().unwrap();
        assert_eq!(disabled.lifecycle, TenantKeyLifecycle::Offboarding);
        assert!(disabled.ready_snapshot().is_err());
        assert!(disabled.served_snapshot.is_none());
        assert!(disabled
            .pending_deletion_arns
            .contains(&"arn:orphan:ec".to_string()));

        let command = TenantKeyCommand {
            tenant_id: "t1".to_string(),
            action: TenantKeyCommandAction::Reconcile,
            operation_id: "onboard-t1-v1".to_string(),
            requested_at: 201,
            governance_dispatch: None,
        };
        *backend.fail_delete.lock().await = false;
        let unchanged = execute_command(&registry, &backend, &command, 201)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.lifecycle, TenantKeyLifecycle::Offboarding);
        assert!(backend.deleted.lock().await.is_empty());

        let completed = offboard_tenant(&registry, &backend, "t1", "offboard-1", 201)
            .await
            .unwrap();
        assert_eq!(completed.lifecycle, TenantKeyLifecycle::Offboarded);
        assert!(completed.pending_deletion_arns.is_empty());
        assert_eq!(
            completed.scheduled_deletion_arns.len(),
            backend.deleted.lock().await.len()
        );

        let created_before = *backend.created.lock().await;
        let repeated = execute_command(&registry, &backend, &command, 202)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(repeated.lifecycle, TenantKeyLifecycle::Offboarded);
        assert_eq!(*backend.created.lock().await, created_before);
    }

    #[tokio::test]
    async fn offboarding_redelivery_recovers_after_provider_success_before_registry_commit() {
        let memory_registry = MemoryTenantKeyRegistry::default();
        let registry = TenantKeyRegistryImpl::Memory(memory_registry.clone());
        let backend = FakeBackend::default();
        ensure_tenant(&registry, &backend, "t1", "op-1", 100)
            .await
            .unwrap();

        *backend.fail_delete.lock().await = true;
        assert!(matches!(
            offboard_tenant(&registry, &backend, "t1", "offboard-1", 200).await,
            Err(ProvisioningError::BackendTransient(_))
        ));
        *backend.fail_delete.lock().await = false;

        memory_registry.fail_next_compare_and_swaps(1);
        assert_eq!(
            offboard_tenant(&registry, &backend, "t1", "offboard-1", 201).await,
            Err(ProvisioningError::Busy)
        );
        let first_dispatch_count = backend.deleted.lock().await.len();
        assert!(first_dispatch_count > 0);

        let completed = offboard_tenant(&registry, &backend, "t1", "offboard-1", 202)
            .await
            .unwrap();
        assert_eq!(completed.lifecycle, TenantKeyLifecycle::Offboarded);
        assert_eq!(
            backend.deleted.lock().await.len(),
            first_dispatch_count * 2,
            "provider scheduling must tolerate replay after an ambiguous local commit"
        );
    }

    #[tokio::test]
    async fn offboarding_missing_registry_records_discovered_keys_before_deletion() {
        let registry = registry();
        let backend = FakeBackend::default();
        backend
            .discovered_rsa
            .lock()
            .await
            .push("arn:orphan:rsa".to_string());

        let completed = offboard_tenant(&registry, &backend, "t1", "offboard-1", 100)
            .await
            .unwrap();
        assert_eq!(completed.lifecycle, TenantKeyLifecycle::Offboarded);
        assert_eq!(
            completed.scheduled_deletion_arns,
            vec!["arn:orphan:rsa".to_string()]
        );
        assert_eq!(backend.deleted.lock().await.as_slice(), ["arn:orphan:rsa"]);
    }
}
