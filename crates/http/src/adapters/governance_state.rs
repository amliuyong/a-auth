//! Shared governance transitions; persistence owns locking and commit.

use crate::ports::StoreError;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Default)]
pub(crate) struct GovernanceState {
    pub(crate) policies: BTreeMap<String, crate::governance::GovernancePolicyRecord>,
    pub(crate) manifests: BTreeMap<(String, String), crate::governance::GovernanceExportManifest>,
    pub(crate) jobs: BTreeMap<(String, String), crate::governance::GovernanceJobRecord>,
    pub(crate) job_leases: BTreeMap<(String, String), crate::governance::GovernanceJobLeaseRecord>,
    pub(crate) mutation_gates: BTreeMap<String, crate::governance::TenantMutationGateRecord>,
    pub(crate) mutation_permits:
        BTreeMap<(String, String), crate::governance::TenantMutationPermit>,
    pub(crate) continuations:
        BTreeMap<(String, String), crate::governance::GovernanceContinuationRecord>,
    pub(crate) continuation_jtis: BTreeSet<(String, String, String)>,
    pub(crate) evidence:
        BTreeMap<(String, String, u64), crate::governance::GovernanceEvidenceRecord>,
    pub(crate) tenant_lifecycles: BTreeMap<String, crate::governance::TenantLifecycleRecord>,
    pub(crate) external_actions:
        BTreeMap<(String, String, String), crate::governance::GovernanceExternalActionRecord>,
    pub(crate) suppressions: BTreeSet<(String, String, String, u64)>,
    #[cfg(test)]
    pub(crate) fail_next_job_update: bool,
}

pub(crate) const MEMORY_GOVERNANCE_DESTRUCTIVE_FENCE_CONFLICT: &str =
    "governance destructive fence conflict";

pub(crate) fn prune_expired_mutation_permits(
    state: &mut GovernanceState,
    tenant_id: &str,
    now: i64,
) -> Result<u64, StoreError> {
    let before = state.mutation_permits.len();
    state
        .mutation_permits
        .retain(|(tenant, _), permit| tenant != tenant_id || permit.deadline > now);
    let removed = before.saturating_sub(state.mutation_permits.len());
    let active = state
        .mutation_permits
        .keys()
        .filter(|(tenant, _)| tenant == tenant_id)
        .count();
    let active = u64::try_from(active)
        .map_err(|_| StoreError::Permanent("tenant mutation permit count exceeds u64".into()))?;
    if let Some(gate) = state.mutation_gates.get_mut(tenant_id) {
        if gate.active_permits != active {
            gate.active_permits = active;
            gate.revision = gate.revision.checked_add(1).ok_or_else(|| {
                StoreError::Permanent("tenant mutation gate revision exhausted".into())
            })?;
            gate.updated_at = now;
        } else if removed > 0 {
            return Err(StoreError::Permanent(
                "tenant mutation gate count did not include expired permits".into(),
            ));
        }
    } else if active > 0 {
        return Err(StoreError::Permanent(
            "tenant mutation permits exist without their gate".into(),
        ));
    }
    Ok(active)
}

pub(crate) fn governance_destructive_fence_matches(
    state: &GovernanceState,
    tenant_id: &str,
    fence: &crate::governance::GovernanceDestructiveFence,
    now: i64,
) -> bool {
    use crate::governance::{GovernanceJobState, LegalHoldState, TenantLifecycleState};

    let policy_matches = match state.policies.get(tenant_id) {
        Some(policy) => {
            fence.policy_revision != 0
                && policy.tenant_id == tenant_id
                && policy.revision == fence.policy_revision
                && policy.legal_hold == LegalHoldState::Disabled
        }
        None => fence.policy_revision == 0,
    };
    let job_matches = state
        .jobs
        .get(&(tenant_id.to_string(), fence.job_id.clone()))
        .is_some_and(|job| {
            job.tenant_id == tenant_id
                && job.job_id == fence.job_id
                && job.revision == fence.job_revision
                && job.policy_revision == fence.policy_revision
                && job.tenant_revision == fence.tenant_revision
                && matches!(
                    job.state,
                    GovernanceJobState::Queued
                        | GovernanceJobState::Running
                        | GovernanceJobState::Retryable
                )
                && fence
                    .target_epoch
                    .is_none_or(|target_epoch| target_epoch == job.target_epoch)
        });
    let lease_matches = state
        .job_leases
        .get(&(tenant_id.to_string(), fence.job_id.clone()))
        .is_some_and(|lease| {
            lease.tenant_id == tenant_id
                && lease.job_id == fence.job_id
                && lease.job_revision == fence.job_revision
                && lease.policy_revision == fence.policy_revision
                && lease.tenant_revision == fence.tenant_revision
                && lease.token_digest == fence.lease_token_digest
                && lease.deadline == fence.lease_deadline
                && lease.deadline > now
        });
    let lifecycle_matches = match state.tenant_lifecycles.get(tenant_id) {
        Some(lifecycle) if fence.tenant_revision == 0 => {
            lifecycle.tenant_id == tenant_id && lifecycle.state == TenantLifecycleState::Active
        }
        None if fence.tenant_revision == 0 => true,
        Some(lifecycle) => {
            lifecycle.tenant_id == tenant_id
                && lifecycle.state == TenantLifecycleState::Offboarding
                && lifecycle.revision == fence.tenant_revision
        }
        None => false,
    };

    policy_matches && job_matches && lease_matches && lifecycle_matches
}

pub(crate) fn governance_external_fence_matches(
    state: &GovernanceState,
    tenant_id: &str,
    fence: &crate::governance::GovernanceExternalActionFence,
    now: i64,
) -> bool {
    let policy = state
        .policies
        .get(tenant_id)
        .cloned()
        .unwrap_or_else(|| crate::governance::GovernancePolicyRecord::default_for(tenant_id));
    let job = state
        .jobs
        .get(&(tenant_id.to_string(), fence.job_id.clone()));
    let lease = state
        .job_leases
        .get(&(tenant_id.to_string(), fence.job_id.clone()));
    let lifecycle = state.tenant_lifecycles.get(tenant_id);
    policy.revision == fence.policy_revision
        && !policy.held()
        && job.is_some_and(|job| {
            job.revision == fence.job_revision
                && job.policy_revision == fence.policy_revision
                && job.tenant_revision == fence.tenant_revision
                && job.kind == crate::governance::GovernanceJobKind::TenantOffboarding
                && matches!(
                    job.state,
                    crate::governance::GovernanceJobState::Running
                        | crate::governance::GovernanceJobState::Retryable
                )
        })
        && lease.is_some_and(|lease| {
            lease.job_revision == fence.job_revision
                && lease.policy_revision == fence.policy_revision
                && lease.tenant_revision == fence.tenant_revision
                && lease.token_digest == fence.lease_token_digest
                && lease.deadline == fence.lease_deadline
                && lease.deadline > now
        })
        && lifecycle.is_some_and(|lifecycle| {
            lifecycle.state == crate::governance::TenantLifecycleState::Offboarding
                && lifecycle.revision == fence.tenant_revision
        })
}

pub(crate) fn governance_job_authority_conflict(
    state: &GovernanceState,
    tenant_id: &str,
    job_id: &str,
    expected_job_revision: u64,
) -> Option<crate::governance::GovernanceJobLeaseConflict> {
    use crate::governance::{GovernanceJobLeaseConflict, GovernanceJobState};

    let Some(job) = state.jobs.get(&(tenant_id.to_string(), job_id.to_string())) else {
        return Some(GovernanceJobLeaseConflict::Job);
    };
    let policy = state
        .policies
        .get(tenant_id)
        .cloned()
        .unwrap_or_else(|| crate::governance::GovernancePolicyRecord::default_for(tenant_id));
    if policy.revision != job.policy_revision || policy.held() {
        return Some(GovernanceJobLeaseConflict::Policy);
    }
    if job.revision != expected_job_revision
        || !matches!(
            job.state,
            GovernanceJobState::Queued
                | GovernanceJobState::Running
                | GovernanceJobState::Retryable
        )
    {
        return Some(GovernanceJobLeaseConflict::Job);
    }
    let lifecycle_conflict = match state.tenant_lifecycles.get(tenant_id) {
        Some(lifecycle) if job.tenant_revision == 0 => {
            lifecycle.state != crate::governance::TenantLifecycleState::Active
        }
        None if job.tenant_revision == 0 => false,
        Some(lifecycle) => {
            lifecycle.state != crate::governance::TenantLifecycleState::Offboarding
                || lifecycle.revision != job.tenant_revision
        }
        None => true,
    };
    if lifecycle_conflict {
        return Some(GovernanceJobLeaseConflict::TenantLifecycle);
    }
    None
}

pub(crate) fn governance_external_reconcile_fence_matches(
    state: &GovernanceState,
    tenant_id: &str,
    fence: &crate::governance::GovernanceExternalActionReconcileFence,
) -> bool {
    let job = state
        .jobs
        .get(&(tenant_id.to_string(), fence.job_id.clone()));
    let lifecycle = state.tenant_lifecycles.get(tenant_id);
    job.is_some_and(|job| {
        job.tenant_revision == fence.tenant_revision
            && job.kind == crate::governance::GovernanceJobKind::TenantOffboarding
    }) && lifecycle.is_some_and(|lifecycle| {
        lifecycle.state == crate::governance::TenantLifecycleState::Offboarding
            && lifecycle.revision == fence.tenant_revision
    })
}

fn same_external_action_identity(
    left: &crate::governance::GovernanceExternalActionRecord,
    right: &crate::governance::GovernanceExternalActionRecord,
) -> bool {
    left.action_id == right.action_id
        && left.tenant_id == right.tenant_id
        && left.job_id == right.job_id
        && left.kind == right.kind
        && left.resource_ref == right.resource_ref
        && left.resource_fingerprint == right.resource_fingerprint
        && left.ownership == right.ownership
}

fn valid_external_dispatch_transition(
    current: &crate::governance::GovernanceExternalActionRecord,
    next: &crate::governance::GovernanceExternalActionRecord,
) -> bool {
    use crate::governance::{GovernanceExternalActionState, GovernanceResourceOwnership};

    let claimed = matches!(
        (current.state, next.state),
        (
            GovernanceExternalActionState::Prepared
                | GovernanceExternalActionState::ClaimTombstoned,
            GovernanceExternalActionState::Claimed
        )
    ) && next.claim_token_digest.is_some()
        && next.claim_deadline.is_some()
        && next.committed_at.is_none()
        && next.verified_at.is_none()
        && (current.state != GovernanceExternalActionState::ClaimTombstoned
            || current.claim_token_digest != next.claim_token_digest);
    let external_verified = current.ownership == GovernanceResourceOwnership::External
        && current.state == GovernanceExternalActionState::OperatorPending
        && next.state == GovernanceExternalActionState::Verified
        && current.claim_token_digest.is_none()
        && next.claim_token_digest.is_none()
        && next.claim_deadline.is_none()
        && next.committed_at.is_none()
        && next.verified_at.is_some()
        && next.retention_until.is_none();
    claimed || external_verified
}

fn valid_external_reconcile_transition(
    current: &crate::governance::GovernanceExternalActionRecord,
    next: &crate::governance::GovernanceExternalActionRecord,
) -> bool {
    use crate::governance::GovernanceExternalActionState;

    matches!(
        (current.state, next.state),
        (
            GovernanceExternalActionState::Claimed,
            GovernanceExternalActionState::ClaimTombstoned
                | GovernanceExternalActionState::ExternalPreparationDispatched
                | GovernanceExternalActionState::ExternallyCommitted
                | GovernanceExternalActionState::Verified
        ) | (
            GovernanceExternalActionState::ExternalPreparationDispatched,
            GovernanceExternalActionState::ClaimTombstoned
                | GovernanceExternalActionState::ExternallyCommitted
                | GovernanceExternalActionState::Verified
        ) | (
            GovernanceExternalActionState::ExternallyCommitted,
            GovernanceExternalActionState::Verified
        )
    ) && current.claim_token_digest.is_some()
        && current.claim_token_digest == next.claim_token_digest
        && current.claim_deadline == next.claim_deadline
}

impl GovernanceState {
    pub(crate) fn acquire_tenant_mutation_permit(
        &mut self,
        permit: crate::governance::TenantMutationPermit,
        now: i64,
    ) -> Result<crate::governance::TenantMutationPermitAcquireOutcome, StoreError> {
        use crate::governance::{
            TenantLifecycleState, TenantMutationGateRecord, TenantMutationGateState,
            TenantMutationPermitAcquireOutcome,
        };

        if permit.tenant_id.is_empty()
            || permit.permit_id.is_empty()
            || permit.permit_id.len() > 128
            || permit.deadline <= now
        {
            return Err(StoreError::Permanent(
                "invalid tenant mutation permit".into(),
            ));
        }
        let state = self;
        prune_expired_mutation_permits(state, &permit.tenant_id, now)?;
        let lifecycle_revision = state
            .tenant_lifecycles
            .get(&permit.tenant_id)
            .filter(|record| record.state == TenantLifecycleState::Offboarding)
            .map(|record| record.revision);
        if lifecycle_revision.is_some()
            || state
                .mutation_gates
                .get(&permit.tenant_id)
                .is_some_and(|gate| gate.state == TenantMutationGateState::Frozen)
        {
            return Ok(TenantMutationPermitAcquireOutcome::Frozen { lifecycle_revision });
        }
        let key = (permit.tenant_id.clone(), permit.permit_id.clone());
        if state.mutation_permits.contains_key(&key) {
            return Err(StoreError::Transient(
                "tenant mutation permit identifier collided; retry".into(),
            ));
        }
        state.mutation_permits.insert(key, permit.clone());
        let gate = state
            .mutation_gates
            .entry(permit.tenant_id.clone())
            .or_insert(TenantMutationGateRecord {
                tenant_id: permit.tenant_id.clone(),
                state: TenantMutationGateState::Active,
                active_permits: 0,
                revision: 0,
                updated_at: now,
            });
        gate.active_permits = gate.active_permits.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("tenant mutation permit count exhausted".into())
        })?;
        gate.revision = gate.revision.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("tenant mutation gate revision exhausted".into())
        })?;
        gate.updated_at = now;
        Ok(TenantMutationPermitAcquireOutcome::Acquired(permit))
    }

    pub(crate) fn renew_tenant_mutation_permit(
        &mut self,
        permit: &crate::governance::TenantMutationPermit,
        now: i64,
        deadline: i64,
    ) -> Result<bool, StoreError> {
        if deadline <= now || deadline <= permit.deadline {
            return Err(StoreError::Permanent(
                "invalid tenant mutation permit renewal".into(),
            ));
        }
        let state = self;
        let Some(current) = state
            .mutation_permits
            .get_mut(&(permit.tenant_id.clone(), permit.permit_id.clone()))
        else {
            return Ok(false);
        };
        if current.deadline != permit.deadline || current.deadline <= now {
            return Ok(false);
        }
        current.deadline = deadline;
        Ok(true)
    }

    pub(crate) fn release_tenant_mutation_permit(
        &mut self,
        permit: crate::governance::TenantMutationPermit,
        now: i64,
    ) -> Result<bool, StoreError> {
        let state = self;
        let key = (permit.tenant_id.clone(), permit.permit_id.clone());
        if state
            .mutation_permits
            .get(&key)
            .is_none_or(|current| current.deadline != permit.deadline)
        {
            return Ok(false);
        }
        let gate = state
            .mutation_gates
            .get_mut(&permit.tenant_id)
            .ok_or_else(|| {
                StoreError::Permanent("tenant mutation permit has no aggregate gate".into())
            })?;
        if gate.state != crate::governance::TenantMutationGateState::Active
            || gate.active_permits == 0
        {
            return Err(StoreError::Permanent(
                "tenant mutation gate count is inconsistent".into(),
            ));
        }
        gate.active_permits -= 1;
        gate.revision = gate.revision.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("tenant mutation gate revision exhausted".into())
        })?;
        gate.updated_at = now;
        state.mutation_permits.remove(&key);
        Ok(true)
    }

    pub(crate) fn get_policy(
        &mut self,
        tenant_id: &str,
    ) -> Result<Option<crate::governance::GovernancePolicyRecord>, StoreError> {
        Ok(self.policies.get(tenant_id).cloned())
    }

    pub(crate) fn put_policy(
        &mut self,
        mut record: crate::governance::GovernancePolicyRecord,
        expected_revision: u64,
    ) -> Result<crate::governance::GovernancePolicyPutOutcome, StoreError> {
        let state = self;
        let current = state
            .policies
            .get(&record.tenant_id)
            .cloned()
            .unwrap_or_else(|| {
                crate::governance::GovernancePolicyRecord::default_for(&record.tenant_id)
            });
        if current.revision != expected_revision {
            return Ok(crate::governance::GovernancePolicyPutOutcome::Conflict(
                current,
            ));
        }
        record.revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("governance policy revision exhausted".into()))?;
        state
            .policies
            .insert(record.tenant_id.clone(), record.clone());
        Ok(crate::governance::GovernancePolicyPutOutcome::Stored(
            record,
        ))
    }

    pub(crate) fn put_export_manifest(
        &mut self,
        manifest: crate::governance::GovernanceExportManifest,
    ) -> Result<bool, StoreError> {
        let key = (manifest.tenant_id.clone(), manifest.export_id.clone());
        let state = self;
        if state.manifests.contains_key(&key) {
            return Ok(false);
        }
        state.manifests.insert(key, manifest);
        Ok(true)
    }

    pub(crate) fn get_export_manifest(
        &mut self,
        tenant_id: &str,
        export_id: &str,
        now: i64,
    ) -> Result<Option<crate::governance::GovernanceExportManifest>, StoreError> {
        let key = (tenant_id.to_string(), export_id.to_string());
        let state = self;
        let manifest = state.manifests.get(&key).cloned();
        if manifest
            .as_ref()
            .is_some_and(|manifest| manifest.expires_at <= now)
        {
            state.manifests.remove(&key);
            return Ok(None);
        }
        Ok(manifest)
    }

    pub(crate) fn start_or_resume_job(
        &mut self,
        mut job: crate::governance::GovernanceJobRecord,
        expected_policy_revision: u64,
        freeze_tenant: bool,
    ) -> Result<crate::governance::GovernanceJobStartOutcome, StoreError> {
        let state = self;
        let policy = state
            .policies
            .get(&job.tenant_id)
            .cloned()
            .unwrap_or_else(|| {
                crate::governance::GovernancePolicyRecord::default_for(&job.tenant_id)
            });
        if policy.revision != expected_policy_revision {
            return Ok(crate::governance::GovernanceJobStartOutcome::PolicyConflict(policy));
        }
        let key = (job.tenant_id.clone(), job.job_id.clone());
        if let Some(mut existing) = state.jobs.get(&key).cloned() {
            let lifecycle = state.tenant_lifecycles.get(&job.tenant_id).cloned();
            if job.tenant_revision == 0 {
                if let Some(lifecycle) = lifecycle.filter(|lifecycle| {
                    lifecycle.state == crate::governance::TenantLifecycleState::Offboarding
                }) {
                    return Ok(crate::governance::GovernanceJobStartOutcome::TenantFrozen {
                        lifecycle_revision: lifecycle.revision,
                    });
                }
            } else {
                if lifecycle.as_ref().is_none_or(|lifecycle| {
                    lifecycle.state != crate::governance::TenantLifecycleState::Offboarding
                        || lifecycle.revision != job.tenant_revision
                }) {
                    return Err(StoreError::Permanent(
                        "offboarding child job has no matching tenant lifecycle".into(),
                    ));
                }
                if existing.tenant_revision == 0
                    && !matches!(
                        existing.state,
                        crate::governance::GovernanceJobState::RetentionPending
                            | crate::governance::GovernanceJobState::Completed
                    )
                {
                    if existing.kind != job.kind
                        || existing.target_id != job.target_id
                        || existing.target_epoch != job.target_epoch
                    {
                        return Err(StoreError::Permanent(
                            "offboarding child job identity mismatch".into(),
                        ));
                    }
                    existing.tenant_revision = job.tenant_revision;
                    existing.policy_revision = policy.revision;
                    if existing.state == crate::governance::GovernanceJobState::BlockedLegalHold {
                        existing.state = crate::governance::GovernanceJobState::Queued;
                    }
                    existing.revision = existing.revision.checked_add(1).ok_or_else(|| {
                        StoreError::Permanent("governance job revision exhausted".into())
                    })?;
                    existing.updated_at = job.updated_at;
                    state.jobs.insert(key, existing.clone());
                    return Ok(crate::governance::GovernanceJobStartOutcome::Existing(
                        existing,
                    ));
                }
                if existing.tenant_revision != 0 && existing.tenant_revision != job.tenant_revision
                {
                    return Err(StoreError::Permanent(
                        "offboarding child job tenant lifecycle mismatch".into(),
                    ));
                }
            }
            if existing.state != crate::governance::GovernanceJobState::BlockedLegalHold
                || policy.held()
            {
                return Ok(crate::governance::GovernanceJobStartOutcome::Existing(
                    existing,
                ));
            }
            existing.state = crate::governance::GovernanceJobState::Queued;
            existing.policy_revision = policy.revision;
            existing.revision = existing
                .revision
                .checked_add(1)
                .ok_or_else(|| StoreError::Permanent("governance job revision exhausted".into()))?;
            existing.updated_at = job.updated_at;
            if freeze_tenant {
                let active = prune_expired_mutation_permits(state, &job.tenant_id, job.updated_at)?;
                if active > 0 {
                    return Ok(
                        crate::governance::GovernanceJobStartOutcome::MutationConflict {
                            active_permits: active,
                        },
                    );
                }
                let revision = match state.tenant_lifecycles.get(&job.tenant_id) {
                    Some(record)
                        if record.state == crate::governance::TenantLifecycleState::Offboarding =>
                    {
                        record.revision
                    }
                    Some(record) => record.revision.checked_add(1).ok_or_else(|| {
                        StoreError::Permanent("tenant lifecycle revision exhausted".into())
                    })?,
                    None => 1,
                };
                state.tenant_lifecycles.insert(
                    job.tenant_id.clone(),
                    crate::governance::TenantLifecycleRecord {
                        tenant_id: job.tenant_id.clone(),
                        state: crate::governance::TenantLifecycleState::Offboarding,
                        revision,
                        updated_at: job.updated_at,
                    },
                );
                existing.tenant_revision = revision;
                let continuation =
                    crate::governance::GovernanceContinuationRecord::for_offboarding_job(&existing)
                        .map_err(StoreError::Permanent)?;
                if state.continuations.get(&key).is_some_and(|current| {
                    current.tenant_id != continuation.tenant_id
                        || current.job_id != continuation.job_id
                        || current.tenant_revision != continuation.tenant_revision
                }) {
                    return Err(StoreError::Permanent(
                        "offboarding continuation identity mismatch".into(),
                    ));
                }
                state
                    .continuations
                    .entry(key.clone())
                    .or_insert(continuation);
                let gate = state.mutation_gates.entry(job.tenant_id.clone()).or_insert(
                    crate::governance::TenantMutationGateRecord {
                        tenant_id: job.tenant_id.clone(),
                        state: crate::governance::TenantMutationGateState::Active,
                        active_permits: 0,
                        revision: 0,
                        updated_at: job.updated_at,
                    },
                );
                gate.state = crate::governance::TenantMutationGateState::Frozen;
                gate.revision = gate.revision.checked_add(1).ok_or_else(|| {
                    StoreError::Permanent("tenant mutation gate revision exhausted".into())
                })?;
                gate.updated_at = job.updated_at;
            }
            state.jobs.insert(key, existing.clone());
            return Ok(crate::governance::GovernanceJobStartOutcome::Existing(
                existing,
            ));
        }

        if !freeze_tenant {
            if job.tenant_revision == 0 {
                if let Some(lifecycle) =
                    state
                        .tenant_lifecycles
                        .get(&job.tenant_id)
                        .filter(|lifecycle| {
                            lifecycle.state == crate::governance::TenantLifecycleState::Offboarding
                        })
                {
                    return Ok(crate::governance::GovernanceJobStartOutcome::TenantFrozen {
                        lifecycle_revision: lifecycle.revision,
                    });
                }
            } else if state
                .tenant_lifecycles
                .get(&job.tenant_id)
                .is_none_or(|lifecycle| {
                    lifecycle.state != crate::governance::TenantLifecycleState::Offboarding
                        || lifecycle.revision != job.tenant_revision
                })
            {
                return Err(StoreError::Permanent(
                    "offboarding child job has no matching tenant lifecycle".into(),
                ));
            }
        }
        if policy.held() {
            job.state = crate::governance::GovernanceJobState::BlockedLegalHold;
        } else if freeze_tenant {
            let active = prune_expired_mutation_permits(state, &job.tenant_id, job.updated_at)?;
            if active > 0 {
                return Ok(
                    crate::governance::GovernanceJobStartOutcome::MutationConflict {
                        active_permits: active,
                    },
                );
            }
            let current_revision = state
                .tenant_lifecycles
                .get(&job.tenant_id)
                .map_or(0, |record| record.revision);
            let revision = current_revision.checked_add(1).ok_or_else(|| {
                StoreError::Permanent("tenant lifecycle revision exhausted".into())
            })?;
            state.tenant_lifecycles.insert(
                job.tenant_id.clone(),
                crate::governance::TenantLifecycleRecord {
                    tenant_id: job.tenant_id.clone(),
                    state: crate::governance::TenantLifecycleState::Offboarding,
                    revision,
                    updated_at: job.updated_at,
                },
            );
            job.tenant_revision = revision;
            let continuation =
                crate::governance::GovernanceContinuationRecord::for_offboarding_job(&job)
                    .map_err(StoreError::Permanent)?;
            state.continuations.insert(key.clone(), continuation);
            let gate = state.mutation_gates.entry(job.tenant_id.clone()).or_insert(
                crate::governance::TenantMutationGateRecord {
                    tenant_id: job.tenant_id.clone(),
                    state: crate::governance::TenantMutationGateState::Active,
                    active_permits: 0,
                    revision: 0,
                    updated_at: job.updated_at,
                },
            );
            gate.state = crate::governance::TenantMutationGateState::Frozen;
            gate.revision = gate.revision.checked_add(1).ok_or_else(|| {
                StoreError::Permanent("tenant mutation gate revision exhausted".into())
            })?;
            gate.updated_at = job.updated_at;
        }
        job.policy_revision = policy.revision;
        state.jobs.insert(key, job.clone());
        Ok(crate::governance::GovernanceJobStartOutcome::Stored(job))
    }

    pub(crate) fn get_job(
        &mut self,
        tenant_id: &str,
        job_id: &str,
    ) -> Result<Option<crate::governance::GovernanceJobRecord>, StoreError> {
        Ok(self
            .jobs
            .get(&(tenant_id.to_string(), job_id.to_string()))
            .cloned())
    }

    pub(crate) fn list_jobs(
        &mut self,
        tenant_id: &str,
    ) -> Result<Vec<crate::governance::GovernanceJobRecord>, StoreError> {
        Ok(self
            .jobs
            .iter()
            .filter_map(|((tenant, _), record)| (tenant == tenant_id).then_some(record.clone()))
            .collect())
    }

    pub(crate) fn get_continuation(
        &mut self,
        tenant_id: &str,
        job_id: &str,
    ) -> Result<Option<crate::governance::GovernanceContinuationRecord>, StoreError> {
        Ok(self
            .continuations
            .get(&(tenant_id.to_string(), job_id.to_string()))
            .cloned())
    }

    pub(crate) fn update_continuation(
        &mut self,
        mut record: crate::governance::GovernanceContinuationRecord,
        expected_revision: u64,
    ) -> Result<crate::governance::GovernanceContinuationUpdateOutcome, StoreError> {
        use crate::governance::GovernanceContinuationUpdateOutcome;

        let key = (record.tenant_id.clone(), record.job_id.clone());
        let state = self;
        let current =
            state.continuations.get(&key).cloned().ok_or_else(|| {
                StoreError::Permanent("governance continuation disappeared".into())
            })?;
        if current.revision != expected_revision {
            return Ok(GovernanceContinuationUpdateOutcome::Conflict(current));
        }
        if current.tenant_id != record.tenant_id
            || current.job_id != record.job_id
            || current.tenant_revision != record.tenant_revision
            || record.resume_revision < current.resume_revision
            || record.read_revision < current.read_revision
        {
            return Err(StoreError::Permanent(
                "governance continuation identity or revision regressed".into(),
            ));
        }
        record.revision = expected_revision.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("governance continuation revision exhausted".into())
        })?;
        state.continuations.insert(key, record.clone());
        Ok(GovernanceContinuationUpdateOutcome::Stored(record))
    }

    pub(crate) fn consume_continuation_resume(
        &mut self,
        tenant_id: &str,
        job_id: &str,
        jti_digest: &str,
        expected_resume_revision: u64,
        _expires_at: i64,
    ) -> Result<bool, StoreError> {
        if jti_digest.is_empty() {
            return Err(StoreError::Permanent(
                "governance continuation JTI digest is empty".into(),
            ));
        }
        let state = self;
        let continuation = state
            .continuations
            .get(&(tenant_id.to_string(), job_id.to_string()))
            .ok_or_else(|| StoreError::Permanent("governance continuation disappeared".into()))?;
        if !continuation.resume_enabled || continuation.resume_revision != expected_resume_revision
        {
            return Ok(false);
        }
        Ok(state.continuation_jtis.insert((
            tenant_id.to_string(),
            job_id.to_string(),
            jti_digest.to_string(),
        )))
    }

    pub(crate) fn update_job(
        &mut self,
        mut job: crate::governance::GovernanceJobRecord,
        expected_revision: u64,
        expected_policy_revision: u64,
    ) -> Result<crate::governance::GovernanceJobUpdateOutcome, StoreError> {
        use crate::governance::GovernanceJobUpdateOutcome;

        let state = self;
        #[cfg(test)]
        if std::mem::take(&mut state.fail_next_job_update) {
            return Err(StoreError::Transient(
                "injected governance job checkpoint failure".into(),
            ));
        }
        let policy = state
            .policies
            .get(&job.tenant_id)
            .cloned()
            .unwrap_or_else(|| {
                crate::governance::GovernancePolicyRecord::default_for(&job.tenant_id)
            });
        if policy.revision != expected_policy_revision {
            return Ok(GovernanceJobUpdateOutcome::PolicyConflict(policy));
        }
        let key = (job.tenant_id.clone(), job.job_id.clone());
        let current = state.jobs.get(&key).cloned().ok_or_else(|| {
            StoreError::Permanent("governance job disappeared during update".into())
        })?;
        if current.revision != expected_revision {
            return Ok(GovernanceJobUpdateOutcome::Conflict(current));
        }
        job.revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("governance job revision exhausted".into()))?;
        job.policy_revision = policy.revision;
        state.jobs.insert(key, job.clone());
        Ok(GovernanceJobUpdateOutcome::Stored(job))
    }

    pub(crate) fn complete_job_with_evidence(
        &mut self,
        mut job: crate::governance::GovernanceJobRecord,
        evidence: crate::governance::GovernanceEvidenceRecord,
        expected_revision: u64,
        expected_policy_revision: u64,
    ) -> Result<crate::governance::GovernanceJobUpdateOutcome, StoreError> {
        use crate::governance::GovernanceJobUpdateOutcome;

        if !evidence.verifies_completion_of(&job) || job.revision != expected_revision {
            return Err(StoreError::Permanent(
                "invalid governance job completion evidence".into(),
            ));
        }
        let state = self;
        #[cfg(test)]
        if std::mem::take(&mut state.fail_next_job_update) {
            return Err(StoreError::Transient(
                "injected governance job checkpoint failure".into(),
            ));
        }
        let policy = state
            .policies
            .get(&job.tenant_id)
            .cloned()
            .unwrap_or_else(|| {
                crate::governance::GovernancePolicyRecord::default_for(&job.tenant_id)
            });
        if policy.revision != expected_policy_revision {
            return Ok(GovernanceJobUpdateOutcome::PolicyConflict(policy));
        }
        if evidence.payload.legal_hold != policy.legal_hold {
            return Err(StoreError::Permanent(
                "governance completion evidence policy mismatch".into(),
            ));
        }
        let job_key = (job.tenant_id.clone(), job.job_id.clone());
        let current = state.jobs.get(&job_key).cloned().ok_or_else(|| {
            StoreError::Permanent("governance job disappeared during completion".into())
        })?;
        if current.revision != expected_revision {
            return Ok(GovernanceJobUpdateOutcome::Conflict(current));
        }
        let evidence_key = (
            evidence.payload.tenant_id.clone(),
            evidence.payload.job_id.clone(),
            evidence.payload.evidence_revision,
        );
        if state.evidence.contains_key(&evidence_key) {
            return Err(StoreError::Permanent(
                "governance completion evidence revision already exists".into(),
            ));
        }
        job.revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("governance job revision exhausted".into()))?;
        job.policy_revision = policy.revision;
        state.jobs.insert(job_key, job.clone());
        state.evidence.insert(evidence_key, evidence);
        Ok(GovernanceJobUpdateOutcome::Stored(job))
    }

    pub(crate) fn claim_job_lease(
        &mut self,
        tenant_id: &str,
        job_id: &str,
        expected_job_revision: u64,
        token_digest: &str,
        now: i64,
        deadline: i64,
    ) -> Result<crate::governance::GovernanceJobLeaseOutcome, StoreError> {
        use crate::governance::{GovernanceJobLeaseConflict, GovernanceJobLeaseOutcome};

        if token_digest.is_empty() || token_digest.len() > 128 || deadline <= now {
            return Err(StoreError::Permanent(
                "invalid governance job lease claim".into(),
            ));
        }
        let state = self;
        if let Some(conflict) =
            governance_job_authority_conflict(state, tenant_id, job_id, expected_job_revision)
        {
            return Ok(GovernanceJobLeaseOutcome::Conflict(conflict));
        }
        let key = (tenant_id.to_string(), job_id.to_string());
        if state
            .job_leases
            .get(&key)
            .is_some_and(|lease| lease.deadline > now)
        {
            return Ok(GovernanceJobLeaseOutcome::Conflict(
                GovernanceJobLeaseConflict::Lease,
            ));
        }
        let job = state
            .jobs
            .get(&key)
            .expect("authority check proved the governance job exists");
        let lease = crate::governance::GovernanceJobLeaseRecord {
            tenant_id: tenant_id.to_string(),
            job_id: job_id.to_string(),
            job_revision: expected_job_revision,
            policy_revision: job.policy_revision,
            tenant_revision: job.tenant_revision,
            token_digest: token_digest.to_string(),
            acquired_at: now,
            deadline,
        };
        state.job_leases.insert(key, lease.clone());
        Ok(GovernanceJobLeaseOutcome::Acquired(lease))
    }

    pub(crate) fn renew_job_lease(
        &mut self,
        tenant_id: &str,
        fence: crate::governance::GovernanceDestructiveFence,
        now: i64,
        deadline: i64,
    ) -> Result<crate::governance::GovernanceJobLeaseOutcome, StoreError> {
        use crate::governance::{GovernanceJobLeaseConflict, GovernanceJobLeaseOutcome};

        if deadline <= now || deadline <= fence.lease_deadline {
            return Err(StoreError::Permanent(
                "invalid governance job lease renewal".into(),
            ));
        }
        let state = self;
        if let Some(conflict) =
            governance_job_authority_conflict(state, tenant_id, &fence.job_id, fence.job_revision)
        {
            return Ok(GovernanceJobLeaseOutcome::Conflict(conflict));
        }
        let key = (tenant_id.to_string(), fence.job_id.clone());
        let Some(current) = state.job_leases.get(&key) else {
            return Ok(GovernanceJobLeaseOutcome::Conflict(
                GovernanceJobLeaseConflict::Lease,
            ));
        };
        if current.token_digest != fence.lease_token_digest
            || current.deadline != fence.lease_deadline
            || current.deadline <= now
            || current.policy_revision != fence.policy_revision
            || current.tenant_revision != fence.tenant_revision
        {
            return Ok(GovernanceJobLeaseOutcome::Conflict(
                GovernanceJobLeaseConflict::Lease,
            ));
        }
        let mut renewed = current.clone();
        renewed.deadline = deadline;
        state.job_leases.insert(key, renewed.clone());
        Ok(GovernanceJobLeaseOutcome::Renewed(renewed))
    }

    pub(crate) fn release_job_lease(
        &mut self,
        tenant_id: &str,
        fence: crate::governance::GovernanceDestructiveFence,
    ) -> Result<crate::governance::GovernanceJobLeaseOutcome, StoreError> {
        use crate::governance::{GovernanceJobLeaseConflict, GovernanceJobLeaseOutcome};

        let state = self;
        let key = (tenant_id.to_string(), fence.job_id);
        let Some(current) = state.job_leases.get(&key) else {
            return Ok(GovernanceJobLeaseOutcome::Conflict(
                GovernanceJobLeaseConflict::Lease,
            ));
        };
        if current.job_revision != fence.job_revision
            || current.policy_revision != fence.policy_revision
            || current.tenant_revision != fence.tenant_revision
            || current.token_digest != fence.lease_token_digest
            || current.deadline != fence.lease_deadline
        {
            return Ok(GovernanceJobLeaseOutcome::Conflict(
                GovernanceJobLeaseConflict::Lease,
            ));
        }
        state.job_leases.remove(&key);
        Ok(GovernanceJobLeaseOutcome::Released)
    }

    pub(crate) fn tenant_has_active_job_leases(
        &mut self,
        tenant_id: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        let state = self;
        Ok(state.job_leases.iter().any(|((tenant, _), lease)| {
            tenant == tenant_id && lease.tenant_id == tenant_id && lease.deadline > now
        }))
    }

    pub(crate) fn get_tenant_lifecycle(
        &mut self,
        tenant_id: &str,
    ) -> Result<Option<crate::governance::TenantLifecycleRecord>, StoreError> {
        Ok(self.tenant_lifecycles.get(tenant_id).cloned())
    }

    pub(crate) fn prepare_external_action(
        &mut self,
        record: crate::governance::GovernanceExternalActionRecord,
        fence: crate::governance::GovernanceExternalActionFence,
    ) -> Result<crate::governance::GovernanceExternalActionPutOutcome, StoreError> {
        use crate::governance::GovernanceExternalActionPutOutcome;

        if record.tenant_id.is_empty()
            || record.job_id != fence.job_id
            || record.action_id.is_empty()
            || record.resource_ref.is_empty()
            || record.resource_fingerprint.is_empty()
            || record.resource_fingerprint
                != crate::governance::resource_fingerprint(&record.resource_ref)
            || record.revision != 1
        {
            return Err(StoreError::Permanent(
                "invalid governance external action".into(),
            ));
        }
        let state = self;
        if !governance_external_fence_matches(state, &record.tenant_id, &fence, record.updated_at) {
            return Ok(GovernanceExternalActionPutOutcome::FenceConflict);
        }
        let key = (
            record.tenant_id.clone(),
            record.job_id.clone(),
            record.action_id.clone(),
        );
        if let Some(existing) = state.external_actions.get(&key) {
            if !same_external_action_identity(existing, &record) {
                return Err(StoreError::Permanent(
                    "governance external action identity changed".into(),
                ));
            }
            return Ok(GovernanceExternalActionPutOutcome::Existing(
                existing.clone(),
            ));
        }
        state.external_actions.insert(key, record.clone());
        Ok(GovernanceExternalActionPutOutcome::Stored(record))
    }

    pub(crate) fn get_external_action(
        &mut self,
        tenant_id: &str,
        job_id: &str,
        action_id: &str,
    ) -> Result<Option<crate::governance::GovernanceExternalActionRecord>, StoreError> {
        Ok(self
            .external_actions
            .get(&(
                tenant_id.to_string(),
                job_id.to_string(),
                action_id.to_string(),
            ))
            .cloned())
    }

    pub(crate) fn list_external_actions(
        &mut self,
        tenant_id: &str,
        job_id: &str,
    ) -> Result<Vec<crate::governance::GovernanceExternalActionRecord>, StoreError> {
        Ok(self
            .external_actions
            .iter()
            .filter_map(|((tenant, job, _), record)| {
                (tenant == tenant_id && job == job_id).then_some(record.clone())
            })
            .collect())
    }

    pub(crate) fn list_tenant_external_actions(
        &mut self,
        tenant_id: &str,
    ) -> Result<Vec<crate::governance::GovernanceExternalActionRecord>, StoreError> {
        Ok(self
            .external_actions
            .iter()
            .filter_map(|((tenant, _, _), record)| (tenant == tenant_id).then_some(record.clone()))
            .collect())
    }

    pub(crate) fn update_external_action(
        &mut self,
        mut record: crate::governance::GovernanceExternalActionRecord,
        expected_revision: u64,
        fence: crate::governance::GovernanceExternalActionFence,
    ) -> Result<crate::governance::GovernanceExternalActionUpdateOutcome, StoreError> {
        use crate::governance::GovernanceExternalActionUpdateOutcome;

        if record.job_id != fence.job_id {
            return Err(StoreError::Permanent(
                "governance external action job mismatch".into(),
            ));
        }
        let state = self;
        if !governance_external_fence_matches(state, &record.tenant_id, &fence, record.updated_at) {
            return Ok(GovernanceExternalActionUpdateOutcome::FenceConflict);
        }
        let key = (
            record.tenant_id.clone(),
            record.job_id.clone(),
            record.action_id.clone(),
        );
        let current = state.external_actions.get(&key).cloned().ok_or_else(|| {
            StoreError::Permanent("governance external action disappeared".into())
        })?;
        if !same_external_action_identity(&current, &record) {
            return Err(StoreError::Permanent(
                "governance external action identity changed".into(),
            ));
        }
        if current.revision != expected_revision {
            return Ok(GovernanceExternalActionUpdateOutcome::Conflict(current));
        }
        if !valid_external_dispatch_transition(&current, &record) {
            return Err(StoreError::Permanent(
                "invalid governance external action dispatch transition".into(),
            ));
        }
        record.revision = expected_revision.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("governance external action revision exhausted".into())
        })?;
        state.external_actions.insert(key, record.clone());
        Ok(GovernanceExternalActionUpdateOutcome::Stored(record))
    }

    pub(crate) fn reconcile_external_action(
        &mut self,
        mut record: crate::governance::GovernanceExternalActionRecord,
        expected_revision: u64,
        fence: crate::governance::GovernanceExternalActionReconcileFence,
    ) -> Result<crate::governance::GovernanceExternalActionUpdateOutcome, StoreError> {
        use crate::governance::GovernanceExternalActionUpdateOutcome;

        if record.job_id != fence.job_id {
            return Err(StoreError::Permanent(
                "governance external action reconciliation job mismatch".into(),
            ));
        }
        let state = self;
        if !governance_external_reconcile_fence_matches(state, &record.tenant_id, &fence) {
            return Ok(GovernanceExternalActionUpdateOutcome::FenceConflict);
        }
        let key = (
            record.tenant_id.clone(),
            record.job_id.clone(),
            record.action_id.clone(),
        );
        let current = state.external_actions.get(&key).cloned().ok_or_else(|| {
            StoreError::Permanent("governance external action disappeared".into())
        })?;
        if !same_external_action_identity(&current, &record) {
            return Err(StoreError::Permanent(
                "governance external action identity changed".into(),
            ));
        }
        if current.revision != expected_revision {
            return Ok(GovernanceExternalActionUpdateOutcome::Conflict(current));
        }
        if current.claim_token_digest.as_deref() != Some(fence.claim_token_digest.as_str())
            || !valid_external_reconcile_transition(&current, &record)
        {
            return Err(StoreError::Permanent(
                "invalid governance external action reconciliation transition".into(),
            ));
        }
        record.revision = expected_revision.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("governance external action revision exhausted".into())
        })?;
        state.external_actions.insert(key, record.clone());
        Ok(GovernanceExternalActionUpdateOutcome::Stored(record))
    }

    pub(crate) fn put_evidence(
        &mut self,
        record: crate::governance::GovernanceEvidenceRecord,
    ) -> Result<crate::governance::GovernanceEvidencePutOutcome, StoreError> {
        use crate::governance::GovernanceEvidencePutOutcome;

        if !record.verify_hash()
            || record.payload.tenant_id.is_empty()
            || record.payload.job_id.is_empty()
            || record.payload.evidence_revision == 0
        {
            return Err(StoreError::Permanent("invalid governance evidence".into()));
        }
        let key = (
            record.payload.tenant_id.clone(),
            record.payload.job_id.clone(),
            record.payload.evidence_revision,
        );
        let state = self;
        if let Some(existing) = state.evidence.get(&key) {
            return Ok(GovernanceEvidencePutOutcome::Existing(existing.clone()));
        }
        state.evidence.insert(key, record.clone());
        Ok(GovernanceEvidencePutOutcome::Stored(record))
    }

    pub(crate) fn latest_evidence(
        &mut self,
        tenant_id: &str,
        job_id: &str,
    ) -> Result<Option<crate::governance::GovernanceEvidenceRecord>, StoreError> {
        Ok(self
            .evidence
            .iter()
            .rev()
            .find_map(|((tenant, job, _), record)| {
                (tenant == tenant_id && job == job_id).then_some(record.clone())
            }))
    }

    pub(crate) fn put_suppression(
        &mut self,
        record: crate::governance::GovernanceSuppressionRecord,
        fence: crate::governance::GovernanceDestructiveFence,
        now: i64,
    ) -> Result<bool, StoreError> {
        let expected_epoch = fence.target_epoch.unwrap_or(fence.tenant_revision);
        if expected_epoch == 0 || record.target_epoch != expected_epoch {
            return Err(StoreError::Permanent(
                "suppression record does not match its destructive fence".into(),
            ));
        }
        let state = self;
        if !governance_destructive_fence_matches(state, &record.tenant_id, &fence, now) {
            return Err(StoreError::Transient(
                MEMORY_GOVERNANCE_DESTRUCTIVE_FENCE_CONFLICT.into(),
            ));
        }
        Ok(state.suppressions.insert((
            record.tenant_id,
            record.target_class,
            record.digest,
            record.target_epoch,
        )))
    }

    pub(crate) fn is_suppressed(
        &mut self,
        tenant_id: &str,
        target_class: &str,
        digest: &str,
    ) -> Result<bool, StoreError> {
        Ok(self
            .suppressions
            .iter()
            .any(|(tenant, class, stored_digest, _)| {
                tenant == tenant_id && class == target_class && stored_digest == digest
            }))
    }

    pub(crate) fn latest_suppression_epoch(
        &mut self,
        tenant_id: &str,
        target_class: &str,
        digest: &str,
    ) -> Result<Option<u64>, StoreError> {
        Ok(self
            .suppressions
            .iter()
            .filter_map(|(tenant, class, stored_digest, epoch)| {
                (tenant == tenant_id && class == target_class && stored_digest == digest)
                    .then_some(*epoch)
            })
            .max())
    }
}
