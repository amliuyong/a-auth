//! Resumable destructive data-governance phases.
//!
//! The HTTP API only records durable intent. A purpose-specific worker calls
//! this module and owns suppression writes plus physical cleanup permissions.

use std::{collections::BTreeMap, future::Future, pin::Pin};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::{
    governance::{
        resource_fingerprint, stable_external_action_id, suppression_digest, GovernanceAliasKind,
        GovernanceEvidenceAction, GovernanceEvidencePayload, GovernanceEvidencePutOutcome,
        GovernanceEvidenceRecord, GovernanceExternalActionKind, GovernanceExternalActionOutcome,
        GovernanceExternalActionPutOutcome, GovernanceExternalActionReconcileFence,
        GovernanceExternalActionRecord, GovernanceExternalActionState,
        GovernanceExternalActionUpdateOutcome, GovernanceJobCommand, GovernanceJobKind,
        GovernanceJobLeaseOutcome, GovernanceJobLeaseRecord, GovernanceJobPhase,
        GovernanceJobRecord, GovernanceJobStartOutcome, GovernanceJobState,
        GovernanceJobUpdateOutcome, GovernancePolicyRecord, GovernanceReplicaEvidence,
        GovernanceResourceOwnership, GovernanceRetentionEvidence, GovernanceSecretReference,
        GovernanceSuppressionRecord, GovernanceTargetAlias, TenantCleanupStage,
        TenantLifecycleState, RECOVERABLE_AUTHORITY_RETENTION_SECS, SUPPRESSION_KEY_VERSION,
        SUPPRESSION_NORMALIZATION_VERSION,
    },
    governance_resources::{
        GovernanceResourceBackend, GovernanceRetentionObservation, SecretDeletionStatus,
        SECRET_DELETION_OPERATION_BOUND_SECS,
    },
    ports::{
        AdminAuthStore, FederationConfigStore, GovernanceJobQueue, GovernanceStore, StoreError,
        UserRecord,
    },
    state::AppState,
};

#[cfg(feature = "aws")]
use crate::governance_resources::{GovernanceRetentionRequest, GovernanceRetentionTarget};

pub const MAX_FAILURE_ATTEMPTS: u8 = 8;
const EXTERNAL_ACTION_CLAIM_SECS: i64 = 30;
const KMS_DELETION_RETENTION_SECS: i64 = 7 * 24 * 60 * 60;
const DAY_SECS: i64 = 24 * 60 * 60;
pub(crate) const BACKUP_RETENTION_SECS: i64 = 36 * DAY_SECS;
pub(crate) const INCIDENT_QUEUE_RETENTION_SECS: i64 = 14 * DAY_SECS;
const SECURITY_EVENT_HOT_RETENTION_SECS: i64 = 400 * DAY_SECS;
pub(crate) const SECURITY_EVENT_ARCHIVE_RETENTION_SECS: i64 = 2_555 * DAY_SECS;
// Longer than the worker's five-minute invocation bound, so an old invocation
// cannot outlive its lease and overlap a reclaiming worker.
const DESTRUCTIVE_JOB_LEASE_SECS: i64 = 6 * 60;

#[derive(Debug)]
pub enum GovernanceEngineError {
    Store(StoreError),
    JobNotFound,
    WrongJobKind,
    PolicyChanged,
    RetryExhausted,
}

enum PhaseDisposition {
    Checkpoint,
    Retryable(&'static str),
    BlockedLegalHold,
}

#[inline(never)]
fn boxed_future<'a, T, F, Fut>(factory: F) -> Pin<Box<dyn Future<Output = T> + Send + 'a>>
where
    T: 'a,
    F: FnOnce() -> Fut,
    Fut: Future<Output = T> + Send + 'a,
{
    Box::pin(factory())
}

impl From<StoreError> for GovernanceEngineError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

fn random_job_lease_token_digest() -> String {
    let mut token = [0_u8; 32];
    OsRng.fill_bytes(&mut token);
    URL_SAFE_NO_PAD.encode(Sha256::digest(token))
}

async fn claim_phase_lease(
    state: &AppState,
    job: &GovernanceJobRecord,
    now: i64,
) -> Result<Option<GovernanceJobLeaseRecord>, GovernanceEngineError> {
    let deadline = now.saturating_add(DESTRUCTIVE_JOB_LEASE_SECS);
    match state
        .governance
        .claim_job_lease(
            &job.tenant_id,
            &job.job_id,
            job.revision,
            &random_job_lease_token_digest(),
            now,
            deadline,
        )
        .await?
    {
        GovernanceJobLeaseOutcome::Acquired(lease) => Ok(Some(lease)),
        GovernanceJobLeaseOutcome::Conflict(_) => Ok(None),
        GovernanceJobLeaseOutcome::Renewed(_) | GovernanceJobLeaseOutcome::Released => {
            Err(GovernanceEngineError::Store(StoreError::Permanent(
                "governance job lease claim returned an invalid outcome".into(),
            )))
        }
    }
}

async fn release_phase_lease(
    state: &AppState,
    lease: &GovernanceJobLeaseRecord,
) -> Result<(), GovernanceEngineError> {
    match state
        .governance
        .release_job_lease(&lease.tenant_id, lease.destructive_fence(None))
        .await?
    {
        GovernanceJobLeaseOutcome::Released => Ok(()),
        GovernanceJobLeaseOutcome::Conflict(_) => Err(GovernanceEngineError::Store(
            StoreError::Transient("governance job lease release conflict".into()),
        )),
        GovernanceJobLeaseOutcome::Acquired(_) | GovernanceJobLeaseOutcome::Renewed(_) => {
            Err(GovernanceEngineError::Store(StoreError::Permanent(
                "governance job lease release returned an invalid outcome".into(),
            )))
        }
    }
}

#[cfg(test)]
struct DestructivePhaseTestHook {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[cfg(test)]
static DESTRUCTIVE_PHASE_TEST_HOOKS: std::sync::LazyLock<
    std::sync::Mutex<BTreeMap<String, std::sync::Arc<DestructivePhaseTestHook>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(BTreeMap::new()));

#[cfg(test)]
async fn wait_for_destructive_phase_test_hook(job_id: &str) {
    let hook = DESTRUCTIVE_PHASE_TEST_HOOKS
        .lock()
        .expect("destructive phase test hook lock")
        .get(job_id)
        .cloned();
    if let Some(hook) = hook {
        hook.entered.notify_one();
        hook.release.notified().await;
    }
}

#[cfg(not(test))]
async fn wait_for_destructive_phase_test_hook(_job_id: &str) {}

fn external_action_record(
    state: &AppState,
    job: &GovernanceJobRecord,
    kind: GovernanceExternalActionKind,
    resource_ref: &str,
    resource_fingerprint: &str,
    ownership: GovernanceResourceOwnership,
    now: i64,
) -> GovernanceExternalActionRecord {
    GovernanceExternalActionRecord {
        action_id: stable_external_action_id(
            &state.governance_hmac_key,
            &job.tenant_id,
            &job.job_id,
            kind,
            resource_ref,
        ),
        tenant_id: job.tenant_id.clone(),
        job_id: job.job_id.clone(),
        kind,
        resource_ref: resource_ref.to_string(),
        resource_fingerprint: resource_fingerprint.to_string(),
        ownership,
        state: if ownership == GovernanceResourceOwnership::External {
            GovernanceExternalActionState::OperatorPending
        } else {
            GovernanceExternalActionState::Prepared
        },
        revision: 1,
        created_at: now,
        updated_at: now,
        claim_token_digest: None,
        claim_deadline: None,
        committed_at: None,
        verified_at: None,
        retention_until: None,
        error_class: None,
    }
}

async fn prepare_external_action(
    state: &AppState,
    lease: &GovernanceJobLeaseRecord,
    action: GovernanceExternalActionRecord,
) -> Result<GovernanceExternalActionRecord, StoreError> {
    match state
        .governance
        .prepare_external_action(action, lease.external_action_fence())
        .await?
    {
        GovernanceExternalActionPutOutcome::Stored(action)
        | GovernanceExternalActionPutOutcome::Existing(action) => Ok(action),
        GovernanceExternalActionPutOutcome::FenceConflict => Err(StoreError::Transient(
            "governance external action fence changed".into(),
        )),
    }
}

async fn prepare_secret_action(
    state: &AppState,
    job: &GovernanceJobRecord,
    lease: &GovernanceJobLeaseRecord,
    reference: &GovernanceSecretReference,
    now: i64,
) -> Result<GovernanceExternalActionRecord, StoreError> {
    let fingerprint = reference
        .resource_fingerprint
        .as_deref()
        .unwrap_or_else(|| unreachable!("AppState normalizes every governance Secret fingerprint"));
    prepare_external_action(
        state,
        lease,
        external_action_record(
            state,
            job,
            GovernanceExternalActionKind::SecretDeletion,
            &reference.secret_ref,
            fingerprint,
            reference.ownership,
            now,
        ),
    )
    .await
}

async fn transition_external_action(
    state: &AppState,
    lease: &GovernanceJobLeaseRecord,
    mut action: GovernanceExternalActionRecord,
    next_state: GovernanceExternalActionState,
    now: i64,
) -> Result<GovernanceExternalActionRecord, StoreError> {
    let expected_revision = action.revision;
    action.state = next_state;
    action.updated_at = now;
    match state
        .governance
        .update_external_action(action, expected_revision, lease.external_action_fence())
        .await?
    {
        GovernanceExternalActionUpdateOutcome::Stored(action)
        | GovernanceExternalActionUpdateOutcome::Conflict(action) => Ok(action),
        GovernanceExternalActionUpdateOutcome::FenceConflict => Err(StoreError::Transient(
            "governance external action fence changed".into(),
        )),
    }
}

async fn verify_external_action(
    state: &AppState,
    lease: &GovernanceJobLeaseRecord,
    mut action: GovernanceExternalActionRecord,
    outcome: &str,
    now: i64,
) -> Result<GovernanceExternalActionRecord, StoreError> {
    if action.ownership != GovernanceResourceOwnership::External
        || action.state != GovernanceExternalActionState::OperatorPending
    {
        return Ok(action);
    }
    action.verified_at = Some(now);
    action.error_class = Some(outcome.to_string());
    transition_external_action(
        state,
        lease,
        action,
        GovernanceExternalActionState::Verified,
        now,
    )
    .await
}

fn evidence_action(
    action: &GovernanceExternalActionRecord,
) -> Result<GovernanceEvidenceAction, StoreError> {
    let outcome = match action.ownership {
        GovernanceResourceOwnership::ProductManaged => {
            if action.retention_until.is_some() {
                GovernanceExternalActionOutcome::PendingDeletion
            } else if action.kind == GovernanceExternalActionKind::SecretDeletion {
                GovernanceExternalActionOutcome::Absent
            } else {
                return Err(StoreError::Permanent(
                    "verified product-managed action has no lifecycle outcome".into(),
                ));
            }
        }
        GovernanceResourceOwnership::External => match action.error_class.as_deref() {
            Some("external_secret_retained" | "external_tenant_key_retained") => {
                GovernanceExternalActionOutcome::ExternalRetained
            }
            Some("external_secret_absent") => GovernanceExternalActionOutcome::Absent,
            _ => {
                return Err(StoreError::Permanent(
                    "verified external action has no recognized lifecycle outcome".into(),
                ))
            }
        },
    };
    evidence_action_with_outcome(action, outcome, action.retention_until)
}

fn evidence_action_with_outcome(
    action: &GovernanceExternalActionRecord,
    outcome: GovernanceExternalActionOutcome,
    retention_until: Option<i64>,
) -> Result<GovernanceEvidenceAction, StoreError> {
    if action.state != GovernanceExternalActionState::Verified {
        return Err(StoreError::Permanent(
            "governance evidence action is not verified".into(),
        ));
    }
    let valid = matches!(
        (action.ownership, outcome, retention_until),
        (
            GovernanceResourceOwnership::ProductManaged,
            GovernanceExternalActionOutcome::PendingDeletion,
            Some(_),
        ) | (
            GovernanceResourceOwnership::ProductManaged,
            GovernanceExternalActionOutcome::Absent,
            None,
        ) | (
            GovernanceResourceOwnership::External,
            GovernanceExternalActionOutcome::ExternalRetained
                | GovernanceExternalActionOutcome::Absent,
            None,
        )
    );
    if !valid {
        return Err(StoreError::Permanent(
            "governance evidence action outcome is inconsistent".into(),
        ));
    }
    Ok(GovernanceEvidenceAction {
        action_id: action.action_id.clone(),
        kind: action.kind,
        ownership: action.ownership,
        state: action.state,
        outcome: Some(outcome),
        retention_until,
    })
}

async fn claim_external_action(
    state: &AppState,
    job: &GovernanceJobRecord,
    lease: &GovernanceJobLeaseRecord,
    mut action: GovernanceExternalActionRecord,
    now: i64,
) -> Result<GovernanceExternalActionRecord, StoreError> {
    if !matches!(
        action.state,
        GovernanceExternalActionState::Prepared | GovernanceExternalActionState::ClaimTombstoned
    ) {
        return Ok(action);
    }
    action.claim_token_digest = Some(stable_external_action_id(
        &state.governance_hmac_key,
        &job.tenant_id,
        &job.job_id,
        action.kind,
        &format!("claim:{}:{}:{now}", action.action_id, action.revision),
    ));
    action.claim_deadline = Some(now.saturating_add(EXTERNAL_ACTION_CLAIM_SECS));
    action.committed_at = None;
    action.verified_at = None;
    action.retention_until = None;
    action.error_class = None;
    transition_external_action(
        state,
        lease,
        action,
        GovernanceExternalActionState::Claimed,
        now,
    )
    .await
}

async fn reread_claim(
    state: &AppState,
    expected: &GovernanceExternalActionRecord,
) -> Result<GovernanceExternalActionRecord, StoreError> {
    let current = state
        .governance
        .get_external_action(&expected.tenant_id, &expected.job_id, &expected.action_id)
        .await?
        .ok_or_else(|| StoreError::Permanent("governance external action disappeared".into()))?;
    if current.revision != expected.revision
        || current.state != expected.state
        || current.claim_token_digest != expected.claim_token_digest
    {
        return Ok(current);
    }
    Ok(current)
}

async fn reconcile_external_action(
    state: &AppState,
    job: &GovernanceJobRecord,
    mut action: GovernanceExternalActionRecord,
    next_state: GovernanceExternalActionState,
    now: i64,
) -> Result<GovernanceExternalActionRecord, StoreError> {
    let expected_revision = action.revision;
    let claim_token_digest = action
        .claim_token_digest
        .clone()
        .ok_or_else(|| StoreError::Permanent("external action claim token is missing".into()))?;
    action.state = next_state;
    action.updated_at = now;
    match state
        .governance
        .reconcile_external_action(
            action,
            expected_revision,
            GovernanceExternalActionReconcileFence {
                job_id: job.job_id.clone(),
                tenant_revision: job.tenant_revision,
                claim_token_digest,
            },
        )
        .await?
    {
        GovernanceExternalActionUpdateOutcome::Stored(action)
        | GovernanceExternalActionUpdateOutcome::Conflict(action) => Ok(action),
        GovernanceExternalActionUpdateOutcome::FenceConflict => Err(StoreError::Transient(
            "governance external action reconciliation fence changed".into(),
        )),
    }
}

async fn tombstone_expired_claim(
    state: &AppState,
    job: &GovernanceJobRecord,
    mut action: GovernanceExternalActionRecord,
    error_class: &str,
    now: i64,
) -> Result<GovernanceExternalActionRecord, StoreError> {
    action.verified_at = Some(now);
    action.error_class = Some(error_class.into());
    reconcile_external_action(
        state,
        job,
        action,
        GovernanceExternalActionState::ClaimTombstoned,
        now,
    )
    .await
}

fn aliases_from_user(user: &UserRecord) -> Vec<GovernanceTargetAlias> {
    let mut aliases = vec![GovernanceTargetAlias {
        kind: GovernanceAliasKind::CanonicalId,
        normalized_value: user.user_id.clone(),
    }];
    for (kind, value) in [
        (GovernanceAliasKind::Email, Some(user.email.as_str())),
        (
            GovernanceAliasKind::ScimExternalId,
            user.scim_external_id.as_deref(),
        ),
        (
            GovernanceAliasKind::ScimUserName,
            user.scim_user_name.as_deref(),
        ),
    ] {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            let alias = GovernanceTargetAlias {
                kind,
                normalized_value: value.to_string(),
            };
            if !aliases.contains(&alias) {
                aliases.push(alias);
            }
        }
    }
    aliases
}

#[derive(serde::Serialize, serde::Deserialize)]
struct VerificationTarget {
    target_id: String,
    aliases: Vec<GovernanceTargetAlias>,
}

fn seal_user_verification_target(
    state: &AppState,
    job_id: &str,
    target_id: &str,
    aliases: &[GovernanceTargetAlias],
) -> Result<String, String> {
    let payload = serde_json::to_string(&VerificationTarget {
        target_id: target_id.to_string(),
        aliases: aliases.to_vec(),
    })
    .map_err(|_| "governance verification target serialization failed".to_string())?;
    crate::governance::seal_verification_target(&state.governance_hmac_key, job_id, &payload)
}

fn open_user_verification_target(
    state: &AppState,
    job: &GovernanceJobRecord,
) -> Result<VerificationTarget, StoreError> {
    let sealed = job
        .verification_target
        .as_deref()
        .ok_or_else(|| StoreError::Permanent("governance verification target is missing".into()))?;
    let plaintext = crate::governance::open_verification_target(
        &state.governance_hmac_key,
        &job.job_id,
        sealed,
    )
    .map_err(StoreError::Permanent)?;
    serde_json::from_str(&plaintext)
        .or_else(|_| {
            Ok::<_, serde_json::Error>(VerificationTarget {
                target_id: plaintext,
                aliases: Vec::new(),
            })
        })
        .map_err(|_| StoreError::Permanent("governance verification target is malformed".into()))
}

fn storage_tenant<'a>(state: &AppState, logical_tenant: &'a str) -> &'a str {
    if state.tenant_partitioning {
        logical_tenant
    } else {
        ""
    }
}

fn digest_for(
    state: &AppState,
    job: &GovernanceJobRecord,
    alias: &GovernanceTargetAlias,
) -> String {
    suppression_digest(
        &state.governance_hmac_key,
        &job.tenant_id,
        "user",
        alias.kind.as_str(),
        SUPPRESSION_NORMALIZATION_VERSION,
        &alias.normalized_value,
    )
}

async fn current_policy(
    state: &AppState,
    tenant_id: &str,
) -> Result<GovernancePolicyRecord, GovernanceEngineError> {
    Ok(state
        .governance
        .get_policy(tenant_id)
        .await?
        .unwrap_or_else(|| GovernancePolicyRecord::default_for(tenant_id)))
}

async fn checkpoint(
    state: &AppState,
    job: GovernanceJobRecord,
    expected_revision: u64,
    expected_policy_revision: u64,
) -> Result<GovernanceJobRecord, GovernanceEngineError> {
    match state
        .governance
        .update_job(job, expected_revision, expected_policy_revision)
        .await?
    {
        GovernanceJobUpdateOutcome::Stored(job) | GovernanceJobUpdateOutcome::Conflict(job) => {
            Ok(job)
        }
        GovernanceJobUpdateOutcome::PolicyConflict(_) => Err(GovernanceEngineError::PolicyChanged),
    }
}

async fn block_for_hold(
    state: &AppState,
    mut job: GovernanceJobRecord,
    policy: &GovernancePolicyRecord,
    now: i64,
) -> Result<GovernanceJobRecord, GovernanceEngineError> {
    if job.state == GovernanceJobState::BlockedLegalHold && job.policy_revision == policy.revision {
        return Ok(job);
    }
    let expected_revision = job.revision;
    job.state = GovernanceJobState::BlockedLegalHold;
    job.updated_at = now;
    job.error_class = Some("legal_hold".into());
    checkpoint(state, job, expected_revision, policy.revision).await
}

async fn retryable(
    state: &AppState,
    mut job: GovernanceJobRecord,
    policy_revision: u64,
    error_class: &'static str,
    now: i64,
) -> Result<GovernanceJobRecord, GovernanceEngineError> {
    let expected_revision = job.revision;
    job.state = GovernanceJobState::Retryable;
    job.updated_at = now;
    job.error_class = Some(error_class.into());
    checkpoint(state, job, expected_revision, policy_revision).await
}

async fn cleanup_user_state(
    state: &AppState,
    job: &GovernanceJobRecord,
    user_id: &str,
    fence: &crate::governance::GovernanceDestructiveFence,
    now: i64,
) -> Result<(), StoreError> {
    let cleanup = boxed_future(|| {
        crate::governance_data::cleanup_user_authority(
            state,
            &job.tenant_id,
            storage_tenant(state, &job.tenant_id),
            user_id,
            &job.target_aliases,
            fence,
            now,
        )
    });
    cleanup.await.map(|_| ())
}

async fn write_suppressions(
    state: &AppState,
    job: &GovernanceJobRecord,
    fence: &crate::governance::GovernanceDestructiveFence,
    now: i64,
) -> Result<(), StoreError> {
    for alias in &job.target_aliases {
        state
            .governance
            .put_suppression(
                GovernanceSuppressionRecord {
                    tenant_id: job.tenant_id.clone(),
                    target_class: "user".into(),
                    key_version: SUPPRESSION_KEY_VERSION,
                    normalization_version: SUPPRESSION_NORMALIZATION_VERSION,
                    digest: digest_for(state, job, alias),
                    target_epoch: job.target_epoch,
                    created_at: now,
                },
                fence.clone(),
                now,
            )
            .await?;
    }
    Ok(())
}

async fn suppressions_exist(
    state: &AppState,
    job: &GovernanceJobRecord,
) -> Result<bool, StoreError> {
    for alias in &job.target_aliases {
        if !state
            .governance
            .is_suppressed(&job.tenant_id, "user", &digest_for(state, job, alias))
            .await?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn tenant_suppression_digest(state: &AppState, tenant_id: &str) -> String {
    suppression_digest(
        &state.governance_hmac_key,
        tenant_id,
        "tenant",
        "tenant_id",
        SUPPRESSION_NORMALIZATION_VERSION,
        tenant_id,
    )
}

async fn write_tenant_suppression(
    state: &AppState,
    job: &GovernanceJobRecord,
    fence: &crate::governance::GovernanceDestructiveFence,
    now: i64,
) -> Result<(), StoreError> {
    state
        .governance
        .put_suppression(
            GovernanceSuppressionRecord {
                tenant_id: job.tenant_id.clone(),
                target_class: "tenant".into(),
                key_version: SUPPRESSION_KEY_VERSION,
                normalization_version: SUPPRESSION_NORMALIZATION_VERSION,
                digest: tenant_suppression_digest(state, &job.tenant_id),
                target_epoch: job.tenant_revision,
                created_at: now,
            },
            fence.clone(),
            now,
        )
        .await?;
    Ok(())
}

async fn tenant_suppression_exists(state: &AppState, tenant_id: &str) -> Result<bool, StoreError> {
    state
        .governance
        .is_suppressed(
            tenant_id,
            "tenant",
            &tenant_suppression_digest(state, tenant_id),
        )
        .await
}

/// Advance exactly one monotonic user-erasure phase.
///
/// A scheduler may call this repeatedly or restart after any return. Every
/// physical operation is idempotent, while the durable phase checkpoint uses
/// job and policy revision CAS.
pub async fn advance_user_erasure_once(
    state: &AppState,
    tenant_id: &str,
    job_id: &str,
    now: i64,
) -> Result<GovernanceJobRecord, GovernanceEngineError> {
    let Some(mut job) = boxed_future(|| state.governance.get_job(tenant_id, job_id)).await? else {
        return Err(GovernanceEngineError::JobNotFound);
    };
    if job.kind != GovernanceJobKind::UserErasure {
        return Err(GovernanceEngineError::WrongJobKind);
    }
    if matches!(
        job.state,
        GovernanceJobState::RetentionPending | GovernanceJobState::Completed
    ) {
        return Ok(job);
    }

    let mut policy = boxed_future(|| current_policy(state, tenant_id)).await?;
    if policy.legal_hold == crate::governance::LegalHoldState::Enabling {
        policy = boxed_future(|| settle_enabling_hold(state, policy, now)).await?;
    }
    if policy.held() {
        return boxed_future(|| block_for_hold(state, job, &policy, now)).await;
    }
    if policy.revision != job.policy_revision {
        return Err(GovernanceEngineError::PolicyChanged);
    }

    let Some(user_id) = job.target_id.clone() else {
        return retryable(state, job, policy.revision, "target_missing", now).await;
    };
    let data_tenant = storage_tenant(state, &job.tenant_id).to_string();
    if matches!(
        job.phase,
        GovernanceJobPhase::RetentionVerification | GovernanceJobPhase::Complete
    ) {
        return Ok(job);
    }
    let Some(lease) = claim_phase_lease(state, &job, now).await? else {
        return Ok(job);
    };
    wait_for_destructive_phase_test_hook(&job.job_id).await;
    let destructive_fence = lease.destructive_fence(Some(job.target_epoch));

    let expected_revision = job.revision;
    let phase_result = match job.phase {
        GovernanceJobPhase::IntentRecorded => {
            match boxed_future(|| {
                crate::governance_data::fence_user_identity(
                    state,
                    &job.tenant_id,
                    &data_tenant,
                    &user_id,
                    &destructive_fence,
                    now,
                )
            })
            .await
            {
                Ok(Some(user)) => {
                    job.target_aliases = aliases_from_user(&user);
                    let sealed = match seal_user_verification_target(
                        state,
                        &job.job_id,
                        &user_id,
                        &job.target_aliases,
                    ) {
                        Ok(sealed) => sealed,
                        Err(_) => {
                            release_phase_lease(state, &lease).await?;
                            return retryable(
                                state,
                                job,
                                policy.revision,
                                "verification_target_seal_failed",
                                now,
                            )
                            .await;
                        }
                    };
                    job.verification_target = Some(sealed);
                    job.phase = GovernanceJobPhase::MutationFenced;
                    Ok(())
                }
                Ok(None) => Err("identity_missing"),
                Err(_) => Err("mutation_fence_failed"),
            }
        }
        GovernanceJobPhase::MutationFenced => {
            match cleanup_user_state(state, &job, &user_id, &destructive_fence, now).await {
                Ok(()) => {
                    job.phase = GovernanceJobPhase::PrimaryCleanup;
                    Ok(())
                }
                Err(_) => Err("primary_cleanup_failed"),
            }
        }
        GovernanceJobPhase::PrimaryCleanup => {
            match write_suppressions(state, &job, &destructive_fence, now).await {
                Ok(()) => {
                    job.phase = GovernanceJobPhase::SuppressionRecorded;
                    Ok(())
                }
                Err(_) => Err("suppression_write_failed"),
            }
        }
        GovernanceJobPhase::SuppressionRecorded => {
            match boxed_future(|| {
                crate::governance_data::delete_user_identity(
                    state,
                    &job.tenant_id,
                    &data_tenant,
                    &user_id,
                    &job.target_aliases,
                    &destructive_fence,
                    now,
                )
            })
            .await
            {
                Ok(true) => {
                    job.phase = GovernanceJobPhase::ReplicaVerification;
                    job.primary_erasure_at = Some(now);
                    job.retention_anchor_at = Some(now);
                    Ok(())
                }
                Ok(false) | Err(_) => Err("identity_delete_failed"),
            }
        }
        GovernanceJobPhase::ReplicaVerification => {
            let inventory = boxed_future(|| {
                crate::governance_data::inventory_user_authority(
                    state,
                    &job.tenant_id,
                    &data_tenant,
                    &user_id,
                    &job.target_aliases,
                )
            })
            .await;
            let clean = inventory
                .as_ref()
                .is_ok_and(|inventory| inventory.live_absent());
            let suppressed = suppressions_exist(state, &job).await.unwrap_or(false);
            if clean && suppressed {
                if job.verification_target.is_none() {
                    let sealed = match seal_user_verification_target(
                        state,
                        &job.job_id,
                        &user_id,
                        &job.target_aliases,
                    ) {
                        Ok(sealed) => sealed,
                        Err(_) => {
                            release_phase_lease(state, &lease).await?;
                            return retryable(
                                state,
                                job,
                                policy.revision,
                                "verification_target_seal_failed",
                                now,
                            )
                            .await;
                        }
                    };
                    job.verification_target = Some(sealed);
                }
                let primary_erasure_at = job.primary_erasure_at.unwrap_or(now);
                match observe_primary_replica_absence(state, &job, primary_erasure_at, now).await {
                    Ok(retention_observation) => {
                        job.phase = GovernanceJobPhase::RetentionVerification;
                        job.state = GovernanceJobState::RetentionPending;
                        job.retention_until =
                            Some(retention_deadline(state, &job, primary_erasure_at).await?);
                        let alias_tombstone_count =
                            u64::try_from(job.target_aliases.len()).unwrap_or(u64::MAX);
                        let inventory = inventory.expect("clean inventory was checked above");
                        let external_actions = state
                            .governance
                            .list_external_actions(&job.tenant_id, &job.job_id)
                            .await
                            .and_then(|actions| actions.iter().map(evidence_action).collect());
                        match external_actions {
                            Ok(external_actions) => match append_evidence(
                                state,
                                &job,
                                &policy,
                                now,
                                inventory.live_counts,
                                inventory.retained_counts,
                                alias_tombstone_count,
                                external_actions,
                                retention_observation.as_ref(),
                            )
                            .await
                            {
                                Ok(evidence) => {
                                    job.evidence_revision = evidence.payload.evidence_revision;
                                    job.target_id = None;
                                    job.target_aliases.clear();
                                    Ok(())
                                }
                                Err(_) => Err("primary_evidence_write_failed"),
                            },
                            Err(_) => Err("primary_evidence_inventory_failed"),
                        }
                    }
                    Err(_) => Err("provider_replica_verification_failed"),
                }
            } else {
                Err("replica_verification_failed")
            }
        }
        GovernanceJobPhase::RetentionVerification | GovernanceJobPhase::Complete => {
            unreachable!("terminal governance phases return before claiming a lease")
        }
    };

    release_phase_lease(state, &lease).await?;
    if let Err(error_class) = phase_result {
        return retryable(state, job, policy.revision, error_class, now).await;
    }
    if job.state != GovernanceJobState::RetentionPending {
        job.state = GovernanceJobState::Running;
    }
    job.updated_at = now;
    job.error_class = None;
    checkpoint(state, job, expected_revision, policy.revision).await
}

fn erasure_epoch(user: &UserRecord) -> Result<u64, GovernanceEngineError> {
    if user.status == crate::ports::UserStatus::Tombstoned && user.credential_epoch > 0 {
        Ok(user.credential_epoch)
    } else {
        user.credential_epoch.checked_add(1).ok_or_else(|| {
            GovernanceEngineError::Store(StoreError::Permanent(
                "user erasure epoch exhausted".into(),
            ))
        })
    }
}

async fn start_offboarding_child(
    state: &AppState,
    parent: &GovernanceJobRecord,
    policy: &GovernancePolicyRecord,
    user: &UserRecord,
    now: i64,
) -> Result<GovernanceJobRecord, GovernanceEngineError> {
    let target_epoch = erasure_epoch(user)?;
    let job_id = crate::governance::stable_job_id(
        &state.governance_hmac_key,
        &parent.tenant_id,
        GovernanceJobKind::UserErasure,
        &user.user_id,
        target_epoch,
    );
    let child = GovernanceJobRecord {
        verification_target: Some(
            crate::governance::seal_verification_target(
                &state.governance_hmac_key,
                &job_id,
                &user.user_id,
            )
            .map_err(|error| GovernanceEngineError::Store(StoreError::Permanent(error)))?,
        ),
        job_id,
        tenant_id: parent.tenant_id.clone(),
        kind: GovernanceJobKind::UserErasure,
        target_id: Some(user.user_id.clone()),
        target_aliases: vec![],
        active_child_job_id: None,
        processed_records: 0,
        tenant_cleanup_stage: TenantCleanupStage::Users,
        target_epoch,
        state: GovernanceJobState::Queued,
        phase: GovernanceJobPhase::IntentRecorded,
        policy_revision: policy.revision,
        tenant_revision: parent.tenant_revision,
        revision: 1,
        created_at: now,
        updated_at: now,
        primary_erasure_at: None,
        retention_anchor_at: None,
        retention_until: None,
        evidence_revision: 0,
        error_class: None,
    };
    let child = match state
        .governance
        .start_or_resume_job(child, policy.revision, false)
        .await?
    {
        GovernanceJobStartOutcome::Stored(child) | GovernanceJobStartOutcome::Existing(child) => {
            child
        }
        GovernanceJobStartOutcome::PolicyConflict(_) => {
            return Err(GovernanceEngineError::PolicyChanged)
        }
        GovernanceJobStartOutcome::MutationConflict { .. } => {
            return Err(GovernanceEngineError::Store(StoreError::Transient(
                "tenant mutation gate changed while starting child job".into(),
            )))
        }
        GovernanceJobStartOutcome::TenantFrozen { .. } => {
            return Err(GovernanceEngineError::Store(StoreError::Transient(
                "offboarding child job lifecycle changed while starting".into(),
            )))
        }
    };
    state
        .governance_jobs
        .enqueue(GovernanceJobCommand {
            tenant_id: child.tenant_id.clone(),
            job_id: child.job_id.clone(),
            expected_revision: child.revision,
            failure_attempt: 0,
        })
        .await?;
    Ok(child)
}

fn add_processed(job: &mut GovernanceJobRecord, count: u64) -> Result<(), StoreError> {
    job.processed_records = job.processed_records.checked_add(count).ok_or_else(|| {
        StoreError::Permanent("offboarding processed record count exhausted".into())
    })?;
    Ok(())
}

async fn capture_external_secret_reference(
    state: &AppState,
    job: &GovernanceJobRecord,
    lease: &GovernanceJobLeaseRecord,
    purpose: &str,
    secret_ref: &str,
    now: i64,
) -> Result<(), StoreError> {
    let reference = GovernanceSecretReference::historical_external(purpose, secret_ref)
        .normalize()
        .map_err(StoreError::Permanent)?;
    prepare_secret_action(state, job, lease, &reference, now)
        .await
        .map(|_| ())
}

fn secret_action_requires_completion(state: GovernanceExternalActionState) -> bool {
    matches!(
        state,
        GovernanceExternalActionState::Claimed
            | GovernanceExternalActionState::ExternalPreparationDispatched
            | GovernanceExternalActionState::ExternallyCommitted
    )
}

async fn complete_claimed_secret_action(
    state: &AppState,
    job: &GovernanceJobRecord,
    mut action: GovernanceExternalActionRecord,
    now: i64,
) -> Result<GovernanceExternalActionRecord, StoreError> {
    if !secret_action_requires_completion(action.state) {
        return Ok(action);
    }
    if matches!(
        action.state,
        GovernanceExternalActionState::Claimed
            | GovernanceExternalActionState::ExternalPreparationDispatched
    ) {
        let expected_state = action.state;
        action = reread_claim(state, &action).await?;
        if action.state != expected_state {
            return Ok(action);
        }
    }
    let mut status = state
        .governance_resources
        .inspect_secret_deletion(&action.resource_ref, &action.resource_fingerprint)
        .await?;
    if matches!(
        status,
        SecretDeletionStatus::Present | SecretDeletionStatus::ReplicaRemovalRequired
    ) {
        if action.state == GovernanceExternalActionState::ExternallyCommitted {
            return Err(StoreError::Permanent(
                "externally committed Secret deletion is no longer scheduled".into(),
            ));
        }
        let deadline = action.claim_deadline.ok_or_else(|| {
            StoreError::Permanent("external action claim deadline is missing".into())
        })?;
        if now >= deadline {
            let error_class =
                if action.state == GovernanceExternalActionState::ExternalPreparationDispatched {
                    "claim_expired_after_external_preparation"
                } else {
                    "claim_expired_no_side_effect"
                };
            return tombstone_expired_claim(state, job, action, error_class, now).await;
        }
        if now.saturating_add(SECRET_DELETION_OPERATION_BOUND_SECS) >= deadline {
            return Ok(action);
        }
        if status == SecretDeletionStatus::ReplicaRemovalRequired
            && action.state == GovernanceExternalActionState::Claimed
        {
            action = reconcile_external_action(
                state,
                job,
                action,
                GovernanceExternalActionState::ExternalPreparationDispatched,
                now,
            )
            .await?;
            if action.state != GovernanceExternalActionState::ExternalPreparationDispatched {
                return Ok(action);
            }
        }
        let expected_state = action.state;
        action = reread_claim(state, &action).await?;
        if action.state != expected_state {
            return Ok(action);
        }
        status = state
            .governance_resources
            .schedule_secret_deletion(&action.resource_ref, &action.resource_fingerprint, now)
            .await?;
    }
    match status {
        SecretDeletionStatus::Absent => {
            action.committed_at.get_or_insert(now);
            action.verified_at = Some(now);
            action.retention_until = None;
            reconcile_external_action(
                state,
                job,
                action,
                GovernanceExternalActionState::Verified,
                now,
            )
            .await
        }
        SecretDeletionStatus::Scheduled { deletion_at } => {
            action.committed_at.get_or_insert(now);
            action.retention_until = Some(deletion_at);
            let next_state = if action.state == GovernanceExternalActionState::ExternallyCommitted {
                action.verified_at = Some(now);
                GovernanceExternalActionState::Verified
            } else {
                GovernanceExternalActionState::ExternallyCommitted
            };
            reconcile_external_action(state, job, action, next_state, now).await
        }
        SecretDeletionStatus::Present
        | SecretDeletionStatus::ReplicaRemovalRequired
        | SecretDeletionStatus::ReplicaRemovalPending => Err(StoreError::Transient(
            "Secret deletion did not produce a terminal external outcome".into(),
        )),
    }
}

async fn advance_tenant_key_external_action(
    state: &AppState,
    job: &GovernanceJobRecord,
    mut action: GovernanceExternalActionRecord,
    now: i64,
) -> Result<GovernanceExternalActionRecord, StoreError> {
    if action.state == GovernanceExternalActionState::Claimed {
        action = reread_claim(state, &action).await?;
    }
    if !matches!(
        action.state,
        GovernanceExternalActionState::Claimed | GovernanceExternalActionState::ExternallyCommitted
    ) {
        return Ok(action);
    }

    let operation_id = format!("offboard-{}", job.job_id);
    let mut status = state
        .tenant_keys
        .inspect_offboarding(&job.tenant_id, &operation_id)
        .await?;
    if matches!(
        status,
        crate::tenant_keys::TenantKeyOffboardingStatus::NotStarted
            | crate::tenant_keys::TenantKeyOffboardingStatus::Dispatched
    ) && action.state == GovernanceExternalActionState::Claimed
    {
        let deadline = action.claim_deadline.ok_or_else(|| {
            StoreError::Permanent("external action claim deadline is missing".into())
        })?;
        if now >= deadline {
            return tombstone_expired_claim(
                state,
                job,
                action,
                "claim_expired_no_side_effect",
                now,
            )
            .await;
        }
        if now.saturating_add(SECRET_DELETION_OPERATION_BOUND_SECS) >= deadline {
            return Ok(action);
        }
        action = reread_claim(state, &action).await?;
        if action.state != GovernanceExternalActionState::Claimed {
            return Ok(action);
        }
        status = state
            .tenant_keys
            .begin_offboarding(
                &job.tenant_id,
                &operation_id,
                now,
                crate::tenant_keys::TenantKeyGovernanceDispatchPermit {
                    job_id: job.job_id.clone(),
                    tenant_revision: job.tenant_revision,
                    action_id: action.action_id.clone(),
                    action_revision: action.revision,
                    claim_token_digest: action.claim_token_digest.clone().ok_or_else(|| {
                        StoreError::Permanent("tenant key dispatch claim token is missing".into())
                    })?,
                    claim_deadline: deadline,
                },
            )
            .await?;
    }
    match status {
        crate::tenant_keys::TenantKeyOffboardingStatus::NotStarted
        | crate::tenant_keys::TenantKeyOffboardingStatus::Dispatched => Ok(action),
        crate::tenant_keys::TenantKeyOffboardingStatus::Complete => {
            action.committed_at.get_or_insert(now);
            action.retention_until = Some(now.saturating_add(KMS_DELETION_RETENTION_SECS));
            let next_state = if action.state == GovernanceExternalActionState::ExternallyCommitted {
                action.verified_at = Some(now);
                GovernanceExternalActionState::Verified
            } else {
                GovernanceExternalActionState::ExternallyCommitted
            };
            reconcile_external_action(state, job, action, next_state, now).await
        }
        crate::tenant_keys::TenantKeyOffboardingStatus::NotTenantManaged => Err(
            StoreError::Permanent("SaaS tenant key registry is not tenant managed".into()),
        ),
    }
}

async fn advance_signing_keys_and_secrets(
    state: &AppState,
    job: &GovernanceJobRecord,
    lease: &GovernanceJobLeaseRecord,
    now: i64,
) -> Result<bool, StoreError> {
    let key_resource_ref = format!("tenant-key-registry:{}", job.tenant_id);
    let key_ownership = if matches!(&state.form, agent_auth_discovery::Form::Saas { .. }) {
        GovernanceResourceOwnership::ProductManaged
    } else {
        GovernanceResourceOwnership::External
    };
    let mut key_action = prepare_external_action(
        state,
        lease,
        external_action_record(
            state,
            job,
            GovernanceExternalActionKind::TenantKeyDeletion,
            &key_resource_ref,
            &resource_fingerprint(&key_resource_ref),
            key_ownership,
            now,
        ),
    )
    .await?;

    if key_action.ownership == GovernanceResourceOwnership::External
        && key_action.state == GovernanceExternalActionState::OperatorPending
    {
        verify_external_action(
            state,
            lease,
            key_action,
            "external_tenant_key_retained",
            now,
        )
        .await?;
        return Ok(false);
    }
    if key_action.ownership == GovernanceResourceOwnership::ProductManaged
        && matches!(
            key_action.state,
            GovernanceExternalActionState::Prepared
                | GovernanceExternalActionState::ClaimTombstoned
        )
    {
        key_action = claim_external_action(state, job, lease, key_action, now).await?;
    }
    if key_action.ownership == GovernanceResourceOwnership::ProductManaged
        && matches!(
            key_action.state,
            GovernanceExternalActionState::Claimed
                | GovernanceExternalActionState::ExternallyCommitted
        )
    {
        key_action = advance_tenant_key_external_action(state, job, key_action, now).await?;
    }
    if key_action.ownership == GovernanceResourceOwnership::ProductManaged
        && key_action.state != GovernanceExternalActionState::Verified
    {
        return Ok(false);
    }

    if let Some(references) = state.tenant_secret_references.get(&job.tenant_id) {
        for reference in references {
            prepare_secret_action(state, job, lease, reference, now).await?;
        }
    }
    let actions = state
        .governance
        .list_external_actions(&job.tenant_id, &job.job_id)
        .await?;
    for mut action in actions
        .into_iter()
        .filter(|action| action.kind == GovernanceExternalActionKind::SecretDeletion)
    {
        match action.ownership {
            GovernanceResourceOwnership::External => {
                if action.state == GovernanceExternalActionState::OperatorPending {
                    let outcome = match state
                        .governance_resources
                        .inspect_secret_deletion(&action.resource_ref, &action.resource_fingerprint)
                        .await?
                    {
                        SecretDeletionStatus::Present
                        | SecretDeletionStatus::ReplicaRemovalRequired
                        | SecretDeletionStatus::ReplicaRemovalPending => "external_secret_retained",
                        SecretDeletionStatus::Absent => "external_secret_absent",
                        SecretDeletionStatus::Scheduled { .. } => return Ok(false),
                    };
                    verify_external_action(state, lease, action, outcome, now).await?;
                    return Ok(false);
                }
            }
            GovernanceResourceOwnership::ProductManaged => {
                if matches!(
                    action.state,
                    GovernanceExternalActionState::Prepared
                        | GovernanceExternalActionState::ClaimTombstoned
                ) {
                    action = claim_external_action(state, job, lease, action, now).await?;
                }
                if secret_action_requires_completion(action.state) {
                    complete_claimed_secret_action(state, job, action, now).await?;
                    return Ok(false);
                }
            }
        }
        if action.state != GovernanceExternalActionState::Verified {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn settle_enabling_hold(
    state: &AppState,
    mut policy: GovernancePolicyRecord,
    now: i64,
) -> Result<GovernancePolicyRecord, GovernanceEngineError> {
    if policy.legal_hold != crate::governance::LegalHoldState::Enabling {
        return Ok(policy);
    }
    if state
        .governance
        .tenant_has_active_job_leases(&policy.tenant_id, now)
        .await?
    {
        return Ok(policy);
    }
    let actions = state
        .governance
        .list_tenant_external_actions(&policy.tenant_id)
        .await?;
    for action in actions
        .into_iter()
        .filter(|action| action.state.requires_hold_drain())
    {
        let action_job = state
            .governance
            .get_job(&action.tenant_id, &action.job_id)
            .await?
            .ok_or_else(|| {
                GovernanceEngineError::Store(StoreError::Permanent(
                    "legal-hold drain action references a missing job".into(),
                ))
            })?;
        match action.kind {
            GovernanceExternalActionKind::SecretDeletion => {
                complete_claimed_secret_action(state, &action_job, action, now).await?;
            }
            GovernanceExternalActionKind::TenantKeyDeletion => {
                advance_tenant_key_external_action(state, &action_job, action, now).await?;
            }
        }
    }

    let pending = state
        .governance
        .list_tenant_external_actions(&policy.tenant_id)
        .await?
        .into_iter()
        .any(|action| action.state.requires_hold_drain());
    if pending {
        return Ok(policy);
    }

    let expected_revision = policy.revision;
    policy.legal_hold = crate::governance::LegalHoldState::Enabled;
    policy.updated_at = now;
    match state
        .governance
        .put_policy(policy, expected_revision)
        .await?
    {
        crate::governance::GovernancePolicyPutOutcome::Stored(policy)
        | crate::governance::GovernancePolicyPutOutcome::Conflict(policy) => Ok(policy),
    }
}

async fn tenant_live_authority_is_absent(
    state: &AppState,
    job: &GovernanceJobRecord,
) -> Result<bool, StoreError> {
    let logical_tenant = job.tenant_id.as_str();
    let data_tenant = storage_tenant(state, logical_tenant);
    if !boxed_future(|| {
        crate::governance_data::inventory_tenant_authority(state, logical_tenant, data_tenant)
    })
    .await?
    .live_absent()
    {
        return Ok(false);
    }

    let actions = state
        .governance
        .list_external_actions(logical_tenant, &job.job_id)
        .await?;
    Ok(actions.iter().all(|action| {
        action.ownership == GovernanceResourceOwnership::External
            || matches!(
                action.state,
                GovernanceExternalActionState::ExternallyCommitted
                    | GovernanceExternalActionState::Verified
            )
    }))
}

fn retention_anchor(job: &GovernanceJobRecord, primary_erasure_at: i64) -> i64 {
    job.retention_anchor_at
        .unwrap_or(primary_erasure_at)
        .max(primary_erasure_at)
}

async fn retention_deadline(
    state: &AppState,
    job: &GovernanceJobRecord,
    primary_erasure_at: i64,
) -> Result<i64, StoreError> {
    let mut deadline = mandatory_retention_deadline(retention_anchor(job, primary_erasure_at));
    for action in state
        .governance
        .list_external_actions(&job.tenant_id, &job.job_id)
        .await?
    {
        if let Some(action_deadline) = action.retention_until {
            deadline = deadline.max(action_deadline);
        }
    }
    Ok(deadline)
}

fn mandatory_retention_deadline(retention_anchor_at: i64) -> i64 {
    [
        RECOVERABLE_AUTHORITY_RETENTION_SECS,
        BACKUP_RETENTION_SECS,
        INCIDENT_QUEUE_RETENTION_SECS,
        SECURITY_EVENT_HOT_RETENTION_SECS,
        SECURITY_EVENT_ARCHIVE_RETENTION_SECS,
    ]
    .into_iter()
    .map(|retention| retention_anchor_at.saturating_add(retention))
    .max()
    .unwrap_or(retention_anchor_at)
}

pub(crate) async fn extend_retention_for_audit(
    state: &AppState,
    tenant_id: &str,
    job_id: &str,
    retention_anchor_at: i64,
) -> Result<(), StoreError> {
    for _ in 0..8 {
        let Some(mut job) = state.governance.get_job(tenant_id, job_id).await? else {
            return Ok(());
        };
        if job.state == GovernanceJobState::Completed
            || job.phase == GovernanceJobPhase::Complete
            || job.primary_erasure_at.is_none()
        {
            return Ok(());
        }
        let current_anchor = job
            .retention_anchor_at
            .or(job.primary_erasure_at)
            .unwrap_or(job.updated_at);
        if current_anchor >= retention_anchor_at {
            return Ok(());
        }
        let policy = state
            .governance
            .get_policy(tenant_id)
            .await?
            .unwrap_or_else(|| GovernancePolicyRecord::default_for(tenant_id));
        let expected_revision = job.revision;
        job.retention_anchor_at = Some(retention_anchor_at);
        job.retention_until = Some(
            job.retention_until
                .unwrap_or_default()
                .max(mandatory_retention_deadline(retention_anchor_at)),
        );
        job.updated_at = job.updated_at.max(crate::current_unix_secs());
        match state
            .governance
            .update_job(job, expected_revision, policy.revision)
            .await?
        {
            GovernanceJobUpdateOutcome::Stored(_) => return Ok(()),
            GovernanceJobUpdateOutcome::Conflict(_)
            | GovernanceJobUpdateOutcome::PolicyConflict(_) => continue,
        }
    }
    Err(StoreError::Transient(
        "governance audit retention anchor remained contended".into(),
    ))
}

async fn observe_retention(
    state: &AppState,
    job: &GovernanceJobRecord,
    residency: &crate::governance::TenantResidency,
    primary_erasure_at: i64,
    now: i64,
) -> Result<Option<GovernanceRetentionObservation>, GovernanceEngineError> {
    #[cfg(feature = "aws")]
    if matches!(
        state.governance.as_ref(),
        crate::governance::GovernanceStoreImpl::Dynamo(_)
    ) {
        return Ok(state
            .governance_resources
            .verify_retention(retention_request(
                state,
                job,
                residency,
                primary_erasure_at,
                now,
            )?)
            .await?);
    }

    let _ = (state, job, residency, primary_erasure_at, now);
    Ok(None)
}

#[cfg(feature = "aws")]
fn retention_request(
    state: &AppState,
    job: &GovernanceJobRecord,
    residency: &crate::governance::TenantResidency,
    primary_erasure_at: i64,
    now: i64,
) -> Result<GovernanceRetentionRequest, GovernanceEngineError> {
    let target = match job.kind {
        GovernanceJobKind::UserErasure => {
            let target = open_user_verification_target(state, job)?;
            GovernanceRetentionTarget::User {
                tenant_id: job.tenant_id.clone(),
                job_id: job.job_id.clone(),
                user_id: target.target_id,
                aliases: target
                    .aliases
                    .into_iter()
                    .map(|alias| alias.normalized_value)
                    .collect(),
            }
        }
        GovernanceJobKind::TenantOffboarding => GovernanceRetentionTarget::Tenant {
            tenant_id: job.tenant_id.clone(),
            job_id: job.job_id.clone(),
        },
    };
    Ok(GovernanceRetentionRequest {
        target,
        storage_tenant: storage_tenant(state, &job.tenant_id).to_string(),
        configured_regions: residency.allowed_regions.clone(),
        primary_erasure_at,
        retention_anchor_at: retention_anchor(job, primary_erasure_at),
        verified_at: now,
    })
}

async fn observe_primary_replica_absence(
    state: &AppState,
    job: &GovernanceJobRecord,
    primary_erasure_at: i64,
    now: i64,
) -> Result<Option<GovernanceRetentionObservation>, GovernanceEngineError> {
    let residency = state
        .governance_config
        .residency(&job.tenant_id)
        .ok_or_else(|| {
            GovernanceEngineError::Store(StoreError::Permanent(
                "tenant residency is missing".into(),
            ))
        })?;
    #[cfg(feature = "aws")]
    if matches!(
        state.governance.as_ref(),
        crate::governance::GovernanceStoreImpl::Dynamo(_)
    ) {
        let replica_live_counts = state
            .governance_resources
            .verify_replicas(retention_request(
                state,
                job,
                residency,
                primary_erasure_at,
                now,
            )?)
            .await?
            .ok_or_else(|| {
                GovernanceEngineError::Store(StoreError::Transient(
                    "provider replica verification is unavailable".into(),
                ))
            })?;
        let observation = GovernanceRetentionObservation {
            complete: false,
            replica_live_counts,
            retention_resources: BTreeMap::new(),
        };
        if !observation.replicas_verified_absent(&residency.allowed_regions) {
            return Err(GovernanceEngineError::Store(StoreError::Transient(
                "provider replica verification is incomplete".into(),
            )));
        }
        return Ok(Some(observation));
    }

    let _ = (state, job, residency, primary_erasure_at, now);
    Ok(None)
}

async fn advance_tenant_authority_once(
    state: &AppState,
    job: &mut GovernanceJobRecord,
    lease: &GovernanceJobLeaseRecord,
    now: i64,
) -> Result<(), StoreError> {
    let logical_tenant = job.tenant_id.clone();
    let data_tenant = storage_tenant(state, &logical_tenant).to_string();
    let stage = job.tenant_cleanup_stage;
    match stage {
        TenantCleanupStage::Users => {
            job.tenant_cleanup_stage = TenantCleanupStage::Clients;
            return Ok(());
        }
        TenantCleanupStage::Federation => {
            for config in state
                .federation_config
                .list_by_tenant(&logical_tenant)
                .await?
            {
                if let Some(oidc) = config.oidc {
                    capture_external_secret_reference(
                        state,
                        job,
                        lease,
                        "federation",
                        &oidc.client_secret_ref,
                        now,
                    )
                    .await?;
                }
            }
        }
        TenantCleanupStage::AdminAuthority => {
            if let Some(config) = state.admin_auth.get_config(&logical_tenant).await? {
                capture_external_secret_reference(
                    state,
                    job,
                    lease,
                    "admin_oidc",
                    &config.client_secret_ref,
                    now,
                )
                .await?;
            }
        }
        TenantCleanupStage::SigningKeysAndSecrets => {
            if advance_signing_keys_and_secrets(state, job, lease, now).await? {
                job.tenant_cleanup_stage = TenantCleanupStage::Complete;
            }
            return Ok(());
        }
        TenantCleanupStage::Complete => {
            return Err(StoreError::Transient(
                "tenant authority cleanup is already complete".into(),
            ));
        }
        TenantCleanupStage::Clients
        | TenantCleanupStage::InitialAccessTokens
        | TenantCleanupStage::DirectoryGroups
        | TenantCleanupStage::WorkloadTrust
        | TenantCleanupStage::ProtocolState
        | TenantCleanupStage::PolicyAndDomains
        | TenantCleanupStage::SharedSignals => {}
    }

    let destructive_fence = lease.destructive_fence(None);
    let removed = boxed_future(|| {
        crate::governance_data::cleanup_tenant_stage(
            state,
            &logical_tenant,
            &data_tenant,
            stage,
            &destructive_fence,
            now,
        )
    })
    .await?;
    add_processed(job, removed)?;
    if stage == TenantCleanupStage::PolicyAndDomains {
        state.current_pv_cache.lock().await.remove(&data_tenant);
    }
    if removed == 0 {
        job.tenant_cleanup_stage = match stage {
            TenantCleanupStage::Clients => TenantCleanupStage::InitialAccessTokens,
            TenantCleanupStage::InitialAccessTokens => TenantCleanupStage::DirectoryGroups,
            TenantCleanupStage::DirectoryGroups => TenantCleanupStage::Federation,
            TenantCleanupStage::Federation => TenantCleanupStage::WorkloadTrust,
            TenantCleanupStage::WorkloadTrust => TenantCleanupStage::AdminAuthority,
            TenantCleanupStage::AdminAuthority => TenantCleanupStage::ProtocolState,
            TenantCleanupStage::ProtocolState => TenantCleanupStage::PolicyAndDomains,
            TenantCleanupStage::PolicyAndDomains => TenantCleanupStage::SharedSignals,
            TenantCleanupStage::SharedSignals => TenantCleanupStage::SigningKeysAndSecrets,
            TenantCleanupStage::Users
            | TenantCleanupStage::SigningKeysAndSecrets
            | TenantCleanupStage::Complete => unreachable!("handled before data-plane cleanup"),
        };
    }
    Ok(())
}

async fn advance_tenant_offboarding_phase(
    state: &AppState,
    tenant_id: &str,
    job: &mut GovernanceJobRecord,
    policy: &GovernancePolicyRecord,
    lease: &GovernanceJobLeaseRecord,
    now: i64,
) -> Result<PhaseDisposition, GovernanceEngineError> {
    match job.phase {
        GovernanceJobPhase::IntentRecorded => {
            job.phase = GovernanceJobPhase::MutationFenced;
        }
        GovernanceJobPhase::MutationFenced => {
            if let Some(child_job_id) = job.active_child_job_id.clone() {
                let Some(child) = state.governance.get_job(tenant_id, &child_job_id).await? else {
                    return Ok(PhaseDisposition::Retryable("child_job_missing"));
                };
                if matches!(
                    child.state,
                    GovernanceJobState::RetentionPending | GovernanceJobState::Completed
                ) {
                    job.active_child_job_id = None;
                    job.processed_records =
                        job.processed_records.checked_add(1).ok_or_else(|| {
                            GovernanceEngineError::Store(StoreError::Permanent(
                                "offboarding processed record count exhausted".into(),
                            ))
                        })?;
                } else if child.state == GovernanceJobState::BlockedLegalHold {
                    return Ok(PhaseDisposition::BlockedLegalHold);
                } else {
                    state
                        .governance_jobs
                        .enqueue(GovernanceJobCommand {
                            tenant_id: child.tenant_id,
                            job_id: child.job_id,
                            expected_revision: child.revision,
                            failure_attempt: 0,
                        })
                        .await?;
                }
            } else {
                let storage_tenant = storage_tenant(state, tenant_id);
                if let Some(user) = boxed_future(|| {
                    crate::governance_data::first_tenant_user(state, storage_tenant)
                })
                .await?
                {
                    let child = start_offboarding_child(state, job, policy, &user, now).await?;
                    job.active_child_job_id = Some(child.job_id);
                } else {
                    job.phase = GovernanceJobPhase::PrimaryCleanup;
                    job.tenant_cleanup_stage = TenantCleanupStage::Clients;
                }
            }
        }
        GovernanceJobPhase::PrimaryCleanup => {
            if advance_tenant_authority_once(state, job, lease, now)
                .await
                .is_err()
            {
                return Ok(PhaseDisposition::Retryable(
                    "tenant_authority_cleanup_pending",
                ));
            }
            if job.tenant_cleanup_stage == TenantCleanupStage::Complete {
                let destructive_fence = lease.destructive_fence(None);
                if write_tenant_suppression(state, job, &destructive_fence, now)
                    .await
                    .is_err()
                {
                    return Ok(PhaseDisposition::Retryable(
                        "tenant_suppression_write_failed",
                    ));
                }
                job.phase = GovernanceJobPhase::ReplicaVerification;
                job.primary_erasure_at = Some(now);
                job.retention_anchor_at = Some(now);
            }
        }
        GovernanceJobPhase::ReplicaVerification => {
            if !tenant_suppression_exists(state, tenant_id).await? {
                return Ok(PhaseDisposition::Retryable(
                    "tenant_suppression_verification_failed",
                ));
            }
            if !tenant_live_authority_is_absent(state, job).await? {
                return Ok(PhaseDisposition::Retryable(
                    "tenant_replica_verification_failed",
                ));
            }
            let primary_erasure_at = job.primary_erasure_at.unwrap_or(now);
            let retention_observation =
                match observe_primary_replica_absence(state, job, primary_erasure_at, now).await {
                    Ok(observation) => observation,
                    Err(_) => {
                        return Ok(PhaseDisposition::Retryable(
                            "provider_replica_verification_failed",
                        ))
                    }
                };
            job.retention_until = Some(retention_deadline(state, job, primary_erasure_at).await?);
            job.phase = GovernanceJobPhase::RetentionVerification;
            job.state = GovernanceJobState::RetentionPending;
            let inventory = crate::governance_data::inventory_tenant_authority(
                state,
                tenant_id,
                storage_tenant(state, tenant_id),
            )
            .await?;
            let external_actions = state
                .governance
                .list_external_actions(&job.tenant_id, &job.job_id)
                .await?
                .iter()
                .map(evidence_action)
                .collect::<Result<Vec<_>, _>>()?;
            let evidence = append_evidence(
                state,
                job,
                policy,
                now,
                inventory.live_counts,
                inventory.retained_counts,
                1,
                external_actions,
                retention_observation.as_ref(),
            )
            .await?;
            job.evidence_revision = evidence.payload.evidence_revision;
        }
        GovernanceJobPhase::SuppressionRecorded
        | GovernanceJobPhase::RetentionVerification
        | GovernanceJobPhase::Complete => {
            unreachable!("terminal governance phases return before claiming a lease")
        }
    }
    Ok(PhaseDisposition::Checkpoint)
}

/// Advance one offboarding checkpoint. User inventory repeatedly consumes the
/// first live page because deleting a user can invalidate a scan cursor.
pub async fn advance_tenant_offboarding_once(
    state: &AppState,
    tenant_id: &str,
    job_id: &str,
    now: i64,
) -> Result<GovernanceJobRecord, GovernanceEngineError> {
    let Some(mut job) = boxed_future(|| state.governance.get_job(tenant_id, job_id)).await? else {
        return Err(GovernanceEngineError::JobNotFound);
    };
    if job.kind != GovernanceJobKind::TenantOffboarding {
        return Err(GovernanceEngineError::WrongJobKind);
    }
    if matches!(
        job.state,
        GovernanceJobState::RetentionPending | GovernanceJobState::Completed
    ) {
        return Ok(job);
    }
    let mut policy = boxed_future(|| current_policy(state, tenant_id)).await?;
    if policy.legal_hold == crate::governance::LegalHoldState::Enabling {
        policy = boxed_future(|| settle_enabling_hold(state, policy, now)).await?;
    }
    if policy.held() {
        return boxed_future(|| block_for_hold(state, job, &policy, now)).await;
    }
    if policy.revision != job.policy_revision {
        return Err(GovernanceEngineError::PolicyChanged);
    }
    let lifecycle = boxed_future(|| state.governance.get_tenant_lifecycle(tenant_id)).await?;
    if lifecycle.as_ref().is_none_or(|lifecycle| {
        lifecycle.state != TenantLifecycleState::Offboarding
            || lifecycle.revision != job.tenant_revision
    }) {
        return boxed_future(|| {
            retryable(state, job, policy.revision, "tenant_fence_missing", now)
        })
        .await;
    }
    if matches!(
        job.phase,
        GovernanceJobPhase::SuppressionRecorded
            | GovernanceJobPhase::RetentionVerification
            | GovernanceJobPhase::Complete
    ) {
        return Ok(job);
    }
    let Some(lease) = boxed_future(|| claim_phase_lease(state, &job, now)).await? else {
        return Ok(job);
    };
    boxed_future(|| wait_for_destructive_phase_test_hook(&job.job_id)).await;

    let expected_revision = job.revision;
    let phase_result = boxed_future(|| {
        advance_tenant_offboarding_phase(state, tenant_id, &mut job, &policy, &lease, now)
    })
    .await;
    boxed_future(|| release_phase_lease(state, &lease)).await?;
    match phase_result? {
        PhaseDisposition::Checkpoint => {}
        PhaseDisposition::Retryable(error_class) => {
            return boxed_future(|| retryable(state, job, policy.revision, error_class, now)).await;
        }
        PhaseDisposition::BlockedLegalHold => {
            return boxed_future(|| block_for_hold(state, job, &policy, now)).await;
        }
    }
    if job.state != GovernanceJobState::RetentionPending {
        job.state = GovernanceJobState::Running;
    }
    job.updated_at = now;
    job.error_class = None;
    boxed_future(|| checkpoint(state, job, expected_revision, policy.revision)).await
}

async fn verify_external_retention(
    state: &AppState,
    job: &GovernanceJobRecord,
) -> Result<(bool, Option<i64>, Vec<GovernanceEvidenceAction>), StoreError> {
    let actions = state
        .governance
        .list_external_actions(&job.tenant_id, &job.job_id)
        .await?;
    let mut complete = true;
    let mut pending_until: Option<i64> = None;
    let mut summaries = Vec::with_capacity(actions.len());
    for action in actions {
        if action.ownership == GovernanceResourceOwnership::External {
            complete &= action.state == GovernanceExternalActionState::Verified;
            if action.state == GovernanceExternalActionState::Verified {
                summaries.push(evidence_action(&action)?);
            }
            continue;
        }
        if action.state != GovernanceExternalActionState::Verified {
            complete = false;
            continue;
        }
        let mut summary = evidence_action(&action)?;
        match action.kind {
            GovernanceExternalActionKind::SecretDeletion => {
                match state
                    .governance_resources
                    .inspect_secret_deletion(&action.resource_ref, &action.resource_fingerprint)
                    .await?
                {
                    SecretDeletionStatus::Absent => {
                        summary = evidence_action_with_outcome(
                            &action,
                            GovernanceExternalActionOutcome::Absent,
                            None,
                        )?;
                    }
                    SecretDeletionStatus::Scheduled { deletion_at } => {
                        complete = false;
                        pending_until = Some(pending_until.unwrap_or_default().max(deletion_at));
                        summary = evidence_action_with_outcome(
                            &action,
                            GovernanceExternalActionOutcome::PendingDeletion,
                            Some(deletion_at),
                        )?;
                    }
                    SecretDeletionStatus::Present
                    | SecretDeletionStatus::ReplicaRemovalRequired
                    | SecretDeletionStatus::ReplicaRemovalPending => complete = false,
                }
            }
            GovernanceExternalActionKind::TenantKeyDeletion => {
                match state
                    .tenant_keys
                    .verify_offboarding_deletion(
                        &job.tenant_id,
                        &format!("offboard-{}", job.job_id),
                    )
                    .await?
                {
                    crate::tenant_keys::TenantKeyDeletionVerification::Complete => {
                        summary = evidence_action_with_outcome(
                            &action,
                            GovernanceExternalActionOutcome::Absent,
                            None,
                        )?;
                    }
                    crate::tenant_keys::TenantKeyDeletionVerification::PendingUntil(deadline) => {
                        complete = false;
                        pending_until = Some(pending_until.unwrap_or_default().max(deadline));
                        summary = evidence_action_with_outcome(
                            &action,
                            GovernanceExternalActionOutcome::PendingDeletion,
                            Some(deadline),
                        )?;
                    }
                    crate::tenant_keys::TenantKeyDeletionVerification::Incomplete => {
                        complete = false;
                    }
                }
            }
        }
        summaries.push(summary);
    }
    Ok((complete, pending_until, summaries))
}

fn retention_resource(
    completed: bool,
    lifecycle_source: &str,
    retention_until: Option<i64>,
) -> GovernanceRetentionEvidence {
    GovernanceRetentionEvidence {
        state: if completed {
            "declared_policy_window_elapsed"
        } else {
            "declared_policy_window_pending"
        }
        .into(),
        evidence_basis: "declared_configuration".into(),
        lifecycle_source: lifecycle_source.into(),
        retention_until,
    }
}

fn retention_resource_evidence(
    job_state: GovernanceJobState,
    retention_anchor_at: i64,
    external_actions: &[GovernanceEvidenceAction],
) -> BTreeMap<String, GovernanceRetentionEvidence> {
    let completed = job_state == GovernanceJobState::Completed;
    let mut resources = BTreeMap::from([
        (
            "dynamodb_security_event_hot".into(),
            retention_resource(
                completed,
                "DynamoDB immutable ledger retention policy",
                Some(retention_anchor_at.saturating_add(SECURITY_EVENT_HOT_RETENTION_SECS)),
            ),
        ),
        (
            "s3_security_event_archive".into(),
            retention_resource(
                completed,
                "S3 lifecycle expiration",
                Some(retention_anchor_at.saturating_add(SECURITY_EVENT_ARCHIVE_RETENTION_SECS)),
            ),
        ),
        (
            "aws_backup_recovery_points".into(),
            retention_resource(
                completed,
                "AWS Backup lifecycle DeleteAfterDays",
                Some(retention_anchor_at.saturating_add(BACKUP_RETENTION_SECS)),
            ),
        ),
        (
            "cloudwatch_logs".into(),
            retention_resource(
                completed,
                "CloudWatch Logs retentionInDays",
                Some(retention_anchor_at.saturating_add(SECURITY_EVENT_ARCHIVE_RETENTION_SECS)),
            ),
        ),
        (
            "sqs_queues".into(),
            retention_resource(
                completed,
                "SQS MessageRetentionPeriod",
                Some(retention_anchor_at.saturating_add(INCIDENT_QUEUE_RETENTION_SECS)),
            ),
        ),
        (
            "ssf_revoke_tombstones".into(),
            GovernanceRetentionEvidence {
                state: "permanent_control_record".into(),
                evidence_basis: "durable_control_record".into(),
                lifecycle_source: "SSF receiver revocation policy".into(),
                retention_until: None,
            },
        ),
    ]);
    if let Some(evidence) = aggregate_action_evidence(
        external_actions
            .iter()
            .filter(|action| action.kind == GovernanceExternalActionKind::TenantKeyDeletion),
        "KMS scheduled deletion",
    ) {
        resources.insert("kms_tenant_signing_keys".into(), evidence);
    }
    if let Some(evidence) = aggregate_action_evidence(
        external_actions.iter().filter(|action| {
            action.kind == GovernanceExternalActionKind::SecretDeletion
                && action.ownership == GovernanceResourceOwnership::ProductManaged
        }),
        "Secrets Manager recovery window",
    ) {
        resources.insert("secrets_manager_product_managed".into(), evidence);
    }
    if let Some(evidence) = aggregate_action_evidence(
        external_actions.iter().filter(|action| {
            action.kind == GovernanceExternalActionKind::SecretDeletion
                && action.ownership == GovernanceResourceOwnership::External
        }),
        "Externally owned Secrets Manager resource",
    ) {
        resources.insert("secrets_manager_external".into(), evidence);
    }
    resources
        .entry("kms_tenant_signing_keys".into())
        .or_insert_with(|| GovernanceRetentionEvidence {
            state: "not_observed".into(),
            evidence_basis: "missing_external_action".into(),
            lifecycle_source: "KMS scheduled deletion".into(),
            retention_until: None,
        });
    resources
        .entry("secrets_manager_product_managed".into())
        .or_insert_with(|| GovernanceRetentionEvidence {
            state: "not_observed".into(),
            evidence_basis: "missing_external_action".into(),
            lifecycle_source: "Secrets Manager recovery window".into(),
            retention_until: None,
        });
    resources
}

fn aggregate_action_evidence<'a>(
    actions: impl Iterator<Item = &'a GovernanceEvidenceAction>,
    lifecycle_source: &str,
) -> Option<GovernanceRetentionEvidence> {
    let mut count = 0_u64;
    let mut retention_until: Option<i64> = None;
    let mut verified = true;
    for action in actions {
        count = count.saturating_add(1);
        verified &= action.state == GovernanceExternalActionState::Verified;
        if let Some(deadline) = action.retention_until {
            retention_until = Some(retention_until.unwrap_or(i64::MIN).max(deadline));
        }
    }
    (count > 0).then(|| GovernanceRetentionEvidence {
        state: if verified { "verified" } else { "pending" }.into(),
        evidence_basis: "aggregated_provider_observations".into(),
        lifecycle_source: lifecycle_source.into(),
        retention_until,
    })
}

fn build_evidence(
    state: &AppState,
    job: &GovernanceJobRecord,
    policy: &GovernancePolicyRecord,
    now: i64,
    live_counts: BTreeMap<String, u64>,
    retained_counts: BTreeMap<String, u64>,
    alias_tombstone_count: u64,
    external_actions: Vec<GovernanceEvidenceAction>,
    retention_observation: Option<&GovernanceRetentionObservation>,
) -> Result<GovernanceEvidenceRecord, GovernanceEngineError> {
    let primary_erasure_at = job.primary_erasure_at.ok_or_else(|| {
        GovernanceEngineError::Store(StoreError::Permanent(
            "primary erasure timestamp is missing".into(),
        ))
    })?;
    let retention_deadline = job.retention_until.ok_or_else(|| {
        GovernanceEngineError::Store(StoreError::Permanent(
            "retention deadline is missing".into(),
        ))
    })?;
    let residency = state
        .governance_config
        .residency(&job.tenant_id)
        .ok_or_else(|| {
            GovernanceEngineError::Store(StoreError::Permanent(
                "tenant residency is missing".into(),
            ))
        })?
        .clone();
    let local_region = state.region.local_region().to_string();
    let replica_live_counts = retention_observation.map_or_else(
        || {
            residency
                .allowed_regions
                .iter()
                .map(|region| {
                    let local = region == &local_region;
                    (
                        region.clone(),
                        GovernanceReplicaEvidence {
                            verification_state: if local {
                                "verified"
                            } else {
                                "live_drill_pending"
                            }
                            .into(),
                            verified_at: local.then_some(now),
                            live_counts: local.then(|| live_counts.clone()).unwrap_or_default(),
                            retained_counts: BTreeMap::new(),
                        },
                    )
                })
                .collect()
        },
        |observation| observation.replica_live_counts.clone(),
    );
    let mut retention_resources = retention_resource_evidence(
        job.state,
        retention_anchor(job, primary_erasure_at),
        &external_actions,
    );
    if let Some(observation) = retention_observation {
        retention_resources.extend(observation.retention_resources.clone());
    }
    let evidence_revision = job.evidence_revision.checked_add(1).ok_or_else(|| {
        GovernanceEngineError::Store(StoreError::Permanent(
            "governance evidence revision exhausted".into(),
        ))
    })?;
    GovernanceEvidenceRecord::new(GovernanceEvidencePayload {
        schema_version: crate::governance::GOVERNANCE_EVIDENCE_SCHEMA_VERSION.into(),
        tenant_id: job.tenant_id.clone(),
        job_id: job.job_id.clone(),
        job_kind: job.kind,
        job_state: job.state,
        evidence_revision,
        deployment_commit: state.deployment_commit.clone(),
        started_at: job.created_at,
        verification_at: now,
        generated_at: now,
        primary_erasure_at,
        retention_deadline,
        residency_jurisdiction: residency.jurisdiction,
        configured_regions: residency.allowed_regions,
        active_writer_region: local_region,
        region_control_revision: state.region.active_revision(),
        legal_hold: policy.legal_hold,
        live_counts,
        retained_counts,
        replica_live_counts,
        alias_tombstone_count,
        retention_resources,
        external_actions,
        permanent_control_records: match job.kind {
            GovernanceJobKind::UserErasure => {
                vec![
                    "governance_suppression".into(),
                    "governance_evidence".into(),
                ]
            }
            GovernanceJobKind::TenantOffboarding => vec![
                "governance_suppression".into(),
                "governance_evidence".into(),
                "ssf_revoke_tombstones".into(),
            ],
        },
    })
    .map_err(|error| GovernanceEngineError::Store(StoreError::Permanent(error)))
}

async fn append_evidence(
    state: &AppState,
    job: &GovernanceJobRecord,
    policy: &GovernancePolicyRecord,
    now: i64,
    live_counts: BTreeMap<String, u64>,
    retained_counts: BTreeMap<String, u64>,
    alias_tombstone_count: u64,
    external_actions: Vec<GovernanceEvidenceAction>,
    retention_observation: Option<&GovernanceRetentionObservation>,
) -> Result<GovernanceEvidenceRecord, GovernanceEngineError> {
    let evidence = build_evidence(
        state,
        job,
        policy,
        now,
        live_counts,
        retained_counts,
        alias_tombstone_count,
        external_actions,
        retention_observation,
    )?;
    let evidence_revision = evidence.payload.evidence_revision;
    let evidence = match state.governance.put_evidence(evidence).await? {
        GovernanceEvidencePutOutcome::Stored(evidence)
        | GovernanceEvidencePutOutcome::Existing(evidence) => evidence,
    };
    if !evidence.verify_hash()
        || evidence.payload.tenant_id != job.tenant_id
        || evidence.payload.job_id != job.job_id
        || evidence.payload.evidence_revision != evidence_revision
        || evidence.payload.job_state != job.state
    {
        return Err(GovernanceEngineError::Store(StoreError::Permanent(
            "governance evidence reconciliation failed".into(),
        )));
    }
    Ok(evidence)
}

async fn retain_pending(
    state: &AppState,
    mut job: GovernanceJobRecord,
    policy_revision: u64,
    now: i64,
    error_class: &'static str,
    pending_until: Option<i64>,
) -> Result<GovernanceJobRecord, GovernanceEngineError> {
    let next_deadline = pending_until.map_or(job.retention_until, |deadline| {
        Some(job.retention_until.unwrap_or_default().max(deadline))
    });
    if job.policy_revision == policy_revision
        && job.error_class.as_deref() == Some(error_class)
        && job.retention_until == next_deadline
    {
        return Ok(job);
    }
    let expected_revision = job.revision;
    job.retention_until = next_deadline;
    job.state = GovernanceJobState::RetentionPending;
    job.phase = GovernanceJobPhase::RetentionVerification;
    job.updated_at = now;
    job.error_class = Some(error_class.into());
    checkpoint(state, job, expected_revision, policy_revision).await
}

pub async fn finalize_retention_job(
    state: &AppState,
    tenant_id: &str,
    job_id: &str,
    now: i64,
) -> Result<GovernanceJobRecord, GovernanceEngineError> {
    let Some(mut job) = state.governance.get_job(tenant_id, job_id).await? else {
        return Err(GovernanceEngineError::JobNotFound);
    };
    if job.state == GovernanceJobState::Completed {
        return Ok(job);
    }
    if job.state != GovernanceJobState::RetentionPending
        || job.phase != GovernanceJobPhase::RetentionVerification
    {
        return Err(GovernanceEngineError::Store(StoreError::Permanent(
            "governance job is not awaiting retention verification".into(),
        )));
    }
    let policy = current_policy(state, tenant_id).await?;
    if policy.held() {
        return retain_pending(state, job, policy.revision, now, "legal_hold", None).await;
    }
    let primary_erasure_at = job.primary_erasure_at.ok_or_else(|| {
        GovernanceEngineError::Store(StoreError::Permanent(
            "primary erasure timestamp is missing".into(),
        ))
    })?;
    let retention_deadline = job.retention_until.ok_or_else(|| {
        GovernanceEngineError::Store(StoreError::Permanent(
            "retention deadline is missing".into(),
        ))
    })?;
    let mandatory_deadline =
        mandatory_retention_deadline(retention_anchor(&job, primary_erasure_at));
    if retention_deadline < mandatory_deadline {
        return retain_pending(
            state,
            job,
            policy.revision,
            now,
            "retention_policy_window_pending",
            Some(mandatory_deadline),
        )
        .await;
    }
    if now < retention_deadline {
        return Ok(job);
    }
    let residency = state
        .governance_config
        .residency(tenant_id)
        .ok_or_else(|| {
            GovernanceEngineError::Store(StoreError::Permanent(
                "tenant residency is missing".into(),
            ))
        })?
        .clone();
    let local_region = state.region.local_region();
    if residency.governance_region != local_region
        || !residency
            .allowed_regions
            .iter()
            .any(|region| region == local_region)
    {
        return Err(GovernanceEngineError::Store(StoreError::Permanent(
            "retention verification is outside the tenant governance Region".into(),
        )));
    }
    if residency.allowed_regions.len() > 1 {
        if !state.region.is_multi_region() {
            return Err(GovernanceEngineError::Store(StoreError::Permanent(
                "multi-Region retention verification requires a controlled regional runtime".into(),
            )));
        }
        if !matches!(
            state.region.admit(now).await?,
            crate::region::RegionAdmission::Active
        ) {
            return retain_pending(
                state,
                job,
                policy.revision,
                now,
                "governance_region_inactive",
                None,
            )
            .await;
        }
    }

    let mut live_counts = BTreeMap::new();
    let live_absent = match job.kind {
        GovernanceJobKind::UserErasure => {
            let verification = open_user_verification_target(state, &job)?;
            let mut verification_job = job.clone();
            verification_job.target_aliases = verification.aliases;
            let data_tenant = storage_tenant(state, tenant_id);
            let inventory = boxed_future(|| {
                crate::governance_data::inventory_user_authority(
                    state,
                    tenant_id,
                    data_tenant,
                    &verification.target_id,
                    &verification_job.target_aliases,
                )
            })
            .await?;
            let suppressed = suppressions_exist(state, &verification_job)
                .await
                .unwrap_or(false);
            let inventory_absent = inventory.live_absent();
            live_counts.extend(inventory.live_counts);
            live_counts.insert("suppression_missing".into(), u64::from(!suppressed));
            inventory_absent && suppressed
        }
        GovernanceJobKind::TenantOffboarding => {
            let inventory = boxed_future(|| {
                crate::governance_data::inventory_tenant_authority(
                    state,
                    tenant_id,
                    storage_tenant(state, tenant_id),
                )
            })
            .await?;
            let suppressed = tenant_suppression_exists(state, tenant_id).await?;
            let absent = inventory.live_absent()
                && tenant_live_authority_is_absent(state, &job).await?
                && suppressed;
            live_counts.extend(inventory.live_counts);
            live_counts.insert("tenant_suppression_missing".into(), u64::from(!suppressed));
            absent
        }
    };
    if !live_absent {
        return retain_pending(
            state,
            job,
            policy.revision,
            now,
            "retention_live_verification_failed",
            None,
        )
        .await;
    }

    let (external_complete, pending_until, external_actions) =
        verify_external_retention(state, &job).await?;
    if !external_complete {
        return retain_pending(
            state,
            job,
            policy.revision,
            now,
            "external_retention_pending",
            pending_until,
        )
        .await;
    }

    let retention_observation =
        observe_retention(state, &job, &residency, primary_erasure_at, now).await?;
    #[cfg(feature = "aws")]
    if matches!(
        state.governance.as_ref(),
        crate::governance::GovernanceStoreImpl::Dynamo(_)
    ) {
        match retention_observation.as_ref() {
            Some(observation) if observation.complete => {}
            Some(observation) => {
                return retain_pending(
                    state,
                    job,
                    policy.revision,
                    now,
                    "retention_resource_verification_pending",
                    observation.pending_until(),
                )
                .await
            }
            None => {
                return retain_pending(
                    state,
                    job,
                    policy.revision,
                    now,
                    "retention_resource_verification_unavailable",
                    None,
                )
                .await
            }
        }
    }

    let previous_evidence = state
        .governance
        .latest_evidence(&job.tenant_id, &job.job_id)
        .await?;
    let alias_tombstone_count = previous_evidence
        .as_ref()
        .map_or(0, |evidence| evidence.payload.alias_tombstone_count);
    let retained_counts = previous_evidence
        .map(|evidence| evidence.payload.retained_counts)
        .unwrap_or_default();
    let mut completed_evidence_job = job.clone();
    completed_evidence_job.state = GovernanceJobState::Completed;
    completed_evidence_job.phase = GovernanceJobPhase::Complete;
    completed_evidence_job.updated_at = now;
    let evidence = build_evidence(
        state,
        &completed_evidence_job,
        &policy,
        now,
        live_counts,
        retained_counts,
        alias_tombstone_count,
        external_actions,
        retention_observation.as_ref(),
    )?;

    let expected_revision = job.revision;
    job.evidence_revision = evidence.payload.evidence_revision;
    job.state = GovernanceJobState::Completed;
    job.phase = GovernanceJobPhase::Complete;
    job.updated_at = now;
    job.target_id = None;
    job.target_aliases.clear();
    job.verification_target = None;
    job.error_class = None;
    match state
        .governance
        .complete_job_with_evidence(job, evidence, expected_revision, policy.revision)
        .await?
    {
        GovernanceJobUpdateOutcome::Stored(job) | GovernanceJobUpdateOutcome::Conflict(job) => {
            Ok(job)
        }
        GovernanceJobUpdateOutcome::PolicyConflict(_) => Err(GovernanceEngineError::PolicyChanged),
    }
}

pub async fn run_retention_pass(
    state: &AppState,
    now: i64,
) -> Result<usize, GovernanceEngineError> {
    let tenant_ids = state
        .governance_config
        .tenant_ids()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let mut completed = 0_usize;
    for tenant_id in tenant_ids {
        let jobs = state.governance.list_jobs(&tenant_id).await?;
        for job in jobs.into_iter().filter(|job| {
            job.state == GovernanceJobState::RetentionPending
                && job.retention_until.is_some_and(|deadline| deadline <= now)
        }) {
            match finalize_retention_job(state, &tenant_id, &job.job_id, now).await {
                Ok(finalized) => {
                    completed += usize::from(finalized.state == GovernanceJobState::Completed);
                }
                Err(error) => {
                    eprintln!(
                        "GOVERNANCE_RETENTION_JOB_FAIL tenant={} job={} error={error:?}",
                        tenant_id, job.job_id
                    );
                }
            }
        }
    }
    Ok(completed)
}

/// Result of one queue invocation. Requeue commands carry the revision just
/// committed, so stale SQS deliveries can repair a lost wake-up without
/// advancing a second phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceCommandOutcome {
    Requeued(GovernanceJobRecord),
    Terminal(GovernanceJobRecord),
}

pub async fn process_command_once(
    state: &AppState,
    command: GovernanceJobCommand,
    now: i64,
) -> Result<GovernanceCommandOutcome, GovernanceEngineError> {
    let Some(current) = state
        .governance
        .get_job(&command.tenant_id, &command.job_id)
        .await?
    else {
        return Err(GovernanceEngineError::JobNotFound);
    };

    let job = if current.revision == command.expected_revision {
        match current.kind {
            GovernanceJobKind::UserErasure => {
                advance_user_erasure_once(state, &command.tenant_id, &command.job_id, now).await?
            }
            GovernanceJobKind::TenantOffboarding => {
                advance_tenant_offboarding_once(state, &command.tenant_id, &command.job_id, now)
                    .await?
            }
        }
    } else {
        current
    };

    let next_attempt = if job.state == GovernanceJobState::Retryable {
        command
            .failure_attempt
            .checked_add(1)
            .filter(|attempt| *attempt < MAX_FAILURE_ATTEMPTS)
            .ok_or(GovernanceEngineError::RetryExhausted)?
    } else {
        0
    };

    let hold_drain_pending = if job.state == GovernanceJobState::BlockedLegalHold {
        current_policy(state, &job.tenant_id).await?.legal_hold
            == crate::governance::LegalHoldState::Enabling
    } else {
        false
    };
    if hold_drain_pending
        || matches!(
            job.state,
            GovernanceJobState::Queued
                | GovernanceJobState::Running
                | GovernanceJobState::Retryable
        )
    {
        state
            .governance_jobs
            .enqueue(GovernanceJobCommand {
                tenant_id: job.tenant_id.clone(),
                job_id: job.job_id.clone(),
                expected_revision: job.revision,
                failure_attempt: next_attempt,
            })
            .await?;
        Ok(GovernanceCommandOutcome::Requeued(job))
    } else {
        Ok(GovernanceCommandOutcome::Terminal(job))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use agent_auth_discovery::Form;

    use super::*;
    use crate::{
        adapters::memory::MemoryGovernanceStore,
        governance::{
            GovernanceConfig, GovernanceJobLeaseOutcome, GovernancePolicyPutOutcome,
            GovernanceResourceOwnership, GovernanceSecretReference, GovernanceStoreImpl,
            LegalHoldState,
        },
        governance_resources::{
            GovernanceResourceBackendImpl, MemoryGovernanceResourceBackend,
            MemorySecretScheduleFault,
        },
        ports::{ClientRecord, ClientStore, RateLimitStore, UsersStore},
        region::{
            MemoryRegionControlStore, RegionControlRecord, RegionControlStoreImpl, RegionRuntime,
        },
    };

    fn verified_evidence_action(
        action_id: &str,
        ownership: GovernanceResourceOwnership,
        outcome: GovernanceExternalActionOutcome,
        retention_until: Option<i64>,
    ) -> GovernanceEvidenceAction {
        GovernanceEvidenceAction {
            action_id: action_id.into(),
            kind: GovernanceExternalActionKind::SecretDeletion,
            ownership,
            state: GovernanceExternalActionState::Verified,
            outcome: Some(outcome),
            retention_until,
        }
    }

    #[test]
    fn secret_preparation_remains_runnable_after_worker_retry() {
        for state in [
            GovernanceExternalActionState::Claimed,
            GovernanceExternalActionState::ExternalPreparationDispatched,
            GovernanceExternalActionState::ExternallyCommitted,
        ] {
            assert!(secret_action_requires_completion(state));
        }
        for state in [
            GovernanceExternalActionState::Prepared,
            GovernanceExternalActionState::ClaimTombstoned,
            GovernanceExternalActionState::Verified,
            GovernanceExternalActionState::OperatorPending,
        ] {
            assert!(!secret_action_requires_completion(state));
        }
    }

    #[test]
    fn secret_retention_evidence_separates_ownership_and_keeps_latest_deadline() {
        let actions = vec![
            verified_evidence_action(
                "product-1",
                GovernanceResourceOwnership::ProductManaged,
                GovernanceExternalActionOutcome::PendingDeletion,
                Some(150),
            ),
            verified_evidence_action(
                "external",
                GovernanceResourceOwnership::External,
                GovernanceExternalActionOutcome::ExternalRetained,
                None,
            ),
            verified_evidence_action(
                "product-2",
                GovernanceResourceOwnership::ProductManaged,
                GovernanceExternalActionOutcome::PendingDeletion,
                Some(250),
            ),
        ];

        let resources =
            retention_resource_evidence(GovernanceJobState::RetentionPending, 100, &actions);
        let product = &resources["secrets_manager_product_managed"];
        assert_eq!(product.state, "verified");
        assert_eq!(product.retention_until, Some(250));
        let external = &resources["secrets_manager_external"];
        assert_eq!(external.state, "verified");
        assert_eq!(external.retention_until, None);
    }

    #[test]
    fn external_secret_evidence_exposes_only_a_typed_verified_outcome() {
        let mut action = GovernanceExternalActionRecord {
            action_id: "external".into(),
            tenant_id: "t1".into(),
            job_id: "job".into(),
            kind: GovernanceExternalActionKind::SecretDeletion,
            resource_ref: "secret-ref-must-not-leak".into(),
            resource_fingerprint: "fingerprint-must-not-leak".into(),
            ownership: GovernanceResourceOwnership::External,
            state: GovernanceExternalActionState::Verified,
            revision: 2,
            created_at: 1,
            updated_at: 2,
            claim_token_digest: None,
            claim_deadline: None,
            committed_at: None,
            verified_at: Some(2),
            retention_until: None,
            error_class: Some("external_secret_retained".into()),
        };
        let retained = evidence_action(&action).unwrap();
        assert_eq!(
            retained.outcome,
            Some(GovernanceExternalActionOutcome::ExternalRetained)
        );
        let serialized = serde_json::to_string(&retained).unwrap();
        assert!(!serialized.contains("must-not-leak"));

        action.error_class = Some("external_secret_absent".into());
        assert_eq!(
            evidence_action(&action).unwrap().outcome,
            Some(GovernanceExternalActionOutcome::Absent)
        );
        action.error_class = Some("unbounded-provider-message".into());
        assert!(evidence_action(&action).is_err());
    }

    async fn claimed_secret_fixture(
        claim_at: i64,
    ) -> (
        AppState,
        MemoryGovernanceResourceBackend,
        GovernanceJobRecord,
        GovernanceExternalActionRecord,
        String,
    ) {
        let backend = MemoryGovernanceResourceBackend::default();
        let secret_ref =
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:tenant-t1-AbCd".to_string();
        backend.insert_secret(&secret_ref).await;

        let mut state = AppState::dev("auth.example.com");
        state.form = Form::Saas {
            zone: "auth.example.com".into(),
            control_host: "c.auth.example.com".into(),
        };
        state.governance_resources =
            Arc::new(GovernanceResourceBackendImpl::Memory(backend.clone()));

        let candidate = GovernanceJobRecord {
            job_id: "job-external-action".into(),
            tenant_id: "default".into(),
            kind: GovernanceJobKind::TenantOffboarding,
            target_id: None,
            target_aliases: Vec::new(),
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
            created_at: claim_at,
            updated_at: claim_at,
            primary_erasure_at: None,
            retention_anchor_at: None,
            retention_until: None,
            evidence_revision: 0,
            error_class: None,
        };
        let mut job = match state
            .governance
            .start_or_resume_job(candidate, 0, true)
            .await
            .unwrap()
        {
            GovernanceJobStartOutcome::Stored(job) => job,
            outcome => panic!("unexpected job start: {outcome:?}"),
        };
        let expected_revision = job.revision;
        job.state = GovernanceJobState::Running;
        job = match state
            .governance
            .update_job(job, expected_revision, 0)
            .await
            .unwrap()
        {
            GovernanceJobUpdateOutcome::Stored(job) => job,
            outcome => panic!("unexpected job update: {outcome:?}"),
        };
        let lease = match state
            .governance
            .claim_job_lease(
                &job.tenant_id,
                &job.job_id,
                job.revision,
                "test-external-action-lease",
                claim_at,
                claim_at + 3_600,
            )
            .await
            .unwrap()
        {
            GovernanceJobLeaseOutcome::Acquired(lease) => lease,
            outcome => panic!("unexpected lease outcome: {outcome:?}"),
        };

        let reference = GovernanceSecretReference {
            purpose: "tenant_admin".into(),
            secret_ref: secret_ref.clone(),
            ownership: GovernanceResourceOwnership::ProductManaged,
            resource_account: Some("123456789012".into()),
            resource_region: Some("us-east-1".into()),
            resource_fingerprint: None,
            ownership_revision: 1,
        }
        .normalize()
        .unwrap();
        let action = prepare_secret_action(&state, &job, &lease, &reference, claim_at)
            .await
            .unwrap();
        let action = claim_external_action(&state, &job, &lease, action, claim_at)
            .await
            .unwrap();
        release_phase_lease(&state, &lease).await.unwrap();
        (state, backend, job, action, secret_ref)
    }

    #[tokio::test]
    async fn final_retention_summary_uses_fresh_absent_secret_observation() {
        let (state, backend, job, action, secret_ref) = claimed_secret_fixture(100).await;
        let action = complete_claimed_secret_action(&state, &job, action, 101)
            .await
            .unwrap();
        let action = complete_claimed_secret_action(&state, &job, action, 102)
            .await
            .unwrap();
        assert_eq!(action.state, GovernanceExternalActionState::Verified);
        assert!(action.retention_until.is_some());

        backend.remove_secret(&secret_ref).await;
        let (complete, pending_until, summaries) =
            verify_external_retention(&state, &job).await.unwrap();
        assert!(complete);
        assert_eq!(pending_until, None);
        assert_eq!(summaries.len(), 1);
        assert_eq!(
            summaries[0].outcome,
            Some(GovernanceExternalActionOutcome::Absent)
        );
        assert_eq!(summaries[0].retention_until, None);
    }

    async fn retention_pending_tenant_fixture(
    ) -> (AppState, MemoryGovernanceStore, GovernanceJobRecord) {
        let store = MemoryGovernanceStore::default();
        let mut state = AppState::dev("auth.example.com");
        state.governance = Arc::new(GovernanceStoreImpl::Memory(store.clone()));
        let candidate = GovernanceJobRecord {
            job_id: "job-retention-retry".into(),
            tenant_id: "default".into(),
            kind: GovernanceJobKind::TenantOffboarding,
            target_id: None,
            target_aliases: Vec::new(),
            verification_target: None,
            active_child_job_id: None,
            processed_records: 0,
            tenant_cleanup_stage: TenantCleanupStage::Complete,
            target_epoch: 1,
            state: GovernanceJobState::Queued,
            phase: GovernanceJobPhase::PrimaryCleanup,
            policy_revision: 0,
            tenant_revision: 0,
            revision: 1,
            created_at: 100,
            updated_at: 100,
            primary_erasure_at: None,
            retention_anchor_at: None,
            retention_until: None,
            evidence_revision: 0,
            error_class: None,
        };
        let mut job = match state
            .governance
            .start_or_resume_job(candidate, 0, true)
            .await
            .unwrap()
        {
            GovernanceJobStartOutcome::Stored(job) => job,
            outcome => panic!("unexpected job start: {outcome:?}"),
        };
        let lease = match state
            .governance
            .claim_job_lease(
                &job.tenant_id,
                &job.job_id,
                job.revision,
                "retention-fixture-lease",
                140,
                200,
            )
            .await
            .unwrap()
        {
            GovernanceJobLeaseOutcome::Acquired(lease) => lease,
            outcome => panic!("unexpected retention fixture lease: {outcome:?}"),
        };
        write_tenant_suppression(&state, &job, &lease.destructive_fence(None), 150)
            .await
            .unwrap();
        release_phase_lease(&state, &lease).await.unwrap();
        let expected_revision = job.revision;
        job.state = GovernanceJobState::RetentionPending;
        job.phase = GovernanceJobPhase::RetentionVerification;
        job.primary_erasure_at = Some(100);
        job.retention_anchor_at = Some(100);
        job.retention_until = Some(mandatory_retention_deadline(100));
        job.updated_at = 150;
        let job = match state
            .governance
            .update_job(job, expected_revision, 0)
            .await
            .unwrap()
        {
            GovernanceJobUpdateOutcome::Stored(job) => job,
            outcome => panic!("unexpected job update: {outcome:?}"),
        };
        (state, store, job)
    }

    #[tokio::test]
    async fn concurrent_workers_allow_only_one_destructive_phase_owner() {
        let state = AppState::dev("auth.example.com");
        let user_id = "user:lease-race";
        state
            .users
            .create_or_get_by_email("", "lease-race@example.com", user_id, 100)
            .await
            .unwrap();
        let candidate = GovernanceJobRecord {
            job_id: "job-lease-race".into(),
            tenant_id: "default".into(),
            kind: GovernanceJobKind::UserErasure,
            target_id: Some(user_id.into()),
            target_aliases: Vec::new(),
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
            created_at: 100,
            updated_at: 100,
            primary_erasure_at: None,
            retention_anchor_at: None,
            retention_until: None,
            evidence_revision: 0,
            error_class: None,
        };
        let job = match state
            .governance
            .start_or_resume_job(candidate, 0, false)
            .await
            .unwrap()
        {
            GovernanceJobStartOutcome::Stored(job) => job,
            outcome => panic!("unexpected job start: {outcome:?}"),
        };

        let hook = Arc::new(DestructivePhaseTestHook {
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        DESTRUCTIVE_PHASE_TEST_HOOKS
            .lock()
            .unwrap()
            .insert(job.job_id.clone(), hook.clone());
        let entered = hook.entered.notified();
        let first_state = state.clone();
        let tenant_id = job.tenant_id.clone();
        let job_id = job.job_id.clone();
        let first = tokio::spawn(async move {
            advance_user_erasure_once(&first_state, &tenant_id, &job_id, 101).await
        });
        entered.await;

        let blocked = advance_user_erasure_once(&state, &job.tenant_id, &job.job_id, 101)
            .await
            .unwrap();
        assert_eq!(blocked.revision, job.revision);
        assert_eq!(blocked.phase, GovernanceJobPhase::IntentRecorded);

        hook.release.notify_one();
        let advanced = first.await.unwrap().unwrap();
        DESTRUCTIVE_PHASE_TEST_HOOKS
            .lock()
            .unwrap()
            .remove(&job.job_id);
        assert_eq!(advanced.phase, GovernanceJobPhase::MutationFenced);
        assert_eq!(advanced.revision, job.revision + 1);
        assert!(!state
            .governance
            .tenant_has_active_job_leases(&job.tenant_id, 101)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn enabling_hold_waits_for_an_active_internal_lease_to_expire() {
        let state = AppState::dev("auth.example.com");
        let candidate = GovernanceJobRecord {
            job_id: "job-hold-lease-drain".into(),
            tenant_id: "default".into(),
            kind: GovernanceJobKind::UserErasure,
            target_id: Some("user:hold-drain".into()),
            target_aliases: Vec::new(),
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
            created_at: 100,
            updated_at: 100,
            primary_erasure_at: None,
            retention_anchor_at: None,
            retention_until: None,
            evidence_revision: 0,
            error_class: None,
        };
        let job = match state
            .governance
            .start_or_resume_job(candidate, 0, false)
            .await
            .unwrap()
        {
            GovernanceJobStartOutcome::Stored(job) => job,
            outcome => panic!("unexpected job start: {outcome:?}"),
        };
        assert!(matches!(
            state
                .governance
                .claim_job_lease(
                    &job.tenant_id,
                    &job.job_id,
                    job.revision,
                    "hold-drain-lease",
                    100,
                    110,
                )
                .await
                .unwrap(),
            GovernanceJobLeaseOutcome::Acquired(_)
        ));
        let mut enabling = GovernancePolicyRecord::default_for(&job.tenant_id);
        enabling.legal_hold = LegalHoldState::Enabling;
        enabling.legal_hold_reason = Some("case-hold-drain".into());
        let enabling = match state.governance.put_policy(enabling, 0).await.unwrap() {
            GovernancePolicyPutOutcome::Stored(policy) => policy,
            outcome => panic!("unexpected policy outcome: {outcome:?}"),
        };

        let still_enabling = settle_enabling_hold(&state, enabling.clone(), 109)
            .await
            .unwrap();
        assert_eq!(still_enabling.legal_hold, LegalHoldState::Enabling);
        assert_eq!(still_enabling.revision, enabling.revision);

        let enabled = settle_enabling_hold(&state, enabling, 110).await.unwrap();
        assert_eq!(enabled.legal_hold, LegalHoldState::Enabled);
        assert_eq!(enabled.revision, 2);
    }

    #[tokio::test]
    async fn tenant_client_cleanup_deletes_the_tenant_scoped_rate_limit_bucket() {
        let mut state = AppState::dev("auth.example.com");
        state.form = Form::Saas {
            zone: "auth.example.com".into(),
            control_host: "control.auth.example.com".into(),
        };
        state.tenant_partitioning = true;

        let client_id = "shared-client";
        state
            .clients
            .put(
                "t1",
                ClientRecord {
                    client_id: client_id.into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let rate_limit = state.rate_limit.as_ref().unwrap();
        let scoped_key = crate::tenant::tpk("t1", client_id);
        assert!(
            rate_limit
                .try_consume(&scoped_key, 100, 1.0, 1.0, 1.0)
                .await
                .unwrap()
                .allowed
        );
        assert!(
            !rate_limit
                .try_consume(&scoped_key, 100, 1.0, 1.0, 1.0)
                .await
                .unwrap()
                .allowed
        );
        assert!(
            rate_limit
                .try_consume(client_id, 100, 1.0, 1.0, 1.0)
                .await
                .unwrap()
                .allowed
        );
        assert!(
            !rate_limit
                .try_consume(client_id, 100, 1.0, 1.0, 1.0)
                .await
                .unwrap()
                .allowed
        );

        let mut job = GovernanceJobRecord {
            job_id: "job-client-cleanup".into(),
            tenant_id: "t1".into(),
            kind: GovernanceJobKind::TenantOffboarding,
            target_id: None,
            target_aliases: Vec::new(),
            verification_target: None,
            active_child_job_id: None,
            processed_records: 0,
            tenant_cleanup_stage: TenantCleanupStage::Clients,
            target_epoch: 1,
            state: GovernanceJobState::Queued,
            phase: GovernanceJobPhase::PrimaryCleanup,
            policy_revision: 0,
            tenant_revision: 0,
            revision: 1,
            created_at: 100,
            updated_at: 100,
            primary_erasure_at: None,
            retention_anchor_at: None,
            retention_until: None,
            evidence_revision: 0,
            error_class: None,
        };
        job = match state
            .governance
            .start_or_resume_job(job, 0, true)
            .await
            .unwrap()
        {
            GovernanceJobStartOutcome::Stored(job) => job,
            outcome => panic!("unexpected job start: {outcome:?}"),
        };
        let expected_revision = job.revision;
        job.state = GovernanceJobState::Running;
        job = match state
            .governance
            .update_job(job, expected_revision, 0)
            .await
            .unwrap()
        {
            GovernanceJobUpdateOutcome::Stored(job) => job,
            outcome => panic!("unexpected job update: {outcome:?}"),
        };
        let lease = match state
            .governance
            .claim_job_lease(
                &job.tenant_id,
                &job.job_id,
                job.revision,
                "client-cleanup-lease",
                100,
                200,
            )
            .await
            .unwrap()
        {
            GovernanceJobLeaseOutcome::Acquired(lease) => lease,
            outcome => panic!("unexpected lease outcome: {outcome:?}"),
        };
        advance_tenant_authority_once(&state, &mut job, &lease, 100)
            .await
            .unwrap();

        assert!(
            rate_limit
                .try_consume(&scoped_key, 100, 1.0, 1.0, 1.0)
                .await
                .unwrap()
                .allowed
        );
        assert!(
            !rate_limit
                .try_consume(client_id, 100, 1.0, 1.0, 1.0)
                .await
                .unwrap()
                .allowed
        );
    }

    #[tokio::test]
    async fn retention_deadline_covers_audit_archive_and_operational_retention_windows() {
        let (state, _, pending) = retention_pending_tenant_fixture().await;

        let deadline = retention_deadline(&state, &pending, 100).await.unwrap();
        assert_eq!(
            deadline,
            100_i64.saturating_add(SECURITY_EVENT_ARCHIVE_RETENTION_SECS)
        );
        assert!(deadline >= 100_i64.saturating_add(SECURITY_EVENT_HOT_RETENTION_SECS));
        assert!(deadline >= 100_i64.saturating_add(BACKUP_RETENTION_SECS));
        assert!(deadline >= 100_i64.saturating_add(INCIDENT_QUEUE_RETENTION_SECS));
    }

    #[tokio::test]
    async fn continuation_audit_extends_the_durable_retention_anchor() {
        let (state, _, pending) = retention_pending_tenant_fixture().await;
        let audit_anchor = 500;

        extend_retention_for_audit(&state, &pending.tenant_id, &pending.job_id, audit_anchor)
            .await
            .unwrap();
        let extended = state
            .governance
            .get_job(&pending.tenant_id, &pending.job_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(extended.retention_anchor_at, Some(audit_anchor));
        assert_eq!(
            extended.retention_until,
            Some(mandatory_retention_deadline(audit_anchor))
        );
        assert_eq!(extended.revision, pending.revision + 1);
    }

    #[tokio::test]
    async fn replica_verification_audit_extends_the_durable_retention_anchor() {
        let (state, _, pending) = retention_pending_tenant_fixture().await;
        let mut verifying = pending.clone();
        verifying.state = GovernanceJobState::Running;
        verifying.phase = GovernanceJobPhase::ReplicaVerification;
        verifying.retention_until = None;
        let verifying = match state
            .governance
            .update_job(verifying, pending.revision, 0)
            .await
            .unwrap()
        {
            GovernanceJobUpdateOutcome::Stored(job) => job,
            outcome => panic!("unexpected job update: {outcome:?}"),
        };
        let audit_anchor = 500;

        extend_retention_for_audit(
            &state,
            &verifying.tenant_id,
            &verifying.job_id,
            audit_anchor,
        )
        .await
        .unwrap();
        let extended = state
            .governance
            .get_job(&verifying.tenant_id, &verifying.job_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(extended.retention_anchor_at, Some(audit_anchor));
        assert_eq!(
            extended.retention_until,
            Some(mandatory_retention_deadline(audit_anchor))
        );
        assert_eq!(extended.revision, verifying.revision + 1);
    }

    #[tokio::test]
    async fn legacy_short_retention_deadline_is_extended_before_completion() {
        let (state, _, pending) = retention_pending_tenant_fixture().await;
        let expected_revision = pending.revision;
        let mut short = pending.clone();
        short.retention_until = Some(100 + BACKUP_RETENTION_SECS);
        let short = match state
            .governance
            .update_job(short, expected_revision, 0)
            .await
            .unwrap()
        {
            GovernanceJobUpdateOutcome::Stored(job) => job,
            outcome => panic!("unexpected job update: {outcome:?}"),
        };

        let extended = finalize_retention_job(
            &state,
            &short.tenant_id,
            &short.job_id,
            short.retention_until.unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(extended.state, GovernanceJobState::RetentionPending);
        assert_eq!(
            extended.retention_until,
            Some(mandatory_retention_deadline(100))
        );
        assert_eq!(
            extended.error_class.as_deref(),
            Some("retention_policy_window_pending")
        );
        assert!(state
            .governance
            .latest_evidence(&extended.tenant_id, &extended.job_id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn multi_region_retention_runs_in_the_active_governance_region() {
        let (mut state, _, pending) = retention_pending_tenant_fixture().await;
        state.governance_config = Arc::new(
            GovernanceConfig::parse_json(
                r#"{"default":{"jurisdiction":"us","allowed_regions":["us-east-1","us-west-2"],"governance_region":"us-east-1"}}"#,
                &["default".into()],
            )
            .unwrap(),
        );
        state.region = RegionRuntime::controlled(
            "us-east-1",
            RegionControlStoreImpl::Memory(MemoryRegionControlStore::with_record(
                RegionControlRecord {
                    active: true,
                    activation_not_before: 100,
                    revision: 7,
                },
            )),
        )
        .unwrap();

        let deadline = pending.retention_until.unwrap();
        let completed =
            finalize_retention_job(&state, &pending.tenant_id, &pending.job_id, deadline)
                .await
                .unwrap();
        assert_eq!(completed.state, GovernanceJobState::Completed);
        let evidence = state
            .governance
            .latest_evidence(&pending.tenant_id, &pending.job_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            evidence.payload.configured_regions,
            ["us-east-1", "us-west-2"]
        );
        assert_eq!(evidence.payload.active_writer_region, "us-east-1");
        assert_eq!(evidence.payload.region_control_revision, 7);
        let backup = &evidence.payload.retention_resources["aws_backup_recovery_points"];
        assert_eq!(backup.state, "declared_policy_window_elapsed");
        assert_eq!(backup.evidence_basis, "declared_configuration");
    }

    #[tokio::test]
    async fn stale_completion_revision_exposes_neither_job_nor_evidence() {
        let (state, _, pending) = retention_pending_tenant_fixture().await;
        let expected_revision = pending.revision;
        let completion_at = pending.retention_until.unwrap();
        let policy = GovernancePolicyRecord::default_for(&pending.tenant_id);
        let mut completed = pending.clone();
        completed.state = GovernanceJobState::Completed;
        completed.phase = GovernanceJobPhase::Complete;
        completed.updated_at = completion_at;
        let evidence = build_evidence(
            &state,
            &completed,
            &policy,
            completion_at,
            BTreeMap::new(),
            BTreeMap::new(),
            0,
            Vec::new(),
            None,
        )
        .unwrap();
        completed.evidence_revision = evidence.payload.evidence_revision;

        extend_retention_for_audit(
            &state,
            &pending.tenant_id,
            &pending.job_id,
            completion_at + 1,
        )
        .await
        .unwrap();
        assert!(matches!(
            state
                .governance
                .complete_job_with_evidence(
                    completed,
                    evidence,
                    expected_revision,
                    policy.revision,
                )
                .await
                .unwrap(),
            GovernanceJobUpdateOutcome::Conflict(current)
                if current.revision == expected_revision + 1
                    && current.state == GovernanceJobState::RetentionPending
        ));
        assert!(state
            .governance
            .latest_evidence(&pending.tenant_id, &pending.job_id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn retention_completion_is_atomic_when_the_store_fails() {
        let (state, store, pending) = retention_pending_tenant_fixture().await;
        let deadline = pending.retention_until.unwrap();

        assert_eq!(run_retention_pass(&state, deadline - 1).await.unwrap(), 0);
        assert!(state
            .governance
            .latest_evidence(&pending.tenant_id, &pending.job_id)
            .await
            .unwrap()
            .is_none());

        store.fail_next_job_update().await;
        assert!(matches!(
            finalize_retention_job(&state, &pending.tenant_id, &pending.job_id, deadline).await,
            Err(GovernanceEngineError::Store(StoreError::Transient(_)))
        ));
        assert!(state
            .governance
            .latest_evidence(&pending.tenant_id, &pending.job_id)
            .await
            .unwrap()
            .is_none());
        let still_pending = state
            .governance
            .get_job(&pending.tenant_id, &pending.job_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(still_pending.state, GovernanceJobState::RetentionPending);
        assert_eq!(still_pending.evidence_revision, 0);

        let completed =
            finalize_retention_job(&state, &pending.tenant_id, &pending.job_id, deadline + 1)
                .await
                .unwrap();
        assert_eq!(completed.state, GovernanceJobState::Completed);
        assert_eq!(completed.evidence_revision, 1);
        let reconciled = state
            .governance
            .latest_evidence(&pending.tenant_id, &pending.job_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reconciled.payload.generated_at, deadline + 1);
    }

    #[tokio::test]
    async fn retention_scheduler_continues_after_one_job_fails_to_finalize() {
        let (state, _, good_job) = retention_pending_tenant_fixture().await;
        let deadline = good_job.retention_until.unwrap();
        let mut bad_job = good_job.clone();
        bad_job.job_id = "a-bad-retention-job".into();
        bad_job.primary_erasure_at = None;
        assert!(matches!(
            state
                .governance
                .start_or_resume_job(bad_job.clone(), 0, false)
                .await
                .unwrap(),
            GovernanceJobStartOutcome::Stored(_)
        ));

        assert_eq!(run_retention_pass(&state, deadline).await.unwrap(), 1);
        assert_eq!(
            state
                .governance
                .get_job(&bad_job.tenant_id, &bad_job.job_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            GovernanceJobState::RetentionPending
        );
        assert_eq!(
            state
                .governance
                .get_job(&good_job.tenant_id, &good_job.job_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            GovernanceJobState::Completed
        );
    }

    #[tokio::test]
    async fn ambiguous_secret_commit_is_reconciled_without_a_second_delete() {
        let (state, backend, job, action, secret_ref) = claimed_secret_fixture(100).await;
        backend
            .fail_next_schedule(MemorySecretScheduleFault::AfterCommit)
            .await;

        assert!(matches!(
            complete_claimed_secret_action(&state, &job, action.clone(), 101).await,
            Err(StoreError::Transient(_))
        ));
        assert_eq!(backend.schedule_attempts(&secret_ref).await, 1);

        let current = state
            .governance
            .get_external_action(&job.tenant_id, &job.job_id, &action.action_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.state, GovernanceExternalActionState::Claimed);

        let mut policy = GovernancePolicyRecord::default_for(&job.tenant_id);
        policy.legal_hold = LegalHoldState::Enabling;
        policy.legal_hold_reason = Some("case-1".into());
        assert!(matches!(
            state.governance.put_policy(policy, 0).await.unwrap(),
            GovernancePolicyPutOutcome::Stored(_)
        ));

        let reconciled = complete_claimed_secret_action(&state, &job, current, 102)
            .await
            .unwrap();
        assert_eq!(
            reconciled.state,
            GovernanceExternalActionState::ExternallyCommitted
        );
        assert_eq!(backend.schedule_attempts(&secret_ref).await, 1);
    }

    #[tokio::test]
    async fn replica_removal_dispatch_survives_lost_response_and_claim_expiry() {
        let (state, backend, job, action, secret_ref) = claimed_secret_fixture(100).await;
        backend
            .insert_replicated_secret(&secret_ref, &["us-west-2"])
            .await;
        backend
            .fail_next_schedule(MemorySecretScheduleFault::AfterReplicaRemoval)
            .await;

        assert!(matches!(
            complete_claimed_secret_action(&state, &job, action.clone(), 101).await,
            Err(StoreError::Transient(_))
        ));
        let current = state
            .governance
            .get_external_action(&job.tenant_id, &job.job_id, &action.action_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            current.state,
            GovernanceExternalActionState::ExternalPreparationDispatched
        );
        assert_eq!(backend.schedule_attempts(&secret_ref).await, 1);
        assert_eq!(
            backend
                .inspect_secret_deletion(&secret_ref, &action.resource_fingerprint)
                .await
                .unwrap(),
            SecretDeletionStatus::Present
        );

        let tombstoned =
            complete_claimed_secret_action(&state, &job, current, 100 + EXTERNAL_ACTION_CLAIM_SECS)
                .await
                .unwrap();
        assert_eq!(
            tombstoned.state,
            GovernanceExternalActionState::ClaimTombstoned
        );
        assert_eq!(
            tombstoned.error_class.as_deref(),
            Some("claim_expired_after_external_preparation")
        );
        assert_eq!(backend.schedule_attempts(&secret_ref).await, 1);

        let lease = claim_phase_lease(&state, &job, 131).await.unwrap().unwrap();
        let reclaimed = claim_external_action(&state, &job, &lease, tombstoned, 131)
            .await
            .unwrap();
        release_phase_lease(&state, &lease).await.unwrap();
        let committed = complete_claimed_secret_action(&state, &job, reclaimed, 132)
            .await
            .unwrap();
        assert_eq!(
            committed.state,
            GovernanceExternalActionState::ExternallyCommitted
        );
        assert_eq!(backend.schedule_attempts(&secret_ref).await, 2);
    }

    #[tokio::test]
    async fn enabling_hold_drains_persisted_secret_preparation_before_activation() {
        let (state, backend, job, action, secret_ref) = claimed_secret_fixture(100).await;
        backend
            .insert_replicated_secret(&secret_ref, &["us-west-2"])
            .await;
        assert!(matches!(
            complete_claimed_secret_action(&state, &job, action, 101).await,
            Err(StoreError::Transient(_))
        ));

        let mut policy = GovernancePolicyRecord::default_for(&job.tenant_id);
        policy.legal_hold = LegalHoldState::Enabling;
        policy.legal_hold_reason = Some("case-replica-drain".into());
        let policy = match state.governance.put_policy(policy, 0).await.unwrap() {
            GovernancePolicyPutOutcome::Stored(policy) => policy,
            outcome => panic!("unexpected policy update: {outcome:?}"),
        };

        let policy = settle_enabling_hold(&state, policy, 102).await.unwrap();
        assert_eq!(policy.legal_hold, LegalHoldState::Enabling);
        let action = state
            .governance
            .list_external_actions(&job.tenant_id, &job.job_id)
            .await
            .unwrap()
            .into_iter()
            .find(|action| action.kind == GovernanceExternalActionKind::SecretDeletion)
            .unwrap();
        assert_eq!(
            action.state,
            GovernanceExternalActionState::ExternallyCommitted
        );

        let policy = settle_enabling_hold(&state, policy, 103).await.unwrap();
        assert_eq!(policy.legal_hold, LegalHoldState::Enabled);
        let action = state
            .governance
            .get_external_action(&job.tenant_id, &job.job_id, &action.action_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(action.state, GovernanceExternalActionState::Verified);
        assert_eq!(backend.schedule_attempts(&secret_ref).await, 2);
    }

    #[tokio::test]
    async fn expired_claim_is_tombstoned_before_a_new_claim_can_dispatch() {
        let (state, backend, job, action, secret_ref) = claimed_secret_fixture(100).await;
        let stale_claim = action.clone();

        let tombstoned =
            complete_claimed_secret_action(&state, &job, action, 100 + EXTERNAL_ACTION_CLAIM_SECS)
                .await
                .unwrap();
        assert_eq!(
            tombstoned.state,
            GovernanceExternalActionState::ClaimTombstoned
        );
        assert_eq!(
            tombstoned.error_class.as_deref(),
            Some("claim_expired_no_side_effect")
        );
        assert_eq!(backend.schedule_attempts(&secret_ref).await, 0);

        let stale_result = complete_claimed_secret_action(&state, &job, stale_claim, 101)
            .await
            .unwrap();
        assert_eq!(
            stale_result.state,
            GovernanceExternalActionState::ClaimTombstoned
        );
        assert_eq!(backend.schedule_attempts(&secret_ref).await, 0);

        let lease = claim_phase_lease(&state, &job, 131).await.unwrap().unwrap();
        let reclaimed = claim_external_action(&state, &job, &lease, tombstoned, 131)
            .await
            .unwrap();
        release_phase_lease(&state, &lease).await.unwrap();
        assert_eq!(reclaimed.state, GovernanceExternalActionState::Claimed);
        let committed = complete_claimed_secret_action(&state, &job, reclaimed, 132)
            .await
            .unwrap();
        assert_eq!(
            committed.state,
            GovernanceExternalActionState::ExternallyCommitted
        );
        assert_eq!(backend.schedule_attempts(&secret_ref).await, 1);
    }

    #[tokio::test]
    async fn enabling_hold_drains_preexisting_claim_before_becoming_enabled() {
        let (state, backend, job, action, secret_ref) = claimed_secret_fixture(100).await;
        let mut policy = GovernancePolicyRecord::default_for(&job.tenant_id);
        policy.legal_hold = LegalHoldState::Enabling;
        policy.legal_hold_reason = Some("case-drain".into());
        assert!(matches!(
            state.governance.put_policy(policy, 0).await.unwrap(),
            GovernancePolicyPutOutcome::Stored(_)
        ));

        let blocked = advance_tenant_offboarding_once(&state, &job.tenant_id, &job.job_id, 101)
            .await
            .unwrap();
        assert_eq!(blocked.state, GovernanceJobState::BlockedLegalHold);
        assert_eq!(
            state
                .governance
                .get_policy(&job.tenant_id)
                .await
                .unwrap()
                .unwrap()
                .legal_hold,
            LegalHoldState::Enabling
        );
        let action = state
            .governance
            .get_external_action(&job.tenant_id, &job.job_id, &action.action_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            action.state,
            GovernanceExternalActionState::ExternallyCommitted
        );
        assert_eq!(backend.schedule_attempts(&secret_ref).await, 1);

        let blocked = advance_tenant_offboarding_once(&state, &job.tenant_id, &job.job_id, 102)
            .await
            .unwrap();
        assert_eq!(blocked.state, GovernanceJobState::BlockedLegalHold);
        let policy = state
            .governance
            .get_policy(&job.tenant_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(policy.legal_hold, LegalHoldState::Enabled);
        assert_eq!(policy.revision, 2);
        let action = state
            .governance
            .get_external_action(&job.tenant_id, &job.job_id, &action.action_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(action.state, GovernanceExternalActionState::Verified);
        assert_eq!(backend.schedule_attempts(&secret_ref).await, 1);
    }
}
