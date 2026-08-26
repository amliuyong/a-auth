use std::collections::HashMap;

use aws_sdk_dynamodb::{
    error::ProvideErrorMetadata,
    types::{AttributeValue, ConditionCheck, Delete, Put, TransactWriteItem, Update},
};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    governance::{
        GovernanceContinuationRecord, GovernanceContinuationUpdateOutcome,
        GovernanceDestructiveFence, GovernanceEvidencePutOutcome, GovernanceEvidenceRecord,
        GovernanceExportManifest, GovernanceExternalActionFence,
        GovernanceExternalActionPutOutcome, GovernanceExternalActionReconcileFence,
        GovernanceExternalActionRecord, GovernanceExternalActionState,
        GovernanceExternalActionUpdateOutcome, GovernanceJobKind, GovernanceJobLeaseConflict,
        GovernanceJobLeaseOutcome, GovernanceJobLeaseRecord, GovernanceJobPhase,
        GovernanceJobRecord, GovernanceJobStartOutcome, GovernanceJobState,
        GovernanceJobUpdateOutcome, GovernancePolicyPutOutcome, GovernancePolicyRecord,
        GovernanceResourceOwnership, GovernanceSuppressionRecord, LegalHoldState,
        TenantLifecycleRecord, TenantLifecycleState, TenantMutationGateRecord,
        TenantMutationGateState, TenantMutationPermit, TenantMutationPermitAcquireOutcome,
    },
    ports::{GovernanceStore, StoreError},
};

const POLICY_KEY: &str = "POLICY";
const LIFECYCLE_KEY: &str = "LIFECYCLE";
const JOB_PREFIX: &str = "JOB#";
const LEASE_PREFIX: &str = "LEASE#";
const EXPORT_PREFIX: &str = "EXPORT#";
const ACTION_PREFIX: &str = "ACTION#";
const EVIDENCE_PREFIX: &str = "EVIDENCE#";
const CONTINUATION_PREFIX: &str = "CONTINUATION#";
const CONTINUATION_JTI_PREFIX: &str = "CONTINUATION_JTI#";
const MUTATION_GATE_KEY: &str = "MUTATION_GATE";
const MUTATION_PERMIT_PREFIX: &str = "MUTATION_PERMIT#";
const DYNAMODB_TRANSACTION_ITEM_LIMIT: usize = 100;
const MUTATION_ACQUIRE_ATTEMPTS: usize = 6;

fn suppression_head_put(table: &str, pk: &str) -> Result<Put, StoreError> {
    Put::builder()
        .table_name(table)
        .item("pk", AttributeValue::S(pk.to_string()))
        .item("epoch", AttributeValue::N("0".into()))
        .item("record_type", AttributeValue::S("suppression_head".into()))
        .condition_expression("attribute_not_exists(pk) OR record_type = :head")
        .expression_attribute_values(":head", AttributeValue::S("suppression_head".into()))
        .build()
        .map_err(|error| StoreError::Permanent(format!("build suppression head put: {error}")))
}

fn suppression_epoch_put(
    table: &str,
    pk: &str,
    record: &GovernanceSuppressionRecord,
) -> Result<Put, StoreError> {
    let json = serde_json::to_string(record).map_err(|error| {
        StoreError::Permanent(format!("suppression serialization failed: {error}"))
    })?;
    Put::builder()
        .table_name(table)
        .item("pk", AttributeValue::S(pk.to_string()))
        .item("epoch", AttributeValue::N(record.target_epoch.to_string()))
        .item("record", AttributeValue::S(json))
        .condition_expression("attribute_not_exists(pk) AND attribute_not_exists(epoch)")
        .build()
        .map_err(|error| StoreError::Permanent(format!("build suppression epoch put: {error}")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum GovernanceDestructiveWriteOutcome {
    Applied,
    FenceConflict,
}

#[derive(Clone)]
pub struct DynamoGovernanceStore {
    db: aws_sdk_dynamodb::Client,
    governance_table: String,
    suppression_table: String,
}

impl DynamoGovernanceStore {
    pub fn new(
        db: aws_sdk_dynamodb::Client,
        governance_table: impl Into<String>,
        suppression_table: impl Into<String>,
    ) -> Self {
        Self {
            db,
            governance_table: governance_table.into(),
            suppression_table: suppression_table.into(),
        }
    }

    async fn get_mutation_gate(
        &self,
        tenant_id: &str,
    ) -> Result<Option<TenantMutationGateRecord>, StoreError> {
        let output = self
            .db
            .get_item()
            .table_name(&self.governance_table)
            .key("pk", AttributeValue::S(tenant_id.to_string()))
            .key("sk", AttributeValue::S(MUTATION_GATE_KEY.into()))
            .consistent_read(true)
            .send()
            .await
            .map_err(super::ddb_err)?;
        output
            .item()
            .map(|item| {
                let item_tenant = item
                    .get("tenant_id")
                    .and_then(|value| value.as_s().ok())
                    .ok_or_else(|| {
                        StoreError::Permanent("tenant mutation gate tenant is missing".into())
                    })?;
                if item_tenant != tenant_id {
                    return Err(StoreError::Permanent(
                        "tenant mutation gate identity mismatch".into(),
                    ));
                }
                let state = match item
                    .get("state")
                    .and_then(|value| value.as_s().ok())
                    .map(String::as_str)
                {
                    Some("active") => TenantMutationGateState::Active,
                    Some("frozen") => TenantMutationGateState::Frozen,
                    _ => {
                        return Err(StoreError::Permanent(
                            "tenant mutation gate state is invalid".into(),
                        ))
                    }
                };
                let number = |name: &str| -> Result<u64, StoreError> {
                    item.get(name)
                        .and_then(|value| value.as_n().ok())
                        .and_then(|value| value.parse().ok())
                        .ok_or_else(|| {
                            StoreError::Permanent(format!("tenant mutation gate {name} is invalid"))
                        })
                };
                let updated_at = item
                    .get("updated_at")
                    .and_then(|value| value.as_n().ok())
                    .and_then(|value| value.parse().ok())
                    .ok_or_else(|| {
                        StoreError::Permanent("tenant mutation gate updated_at is invalid".into())
                    })?;
                Ok(TenantMutationGateRecord {
                    tenant_id: tenant_id.to_string(),
                    state,
                    active_permits: number("active_permits")?,
                    revision: number("revision")?,
                    updated_at,
                })
            })
            .transpose()
    }

    async fn get_mutation_permit(
        &self,
        tenant_id: &str,
        permit_id: &str,
    ) -> Result<Option<TenantMutationPermit>, StoreError> {
        let output = self
            .db
            .get_item()
            .table_name(&self.governance_table)
            .key("pk", AttributeValue::S(tenant_id.to_string()))
            .key("sk", AttributeValue::S(mutation_permit_key(permit_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(super::ddb_err)?;
        output
            .item()
            .map(|item| {
                let deadline = item
                    .get("permit_deadline")
                    .and_then(|value| value.as_n().ok())
                    .and_then(|value| value.parse().ok())
                    .ok_or_else(|| {
                        StoreError::Permanent("tenant mutation permit deadline is invalid".into())
                    })?;
                Ok(TenantMutationPermit {
                    tenant_id: tenant_id.to_string(),
                    permit_id: permit_id.to_string(),
                    deadline,
                })
            })
            .transpose()
    }

    async fn reap_expired_mutation_permits(
        &self,
        tenant_id: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        let mut exclusive_start_key = None;
        loop {
            let output = self
                .db
                .query()
                .table_name(&self.governance_table)
                .key_condition_expression("pk = :tenant AND begins_with(sk, :prefix)")
                .expression_attribute_values(":tenant", AttributeValue::S(tenant_id.to_string()))
                .expression_attribute_values(
                    ":prefix",
                    AttributeValue::S(MUTATION_PERMIT_PREFIX.into()),
                )
                .projection_expression("pk, sk, permit_deadline")
                .consistent_read(true)
                .set_exclusive_start_key(exclusive_start_key)
                .send()
                .await
                .map_err(super::ddb_err)?;
            for item in output.items() {
                let Some(deadline) = item
                    .get("permit_deadline")
                    .and_then(|value| value.as_n().ok())
                    .and_then(|value| value.parse::<i64>().ok())
                else {
                    return Err(StoreError::Permanent(
                        "tenant mutation permit deadline is invalid".into(),
                    ));
                };
                if deadline > now {
                    continue;
                }
                let sk = item.get("sk").cloned().ok_or_else(|| {
                    StoreError::Permanent("tenant mutation permit key is missing".into())
                })?;
                let delete = Delete::builder()
                    .table_name(&self.governance_table)
                    .key("pk", AttributeValue::S(tenant_id.to_string()))
                    .key("sk", sk)
                    .condition_expression("permit_deadline = :deadline")
                    .expression_attribute_values(
                        ":deadline",
                        AttributeValue::N(deadline.to_string()),
                    )
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!(
                            "expired tenant mutation permit delete is incomplete: {error}"
                        ))
                    })?;
                let gate = mutation_gate_decrement(&self.governance_table, tenant_id, now)?;
                match self
                    .db
                    .transact_write_items()
                    .transact_items(TransactWriteItem::builder().delete(delete).build())
                    .transact_items(gate)
                    .send()
                    .await
                {
                    Ok(_) => {}
                    Err(error) if is_transaction_conflict(&error) => {}
                    Err(error) => return Err(super::ddb_err(error)),
                }
            }
            exclusive_start_key = output.last_evaluated_key().cloned();
            if exclusive_start_key.is_none() {
                return Ok(());
            }
        }
    }

    async fn prepare_mutation_gate_freeze(
        &self,
        tenant_id: &str,
        now: i64,
    ) -> Result<Result<TransactWriteItem, u64>, StoreError> {
        self.reap_expired_mutation_permits(tenant_id, now).await?;
        let gate = self.get_mutation_gate(tenant_id).await?;
        if let Some(gate) = gate.as_ref() {
            if gate.state == TenantMutationGateState::Frozen {
                return Err(StoreError::Permanent(
                    "tenant mutation gate is frozen without its offboarding job".into(),
                ));
            }
            if gate.active_permits > 0 {
                return Ok(Err(gate.active_permits));
            }
        }
        Ok(Ok(mutation_gate_freeze_item(
            &self.governance_table,
            tenant_id,
            gate.as_ref(),
            now,
        )?))
    }

    async fn suppression_epoch_matches(
        &self,
        record: &GovernanceSuppressionRecord,
    ) -> Result<bool, StoreError> {
        let output = self
            .db
            .get_item()
            .table_name(&self.suppression_table)
            .key(
                "pk",
                AttributeValue::S(crate::governance::suppression_partition_key(
                    &record.tenant_id,
                    &record.target_class,
                    &record.digest,
                )),
            )
            .key("epoch", AttributeValue::N(record.target_epoch.to_string()))
            .consistent_read(true)
            .send()
            .await
            .map_err(super::ddb_err)?;
        let Some(item) = output.item() else {
            return Ok(false);
        };
        let encoded = item
            .get("record")
            .and_then(|value| value.as_s().ok())
            .ok_or_else(|| StoreError::Permanent("suppression epoch contains no record".into()))?;
        let stored: GovernanceSuppressionRecord =
            serde_json::from_str(encoded).map_err(|error| {
                StoreError::Permanent(format!("suppression epoch is invalid: {error}"))
            })?;
        if stored.tenant_id != record.tenant_id
            || stored.target_class != record.target_class
            || stored.key_version != record.key_version
            || stored.normalization_version != record.normalization_version
            || stored.digest != record.digest
            || stored.target_epoch != record.target_epoch
        {
            return Err(StoreError::Permanent(
                "suppression epoch identity changed".into(),
            ));
        }
        Ok(true)
    }

    /// Revalidates a claimed one-shot governance permit immediately before the
    /// tenant-key provisioner starts its bounded KMS operation.
    pub async fn authorize_tenant_key_dispatch(
        &self,
        tenant_id: &str,
        permit: &crate::tenant_keys::TenantKeyGovernanceDispatchPermit,
        now: i64,
    ) -> Result<bool, StoreError> {
        if tenant_id.is_empty()
            || permit.job_id.is_empty()
            || permit.action_id.is_empty()
            || permit.action_revision == 0
            || permit.claim_token_digest.is_empty()
            || permit.tenant_revision == 0
        {
            return Ok(false);
        }

        let Some(current) = self
            .get_external_action(tenant_id, &permit.job_id, &permit.action_id)
            .await?
        else {
            return Ok(false);
        };
        let same_claim = current.tenant_id == tenant_id
            && current.job_id == permit.job_id
            && current.action_id == permit.action_id
            && current.kind == crate::governance::GovernanceExternalActionKind::TenantKeyDeletion
            && current.claim_token_digest.as_deref() == Some(permit.claim_token_digest.as_str())
            && current.claim_deadline == Some(permit.claim_deadline);
        if !same_claim
            || current.state != GovernanceExternalActionState::Claimed
            || current.revision != permit.action_revision
            || permit.claim_deadline <= now
        {
            return Ok(false);
        }

        let policy = self
            .get_policy(tenant_id)
            .await?
            .unwrap_or_else(|| GovernancePolicyRecord::default_for(tenant_id));
        let job = self.get_job(tenant_id, &permit.job_id).await?;
        let lifecycle = self.get_tenant_lifecycle(tenant_id).await?;
        if policy.held()
            || job.as_ref().is_none_or(|job| {
                job.kind != GovernanceJobKind::TenantOffboarding
                    || job.tenant_revision != permit.tenant_revision
            })
            || lifecycle.as_ref().is_none_or(|lifecycle| {
                lifecycle.state != TenantLifecycleState::Offboarding
                    || lifecycle.revision != permit.tenant_revision
            })
        {
            return Ok(false);
        }
        Ok(true)
    }

    /// Records the successful external KMS outcome after it happened. This is
    /// reconciliation rather than authorization, so an enabling legal hold may
    /// not erase an already-issued claim's observed result.
    pub async fn commit_tenant_key_dispatch(
        &self,
        tenant_id: &str,
        permit: &crate::tenant_keys::TenantKeyGovernanceDispatchPermit,
        now: i64,
    ) -> Result<bool, StoreError> {
        let Some(current) = self
            .get_external_action(tenant_id, &permit.job_id, &permit.action_id)
            .await?
        else {
            return Ok(false);
        };
        let same_claim = current.tenant_id == tenant_id
            && current.job_id == permit.job_id
            && current.action_id == permit.action_id
            && current.kind == crate::governance::GovernanceExternalActionKind::TenantKeyDeletion
            && current.claim_token_digest.as_deref() == Some(permit.claim_token_digest.as_str())
            && current.claim_deadline == Some(permit.claim_deadline);
        if current.state == GovernanceExternalActionState::ExternallyCommitted && same_claim {
            return Ok(true);
        }
        if !same_claim || current.state != GovernanceExternalActionState::Claimed {
            return Ok(false);
        }
        let expected_revision = current.revision;
        let mut committed = current;
        committed.state = GovernanceExternalActionState::ExternallyCommitted;
        committed.committed_at = Some(now);
        committed.updated_at = now;
        committed.revision = expected_revision.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("governance external action revision exhausted".into())
        })?;

        let reconcile_fence = GovernanceExternalActionReconcileFence {
            job_id: permit.job_id.clone(),
            tenant_revision: permit.tenant_revision,
            claim_token_digest: permit.claim_token_digest.clone(),
        };
        let mut transaction = self.external_reconcile_conditions(tenant_id, &reconcile_fence)?;
        transaction.push(self.external_action_put(&committed, false, Some(expected_revision))?);
        match self
            .db
            .transact_write_items()
            .set_transact_items(Some(transaction))
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(error) if is_transaction_conflict(&error) => {
                let latest = self
                    .get_external_action(tenant_id, &permit.job_id, &permit.action_id)
                    .await?;
                Ok(latest.is_some_and(|action| {
                    action.state == GovernanceExternalActionState::ExternallyCommitted
                        && action.claim_token_digest.as_deref()
                            == Some(permit.claim_token_digest.as_str())
                        && action.claim_deadline == Some(permit.claim_deadline)
                }))
            }
            Err(error) => Err(super::ddb_err(error)),
        }
    }

    async fn get_record<T: DeserializeOwned>(
        &self,
        tenant_id: &str,
        record_key: &str,
    ) -> Result<Option<T>, StoreError> {
        let output = self
            .db
            .get_item()
            .table_name(&self.governance_table)
            .key("pk", AttributeValue::S(tenant_id.to_string()))
            .key("sk", AttributeValue::S(record_key.to_string()))
            .consistent_read(true)
            .send()
            .await
            .map_err(super::ddb_err)?;
        output
            .item()
            .map(|item| record_from_item(item, tenant_id, record_key))
            .transpose()
    }

    fn record_item<T: Serialize>(
        tenant_id: &str,
        record_key: &str,
        record_type: &str,
        record: &T,
    ) -> Result<HashMap<String, AttributeValue>, StoreError> {
        let json = serde_json::to_string(record).map_err(|error| {
            StoreError::Permanent(format!("governance record serialization failed: {error}"))
        })?;
        Ok(HashMap::from([
            ("pk".into(), AttributeValue::S(tenant_id.to_string())),
            ("sk".into(), AttributeValue::S(record_key.to_string())),
            ("record_type".into(), AttributeValue::S(record_type.into())),
            ("record".into(), AttributeValue::S(json)),
        ]))
    }

    fn job_item(job: &GovernanceJobRecord) -> Result<HashMap<String, AttributeValue>, StoreError> {
        let key = format!("{JOB_PREFIX}{}", job.job_id);
        let mut item = Self::record_item(&job.tenant_id, &key, "job", job)?;
        item.insert(
            "revision".into(),
            AttributeValue::N(job.revision.to_string()),
        );
        item.insert(
            "state".into(),
            AttributeValue::S(job_state_name(job.state).into()),
        );
        item.insert(
            "phase".into(),
            AttributeValue::S(job_phase_name(job.phase).into()),
        );
        item.insert(
            "policy_revision".into(),
            AttributeValue::N(job.policy_revision.to_string()),
        );
        item.insert(
            "tenant_revision".into(),
            AttributeValue::N(job.tenant_revision.to_string()),
        );
        item.insert(
            "job_kind".into(),
            AttributeValue::S(job_kind_name(job.kind).into()),
        );
        item.insert(
            "target_epoch".into(),
            AttributeValue::N(job.target_epoch.to_string()),
        );
        Ok(item)
    }

    fn policy_condition(
        &self,
        tenant_id: &str,
        policy: &GovernancePolicyRecord,
    ) -> Result<TransactWriteItem, StoreError> {
        let mut condition = ConditionCheck::builder()
            .table_name(&self.governance_table)
            .key("pk", AttributeValue::S(tenant_id.to_string()))
            .key("sk", AttributeValue::S(POLICY_KEY.to_string()));
        if policy.revision == 0 {
            condition = condition.condition_expression("attribute_not_exists(pk)");
        } else {
            condition = condition
                .condition_expression("revision = :revision AND legal_hold = :legal_hold")
                .expression_attribute_values(
                    ":revision",
                    AttributeValue::N(policy.revision.to_string()),
                )
                .expression_attribute_values(
                    ":legal_hold",
                    AttributeValue::S(legal_hold_name(policy.legal_hold).into()),
                );
        }
        Ok(TransactWriteItem::builder()
            .condition_check(condition.build().map_err(|error| {
                StoreError::Permanent(format!(
                    "governance policy condition is incomplete: {error}"
                ))
            })?)
            .build())
    }

    fn job_put(
        &self,
        job: &GovernanceJobRecord,
        create: bool,
        expected_revision: Option<u64>,
    ) -> Result<TransactWriteItem, StoreError> {
        let item = Self::job_item(job)?;
        let mut put = Put::builder()
            .table_name(&self.governance_table)
            .set_item(Some(item));
        if create {
            put = put.condition_expression("attribute_not_exists(pk)");
        } else if let Some(revision) = expected_revision {
            put = put
                .condition_expression("revision = :revision")
                .expression_attribute_values(":revision", AttributeValue::N(revision.to_string()));
        }
        Ok(TransactWriteItem::builder()
            .put(put.build().map_err(|error| {
                StoreError::Permanent(format!("governance job put is incomplete: {error}"))
            })?)
            .build())
    }

    fn lifecycle_condition(
        governance_table: &str,
        tenant_id: &str,
        tenant_revision: u64,
        label: &str,
    ) -> Result<TransactWriteItem, StoreError> {
        let condition = if tenant_revision == 0 {
            ConditionCheck::builder()
                .table_name(governance_table)
                .key("pk", AttributeValue::S(tenant_id.to_string()))
                .key("sk", AttributeValue::S(LIFECYCLE_KEY.to_string()))
                .condition_expression("attribute_not_exists(pk) OR #state = :active")
                .expression_attribute_names("#state", "state")
                .expression_attribute_values(
                    ":active",
                    AttributeValue::S(lifecycle_state_name(TenantLifecycleState::Active).into()),
                )
        } else {
            ConditionCheck::builder()
                .table_name(governance_table)
                .key("pk", AttributeValue::S(tenant_id.to_string()))
                .key("sk", AttributeValue::S(LIFECYCLE_KEY.to_string()))
                .condition_expression("revision = :revision AND #state = :offboarding")
                .expression_attribute_names("#state", "state")
                .expression_attribute_values(
                    ":revision",
                    AttributeValue::N(tenant_revision.to_string()),
                )
                .expression_attribute_values(
                    ":offboarding",
                    AttributeValue::S(
                        lifecycle_state_name(TenantLifecycleState::Offboarding).into(),
                    ),
                )
        }
        .build()
        .map_err(|error| {
            StoreError::Permanent(format!(
                "governance {label} lifecycle condition is incomplete: {error}"
            ))
        })?;
        Ok(TransactWriteItem::builder()
            .condition_check(condition)
            .build())
    }

    fn destructive_transaction_items(
        governance_table: &str,
        tenant_id: &str,
        fence: &GovernanceDestructiveFence,
        job: &GovernanceJobRecord,
        now: i64,
        target_writes: Vec<TransactWriteItem>,
    ) -> Result<Vec<TransactWriteItem>, StoreError> {
        if target_writes.is_empty() {
            return Err(StoreError::Permanent(
                "governance destructive transaction has no target writes".into(),
            ));
        }
        let fixed_item_count = 4;
        let target_limit = DYNAMODB_TRANSACTION_ITEM_LIMIT - fixed_item_count;
        if target_writes.len() > target_limit {
            return Err(StoreError::Permanent(format!(
                "governance destructive transaction exceeds target write limit {target_limit}"
            )));
        }

        let mut policy = ConditionCheck::builder()
            .table_name(governance_table)
            .key("pk", AttributeValue::S(tenant_id.to_string()))
            .key("sk", AttributeValue::S(POLICY_KEY.to_string()));
        if fence.policy_revision == 0 {
            policy = policy.condition_expression("attribute_not_exists(pk)");
        } else {
            policy = policy
                .condition_expression("revision = :policy_revision AND legal_hold = :disabled")
                .expression_attribute_values(
                    ":policy_revision",
                    AttributeValue::N(fence.policy_revision.to_string()),
                )
                .expression_attribute_values(
                    ":disabled",
                    AttributeValue::S(legal_hold_name(LegalHoldState::Disabled).into()),
                );
        }
        let policy = policy.build().map_err(|error| {
            StoreError::Permanent(format!(
                "governance destructive policy fence is incomplete: {error}"
            ))
        })?;

        let job_condition = ConditionCheck::builder()
            .table_name(governance_table)
            .key("pk", AttributeValue::S(tenant_id.to_string()))
            .key(
                "sk",
                AttributeValue::S(format!("{JOB_PREFIX}{}", fence.job_id)),
            )
            .condition_expression(
                "revision = :job_revision AND policy_revision = :policy_revision \
                 AND tenant_revision = :tenant_revision AND #state = :job_state \
                 AND phase = :job_phase AND job_kind = :job_kind \
                 AND target_epoch = :target_epoch",
            )
            .expression_attribute_names("#state", "state")
            .expression_attribute_values(
                ":job_revision",
                AttributeValue::N(fence.job_revision.to_string()),
            )
            .expression_attribute_values(
                ":policy_revision",
                AttributeValue::N(fence.policy_revision.to_string()),
            )
            .expression_attribute_values(
                ":tenant_revision",
                AttributeValue::N(fence.tenant_revision.to_string()),
            )
            .expression_attribute_values(
                ":job_state",
                AttributeValue::S(job_state_name(job.state).into()),
            )
            .expression_attribute_values(
                ":job_phase",
                AttributeValue::S(job_phase_name(job.phase).into()),
            )
            .expression_attribute_values(
                ":job_kind",
                AttributeValue::S(job_kind_name(job.kind).into()),
            )
            .expression_attribute_values(
                ":target_epoch",
                AttributeValue::N(job.target_epoch.to_string()),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "governance destructive job fence is incomplete: {error}"
                ))
            })?;

        let lease = ConditionCheck::builder()
            .table_name(governance_table)
            .key("pk", AttributeValue::S(tenant_id.to_string()))
            .key("sk", AttributeValue::S(job_lease_key(&fence.job_id)))
            .condition_expression(
                "job_revision = :job_revision AND policy_revision = :policy_revision \
                 AND tenant_revision = :tenant_revision AND token_digest = :token_digest \
                 AND lease_deadline = :lease_deadline AND lease_deadline > :now",
            )
            .expression_attribute_values(
                ":job_revision",
                AttributeValue::N(fence.job_revision.to_string()),
            )
            .expression_attribute_values(
                ":policy_revision",
                AttributeValue::N(fence.policy_revision.to_string()),
            )
            .expression_attribute_values(
                ":tenant_revision",
                AttributeValue::N(fence.tenant_revision.to_string()),
            )
            .expression_attribute_values(
                ":token_digest",
                AttributeValue::S(fence.lease_token_digest.clone()),
            )
            .expression_attribute_values(
                ":lease_deadline",
                AttributeValue::N(fence.lease_deadline.to_string()),
            )
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "governance destructive lease fence is incomplete: {error}"
                ))
            })?;

        let mut transaction = Vec::with_capacity(fixed_item_count + target_writes.len());
        transaction.push(TransactWriteItem::builder().condition_check(policy).build());
        transaction.push(
            TransactWriteItem::builder()
                .condition_check(job_condition)
                .build(),
        );
        transaction.push(Self::lifecycle_condition(
            governance_table,
            tenant_id,
            fence.tenant_revision,
            "destructive fence",
        )?);
        transaction.push(TransactWriteItem::builder().condition_check(lease).build());
        transaction.extend(target_writes);
        Ok(transaction)
    }

    #[allow(dead_code)]
    pub(crate) async fn execute_destructive_transaction(
        &self,
        tenant_id: &str,
        fence: GovernanceDestructiveFence,
        now: i64,
        target_writes: Vec<TransactWriteItem>,
    ) -> Result<GovernanceDestructiveWriteOutcome, StoreError> {
        if fence.lease_token_digest.is_empty() || fence.lease_deadline <= now {
            return Ok(GovernanceDestructiveWriteOutcome::FenceConflict);
        }
        let Some(job) = self.get_job(tenant_id, &fence.job_id).await? else {
            return Ok(GovernanceDestructiveWriteOutcome::FenceConflict);
        };
        if job.revision != fence.job_revision
            || job.policy_revision != fence.policy_revision
            || job.tenant_revision != fence.tenant_revision
            || fence
                .target_epoch
                .is_some_and(|target_epoch| target_epoch != job.target_epoch)
        {
            return Ok(GovernanceDestructiveWriteOutcome::FenceConflict);
        }
        let transaction = Self::destructive_transaction_items(
            &self.governance_table,
            tenant_id,
            &fence,
            &job,
            now,
            target_writes,
        )?;
        match self
            .db
            .transact_write_items()
            .set_transact_items(Some(transaction))
            .send()
            .await
        {
            Ok(_) => Ok(GovernanceDestructiveWriteOutcome::Applied),
            Err(error) => match classify_destructive_transaction_error(&error) {
                Some(DestructiveTransactionError::FenceConflict) => {
                    Ok(GovernanceDestructiveWriteOutcome::FenceConflict)
                }
                Some(DestructiveTransactionError::Transient) => Err(StoreError::Transient(
                    "DynamoDB destructive transaction canceled".into(),
                )),
                Some(DestructiveTransactionError::Permanent) => Err(StoreError::Permanent(
                    "DynamoDB destructive transaction validation failed".into(),
                )),
                None => Err(super::ddb_err(error)),
            },
        }
    }

    fn lifecycle_put(
        &self,
        lifecycle: &TenantLifecycleRecord,
        create: bool,
    ) -> Result<TransactWriteItem, StoreError> {
        let mut item = Self::record_item(
            &lifecycle.tenant_id,
            LIFECYCLE_KEY,
            "tenant_lifecycle",
            lifecycle,
        )?;
        item.insert(
            "revision".into(),
            AttributeValue::N(lifecycle.revision.to_string()),
        );
        item.insert(
            "state".into(),
            AttributeValue::S(lifecycle_state_name(lifecycle.state).into()),
        );
        let mut put = Put::builder()
            .table_name(&self.governance_table)
            .set_item(Some(item));
        if create {
            put = put.condition_expression("attribute_not_exists(pk)");
        } else {
            put = put
                .condition_expression("revision = :previous AND #state = :active")
                .expression_attribute_names("#state", "state")
                .expression_attribute_values(
                    ":previous",
                    AttributeValue::N(lifecycle.revision.saturating_sub(1).to_string()),
                )
                .expression_attribute_values(
                    ":active",
                    AttributeValue::S(lifecycle_state_name(TenantLifecycleState::Active).into()),
                );
        }
        Ok(TransactWriteItem::builder()
            .put(put.build().map_err(|error| {
                StoreError::Permanent(format!(
                    "governance tenant lifecycle put is incomplete: {error}"
                ))
            })?)
            .build())
    }

    fn continuation_put(
        &self,
        record: &GovernanceContinuationRecord,
        create: bool,
        expected_revision: Option<u64>,
    ) -> Result<TransactWriteItem, StoreError> {
        let key = continuation_key(&record.job_id);
        let mut item =
            Self::record_item(&record.tenant_id, &key, "governance_continuation", record)?;
        item.insert(
            "revision".into(),
            AttributeValue::N(record.revision.to_string()),
        );
        item.insert(
            "resume_revision".into(),
            AttributeValue::N(record.resume_revision.to_string()),
        );
        item.insert(
            "read_revision".into(),
            AttributeValue::N(record.read_revision.to_string()),
        );
        item.insert(
            "resume_enabled".into(),
            AttributeValue::Bool(record.resume_enabled),
        );
        item.insert(
            "read_enabled".into(),
            AttributeValue::Bool(record.read_enabled),
        );
        let mut put = Put::builder()
            .table_name(&self.governance_table)
            .set_item(Some(item));
        if create {
            put = put.condition_expression("attribute_not_exists(pk)");
        } else if let Some(revision) = expected_revision {
            put = put
                .condition_expression("revision = :revision")
                .expression_attribute_values(":revision", AttributeValue::N(revision.to_string()));
        }
        Ok(TransactWriteItem::builder()
            .put(put.build().map_err(|error| {
                StoreError::Permanent(format!(
                    "governance continuation put is incomplete: {error}"
                ))
            })?)
            .build())
    }

    fn external_action_put(
        &self,
        record: &GovernanceExternalActionRecord,
        create: bool,
        expected_revision: Option<u64>,
    ) -> Result<TransactWriteItem, StoreError> {
        let key = external_action_key(&record.job_id, &record.action_id);
        let mut item = Self::record_item(&record.tenant_id, &key, "external_action", record)?;
        item.insert(
            "revision".into(),
            AttributeValue::N(record.revision.to_string()),
        );
        let mut put = Put::builder()
            .table_name(&self.governance_table)
            .set_item(Some(item));
        if create {
            put = put.condition_expression("attribute_not_exists(pk)");
        } else if let Some(revision) = expected_revision {
            put = put
                .condition_expression("revision = :revision")
                .expression_attribute_values(":revision", AttributeValue::N(revision.to_string()));
        }
        Ok(TransactWriteItem::builder()
            .put(put.build().map_err(|error| {
                StoreError::Permanent(format!(
                    "governance external action put is incomplete: {error}"
                ))
            })?)
            .build())
    }

    fn job_authority_conditions(
        &self,
        tenant_id: &str,
        job: &GovernanceJobRecord,
    ) -> Result<Vec<TransactWriteItem>, StoreError> {
        let job_condition = ConditionCheck::builder()
            .table_name(&self.governance_table)
            .key("pk", AttributeValue::S(tenant_id.to_string()))
            .key(
                "sk",
                AttributeValue::S(format!("{JOB_PREFIX}{}", job.job_id)),
            )
            .condition_expression(
                "revision = :job_revision AND policy_revision = :policy_revision \
                 AND tenant_revision = :tenant_revision \
                 AND (#state = :queued OR #state = :running OR #state = :retryable)",
            )
            .expression_attribute_names("#state", "state")
            .expression_attribute_values(
                ":job_revision",
                AttributeValue::N(job.revision.to_string()),
            )
            .expression_attribute_values(
                ":policy_revision",
                AttributeValue::N(job.policy_revision.to_string()),
            )
            .expression_attribute_values(
                ":tenant_revision",
                AttributeValue::N(job.tenant_revision.to_string()),
            )
            .expression_attribute_values(
                ":queued",
                AttributeValue::S(job_state_name(GovernanceJobState::Queued).into()),
            )
            .expression_attribute_values(
                ":running",
                AttributeValue::S(job_state_name(GovernanceJobState::Running).into()),
            )
            .expression_attribute_values(
                ":retryable",
                AttributeValue::S(job_state_name(GovernanceJobState::Retryable).into()),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "governance job lease condition is incomplete: {error}"
                ))
            })?;
        let mut conditions = vec![TransactWriteItem::builder()
            .condition_check(job_condition)
            .build()];
        conditions.push(Self::lifecycle_condition(
            &self.governance_table,
            tenant_id,
            job.tenant_revision,
            "job lease",
        )?);
        Ok(conditions)
    }

    fn job_lease_put(
        &self,
        lease: &GovernanceJobLeaseRecord,
        expected: Option<&GovernanceDestructiveFence>,
        now: i64,
    ) -> Result<TransactWriteItem, StoreError> {
        let key = job_lease_key(&lease.job_id);
        let mut item = Self::record_item(&lease.tenant_id, &key, "job_lease", lease)?;
        item.insert(
            "job_revision".into(),
            AttributeValue::N(lease.job_revision.to_string()),
        );
        item.insert(
            "policy_revision".into(),
            AttributeValue::N(lease.policy_revision.to_string()),
        );
        item.insert(
            "tenant_revision".into(),
            AttributeValue::N(lease.tenant_revision.to_string()),
        );
        item.insert(
            "token_digest".into(),
            AttributeValue::S(lease.token_digest.clone()),
        );
        item.insert(
            "lease_deadline".into(),
            AttributeValue::N(lease.deadline.to_string()),
        );
        let mut put = Put::builder()
            .table_name(&self.governance_table)
            .set_item(Some(item))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()));
        if let Some(expected) = expected {
            put = put
                .condition_expression(
                    "job_revision = :job_revision AND token_digest = :token_digest \
                     AND lease_deadline = :lease_deadline AND lease_deadline > :now",
                )
                .expression_attribute_values(
                    ":job_revision",
                    AttributeValue::N(expected.job_revision.to_string()),
                )
                .expression_attribute_values(
                    ":token_digest",
                    AttributeValue::S(expected.lease_token_digest.clone()),
                )
                .expression_attribute_values(
                    ":lease_deadline",
                    AttributeValue::N(expected.lease_deadline.to_string()),
                );
        } else {
            put = put.condition_expression("attribute_not_exists(pk) OR lease_deadline <= :now");
        }
        let put = put.build().map_err(|error| {
            StoreError::Permanent(format!("governance job lease put is incomplete: {error}"))
        })?;
        Ok(TransactWriteItem::builder().put(put).build())
    }

    async fn get_job_lease(
        &self,
        tenant_id: &str,
        job_id: &str,
    ) -> Result<Option<GovernanceJobLeaseRecord>, StoreError> {
        self.get_record(tenant_id, &job_lease_key(job_id)).await
    }

    async fn classify_job_lease_conflict(
        &self,
        tenant_id: &str,
        job_id: &str,
        expected_job_revision: u64,
        expected_token_digest: Option<&str>,
        expected_deadline: Option<i64>,
        now: i64,
    ) -> Result<GovernanceJobLeaseConflict, StoreError> {
        let Some(job) = self.get_job(tenant_id, job_id).await? else {
            return Ok(GovernanceJobLeaseConflict::Job);
        };
        let policy = self
            .get_policy(tenant_id)
            .await?
            .unwrap_or_else(|| GovernancePolicyRecord::default_for(tenant_id));
        if policy.revision != job.policy_revision || policy.held() {
            return Ok(GovernanceJobLeaseConflict::Policy);
        }
        if job.revision != expected_job_revision
            || !matches!(
                job.state,
                GovernanceJobState::Queued
                    | GovernanceJobState::Running
                    | GovernanceJobState::Retryable
            )
        {
            return Ok(GovernanceJobLeaseConflict::Job);
        }
        if job.tenant_revision != 0
            && self
                .get_tenant_lifecycle(tenant_id)
                .await?
                .is_none_or(|lifecycle| {
                    lifecycle.state != TenantLifecycleState::Offboarding
                        || lifecycle.revision != job.tenant_revision
                })
        {
            return Ok(GovernanceJobLeaseConflict::TenantLifecycle);
        }
        let lease = self.get_job_lease(tenant_id, job_id).await?;
        if expected_token_digest.is_some_and(|digest| {
            lease
                .as_ref()
                .is_none_or(|lease| lease.token_digest != digest)
        }) || expected_deadline.is_some_and(|deadline| {
            lease
                .as_ref()
                .is_none_or(|lease| lease.deadline != deadline)
        }) || lease.is_some_and(|lease| lease.deadline > now)
        {
            return Ok(GovernanceJobLeaseConflict::Lease);
        }
        Ok(GovernanceJobLeaseConflict::Lease)
    }

    fn external_fence_conditions(
        &self,
        tenant_id: &str,
        fence: &GovernanceExternalActionFence,
        now: i64,
    ) -> Result<Vec<TransactWriteItem>, StoreError> {
        let job_key = format!("{JOB_PREFIX}{}", fence.job_id);
        let job = ConditionCheck::builder()
            .table_name(&self.governance_table)
            .key("pk", AttributeValue::S(tenant_id.to_string()))
            .key("sk", AttributeValue::S(job_key))
            .condition_expression(
                "revision = :job_revision AND policy_revision = :policy_revision \
                 AND tenant_revision = :tenant_revision \
                 AND (#state = :running OR #state = :retryable)",
            )
            .expression_attribute_names("#state", "state")
            .expression_attribute_values(
                ":job_revision",
                AttributeValue::N(fence.job_revision.to_string()),
            )
            .expression_attribute_values(
                ":policy_revision",
                AttributeValue::N(fence.policy_revision.to_string()),
            )
            .expression_attribute_values(
                ":tenant_revision",
                AttributeValue::N(fence.tenant_revision.to_string()),
            )
            .expression_attribute_values(
                ":running",
                AttributeValue::S(job_state_name(GovernanceJobState::Running).into()),
            )
            .expression_attribute_values(
                ":retryable",
                AttributeValue::S(job_state_name(GovernanceJobState::Retryable).into()),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "governance external action job fence is incomplete: {error}"
                ))
            })?;
        let lifecycle = ConditionCheck::builder()
            .table_name(&self.governance_table)
            .key("pk", AttributeValue::S(tenant_id.to_string()))
            .key("sk", AttributeValue::S(LIFECYCLE_KEY.to_string()))
            .condition_expression("revision = :tenant_revision AND #state = :offboarding")
            .expression_attribute_names("#state", "state")
            .expression_attribute_values(
                ":tenant_revision",
                AttributeValue::N(fence.tenant_revision.to_string()),
            )
            .expression_attribute_values(
                ":offboarding",
                AttributeValue::S(lifecycle_state_name(TenantLifecycleState::Offboarding).into()),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "governance external action tenant fence is incomplete: {error}"
                ))
            })?;
        let lease = ConditionCheck::builder()
            .table_name(&self.governance_table)
            .key("pk", AttributeValue::S(tenant_id.to_string()))
            .key("sk", AttributeValue::S(job_lease_key(&fence.job_id)))
            .condition_expression(
                "job_revision = :job_revision AND policy_revision = :policy_revision \
                 AND tenant_revision = :tenant_revision \
                 AND token_digest = :lease_token_digest \
                 AND lease_deadline = :lease_deadline AND lease_deadline > :now",
            )
            .expression_attribute_values(
                ":job_revision",
                AttributeValue::N(fence.job_revision.to_string()),
            )
            .expression_attribute_values(
                ":policy_revision",
                AttributeValue::N(fence.policy_revision.to_string()),
            )
            .expression_attribute_values(
                ":tenant_revision",
                AttributeValue::N(fence.tenant_revision.to_string()),
            )
            .expression_attribute_values(
                ":lease_token_digest",
                AttributeValue::S(fence.lease_token_digest.clone()),
            )
            .expression_attribute_values(
                ":lease_deadline",
                AttributeValue::N(fence.lease_deadline.to_string()),
            )
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "governance external action lease fence is incomplete: {error}"
                ))
            })?;
        Ok(vec![
            TransactWriteItem::builder().condition_check(job).build(),
            TransactWriteItem::builder()
                .condition_check(lifecycle)
                .build(),
            TransactWriteItem::builder().condition_check(lease).build(),
        ])
    }

    fn external_reconcile_conditions(
        &self,
        tenant_id: &str,
        fence: &GovernanceExternalActionReconcileFence,
    ) -> Result<Vec<TransactWriteItem>, StoreError> {
        let job = ConditionCheck::builder()
            .table_name(&self.governance_table)
            .key("pk", AttributeValue::S(tenant_id.to_string()))
            .key(
                "sk",
                AttributeValue::S(format!("{JOB_PREFIX}{}", fence.job_id)),
            )
            .condition_expression("tenant_revision = :tenant_revision AND job_kind = :offboarding")
            .expression_attribute_values(
                ":tenant_revision",
                AttributeValue::N(fence.tenant_revision.to_string()),
            )
            .expression_attribute_values(
                ":offboarding",
                AttributeValue::S(job_kind_name(GovernanceJobKind::TenantOffboarding).into()),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "governance external reconciliation job fence is incomplete: {error}"
                ))
            })?;
        let lifecycle = ConditionCheck::builder()
            .table_name(&self.governance_table)
            .key("pk", AttributeValue::S(tenant_id.to_string()))
            .key("sk", AttributeValue::S(LIFECYCLE_KEY.to_string()))
            .condition_expression("revision = :tenant_revision AND #state = :offboarding")
            .expression_attribute_names("#state", "state")
            .expression_attribute_values(
                ":tenant_revision",
                AttributeValue::N(fence.tenant_revision.to_string()),
            )
            .expression_attribute_values(
                ":offboarding",
                AttributeValue::S(lifecycle_state_name(TenantLifecycleState::Offboarding).into()),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "governance external reconciliation tenant fence is incomplete: {error}"
                ))
            })?;
        Ok(vec![
            TransactWriteItem::builder().condition_check(job).build(),
            TransactWriteItem::builder()
                .condition_check(lifecycle)
                .build(),
        ])
    }

    async fn external_fence_is_current(
        &self,
        tenant_id: &str,
        fence: &GovernanceExternalActionFence,
        now: i64,
    ) -> Result<bool, StoreError> {
        let policy = self
            .get_policy(tenant_id)
            .await?
            .unwrap_or_else(|| GovernancePolicyRecord::default_for(tenant_id));
        let job = self.get_job(tenant_id, &fence.job_id).await?;
        let lease = self.get_job_lease(tenant_id, &fence.job_id).await?;
        let lifecycle = self.get_tenant_lifecycle(tenant_id).await?;
        Ok(policy.revision == fence.policy_revision
            && !policy.held()
            && job.is_some_and(|job| {
                job.kind == GovernanceJobKind::TenantOffboarding
                    && job.revision == fence.job_revision
                    && job.policy_revision == fence.policy_revision
                    && job.tenant_revision == fence.tenant_revision
                    && matches!(
                        job.state,
                        GovernanceJobState::Running | GovernanceJobState::Retryable
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
                lifecycle.state == TenantLifecycleState::Offboarding
                    && lifecycle.revision == fence.tenant_revision
            }))
    }

    async fn external_reconcile_fence_is_current(
        &self,
        tenant_id: &str,
        fence: &GovernanceExternalActionReconcileFence,
    ) -> Result<bool, StoreError> {
        let job = self.get_job(tenant_id, &fence.job_id).await?;
        let lifecycle = self.get_tenant_lifecycle(tenant_id).await?;
        Ok(job.is_some_and(|job| {
            job.kind == GovernanceJobKind::TenantOffboarding
                && job.tenant_revision == fence.tenant_revision
        }) && lifecycle.is_some_and(|lifecycle| {
            lifecycle.state == TenantLifecycleState::Offboarding
                && lifecycle.revision == fence.tenant_revision
        }))
    }

    async fn reconcile_start_conflict(
        &self,
        tenant_id: &str,
        job_id: &str,
        expected_policy_revision: u64,
        freeze_tenant: bool,
    ) -> Result<GovernanceJobStartOutcome, StoreError> {
        let policy = self
            .get_policy(tenant_id)
            .await?
            .unwrap_or_else(|| GovernancePolicyRecord::default_for(tenant_id));
        if policy.revision != expected_policy_revision {
            return Ok(GovernanceJobStartOutcome::PolicyConflict(policy));
        }
        if let Some(job) = self.get_job(tenant_id, job_id).await? {
            if !freeze_tenant && job.tenant_revision == 0 {
                if let Some(lifecycle) = self
                    .get_tenant_lifecycle(tenant_id)
                    .await?
                    .filter(|lifecycle| lifecycle.state == TenantLifecycleState::Offboarding)
                {
                    return Ok(GovernanceJobStartOutcome::TenantFrozen {
                        lifecycle_revision: lifecycle.revision,
                    });
                }
            }
            if freeze_tenant && job.tenant_revision > 0 {
                let lifecycle = self.get_tenant_lifecycle(tenant_id).await?;
                let continuation = self.get_continuation(tenant_id, job_id).await?;
                if !lifecycle.is_some_and(|lifecycle| {
                    lifecycle.state == TenantLifecycleState::Offboarding
                        && lifecycle.revision == job.tenant_revision
                }) || continuation
                    .is_none_or(|continuation| continuation.tenant_revision != job.tenant_revision)
                {
                    return Err(StoreError::Permanent(
                        "offboarding job, lifecycle, and continuation did not converge".into(),
                    ));
                }
            }
            return Ok(GovernanceJobStartOutcome::Existing(job));
        }
        if !freeze_tenant {
            if let Some(lifecycle) = self
                .get_tenant_lifecycle(tenant_id)
                .await?
                .filter(|lifecycle| lifecycle.state == TenantLifecycleState::Offboarding)
            {
                return Ok(GovernanceJobStartOutcome::TenantFrozen {
                    lifecycle_revision: lifecycle.revision,
                });
            }
        }
        if freeze_tenant {
            self.reap_expired_mutation_permits(tenant_id, crate::current_unix_secs())
                .await?;
            if let Some(gate) = self.get_mutation_gate(tenant_id).await? {
                if gate.state == TenantMutationGateState::Frozen {
                    return Err(StoreError::Permanent(
                        "tenant mutation gate froze without its offboarding job".into(),
                    ));
                }
                if gate.active_permits > 0 {
                    return Ok(GovernanceJobStartOutcome::MutationConflict {
                        active_permits: gate.active_permits,
                    });
                }
            }
        }
        Err(StoreError::Transient(
            "governance job transaction conflicted; retry".into(),
        ))
    }
}

impl GovernanceStore for DynamoGovernanceStore {
    async fn acquire_tenant_mutation_permit(
        &self,
        permit: TenantMutationPermit,
        now: i64,
    ) -> Result<TenantMutationPermitAcquireOutcome, StoreError> {
        if permit.tenant_id.is_empty()
            || permit.permit_id.is_empty()
            || permit.permit_id.len() > 128
            || permit.deadline <= now
        {
            return Err(StoreError::Permanent(
                "invalid tenant mutation permit".into(),
            ));
        }
        for attempt in 0..MUTATION_ACQUIRE_ATTEMPTS {
            let lifecycle = ConditionCheck::builder()
                .table_name(&self.governance_table)
                .key("pk", AttributeValue::S(permit.tenant_id.clone()))
                .key("sk", AttributeValue::S(LIFECYCLE_KEY.into()))
                .condition_expression("attribute_not_exists(pk) OR #state = :active")
                .expression_attribute_names("#state", "state")
                .expression_attribute_values(":active", AttributeValue::S("active".into()))
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!(
                        "tenant mutation lifecycle condition is incomplete: {error}"
                    ))
                })?;
            let gate = Update::builder()
                .table_name(&self.governance_table)
                .key("pk", AttributeValue::S(permit.tenant_id.clone()))
                .key("sk", AttributeValue::S(MUTATION_GATE_KEY.into()))
                .update_expression(
                    "SET tenant_id = if_not_exists(tenant_id, :tenant_id), \
                     record_type = if_not_exists(record_type, :record_type), \
                     #state = if_not_exists(#state, :active), updated_at = :now \
                     ADD active_permits :one, revision :one",
                )
                .condition_expression("attribute_not_exists(pk) OR #state = :active")
                .expression_attribute_names("#state", "state")
                .expression_attribute_values(
                    ":tenant_id",
                    AttributeValue::S(permit.tenant_id.clone()),
                )
                .expression_attribute_values(
                    ":record_type",
                    AttributeValue::S("tenant_mutation_gate".into()),
                )
                .expression_attribute_values(":active", AttributeValue::S("active".into()))
                .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
                .expression_attribute_values(":one", AttributeValue::N("1".into()))
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!(
                        "tenant mutation gate acquire is incomplete: {error}"
                    ))
                })?;
            let permit_item = HashMap::from([
                ("pk".into(), AttributeValue::S(permit.tenant_id.clone())),
                (
                    "sk".into(),
                    AttributeValue::S(mutation_permit_key(&permit.permit_id)),
                ),
                (
                    "record_type".into(),
                    AttributeValue::S("tenant_mutation_permit".into()),
                ),
                (
                    "permit_deadline".into(),
                    AttributeValue::N(permit.deadline.to_string()),
                ),
            ]);
            let permit_put = Put::builder()
                .table_name(&self.governance_table)
                .set_item(Some(permit_item))
                .condition_expression("attribute_not_exists(pk)")
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!(
                        "tenant mutation permit put is incomplete: {error}"
                    ))
                })?;
            match self
                .db
                .transact_write_items()
                .transact_items(
                    TransactWriteItem::builder()
                        .condition_check(lifecycle)
                        .build(),
                )
                .transact_items(TransactWriteItem::builder().update(gate).build())
                .transact_items(TransactWriteItem::builder().put(permit_put).build())
                .send()
                .await
            {
                Ok(_) => return Ok(TenantMutationPermitAcquireOutcome::Acquired(permit)),
                Err(error) if is_transaction_conflict(&error) => {
                    if self
                        .get_mutation_permit(&permit.tenant_id, &permit.permit_id)
                        .await?
                        .is_some_and(|stored| stored.deadline == permit.deadline)
                    {
                        return Ok(TenantMutationPermitAcquireOutcome::Acquired(permit));
                    }
                    let lifecycle = self.get_tenant_lifecycle(&permit.tenant_id).await?;
                    let gate = self.get_mutation_gate(&permit.tenant_id).await?;
                    if lifecycle
                        .as_ref()
                        .is_some_and(|record| record.state == TenantLifecycleState::Offboarding)
                        || gate
                            .as_ref()
                            .is_some_and(|gate| gate.state == TenantMutationGateState::Frozen)
                    {
                        return Ok(TenantMutationPermitAcquireOutcome::Frozen {
                            lifecycle_revision: lifecycle.map(|record| record.revision),
                        });
                    }
                    if attempt + 1 < MUTATION_ACQUIRE_ATTEMPTS {
                        tokio::time::sleep(std::time::Duration::from_millis(
                            5 * (attempt as u64 + 1),
                        ))
                        .await;
                    }
                }
                Err(error) => return Err(super::ddb_err(error)),
            }
        }
        Err(StoreError::Transient(
            "tenant mutation permit contention exceeded retry budget".into(),
        ))
    }

    async fn renew_tenant_mutation_permit(
        &self,
        permit: &TenantMutationPermit,
        now: i64,
        deadline: i64,
    ) -> Result<bool, StoreError> {
        if deadline <= now || deadline <= permit.deadline {
            return Err(StoreError::Permanent(
                "invalid tenant mutation permit renewal".into(),
            ));
        }
        match self
            .db
            .update_item()
            .table_name(&self.governance_table)
            .key("pk", AttributeValue::S(permit.tenant_id.clone()))
            .key(
                "sk",
                AttributeValue::S(mutation_permit_key(&permit.permit_id)),
            )
            .update_expression("SET permit_deadline = :deadline")
            .condition_expression("permit_deadline = :previous_deadline AND permit_deadline > :now")
            .expression_attribute_values(
                ":previous_deadline",
                AttributeValue::N(permit.deadline.to_string()),
            )
            .expression_attribute_values(":deadline", AttributeValue::N(deadline.to_string()))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(error) if is_conditional(&error) => Ok(self
                .get_mutation_permit(&permit.tenant_id, &permit.permit_id)
                .await?
                .is_some_and(|stored| stored.deadline == deadline)),
            Err(error) => Err(super::ddb_err(error)),
        }
    }

    async fn release_tenant_mutation_permit(
        &self,
        permit: TenantMutationPermit,
        now: i64,
    ) -> Result<bool, StoreError> {
        let delete = Delete::builder()
            .table_name(&self.governance_table)
            .key("pk", AttributeValue::S(permit.tenant_id.clone()))
            .key(
                "sk",
                AttributeValue::S(mutation_permit_key(&permit.permit_id)),
            )
            .condition_expression("permit_deadline = :deadline")
            .expression_attribute_values(
                ":deadline",
                AttributeValue::N(permit.deadline.to_string()),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "tenant mutation permit release is incomplete: {error}"
                ))
            })?;
        let gate = mutation_gate_decrement(&self.governance_table, &permit.tenant_id, now)?;
        match self
            .db
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().delete(delete).build())
            .transact_items(gate)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(error) if is_transaction_conflict(&error) => Ok(self
                .get_mutation_permit(&permit.tenant_id, &permit.permit_id)
                .await?
                .is_none()),
            Err(error) => Err(super::ddb_err(error)),
        }
    }

    async fn get_policy(
        &self,
        tenant_id: &str,
    ) -> Result<Option<GovernancePolicyRecord>, StoreError> {
        let policy: Option<GovernancePolicyRecord> = self.get_record(tenant_id, POLICY_KEY).await?;
        if policy
            .as_ref()
            .is_some_and(|policy| policy.tenant_id != tenant_id)
        {
            return Err(StoreError::Permanent(
                "governance policy tenant mismatch".into(),
            ));
        }
        Ok(policy)
    }

    async fn put_policy(
        &self,
        mut record: GovernancePolicyRecord,
        expected_revision: u64,
    ) -> Result<GovernancePolicyPutOutcome, StoreError> {
        let current = self
            .get_policy(&record.tenant_id)
            .await?
            .unwrap_or_else(|| GovernancePolicyRecord::default_for(&record.tenant_id));
        if current.revision != expected_revision {
            return Ok(GovernancePolicyPutOutcome::Conflict(current));
        }
        record.revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("governance policy revision exhausted".into()))?;
        let mut item = Self::record_item(&record.tenant_id, POLICY_KEY, "policy", &record)?;
        item.insert(
            "revision".into(),
            AttributeValue::N(record.revision.to_string()),
        );
        item.insert(
            "legal_hold".into(),
            AttributeValue::S(legal_hold_name(record.legal_hold).into()),
        );
        let mut request = self
            .db
            .put_item()
            .table_name(&self.governance_table)
            .set_item(Some(item));
        if expected_revision == 0 {
            request = request.condition_expression("attribute_not_exists(pk)");
        } else {
            request = request
                .condition_expression("revision = :expected")
                .expression_attribute_values(
                    ":expected",
                    AttributeValue::N(expected_revision.to_string()),
                );
        }
        match request.send().await {
            Ok(_) => Ok(GovernancePolicyPutOutcome::Stored(record)),
            Err(error) if is_conditional(&error) => {
                let current = self
                    .get_policy(&record.tenant_id)
                    .await?
                    .unwrap_or_else(|| GovernancePolicyRecord::default_for(&record.tenant_id));
                Ok(GovernancePolicyPutOutcome::Conflict(current))
            }
            Err(error) => Err(super::ddb_err(error)),
        }
    }

    async fn put_export_manifest(
        &self,
        manifest: GovernanceExportManifest,
    ) -> Result<bool, StoreError> {
        let key = format!("{EXPORT_PREFIX}{}", manifest.export_id);
        let mut item = Self::record_item(&manifest.tenant_id, &key, "export", &manifest)?;
        item.insert(
            "expires_at".into(),
            AttributeValue::N(manifest.expires_at.to_string()),
        );
        match self
            .db
            .put_item()
            .table_name(&self.governance_table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(pk)")
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(error) if is_conditional(&error) => Ok(false),
            Err(error) => Err(super::ddb_err(error)),
        }
    }

    async fn get_export_manifest(
        &self,
        tenant_id: &str,
        export_id: &str,
        now: i64,
    ) -> Result<Option<GovernanceExportManifest>, StoreError> {
        let key = format!("{EXPORT_PREFIX}{export_id}");
        let manifest: Option<GovernanceExportManifest> = self.get_record(tenant_id, &key).await?;
        Ok(manifest.filter(|manifest| {
            manifest.tenant_id == tenant_id
                && manifest.export_id == export_id
                && manifest.expires_at > now
        }))
    }

    async fn start_or_resume_job(
        &self,
        mut job: GovernanceJobRecord,
        expected_policy_revision: u64,
        freeze_tenant: bool,
    ) -> Result<GovernanceJobStartOutcome, StoreError> {
        let policy = self
            .get_policy(&job.tenant_id)
            .await?
            .unwrap_or_else(|| GovernancePolicyRecord::default_for(&job.tenant_id));
        if policy.revision != expected_policy_revision {
            return Ok(GovernanceJobStartOutcome::PolicyConflict(policy));
        }
        let existing = self.get_job(&job.tenant_id, &job.job_id).await?;
        if let Some(mut existing) = existing {
            let lifecycle = self.get_tenant_lifecycle(&job.tenant_id).await?;
            if job.tenant_revision == 0 {
                if let Some(lifecycle) = lifecycle
                    .filter(|lifecycle| lifecycle.state == TenantLifecycleState::Offboarding)
                {
                    return Ok(GovernanceJobStartOutcome::TenantFrozen {
                        lifecycle_revision: lifecycle.revision,
                    });
                }
            } else {
                if lifecycle.as_ref().is_none_or(|lifecycle| {
                    lifecycle.state != TenantLifecycleState::Offboarding
                        || lifecycle.revision != job.tenant_revision
                }) {
                    return Err(StoreError::Permanent(
                        "offboarding child job has no matching tenant lifecycle".into(),
                    ));
                }
                if existing.tenant_revision == 0
                    && !matches!(
                        existing.state,
                        GovernanceJobState::RetentionPending | GovernanceJobState::Completed
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
                    let previous_revision = existing.revision;
                    existing.tenant_revision = job.tenant_revision;
                    existing.policy_revision = policy.revision;
                    if existing.state == GovernanceJobState::BlockedLegalHold {
                        existing.state = GovernanceJobState::Queued;
                    }
                    existing.revision = existing.revision.checked_add(1).ok_or_else(|| {
                        StoreError::Permanent("governance job revision exhausted".into())
                    })?;
                    existing.updated_at = job.updated_at;
                    let transaction = vec![
                        self.policy_condition(&job.tenant_id, &policy)?,
                        Self::lifecycle_condition(
                            &self.governance_table,
                            &job.tenant_id,
                            job.tenant_revision,
                            "child adoption",
                        )?,
                        self.job_put(&existing, false, Some(previous_revision))?,
                    ];
                    return match self
                        .db
                        .transact_write_items()
                        .set_transact_items(Some(transaction))
                        .send()
                        .await
                    {
                        Ok(_) => Ok(GovernanceJobStartOutcome::Existing(existing)),
                        Err(error) if is_transaction_conflict(&error) => Err(
                            StoreError::Transient("offboarding child adoption conflicted".into()),
                        ),
                        Err(error) => Err(super::ddb_err(error)),
                    };
                }
                if existing.tenant_revision != 0 && existing.tenant_revision != job.tenant_revision
                {
                    return Err(StoreError::Permanent(
                        "offboarding child job tenant lifecycle mismatch".into(),
                    ));
                }
            }
            if existing.state != GovernanceJobState::BlockedLegalHold || policy.held() {
                return Ok(GovernanceJobStartOutcome::Existing(existing));
            }
            let previous_revision = existing.revision;
            existing.revision = existing
                .revision
                .checked_add(1)
                .ok_or_else(|| StoreError::Permanent("governance job revision exhausted".into()))?;
            existing.state = GovernanceJobState::Queued;
            existing.policy_revision = policy.revision;
            existing.updated_at = job.updated_at;
            let mut transaction = vec![self.policy_condition(&job.tenant_id, &policy)?];
            if freeze_tenant {
                let gate = match self
                    .prepare_mutation_gate_freeze(&job.tenant_id, job.updated_at)
                    .await?
                {
                    Ok(gate) => gate,
                    Err(active_permits) => {
                        return Ok(GovernanceJobStartOutcome::MutationConflict { active_permits })
                    }
                };
                transaction.push(gate);
                let current = self.get_tenant_lifecycle(&job.tenant_id).await?;
                match current {
                    Some(record) if record.state == TenantLifecycleState::Offboarding => {
                        existing.tenant_revision = record.revision;
                    }
                    Some(record) => {
                        let lifecycle = TenantLifecycleRecord {
                            tenant_id: job.tenant_id.clone(),
                            state: TenantLifecycleState::Offboarding,
                            revision: record.revision.checked_add(1).ok_or_else(|| {
                                StoreError::Permanent("tenant lifecycle revision exhausted".into())
                            })?,
                            updated_at: job.updated_at,
                        };
                        existing.tenant_revision = lifecycle.revision;
                        transaction.push(self.lifecycle_put(&lifecycle, false)?);
                    }
                    None => {
                        let lifecycle = TenantLifecycleRecord {
                            tenant_id: job.tenant_id.clone(),
                            state: TenantLifecycleState::Offboarding,
                            revision: 1,
                            updated_at: job.updated_at,
                        };
                        existing.tenant_revision = 1;
                        transaction.push(self.lifecycle_put(&lifecycle, true)?);
                    }
                }
                match self.get_continuation(&job.tenant_id, &job.job_id).await? {
                    Some(continuation)
                        if continuation.tenant_revision == existing.tenant_revision => {}
                    Some(_) => {
                        return Err(StoreError::Permanent(
                            "offboarding continuation identity mismatch".into(),
                        ))
                    }
                    None => {
                        let continuation =
                            GovernanceContinuationRecord::for_offboarding_job(&existing)
                                .map_err(StoreError::Permanent)?;
                        transaction.push(self.continuation_put(&continuation, true, None)?);
                    }
                }
            }
            transaction.push(self.job_put(&existing, false, Some(previous_revision))?);
            return match self
                .db
                .transact_write_items()
                .set_transact_items(Some(transaction))
                .send()
                .await
            {
                Ok(_) => Ok(GovernanceJobStartOutcome::Existing(existing)),
                Err(error) if is_transaction_conflict(&error) => {
                    self.reconcile_start_conflict(
                        &job.tenant_id,
                        &job.job_id,
                        expected_policy_revision,
                        freeze_tenant,
                    )
                    .await
                }
                Err(error) => Err(super::ddb_err(error)),
            };
        }

        if policy.held() {
            job.state = GovernanceJobState::BlockedLegalHold;
        }
        job.policy_revision = policy.revision;
        let mut transaction = vec![self.policy_condition(&job.tenant_id, &policy)?];
        if !freeze_tenant {
            transaction.push(Self::lifecycle_condition(
                &self.governance_table,
                &job.tenant_id,
                job.tenant_revision,
                "job start",
            )?);
        }
        if freeze_tenant && !policy.held() {
            let gate = match self
                .prepare_mutation_gate_freeze(&job.tenant_id, job.updated_at)
                .await?
            {
                Ok(gate) => gate,
                Err(active_permits) => {
                    return Ok(GovernanceJobStartOutcome::MutationConflict { active_permits })
                }
            };
            transaction.push(gate);
            let current = self.get_tenant_lifecycle(&job.tenant_id).await?;
            let (revision, create) = match current {
                Some(record) if record.state == TenantLifecycleState::Offboarding => {
                    return Err(StoreError::Permanent(
                        "tenant is offboarding without its deterministic governance job".into(),
                    ))
                }
                Some(record) => (
                    record.revision.checked_add(1).ok_or_else(|| {
                        StoreError::Permanent("tenant lifecycle revision exhausted".into())
                    })?,
                    false,
                ),
                None => (1, true),
            };
            let lifecycle = TenantLifecycleRecord {
                tenant_id: job.tenant_id.clone(),
                state: TenantLifecycleState::Offboarding,
                revision,
                updated_at: job.updated_at,
            };
            job.tenant_revision = revision;
            transaction.push(self.lifecycle_put(&lifecycle, create)?);
            if self
                .get_continuation(&job.tenant_id, &job.job_id)
                .await?
                .is_some()
            {
                return Err(StoreError::Permanent(
                    "offboarding continuation exists without its job".into(),
                ));
            }
            let continuation = GovernanceContinuationRecord::for_offboarding_job(&job)
                .map_err(StoreError::Permanent)?;
            transaction.push(self.continuation_put(&continuation, true, None)?);
        }
        transaction.push(self.job_put(&job, true, None)?);
        match self
            .db
            .transact_write_items()
            .set_transact_items(Some(transaction))
            .send()
            .await
        {
            Ok(_) => Ok(GovernanceJobStartOutcome::Stored(job)),
            Err(error) if is_transaction_conflict(&error) => {
                self.reconcile_start_conflict(
                    &job.tenant_id,
                    &job.job_id,
                    expected_policy_revision,
                    freeze_tenant,
                )
                .await
            }
            Err(error) => Err(super::ddb_err(error)),
        }
    }

    async fn get_job(
        &self,
        tenant_id: &str,
        job_id: &str,
    ) -> Result<Option<GovernanceJobRecord>, StoreError> {
        let key = format!("{JOB_PREFIX}{job_id}");
        let job: Option<GovernanceJobRecord> = self.get_record(tenant_id, &key).await?;
        if job
            .as_ref()
            .is_some_and(|job| job.tenant_id != tenant_id || job.job_id != job_id)
        {
            return Err(StoreError::Permanent(
                "governance job identity mismatch".into(),
            ));
        }
        Ok(job)
    }

    async fn list_jobs(&self, tenant_id: &str) -> Result<Vec<GovernanceJobRecord>, StoreError> {
        let mut exclusive_start_key = None;
        let mut records = Vec::new();
        loop {
            let output = self
                .db
                .query()
                .table_name(&self.governance_table)
                .key_condition_expression("pk = :pk AND begins_with(sk, :prefix)")
                .expression_attribute_values(":pk", AttributeValue::S(tenant_id.to_string()))
                .expression_attribute_values(":prefix", AttributeValue::S(JOB_PREFIX.into()))
                .consistent_read(true)
                .set_exclusive_start_key(exclusive_start_key)
                .send()
                .await
                .map_err(super::ddb_err)?;
            for item in output.items() {
                let key = item
                    .get("sk")
                    .and_then(|value| value.as_s().ok())
                    .ok_or_else(|| StoreError::Permanent("governance job key is missing".into()))?;
                let record: GovernanceJobRecord = record_from_item(item, tenant_id, key)?;
                if record.tenant_id != tenant_id {
                    return Err(StoreError::Permanent(
                        "governance job list identity mismatch".into(),
                    ));
                }
                records.push(record);
            }
            exclusive_start_key = output.last_evaluated_key().cloned();
            if exclusive_start_key.is_none() {
                break;
            }
        }
        records.sort_by(|left, right| left.job_id.cmp(&right.job_id));
        Ok(records)
    }

    async fn get_continuation(
        &self,
        tenant_id: &str,
        job_id: &str,
    ) -> Result<Option<GovernanceContinuationRecord>, StoreError> {
        let record: Option<GovernanceContinuationRecord> = self
            .get_record(tenant_id, &continuation_key(job_id))
            .await?;
        if record.as_ref().is_some_and(|record| {
            record.tenant_id != tenant_id || record.job_id != job_id || record.tenant_revision == 0
        }) {
            return Err(StoreError::Permanent(
                "governance continuation identity mismatch".into(),
            ));
        }
        Ok(record)
    }

    async fn update_continuation(
        &self,
        mut record: GovernanceContinuationRecord,
        expected_revision: u64,
    ) -> Result<GovernanceContinuationUpdateOutcome, StoreError> {
        let current = self
            .get_continuation(&record.tenant_id, &record.job_id)
            .await?
            .ok_or_else(|| StoreError::Permanent("governance continuation disappeared".into()))?;
        if current.revision != expected_revision {
            return Ok(GovernanceContinuationUpdateOutcome::Conflict(current));
        }
        if current.tenant_revision != record.tenant_revision
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
        let key = continuation_key(&record.job_id);
        let mut item =
            Self::record_item(&record.tenant_id, &key, "governance_continuation", &record)?;
        item.insert(
            "revision".into(),
            AttributeValue::N(record.revision.to_string()),
        );
        item.insert(
            "resume_revision".into(),
            AttributeValue::N(record.resume_revision.to_string()),
        );
        item.insert(
            "read_revision".into(),
            AttributeValue::N(record.read_revision.to_string()),
        );
        item.insert(
            "resume_enabled".into(),
            AttributeValue::Bool(record.resume_enabled),
        );
        item.insert(
            "read_enabled".into(),
            AttributeValue::Bool(record.read_enabled),
        );
        match self
            .db
            .put_item()
            .table_name(&self.governance_table)
            .set_item(Some(item))
            .condition_expression("revision = :revision")
            .expression_attribute_values(
                ":revision",
                AttributeValue::N(expected_revision.to_string()),
            )
            .send()
            .await
        {
            Ok(_) => Ok(GovernanceContinuationUpdateOutcome::Stored(record)),
            Err(error) if is_conditional(&error) => {
                let latest = self
                    .get_continuation(&record.tenant_id, &record.job_id)
                    .await?
                    .ok_or_else(|| {
                        StoreError::Permanent(
                            "governance continuation disappeared after conflict".into(),
                        )
                    })?;
                Ok(GovernanceContinuationUpdateOutcome::Conflict(latest))
            }
            Err(error) => Err(super::ddb_err(error)),
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
        if jti_digest.is_empty()
            || jti_digest.len() > 128
            || expires_at <= 0
            || expected_resume_revision == 0
        {
            return Err(StoreError::Permanent(
                "invalid governance continuation consumption".into(),
            ));
        }
        let condition = ConditionCheck::builder()
            .table_name(&self.governance_table)
            .key("pk", AttributeValue::S(tenant_id.to_string()))
            .key("sk", AttributeValue::S(continuation_key(job_id)))
            .condition_expression(
                "resume_revision = :resume_revision AND resume_enabled = :enabled",
            )
            .expression_attribute_values(
                ":resume_revision",
                AttributeValue::N(expected_resume_revision.to_string()),
            )
            .expression_attribute_values(":enabled", AttributeValue::Bool(true))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "governance continuation condition is incomplete: {error}"
                ))
            })?;
        let jti_key = format!("{CONTINUATION_JTI_PREFIX}{job_id}#{jti_digest}");
        let put = Put::builder()
            .table_name(&self.governance_table)
            .item("pk", AttributeValue::S(tenant_id.to_string()))
            .item("sk", AttributeValue::S(jti_key))
            .item(
                "record_type",
                AttributeValue::S("governance_continuation_jti".into()),
            )
            .item("expires_at", AttributeValue::N(expires_at.to_string()))
            .condition_expression("attribute_not_exists(pk)")
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "governance continuation JTI put is incomplete: {error}"
                ))
            })?;
        let transaction = vec![
            TransactWriteItem::builder()
                .condition_check(condition)
                .build(),
            TransactWriteItem::builder().put(put).build(),
        ];
        match self
            .db
            .transact_write_items()
            .set_transact_items(Some(transaction))
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(error) if is_transaction_conflict(&error) => Ok(false),
            Err(error) => Err(super::ddb_err(error)),
        }
    }

    async fn update_job(
        &self,
        mut job: GovernanceJobRecord,
        expected_revision: u64,
        expected_policy_revision: u64,
    ) -> Result<GovernanceJobUpdateOutcome, StoreError> {
        let policy = self
            .get_policy(&job.tenant_id)
            .await?
            .unwrap_or_else(|| GovernancePolicyRecord::default_for(&job.tenant_id));
        if policy.revision != expected_policy_revision {
            return Ok(GovernanceJobUpdateOutcome::PolicyConflict(policy));
        }
        let current = self
            .get_job(&job.tenant_id, &job.job_id)
            .await?
            .ok_or_else(|| {
                StoreError::Permanent("governance job disappeared during update".into())
            })?;
        if current.revision != expected_revision {
            return Ok(GovernanceJobUpdateOutcome::Conflict(current));
        }
        job.revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("governance job revision exhausted".into()))?;
        job.policy_revision = policy.revision;
        let transaction = vec![
            self.policy_condition(&job.tenant_id, &policy)?,
            self.job_put(&job, false, Some(expected_revision))?,
        ];
        match self
            .db
            .transact_write_items()
            .set_transact_items(Some(transaction))
            .send()
            .await
        {
            Ok(_) => Ok(GovernanceJobUpdateOutcome::Stored(job)),
            Err(error) if is_transaction_conflict(&error) => {
                let latest_policy = self
                    .get_policy(&job.tenant_id)
                    .await?
                    .unwrap_or_else(|| GovernancePolicyRecord::default_for(&job.tenant_id));
                if latest_policy.revision != expected_policy_revision {
                    return Ok(GovernanceJobUpdateOutcome::PolicyConflict(latest_policy));
                }
                let latest = self
                    .get_job(&job.tenant_id, &job.job_id)
                    .await?
                    .ok_or_else(|| {
                        StoreError::Permanent(
                            "governance job disappeared after update conflict".into(),
                        )
                    })?;
                Ok(GovernanceJobUpdateOutcome::Conflict(latest))
            }
            Err(error) => Err(super::ddb_err(error)),
        }
    }

    async fn complete_job_with_evidence(
        &self,
        mut job: GovernanceJobRecord,
        evidence: GovernanceEvidenceRecord,
        expected_revision: u64,
        expected_policy_revision: u64,
    ) -> Result<GovernanceJobUpdateOutcome, StoreError> {
        if !evidence.verifies_completion_of(&job) || job.revision != expected_revision {
            return Err(StoreError::Permanent(
                "invalid governance job completion evidence".into(),
            ));
        }
        let policy = self
            .get_policy(&job.tenant_id)
            .await?
            .unwrap_or_else(|| GovernancePolicyRecord::default_for(&job.tenant_id));
        if policy.revision != expected_policy_revision {
            return Ok(GovernanceJobUpdateOutcome::PolicyConflict(policy));
        }
        if evidence.payload.legal_hold != policy.legal_hold {
            return Err(StoreError::Permanent(
                "governance completion evidence policy mismatch".into(),
            ));
        }
        let current = self
            .get_job(&job.tenant_id, &job.job_id)
            .await?
            .ok_or_else(|| {
                StoreError::Permanent("governance job disappeared during completion".into())
            })?;
        if current.revision != expected_revision {
            return Ok(GovernanceJobUpdateOutcome::Conflict(current));
        }
        job.revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("governance job revision exhausted".into()))?;
        job.policy_revision = policy.revision;
        let evidence_key =
            evidence_key(&evidence.payload.job_id, evidence.payload.evidence_revision);
        let evidence_item = Self::record_item(
            &evidence.payload.tenant_id,
            &evidence_key,
            "governance_evidence",
            &evidence,
        )?;
        let evidence_put = Put::builder()
            .table_name(&self.governance_table)
            .set_item(Some(evidence_item))
            .condition_expression("attribute_not_exists(pk) AND attribute_not_exists(sk)")
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "governance completion evidence put is incomplete: {error}"
                ))
            })?;
        let transaction = vec![
            self.policy_condition(&job.tenant_id, &policy)?,
            self.job_put(&job, false, Some(expected_revision))?,
            TransactWriteItem::builder().put(evidence_put).build(),
        ];
        match self
            .db
            .transact_write_items()
            .set_transact_items(Some(transaction))
            .send()
            .await
        {
            Ok(_) => Ok(GovernanceJobUpdateOutcome::Stored(job)),
            Err(error) if is_transaction_conflict(&error) => {
                let latest_policy = self
                    .get_policy(&job.tenant_id)
                    .await?
                    .unwrap_or_else(|| GovernancePolicyRecord::default_for(&job.tenant_id));
                if latest_policy.revision != expected_policy_revision {
                    return Ok(GovernanceJobUpdateOutcome::PolicyConflict(latest_policy));
                }
                let latest = self
                    .get_job(&job.tenant_id, &job.job_id)
                    .await?
                    .ok_or_else(|| {
                        StoreError::Permanent(
                            "governance job disappeared after completion conflict".into(),
                        )
                    })?;
                if latest.revision != expected_revision {
                    return Ok(GovernanceJobUpdateOutcome::Conflict(latest));
                }
                if self
                    .get_record::<GovernanceEvidenceRecord>(
                        &evidence.payload.tenant_id,
                        &evidence_key,
                    )
                    .await?
                    .is_some()
                {
                    return Err(StoreError::Permanent(
                        "governance completion evidence revision already exists".into(),
                    ));
                }
                Err(StoreError::Transient(
                    "governance job completion transaction conflicted; retry".into(),
                ))
            }
            Err(error) => Err(super::ddb_err(error)),
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
        if token_digest.is_empty() || token_digest.len() > 128 || deadline <= now {
            return Err(StoreError::Permanent(
                "invalid governance job lease claim".into(),
            ));
        }
        let Some(job) = self.get_job(tenant_id, job_id).await? else {
            return Ok(GovernanceJobLeaseOutcome::Conflict(
                GovernanceJobLeaseConflict::Job,
            ));
        };
        let policy = self
            .get_policy(tenant_id)
            .await?
            .unwrap_or_else(|| GovernancePolicyRecord::default_for(tenant_id));
        if policy.revision != job.policy_revision || policy.held() {
            return Ok(GovernanceJobLeaseOutcome::Conflict(
                GovernanceJobLeaseConflict::Policy,
            ));
        }
        if job.revision != expected_job_revision
            || !matches!(
                job.state,
                GovernanceJobState::Queued
                    | GovernanceJobState::Running
                    | GovernanceJobState::Retryable
            )
        {
            return Ok(GovernanceJobLeaseOutcome::Conflict(
                GovernanceJobLeaseConflict::Job,
            ));
        }
        if job.tenant_revision != 0
            && self
                .get_tenant_lifecycle(tenant_id)
                .await?
                .is_none_or(|lifecycle| {
                    lifecycle.state != TenantLifecycleState::Offboarding
                        || lifecycle.revision != job.tenant_revision
                })
        {
            return Ok(GovernanceJobLeaseOutcome::Conflict(
                GovernanceJobLeaseConflict::TenantLifecycle,
            ));
        }
        let lease = GovernanceJobLeaseRecord {
            tenant_id: tenant_id.to_string(),
            job_id: job_id.to_string(),
            job_revision: job.revision,
            policy_revision: job.policy_revision,
            tenant_revision: job.tenant_revision,
            token_digest: token_digest.to_string(),
            acquired_at: now,
            deadline,
        };
        let mut transaction = vec![self.policy_condition(tenant_id, &policy)?];
        transaction.extend(self.job_authority_conditions(tenant_id, &job)?);
        transaction.push(self.job_lease_put(&lease, None, now)?);
        match self
            .db
            .transact_write_items()
            .set_transact_items(Some(transaction))
            .send()
            .await
        {
            Ok(_) => Ok(GovernanceJobLeaseOutcome::Acquired(lease)),
            Err(error) if is_transaction_conflict(&error) => {
                let conflict = self
                    .classify_job_lease_conflict(
                        tenant_id,
                        job_id,
                        expected_job_revision,
                        None,
                        None,
                        now,
                    )
                    .await?;
                Ok(GovernanceJobLeaseOutcome::Conflict(conflict))
            }
            Err(error) => Err(super::ddb_err(error)),
        }
    }

    async fn renew_job_lease(
        &self,
        tenant_id: &str,
        fence: GovernanceDestructiveFence,
        now: i64,
        deadline: i64,
    ) -> Result<GovernanceJobLeaseOutcome, StoreError> {
        if deadline <= now || deadline <= fence.lease_deadline {
            return Err(StoreError::Permanent(
                "invalid governance job lease renewal".into(),
            ));
        }
        let Some(job) = self.get_job(tenant_id, &fence.job_id).await? else {
            return Ok(GovernanceJobLeaseOutcome::Conflict(
                GovernanceJobLeaseConflict::Job,
            ));
        };
        let policy = self
            .get_policy(tenant_id)
            .await?
            .unwrap_or_else(|| GovernancePolicyRecord::default_for(tenant_id));
        if policy.revision != fence.policy_revision || policy.held() {
            return Ok(GovernanceJobLeaseOutcome::Conflict(
                GovernanceJobLeaseConflict::Policy,
            ));
        }
        if job.revision != fence.job_revision
            || job.policy_revision != fence.policy_revision
            || job.tenant_revision != fence.tenant_revision
        {
            return Ok(GovernanceJobLeaseOutcome::Conflict(
                GovernanceJobLeaseConflict::Job,
            ));
        }
        let Some(current) = self.get_job_lease(tenant_id, &fence.job_id).await? else {
            return Ok(GovernanceJobLeaseOutcome::Conflict(
                GovernanceJobLeaseConflict::Lease,
            ));
        };
        if current.token_digest != fence.lease_token_digest
            || current.deadline != fence.lease_deadline
            || current.deadline <= now
        {
            return Ok(GovernanceJobLeaseOutcome::Conflict(
                GovernanceJobLeaseConflict::Lease,
            ));
        }
        let mut renewed = current;
        renewed.deadline = deadline;
        let mut transaction = vec![self.policy_condition(tenant_id, &policy)?];
        transaction.extend(self.job_authority_conditions(tenant_id, &job)?);
        transaction.push(self.job_lease_put(&renewed, Some(&fence), now)?);
        match self
            .db
            .transact_write_items()
            .set_transact_items(Some(transaction))
            .send()
            .await
        {
            Ok(_) => Ok(GovernanceJobLeaseOutcome::Renewed(renewed)),
            Err(error) if is_transaction_conflict(&error) => {
                let conflict = self
                    .classify_job_lease_conflict(
                        tenant_id,
                        &fence.job_id,
                        fence.job_revision,
                        Some(&fence.lease_token_digest),
                        Some(fence.lease_deadline),
                        now,
                    )
                    .await?;
                Ok(GovernanceJobLeaseOutcome::Conflict(conflict))
            }
            Err(error) => Err(super::ddb_err(error)),
        }
    }

    async fn release_job_lease(
        &self,
        tenant_id: &str,
        fence: GovernanceDestructiveFence,
    ) -> Result<GovernanceJobLeaseOutcome, StoreError> {
        let delete = Delete::builder()
            .table_name(&self.governance_table)
            .key("pk", AttributeValue::S(tenant_id.to_string()))
            .key("sk", AttributeValue::S(job_lease_key(&fence.job_id)))
            .condition_expression(
                "job_revision = :job_revision AND policy_revision = :policy_revision \
                 AND tenant_revision = :tenant_revision AND token_digest = :token_digest \
                 AND lease_deadline = :lease_deadline",
            )
            .expression_attribute_values(
                ":job_revision",
                AttributeValue::N(fence.job_revision.to_string()),
            )
            .expression_attribute_values(
                ":policy_revision",
                AttributeValue::N(fence.policy_revision.to_string()),
            )
            .expression_attribute_values(
                ":tenant_revision",
                AttributeValue::N(fence.tenant_revision.to_string()),
            )
            .expression_attribute_values(
                ":token_digest",
                AttributeValue::S(fence.lease_token_digest),
            )
            .expression_attribute_values(
                ":lease_deadline",
                AttributeValue::N(fence.lease_deadline.to_string()),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "governance job lease delete is incomplete: {error}"
                ))
            })?;
        match self
            .db
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().delete(delete).build())
            .send()
            .await
        {
            Ok(_) => Ok(GovernanceJobLeaseOutcome::Released),
            Err(error) if is_transaction_conflict(&error) => Ok(
                GovernanceJobLeaseOutcome::Conflict(GovernanceJobLeaseConflict::Lease),
            ),
            Err(error) => Err(super::ddb_err(error)),
        }
    }

    async fn tenant_has_active_job_leases(
        &self,
        tenant_id: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut exclusive_start_key = None;
        loop {
            let output = self
                .db
                .query()
                .table_name(&self.governance_table)
                .key_condition_expression("pk = :pk AND begins_with(sk, :prefix)")
                .expression_attribute_values(":pk", AttributeValue::S(tenant_id.to_string()))
                .expression_attribute_values(":prefix", AttributeValue::S(LEASE_PREFIX.into()))
                .projection_expression("lease_deadline")
                .consistent_read(true)
                .set_exclusive_start_key(exclusive_start_key)
                .send()
                .await
                .map_err(super::ddb_err)?;
            for item in output.items() {
                let deadline = item
                    .get("lease_deadline")
                    .and_then(|value| value.as_n().ok())
                    .and_then(|value| value.parse::<i64>().ok())
                    .ok_or_else(|| {
                        StoreError::Permanent(
                            "governance job lease is missing a valid deadline".into(),
                        )
                    })?;
                if deadline > now {
                    return Ok(true);
                }
            }
            exclusive_start_key = output.last_evaluated_key().cloned();
            if exclusive_start_key.is_none() {
                return Ok(false);
            }
        }
    }

    async fn get_tenant_lifecycle(
        &self,
        tenant_id: &str,
    ) -> Result<Option<TenantLifecycleRecord>, StoreError> {
        let lifecycle: Option<TenantLifecycleRecord> =
            self.get_record(tenant_id, LIFECYCLE_KEY).await?;
        if lifecycle
            .as_ref()
            .is_some_and(|record| record.tenant_id != tenant_id)
        {
            return Err(StoreError::Permanent(
                "tenant lifecycle identity mismatch".into(),
            ));
        }
        Ok(lifecycle)
    }

    async fn prepare_external_action(
        &self,
        record: GovernanceExternalActionRecord,
        fence: GovernanceExternalActionFence,
    ) -> Result<GovernanceExternalActionPutOutcome, StoreError> {
        if record.tenant_id.is_empty()
            || record.job_id != fence.job_id
            || record.action_id.is_empty()
            || record.resource_ref.is_empty()
            || record.resource_fingerprint.is_empty()
            || record.revision != 1
        {
            return Err(StoreError::Permanent(
                "invalid governance external action".into(),
            ));
        }
        let policy = self
            .get_policy(&record.tenant_id)
            .await?
            .unwrap_or_else(|| GovernancePolicyRecord::default_for(&record.tenant_id));
        if policy.revision != fence.policy_revision || policy.held() {
            return Ok(GovernanceExternalActionPutOutcome::FenceConflict);
        }
        let mut transaction = vec![self.policy_condition(&record.tenant_id, &policy)?];
        transaction.extend(self.external_fence_conditions(
            &record.tenant_id,
            &fence,
            record.updated_at,
        )?);
        transaction.push(self.external_action_put(&record, true, None)?);
        match self
            .db
            .transact_write_items()
            .set_transact_items(Some(transaction))
            .send()
            .await
        {
            Ok(_) => Ok(GovernanceExternalActionPutOutcome::Stored(record)),
            Err(error) if is_transaction_conflict(&error) => {
                if !self
                    .external_fence_is_current(&record.tenant_id, &fence, record.updated_at)
                    .await?
                {
                    return Ok(GovernanceExternalActionPutOutcome::FenceConflict);
                }
                let existing = self
                    .get_external_action(&record.tenant_id, &record.job_id, &record.action_id)
                    .await?;
                match existing {
                    Some(existing) if same_external_action_identity(&existing, &record) => {
                        Ok(GovernanceExternalActionPutOutcome::Existing(existing))
                    }
                    Some(_) => Err(StoreError::Permanent(
                        "governance external action identity changed".into(),
                    )),
                    None => Err(StoreError::Transient(
                        "governance external action prepare conflicted; retry".into(),
                    )),
                }
            }
            Err(error) => Err(super::ddb_err(error)),
        }
    }

    async fn get_external_action(
        &self,
        tenant_id: &str,
        job_id: &str,
        action_id: &str,
    ) -> Result<Option<GovernanceExternalActionRecord>, StoreError> {
        let key = external_action_key(job_id, action_id);
        let record: Option<GovernanceExternalActionRecord> =
            self.get_record(tenant_id, &key).await?;
        if record.as_ref().is_some_and(|record| {
            record.tenant_id != tenant_id
                || record.job_id != job_id
                || record.action_id != action_id
        }) {
            return Err(StoreError::Permanent(
                "governance external action identity mismatch".into(),
            ));
        }
        Ok(record)
    }

    async fn list_external_actions(
        &self,
        tenant_id: &str,
        job_id: &str,
    ) -> Result<Vec<GovernanceExternalActionRecord>, StoreError> {
        let prefix = external_action_prefix(job_id);
        let mut exclusive_start_key = None;
        let mut records = Vec::new();
        loop {
            let output = self
                .db
                .query()
                .table_name(&self.governance_table)
                .key_condition_expression("pk = :pk AND begins_with(sk, :prefix)")
                .expression_attribute_values(":pk", AttributeValue::S(tenant_id.to_string()))
                .expression_attribute_values(":prefix", AttributeValue::S(prefix.clone()))
                .consistent_read(true)
                .set_exclusive_start_key(exclusive_start_key)
                .send()
                .await
                .map_err(super::ddb_err)?;
            for item in output.items() {
                let key = item
                    .get("sk")
                    .and_then(|value| value.as_s().ok())
                    .ok_or_else(|| {
                        StoreError::Permanent("governance external action key is missing".into())
                    })?;
                let record: GovernanceExternalActionRecord =
                    record_from_item(item, tenant_id, key)?;
                if record.tenant_id != tenant_id || record.job_id != job_id {
                    return Err(StoreError::Permanent(
                        "governance external action list identity mismatch".into(),
                    ));
                }
                records.push(record);
            }
            exclusive_start_key = output.last_evaluated_key().cloned();
            if exclusive_start_key.is_none() {
                break;
            }
        }
        records.sort_by(|left, right| left.action_id.cmp(&right.action_id));
        Ok(records)
    }

    async fn list_tenant_external_actions(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<GovernanceExternalActionRecord>, StoreError> {
        let mut exclusive_start_key = None;
        let mut records = Vec::new();
        loop {
            let output = self
                .db
                .query()
                .table_name(&self.governance_table)
                .key_condition_expression("pk = :pk AND begins_with(sk, :prefix)")
                .expression_attribute_values(":pk", AttributeValue::S(tenant_id.to_string()))
                .expression_attribute_values(":prefix", AttributeValue::S(ACTION_PREFIX.into()))
                .consistent_read(true)
                .set_exclusive_start_key(exclusive_start_key)
                .send()
                .await
                .map_err(super::ddb_err)?;
            for item in output.items() {
                let key = item
                    .get("sk")
                    .and_then(|value| value.as_s().ok())
                    .ok_or_else(|| {
                        StoreError::Permanent("governance external action key is missing".into())
                    })?;
                let record: GovernanceExternalActionRecord =
                    record_from_item(item, tenant_id, key)?;
                if record.tenant_id != tenant_id {
                    return Err(StoreError::Permanent(
                        "governance external action tenant list identity mismatch".into(),
                    ));
                }
                records.push(record);
            }
            exclusive_start_key = output.last_evaluated_key().cloned();
            if exclusive_start_key.is_none() {
                break;
            }
        }
        records.sort_by(|left, right| {
            left.job_id
                .cmp(&right.job_id)
                .then_with(|| left.action_id.cmp(&right.action_id))
        });
        Ok(records)
    }

    async fn update_external_action(
        &self,
        mut record: GovernanceExternalActionRecord,
        expected_revision: u64,
        fence: GovernanceExternalActionFence,
    ) -> Result<GovernanceExternalActionUpdateOutcome, StoreError> {
        if record.job_id != fence.job_id {
            return Err(StoreError::Permanent(
                "governance external action job mismatch".into(),
            ));
        }
        let current = self
            .get_external_action(&record.tenant_id, &record.job_id, &record.action_id)
            .await?
            .ok_or_else(|| {
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
        let policy = self
            .get_policy(&record.tenant_id)
            .await?
            .unwrap_or_else(|| GovernancePolicyRecord::default_for(&record.tenant_id));
        if policy.revision != fence.policy_revision || policy.held() {
            return Ok(GovernanceExternalActionUpdateOutcome::FenceConflict);
        }
        record.revision = expected_revision.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("governance external action revision exhausted".into())
        })?;
        let mut transaction = vec![self.policy_condition(&record.tenant_id, &policy)?];
        transaction.extend(self.external_fence_conditions(
            &record.tenant_id,
            &fence,
            record.updated_at,
        )?);
        transaction.push(self.external_action_put(&record, false, Some(expected_revision))?);
        match self
            .db
            .transact_write_items()
            .set_transact_items(Some(transaction))
            .send()
            .await
        {
            Ok(_) => Ok(GovernanceExternalActionUpdateOutcome::Stored(record)),
            Err(error) if is_transaction_conflict(&error) => {
                if !self
                    .external_fence_is_current(&record.tenant_id, &fence, record.updated_at)
                    .await?
                {
                    return Ok(GovernanceExternalActionUpdateOutcome::FenceConflict);
                }
                let latest = self
                    .get_external_action(&record.tenant_id, &record.job_id, &record.action_id)
                    .await?
                    .ok_or_else(|| {
                        StoreError::Permanent(
                            "governance external action disappeared after conflict".into(),
                        )
                    })?;
                Ok(GovernanceExternalActionUpdateOutcome::Conflict(latest))
            }
            Err(error) => Err(super::ddb_err(error)),
        }
    }

    async fn reconcile_external_action(
        &self,
        mut record: GovernanceExternalActionRecord,
        expected_revision: u64,
        fence: GovernanceExternalActionReconcileFence,
    ) -> Result<GovernanceExternalActionUpdateOutcome, StoreError> {
        if record.job_id != fence.job_id {
            return Err(StoreError::Permanent(
                "governance external action reconciliation job mismatch".into(),
            ));
        }
        let current = self
            .get_external_action(&record.tenant_id, &record.job_id, &record.action_id)
            .await?
            .ok_or_else(|| {
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
        if !self
            .external_reconcile_fence_is_current(&record.tenant_id, &fence)
            .await?
        {
            return Ok(GovernanceExternalActionUpdateOutcome::FenceConflict);
        }
        record.revision = expected_revision.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("governance external action revision exhausted".into())
        })?;
        let mut transaction = self.external_reconcile_conditions(&record.tenant_id, &fence)?;
        transaction.push(self.external_action_put(&record, false, Some(expected_revision))?);
        match self
            .db
            .transact_write_items()
            .set_transact_items(Some(transaction))
            .send()
            .await
        {
            Ok(_) => Ok(GovernanceExternalActionUpdateOutcome::Stored(record)),
            Err(error) if is_transaction_conflict(&error) => {
                if !self
                    .external_reconcile_fence_is_current(&record.tenant_id, &fence)
                    .await?
                {
                    return Ok(GovernanceExternalActionUpdateOutcome::FenceConflict);
                }
                let latest = self
                    .get_external_action(&record.tenant_id, &record.job_id, &record.action_id)
                    .await?
                    .ok_or_else(|| {
                        StoreError::Permanent(
                            "governance external action disappeared after conflict".into(),
                        )
                    })?;
                Ok(GovernanceExternalActionUpdateOutcome::Conflict(latest))
            }
            Err(error) => Err(super::ddb_err(error)),
        }
    }

    async fn put_evidence(
        &self,
        record: GovernanceEvidenceRecord,
    ) -> Result<GovernanceEvidencePutOutcome, StoreError> {
        if !record.verify_hash()
            || record.payload.tenant_id.is_empty()
            || record.payload.job_id.is_empty()
            || record.payload.evidence_revision == 0
        {
            return Err(StoreError::Permanent("invalid governance evidence".into()));
        }
        let key = evidence_key(&record.payload.job_id, record.payload.evidence_revision);
        let item = Self::record_item(
            &record.payload.tenant_id,
            &key,
            "governance_evidence",
            &record,
        )?;
        match self
            .db
            .put_item()
            .table_name(&self.governance_table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(pk) AND attribute_not_exists(sk)")
            .send()
            .await
        {
            Ok(_) => Ok(GovernanceEvidencePutOutcome::Stored(record)),
            Err(error) if is_conditional(&error) => {
                let existing = self
                    .get_record(
                        &record.payload.tenant_id,
                        &evidence_key(&record.payload.job_id, record.payload.evidence_revision),
                    )
                    .await?
                    .ok_or_else(|| {
                        StoreError::Transient(
                            "governance evidence conflict did not converge".into(),
                        )
                    })?;
                Ok(GovernanceEvidencePutOutcome::Existing(existing))
            }
            Err(error) => Err(super::ddb_err(error)),
        }
    }

    async fn latest_evidence(
        &self,
        tenant_id: &str,
        job_id: &str,
    ) -> Result<Option<GovernanceEvidenceRecord>, StoreError> {
        let output = self
            .db
            .query()
            .table_name(&self.governance_table)
            .key_condition_expression("pk = :pk AND begins_with(sk, :prefix)")
            .expression_attribute_values(":pk", AttributeValue::S(tenant_id.to_string()))
            .expression_attribute_values(":prefix", AttributeValue::S(evidence_prefix(job_id)))
            .consistent_read(true)
            .scan_index_forward(false)
            .limit(1)
            .send()
            .await
            .map_err(super::ddb_err)?;
        let Some(item) = output.items().first() else {
            return Ok(None);
        };
        let key = item
            .get("sk")
            .and_then(|value| value.as_s().ok())
            .ok_or_else(|| StoreError::Permanent("governance evidence key is missing".into()))?;
        let record: GovernanceEvidenceRecord = record_from_item(item, tenant_id, key)?;
        if record.payload.tenant_id != tenant_id
            || record.payload.job_id != job_id
            || !record.verify_hash()
        {
            return Err(StoreError::Permanent(
                "governance evidence identity or hash mismatch".into(),
            ));
        }
        Ok(Some(record))
    }

    async fn put_suppression(
        &self,
        record: GovernanceSuppressionRecord,
        fence: GovernanceDestructiveFence,
        now: i64,
    ) -> Result<bool, StoreError> {
        let expected_epoch = fence.target_epoch.unwrap_or(fence.tenant_revision);
        if record.tenant_id.is_empty()
            || expected_epoch == 0
            || record.target_epoch != expected_epoch
        {
            return Err(StoreError::Permanent(
                "suppression record does not match its destructive fence".into(),
            ));
        }
        let pk = crate::governance::suppression_partition_key(
            &record.tenant_id,
            &record.target_class,
            &record.digest,
        );
        let head = suppression_head_put(&self.suppression_table, &pk)?;
        let epoch = suppression_epoch_put(&self.suppression_table, &pk, &record)?;
        match self
            .execute_destructive_transaction(
                &record.tenant_id,
                fence,
                now,
                vec![
                    TransactWriteItem::builder().put(head).build(),
                    TransactWriteItem::builder().put(epoch).build(),
                ],
            )
            .await?
        {
            GovernanceDestructiveWriteOutcome::Applied => Ok(true),
            GovernanceDestructiveWriteOutcome::FenceConflict => {
                if self.suppression_epoch_matches(&record).await? {
                    Ok(false)
                } else {
                    Err(StoreError::Transient(
                        "suppression transaction conflicted; retry".into(),
                    ))
                }
            }
        }
    }

    async fn is_suppressed(
        &self,
        tenant_id: &str,
        target_class: &str,
        digest: &str,
    ) -> Result<bool, StoreError> {
        let output = self
            .db
            .query()
            .table_name(&self.suppression_table)
            .key_condition_expression("pk = :pk AND epoch > :zero")
            .expression_attribute_values(
                ":pk",
                AttributeValue::S(crate::governance::suppression_partition_key(
                    tenant_id,
                    target_class,
                    digest,
                )),
            )
            .expression_attribute_values(":zero", AttributeValue::N("0".into()))
            .consistent_read(true)
            .limit(1)
            .send()
            .await
            .map_err(super::ddb_err)?;
        Ok(!output.items().is_empty())
    }

    async fn latest_suppression_epoch(
        &self,
        tenant_id: &str,
        target_class: &str,
        digest: &str,
    ) -> Result<Option<u64>, StoreError> {
        let output = self
            .db
            .query()
            .table_name(&self.suppression_table)
            .key_condition_expression("pk = :pk AND epoch > :zero")
            .expression_attribute_values(
                ":pk",
                AttributeValue::S(crate::governance::suppression_partition_key(
                    tenant_id,
                    target_class,
                    digest,
                )),
            )
            .expression_attribute_values(":zero", AttributeValue::N("0".into()))
            .consistent_read(true)
            .scan_index_forward(false)
            .limit(1)
            .send()
            .await
            .map_err(super::ddb_err)?;
        output
            .items()
            .first()
            .map(|item| {
                item.get("epoch")
                    .and_then(|value| value.as_n().ok())
                    .and_then(|value| value.parse::<u64>().ok())
                    .ok_or_else(|| {
                        StoreError::Permanent(
                            "suppression record is missing a valid target epoch".into(),
                        )
                    })
            })
            .transpose()
    }
}

fn record_from_item<T: DeserializeOwned>(
    item: &HashMap<String, AttributeValue>,
    tenant_id: &str,
    record_key: &str,
) -> Result<T, StoreError> {
    let pk = item
        .get("pk")
        .and_then(|value| value.as_s().ok())
        .map(String::as_str);
    let sk = item
        .get("sk")
        .and_then(|value| value.as_s().ok())
        .map(String::as_str);
    if pk != Some(tenant_id) || sk != Some(record_key) {
        return Err(StoreError::Permanent(
            "governance record key mismatch".into(),
        ));
    }
    let json = item
        .get("record")
        .and_then(|value| value.as_s().ok())
        .ok_or_else(|| StoreError::Permanent("governance record payload missing".into()))?;
    serde_json::from_str(json)
        .map_err(|error| StoreError::Permanent(format!("invalid governance record: {error}")))
}

fn legal_hold_name(state: LegalHoldState) -> &'static str {
    match state {
        LegalHoldState::Disabled => "disabled",
        LegalHoldState::Enabling => "enabling",
        LegalHoldState::Enabled => "enabled",
    }
}

fn job_state_name(state: GovernanceJobState) -> &'static str {
    match state {
        GovernanceJobState::Queued => "queued",
        GovernanceJobState::BlockedLegalHold => "blocked_legal_hold",
        GovernanceJobState::Running => "running",
        GovernanceJobState::Retryable => "retryable",
        GovernanceJobState::RetentionPending => "retention_pending",
        GovernanceJobState::Completed => "completed",
    }
}

fn job_phase_name(phase: GovernanceJobPhase) -> &'static str {
    match phase {
        GovernanceJobPhase::IntentRecorded => "intent_recorded",
        GovernanceJobPhase::MutationFenced => "mutation_fenced",
        GovernanceJobPhase::PrimaryCleanup => "primary_cleanup",
        GovernanceJobPhase::SuppressionRecorded => "suppression_recorded",
        GovernanceJobPhase::ReplicaVerification => "replica_verification",
        GovernanceJobPhase::RetentionVerification => "retention_verification",
        GovernanceJobPhase::Complete => "complete",
    }
}

fn job_kind_name(kind: GovernanceJobKind) -> &'static str {
    match kind {
        GovernanceJobKind::UserErasure => "user_erasure",
        GovernanceJobKind::TenantOffboarding => "tenant_offboarding",
    }
}

fn lifecycle_state_name(state: TenantLifecycleState) -> &'static str {
    match state {
        TenantLifecycleState::Active => "active",
        TenantLifecycleState::Offboarding => "offboarding",
    }
}

fn external_action_prefix(job_id: &str) -> String {
    format!("{ACTION_PREFIX}{job_id}#")
}

fn external_action_key(job_id: &str, action_id: &str) -> String {
    format!("{}{action_id}", external_action_prefix(job_id))
}

fn continuation_key(job_id: &str) -> String {
    format!("{CONTINUATION_PREFIX}{job_id}")
}

fn mutation_permit_key(permit_id: &str) -> String {
    format!("{MUTATION_PERMIT_PREFIX}{permit_id}")
}

fn mutation_gate_freeze_item(
    governance_table: &str,
    tenant_id: &str,
    gate: Option<&TenantMutationGateRecord>,
    now: i64,
) -> Result<TransactWriteItem, StoreError> {
    let revision = match gate {
        Some(gate) => gate.revision.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("tenant mutation gate revision exhausted".into())
        })?,
        None => 1,
    };
    let mut update = Update::builder()
        .table_name(governance_table)
        .key("pk", AttributeValue::S(tenant_id.to_string()))
        .key("sk", AttributeValue::S(MUTATION_GATE_KEY.into()))
        .update_expression(
            "SET tenant_id = :tenant_id, record_type = :record_type, #state = :frozen, \
             active_permits = :zero, revision = :next_revision, updated_at = :now",
        )
        .expression_attribute_names("#state", "state")
        .expression_attribute_values(":tenant_id", AttributeValue::S(tenant_id.to_string()))
        .expression_attribute_values(
            ":record_type",
            AttributeValue::S("tenant_mutation_gate".into()),
        )
        .expression_attribute_values(":frozen", AttributeValue::S("frozen".into()))
        .expression_attribute_values(":zero", AttributeValue::N("0".into()))
        .expression_attribute_values(":next_revision", AttributeValue::N(revision.to_string()))
        .expression_attribute_values(":now", AttributeValue::N(now.to_string()));
    update = match gate {
        None => update.condition_expression("attribute_not_exists(pk)"),
        Some(gate) => update
            .condition_expression(
                "#state = :active AND active_permits = :zero AND revision = :revision",
            )
            .expression_attribute_values(":active", AttributeValue::S("active".into()))
            .expression_attribute_values(":revision", AttributeValue::N(gate.revision.to_string())),
    };
    Ok(TransactWriteItem::builder()
        .update(update.build().map_err(|error| {
            StoreError::Permanent(format!(
                "tenant mutation gate freeze is incomplete: {error}"
            ))
        })?)
        .build())
}

fn mutation_gate_decrement(
    governance_table: &str,
    tenant_id: &str,
    now: i64,
) -> Result<TransactWriteItem, StoreError> {
    let update = Update::builder()
        .table_name(governance_table)
        .key("pk", AttributeValue::S(tenant_id.to_string()))
        .key("sk", AttributeValue::S(MUTATION_GATE_KEY.into()))
        .update_expression("SET updated_at = :now ADD active_permits :minus_one, revision :one")
        .condition_expression("#state = :active AND active_permits > :zero")
        .expression_attribute_names("#state", "state")
        .expression_attribute_values(":active", AttributeValue::S("active".into()))
        .expression_attribute_values(":zero", AttributeValue::N("0".into()))
        .expression_attribute_values(":minus_one", AttributeValue::N("-1".into()))
        .expression_attribute_values(":one", AttributeValue::N("1".into()))
        .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
        .build()
        .map_err(|error| {
            StoreError::Permanent(format!(
                "tenant mutation gate decrement is incomplete: {error}"
            ))
        })?;
    Ok(TransactWriteItem::builder().update(update).build())
}

fn job_lease_key(job_id: &str) -> String {
    format!("{LEASE_PREFIX}{job_id}")
}

fn evidence_prefix(job_id: &str) -> String {
    format!("{EVIDENCE_PREFIX}{job_id}#")
}

fn evidence_key(job_id: &str, revision: u64) -> String {
    format!("{}{revision:020}", evidence_prefix(job_id))
}

fn same_external_action_identity(
    left: &GovernanceExternalActionRecord,
    right: &GovernanceExternalActionRecord,
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
    current: &GovernanceExternalActionRecord,
    next: &GovernanceExternalActionRecord,
) -> bool {
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
    current: &GovernanceExternalActionRecord,
    next: &GovernanceExternalActionRecord,
) -> bool {
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

fn is_conditional<E>(error: &aws_sdk_dynamodb::error::SdkError<E>) -> bool
where
    E: ProvideErrorMetadata,
{
    error
        .code()
        .is_some_and(|code| code.contains("ConditionalCheckFailed"))
}

fn is_transaction_conflict<E>(error: &aws_sdk_dynamodb::error::SdkError<E>) -> bool
where
    E: ProvideErrorMetadata,
{
    error.code().is_some_and(|code| {
        code.contains("TransactionCanceled") || code.contains("TransactionConflict")
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DestructiveTransactionError {
    FenceConflict,
    Transient,
    Permanent,
}

#[allow(dead_code)]
fn classify_destructive_transaction_error<R>(
    error: &aws_sdk_dynamodb::error::SdkError<
        aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError,
        R,
    >,
) -> Option<DestructiveTransactionError> {
    let Some(
        aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError::TransactionCanceledException(
            canceled,
        ),
    ) = error.as_service_error()
    else {
        return None;
    };
    Some(classify_destructive_cancellation(canceled))
}

fn classify_destructive_cancellation(
    canceled: &aws_sdk_dynamodb::types::error::TransactionCanceledException,
) -> DestructiveTransactionError {
    let codes: Vec<_> = canceled
        .cancellation_reasons()
        .iter()
        .filter_map(|reason| reason.code())
        .filter(|code| *code != "None")
        .collect();
    if codes
        .iter()
        .any(|code| matches!(*code, "ValidationError" | "ItemCollectionSizeLimitExceeded"))
    {
        DestructiveTransactionError::Permanent
    } else if !codes.is_empty() && codes.iter().all(|code| *code == "ConditionalCheckFailed") {
        DestructiveTransactionError::FenceConflict
    } else {
        DestructiveTransactionError::Transient
    }
}

#[cfg(test)]
mod tests {
    use super::{
        classify_destructive_cancellation, mutation_gate_decrement, mutation_gate_freeze_item,
        suppression_epoch_put, suppression_head_put, DestructiveTransactionError,
        DynamoGovernanceStore, GovernanceDestructiveFence, GovernanceJobKind, GovernanceJobPhase,
        GovernanceJobRecord, GovernanceJobState,
    };
    use crate::{
        governance::{
            GovernanceSuppressionRecord, TenantCleanupStage, TenantMutationGateRecord,
            TenantMutationGateState,
        },
        ports::StoreError,
    };
    use aws_sdk_dynamodb::types::{
        error::TransactionCanceledException, AttributeValue, CancellationReason, Delete,
        TransactWriteItem,
    };

    fn job(tenant_revision: u64) -> GovernanceJobRecord {
        GovernanceJobRecord {
            job_id: "job-1".into(),
            tenant_id: "tenant-1".into(),
            kind: GovernanceJobKind::UserErasure,
            target_id: Some("user-1".into()),
            target_aliases: Vec::new(),
            verification_target: None,
            active_child_job_id: None,
            processed_records: 0,
            tenant_cleanup_stage: TenantCleanupStage::Users,
            target_epoch: 7,
            state: GovernanceJobState::Running,
            phase: GovernanceJobPhase::PrimaryCleanup,
            policy_revision: 9,
            tenant_revision,
            revision: 11,
            created_at: 1,
            updated_at: 2,
            primary_erasure_at: None,
            retention_anchor_at: None,
            retention_until: None,
            evidence_revision: 0,
            error_class: None,
        }
    }

    fn fence(tenant_revision: u64) -> GovernanceDestructiveFence {
        GovernanceDestructiveFence {
            job_id: "job-1".into(),
            job_revision: 11,
            policy_revision: 9,
            tenant_revision,
            lease_token_digest: "lease-token-a".into(),
            lease_deadline: 200,
            target_epoch: Some(7),
        }
    }

    fn target_write(index: usize) -> TransactWriteItem {
        let delete = Delete::builder()
            .table_name("target-table")
            .key("pk", AttributeValue::S(format!("target-{index}")))
            .build()
            .unwrap();
        TransactWriteItem::builder().delete(delete).build()
    }

    fn attribute_string<'a>(
        values: &'a std::collections::HashMap<String, AttributeValue>,
        name: &str,
    ) -> &'a str {
        values.get(name).unwrap().as_s().unwrap()
    }

    fn attribute_number<'a>(
        values: &'a std::collections::HashMap<String, AttributeValue>,
        name: &str,
    ) -> &'a str {
        values.get(name).unwrap().as_n().unwrap()
    }

    #[test]
    fn mutation_gate_builders_bind_count_state_and_revision() {
        let created = mutation_gate_freeze_item("governance", "t1", None, 100)
            .unwrap()
            .update()
            .unwrap()
            .clone();
        assert_eq!(
            created.condition_expression(),
            Some("attribute_not_exists(pk)")
        );
        assert_eq!(
            attribute_number(
                created.expression_attribute_values().unwrap(),
                ":next_revision"
            ),
            "1"
        );

        let gate = TenantMutationGateRecord {
            tenant_id: "t1".into(),
            state: TenantMutationGateState::Active,
            active_permits: 0,
            revision: 7,
            updated_at: 90,
        };
        let frozen = mutation_gate_freeze_item("governance", "t1", Some(&gate), 100)
            .unwrap()
            .update()
            .unwrap()
            .clone();
        assert_eq!(
            frozen.condition_expression(),
            Some("#state = :active AND active_permits = :zero AND revision = :revision")
        );
        assert_eq!(
            attribute_number(frozen.expression_attribute_values().unwrap(), ":revision"),
            "7"
        );
        assert_eq!(
            attribute_number(
                frozen.expression_attribute_values().unwrap(),
                ":next_revision"
            ),
            "8"
        );

        let decremented = mutation_gate_decrement("governance", "t1", 101)
            .unwrap()
            .update()
            .unwrap()
            .clone();
        assert_eq!(
            decremented.condition_expression(),
            Some("#state = :active AND active_permits > :zero")
        );
        assert!(decremented
            .update_expression()
            .contains("active_permits :minus_one"));
        assert_eq!(
            attribute_number(
                decremented.expression_attribute_values().unwrap(),
                ":minus_one"
            ),
            "-1"
        );
    }

    #[test]
    fn suppression_partition_is_tenant_and_domain_scoped() {
        assert_ne!(
            crate::governance::suppression_partition_key("t1", "user", "digest"),
            crate::governance::suppression_partition_key("t2", "user", "digest")
        );
        assert_ne!(
            crate::governance::suppression_partition_key("t1", "user", "digest"),
            crate::governance::suppression_partition_key("t1", "tenant", "digest")
        );
    }

    #[test]
    fn suppression_put_builders_preserve_head_and_append_exact_epoch() {
        let record = GovernanceSuppressionRecord {
            tenant_id: "t1".into(),
            target_class: "user".into(),
            key_version: 1,
            normalization_version: 1,
            digest: "digest-1".into(),
            target_epoch: 7,
            created_at: 100,
        };
        let pk = crate::governance::suppression_partition_key(
            &record.tenant_id,
            &record.target_class,
            &record.digest,
        );
        let head = suppression_head_put("suppression", &pk).unwrap();
        assert_eq!(head.table_name(), "suppression");
        assert_eq!(
            head.condition_expression(),
            Some("attribute_not_exists(pk) OR record_type = :head")
        );
        assert_eq!(attribute_string(head.item(), "pk"), pk);
        assert_eq!(attribute_number(head.item(), "epoch"), "0");
        assert_eq!(
            attribute_string(head.item(), "record_type"),
            "suppression_head"
        );
        assert_eq!(
            attribute_string(head.expression_attribute_values().unwrap(), ":head"),
            "suppression_head"
        );

        let epoch = suppression_epoch_put("suppression", &pk, &record).unwrap();
        assert_eq!(epoch.table_name(), "suppression");
        assert_eq!(
            epoch.condition_expression(),
            Some("attribute_not_exists(pk) AND attribute_not_exists(epoch)")
        );
        assert_eq!(attribute_string(epoch.item(), "pk"), pk);
        assert_eq!(attribute_number(epoch.item(), "epoch"), "7");
        let stored: GovernanceSuppressionRecord =
            serde_json::from_str(attribute_string(epoch.item(), "record")).unwrap();
        assert_eq!(stored, record);
    }

    #[test]
    fn job_item_materializes_every_destructive_fence_field() {
        let item = DynamoGovernanceStore::job_item(&job(4)).unwrap();
        assert_eq!(attribute_number(&item, "revision"), "11");
        assert_eq!(attribute_string(&item, "state"), "running");
        assert_eq!(attribute_string(&item, "phase"), "primary_cleanup");
        assert_eq!(attribute_number(&item, "policy_revision"), "9");
        assert_eq!(attribute_number(&item, "tenant_revision"), "4");
        assert_eq!(attribute_string(&item, "job_kind"), "user_erasure");
        assert_eq!(attribute_number(&item, "target_epoch"), "7");
    }

    #[test]
    fn destructive_builder_checks_exact_authority_fields() {
        let transaction = DynamoGovernanceStore::destructive_transaction_items(
            "governance-table",
            "tenant-1",
            &fence(4),
            &job(4),
            100,
            vec![target_write(0)],
        )
        .unwrap();
        assert_eq!(transaction.len(), 5);

        let policy = transaction[0].condition_check().unwrap();
        assert_eq!(
            policy.condition_expression(),
            "revision = :policy_revision AND legal_hold = :disabled"
        );
        assert_eq!(
            attribute_number(
                policy.expression_attribute_values().unwrap(),
                ":policy_revision"
            ),
            "9"
        );
        assert_eq!(
            attribute_string(policy.expression_attribute_values().unwrap(), ":disabled"),
            "disabled"
        );

        let job = transaction[1].condition_check().unwrap();
        let expression = job.condition_expression();
        for field in [
            "revision = :job_revision",
            "policy_revision = :policy_revision",
            "tenant_revision = :tenant_revision",
            "#state = :job_state",
            "phase = :job_phase",
            "job_kind = :job_kind",
            "target_epoch = :target_epoch",
        ] {
            assert!(
                expression.contains(field),
                "missing job fence field {field}"
            );
        }
        assert_eq!(
            attribute_string(job.expression_attribute_values().unwrap(), ":job_state"),
            "running"
        );
        assert_eq!(
            attribute_string(job.expression_attribute_values().unwrap(), ":job_phase"),
            "primary_cleanup"
        );
        assert_eq!(
            attribute_string(job.expression_attribute_values().unwrap(), ":job_kind"),
            "user_erasure"
        );
        assert_eq!(
            attribute_number(job.expression_attribute_values().unwrap(), ":target_epoch"),
            "7"
        );

        let lifecycle = transaction[2].condition_check().unwrap();
        assert_eq!(
            lifecycle.condition_expression(),
            "revision = :revision AND #state = :offboarding"
        );
        assert_eq!(
            attribute_number(
                lifecycle.expression_attribute_values().unwrap(),
                ":revision"
            ),
            "4"
        );

        let lease = transaction[3].condition_check().unwrap();
        let expression = lease.condition_expression();
        assert!(expression.contains("token_digest = :token_digest"));
        assert!(expression.contains("lease_deadline = :lease_deadline"));
        assert!(expression.contains("lease_deadline > :now"));
        assert_eq!(
            attribute_string(
                lease.expression_attribute_values().unwrap(),
                ":token_digest"
            ),
            "lease-token-a"
        );
        assert_eq!(
            attribute_number(
                lease.expression_attribute_values().unwrap(),
                ":lease_deadline"
            ),
            "200"
        );
        assert_eq!(
            attribute_number(lease.expression_attribute_values().unwrap(), ":now"),
            "100"
        );
        assert!(transaction[4].delete().is_some());
    }

    #[test]
    fn destructive_builder_handles_default_policy_and_target_limits() {
        let mut default_fence = fence(0);
        default_fence.policy_revision = 0;
        let mut default_job = job(0);
        default_job.policy_revision = 0;
        let writes = (0..96).map(target_write).collect();
        let transaction = DynamoGovernanceStore::destructive_transaction_items(
            "governance-table",
            "tenant-1",
            &default_fence,
            &default_job,
            100,
            writes,
        )
        .unwrap();
        assert_eq!(transaction.len(), 100);
        assert_eq!(
            transaction[0]
                .condition_check()
                .unwrap()
                .condition_expression(),
            "attribute_not_exists(pk)"
        );
        assert_eq!(
            transaction[2]
                .condition_check()
                .unwrap()
                .condition_expression(),
            "attribute_not_exists(pk) OR #state = :active"
        );

        let too_many = DynamoGovernanceStore::destructive_transaction_items(
            "governance-table",
            "tenant-1",
            &default_fence,
            &default_job,
            100,
            (0..97).map(target_write).collect(),
        );
        assert!(matches!(too_many, Err(StoreError::Permanent(_))));

        let tenant_too_many = DynamoGovernanceStore::destructive_transaction_items(
            "governance-table",
            "tenant-1",
            &fence(4),
            &job(4),
            100,
            (0..97).map(target_write).collect(),
        );
        assert!(matches!(tenant_too_many, Err(StoreError::Permanent(_))));

        let empty = DynamoGovernanceStore::destructive_transaction_items(
            "governance-table",
            "tenant-1",
            &fence(4),
            &job(4),
            100,
            Vec::new(),
        );
        assert!(matches!(empty, Err(StoreError::Permanent(_))));
    }

    #[test]
    fn destructive_cancellation_requires_an_unambiguous_condition_conflict() {
        let conditional = TransactionCanceledException::builder()
            .cancellation_reasons(CancellationReason::builder().build())
            .cancellation_reasons(
                CancellationReason::builder()
                    .code("ConditionalCheckFailed")
                    .build(),
            )
            .build();
        assert_eq!(
            classify_destructive_cancellation(&conditional),
            DestructiveTransactionError::FenceConflict
        );

        let ambiguous = TransactionCanceledException::builder().build();
        assert_eq!(
            classify_destructive_cancellation(&ambiguous),
            DestructiveTransactionError::Transient
        );

        let transient = TransactionCanceledException::builder()
            .cancellation_reasons(
                CancellationReason::builder()
                    .code("ConditionalCheckFailed")
                    .build(),
            )
            .cancellation_reasons(
                CancellationReason::builder()
                    .code("TransactionConflict")
                    .build(),
            )
            .build();
        assert_eq!(
            classify_destructive_cancellation(&transient),
            DestructiveTransactionError::Transient
        );

        let permanent = TransactionCanceledException::builder()
            .cancellation_reasons(
                CancellationReason::builder()
                    .code("ValidationError")
                    .build(),
            )
            .build();
        assert_eq!(
            classify_destructive_cancellation(&permanent),
            DestructiveTransactionError::Permanent
        );
    }
}
