//! Durable governance authority. Pure transitions run under the same tenant
//! directory lock as identity admission; only successful transitions commit.

use super::{db_error, users::PostgresUsersStore, PostgresStore};
use crate::{
    adapters::governance_state::GovernanceState,
    governance::*,
    ports::{GovernanceStore, StoreError},
};
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};

mod resources;
mod snapshot;
mod tenant_data;
mod user_data;

#[derive(Clone)]
pub struct PostgresGovernanceStore {
    database: PostgresStore,
}

fn invalid() -> StoreError {
    StoreError::Permanent("Invalid governance suppression authority".into())
}

fn decode_suppression(
    row: PgRow,
    tenant: &str,
    class: &str,
    digest: &str,
) -> Result<GovernanceSuppressionRecord, StoreError> {
    let epoch: String = row.try_get("epoch").map_err(db_error)?;
    let epoch: u64 = epoch.parse().map_err(|_| invalid())?;
    let payload: String = row.try_get("record").map_err(db_error)?;
    let value: serde_json::Value = serde_json::from_str(&payload).map_err(|_| invalid())?;
    let record: GovernanceSuppressionRecord =
        serde_json::from_str(&payload).map_err(|_| invalid())?;
    if record.tenant_id != tenant
        || record.target_class != class
        || record.digest != digest
        || record.target_epoch != epoch
        || serde_json::to_value(&record).map_err(|_| invalid())? != value
    {
        return Err(invalid());
    }
    Ok(record)
}

impl PostgresGovernanceStore {
    pub fn new(database: PostgresStore) -> Self {
        Self { database }
    }

    pub(crate) fn belongs_to(&self, store: &PostgresStore) -> bool {
        self.database.shares_pool_with(store)
    }

    pub(crate) fn shares_pool_with(&self, other: &Self) -> bool {
        self.database.shares_pool_with(&other.database)
    }

    async fn read<T>(
        &self,
        tenant: &str,
        operation: impl FnOnce(&mut GovernanceState) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let row = sqlx::query(
            "SELECT generation::text AS generation, record \
             FROM a_auth.governance_authority WHERE tenant = $1",
        )
        .bind(tenant.as_bytes())
        .fetch_optional(&self.database.pool)
        .await
        .map_err(db_error)?;
        let (_, mut state) = Self::decode(tenant, row)?;
        operation(&mut state)
    }

    fn decode(tenant: &str, row: Option<PgRow>) -> Result<(u64, GovernanceState), StoreError> {
        let Some(row) = row else {
            return Ok((0, GovernanceState::default()));
        };
        let generation: String = row.try_get("generation").map_err(db_error)?;
        let generation = generation
            .parse()
            .map_err(|_| StoreError::Permanent("Invalid governance authority generation".into()))?;
        let payload: String = row.try_get("record").map_err(db_error)?;
        Ok((generation, snapshot::decode(tenant, generation, &payload)?))
    }

    async fn lock(
        transaction: &mut Transaction<'_, Postgres>,
        tenant: &str,
    ) -> Result<(u64, GovernanceState), StoreError> {
        PostgresUsersStore::lock_directory(transaction, tenant).await?;
        let row = sqlx::query(
            "SELECT generation::text AS generation, record \
             FROM a_auth.governance_authority WHERE tenant = $1 FOR UPDATE",
        )
        .bind(tenant.as_bytes())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(db_error)?;
        Self::decode(tenant, row)
    }

    async fn run<T>(
        &self,
        tenant: &str,
        operation: impl FnOnce(&mut GovernanceState) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut transaction = self.database.pool.begin().await.map_err(db_error)?;
        let (generation, mut state) = Self::lock(&mut transaction, tenant).await?;
        let before = snapshot::encode(tenant, generation, &state)?;
        let outcome = operation(&mut state)?;
        if snapshot::encode(tenant, generation, &state)? != before {
            let generation = generation.checked_add(1).ok_or_else(|| {
                StoreError::Permanent("Governance authority generation exhausted".into())
            })?;
            let payload = snapshot::encode(tenant, generation, &state)?;
            // Reject invalid newly created authority before committing it too.
            snapshot::decode(tenant, generation, &payload)?;
            sqlx::query(
                "INSERT INTO a_auth.governance_authority (tenant, generation, record) \
                 VALUES ($1, $2::TEXT::NUMERIC, $3) ON CONFLICT (tenant) DO UPDATE \
                 SET generation = EXCLUDED.generation, record = EXCLUDED.record",
            )
            .bind(tenant.as_bytes())
            .bind(generation.to_string())
            .bind(payload)
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(outcome)
    }

    async fn suppression_epochs(
        &self,
        tenant: &str,
        target_class: &str,
        digest: &str,
    ) -> Result<Vec<u64>, StoreError> {
        let rows = sqlx::query(
            "SELECT epoch::text AS epoch, record FROM a_auth.governance_suppressions \
             WHERE tenant = $1 AND target_class = $2 AND digest = $3",
        )
        .bind(tenant.as_bytes())
        .bind(target_class.as_bytes())
        .bind(digest.as_bytes())
        .fetch_all(&self.database.pool)
        .await
        .map_err(db_error)?;
        rows.into_iter()
            .map(|row| {
                decode_suppression(row, tenant, target_class, digest)
                    .map(|record| record.target_epoch)
            })
            .collect()
    }
}

impl GovernanceStore for PostgresGovernanceStore {
    async fn acquire_tenant_mutation_permit(
        &self,
        permit: crate::governance::TenantMutationPermit,
        now: i64,
    ) -> Result<crate::governance::TenantMutationPermitAcquireOutcome, StoreError> {
        let tenant = permit.tenant_id.clone();
        self.run(&tenant, move |state| {
            state.acquire_tenant_mutation_permit(permit, now)
        })
        .await
    }

    async fn renew_tenant_mutation_permit(
        &self,
        permit: &crate::governance::TenantMutationPermit,
        now: i64,
        deadline: i64,
    ) -> Result<bool, StoreError> {
        let tenant = permit.tenant_id.clone();
        self.run(&tenant, move |state| {
            state.renew_tenant_mutation_permit(permit, now, deadline)
        })
        .await
    }

    async fn release_tenant_mutation_permit(
        &self,
        permit: crate::governance::TenantMutationPermit,
        now: i64,
    ) -> Result<bool, StoreError> {
        let tenant = permit.tenant_id.clone();
        self.run(&tenant, move |state| {
            state.release_tenant_mutation_permit(permit, now)
        })
        .await
    }

    async fn get_policy(
        &self,
        tenant_id: &str,
    ) -> Result<Option<crate::governance::GovernancePolicyRecord>, StoreError> {
        let tenant = tenant_id.to_owned();
        self.read(&tenant, move |state| state.get_policy(tenant_id))
            .await
    }

    async fn put_policy(
        &self,
        record: crate::governance::GovernancePolicyRecord,
        expected_revision: u64,
    ) -> Result<crate::governance::GovernancePolicyPutOutcome, StoreError> {
        let tenant = record.tenant_id.clone();
        self.run(&tenant, move |state| {
            state.put_policy(record, expected_revision)
        })
        .await
    }

    async fn put_export_manifest(
        &self,
        manifest: crate::governance::GovernanceExportManifest,
    ) -> Result<bool, StoreError> {
        let tenant = manifest.tenant_id.clone();
        self.run(&tenant, move |state| state.put_export_manifest(manifest))
            .await
    }

    async fn get_export_manifest(
        &self,
        tenant_id: &str,
        export_id: &str,
        now: i64,
    ) -> Result<Option<crate::governance::GovernanceExportManifest>, StoreError> {
        let tenant = tenant_id.to_owned();
        self.run(&tenant, move |state| {
            state.get_export_manifest(tenant_id, export_id, now)
        })
        .await
    }

    async fn start_or_resume_job(
        &self,
        job: crate::governance::GovernanceJobRecord,
        expected_policy_revision: u64,
        freeze_tenant: bool,
    ) -> Result<crate::governance::GovernanceJobStartOutcome, StoreError> {
        let tenant = job.tenant_id.clone();
        self.run(&tenant, move |state| {
            state.start_or_resume_job(job, expected_policy_revision, freeze_tenant)
        })
        .await
    }

    async fn get_job(
        &self,
        tenant_id: &str,
        job_id: &str,
    ) -> Result<Option<crate::governance::GovernanceJobRecord>, StoreError> {
        let tenant = tenant_id.to_owned();
        self.read(&tenant, move |state| state.get_job(tenant_id, job_id))
            .await
    }

    async fn list_jobs(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<crate::governance::GovernanceJobRecord>, StoreError> {
        let tenant = tenant_id.to_owned();
        self.read(&tenant, move |state| state.list_jobs(tenant_id))
            .await
    }

    async fn get_continuation(
        &self,
        tenant_id: &str,
        job_id: &str,
    ) -> Result<Option<crate::governance::GovernanceContinuationRecord>, StoreError> {
        let tenant = tenant_id.to_owned();
        self.read(&tenant, move |state| {
            state.get_continuation(tenant_id, job_id)
        })
        .await
    }

    async fn update_continuation(
        &self,
        record: crate::governance::GovernanceContinuationRecord,
        expected_revision: u64,
    ) -> Result<crate::governance::GovernanceContinuationUpdateOutcome, StoreError> {
        let tenant = record.tenant_id.clone();
        self.run(&tenant, move |state| {
            state.update_continuation(record, expected_revision)
        })
        .await
    }

    async fn consume_continuation_resume(
        &self,
        tenant_id: &str,
        job_id: &str,
        jti_digest: &str,
        expected_resume_revision: u64,
        _expires_at: i64,
    ) -> Result<bool, StoreError> {
        let tenant = tenant_id.to_owned();
        self.run(&tenant, move |state| {
            state.consume_continuation_resume(
                tenant_id,
                job_id,
                jti_digest,
                expected_resume_revision,
                _expires_at,
            )
        })
        .await
    }

    async fn update_job(
        &self,
        job: crate::governance::GovernanceJobRecord,
        expected_revision: u64,
        expected_policy_revision: u64,
    ) -> Result<crate::governance::GovernanceJobUpdateOutcome, StoreError> {
        let tenant = job.tenant_id.clone();
        self.run(&tenant, move |state| {
            state.update_job(job, expected_revision, expected_policy_revision)
        })
        .await
    }

    async fn complete_job_with_evidence(
        &self,
        job: crate::governance::GovernanceJobRecord,
        evidence: crate::governance::GovernanceEvidenceRecord,
        expected_revision: u64,
        expected_policy_revision: u64,
    ) -> Result<crate::governance::GovernanceJobUpdateOutcome, StoreError> {
        let tenant = job.tenant_id.clone();
        self.run(&tenant, move |state| {
            state.complete_job_with_evidence(
                job,
                evidence,
                expected_revision,
                expected_policy_revision,
            )
        })
        .await
    }

    async fn claim_job_lease(
        &self,
        tenant_id: &str,
        job_id: &str,
        expected_job_revision: u64,
        token_digest: &str,
        now: i64,
        deadline: i64,
    ) -> Result<crate::governance::GovernanceJobLeaseOutcome, StoreError> {
        let tenant = tenant_id.to_owned();
        self.run(&tenant, move |state| {
            state.claim_job_lease(
                tenant_id,
                job_id,
                expected_job_revision,
                token_digest,
                now,
                deadline,
            )
        })
        .await
    }

    async fn renew_job_lease(
        &self,
        tenant_id: &str,
        fence: crate::governance::GovernanceDestructiveFence,
        now: i64,
        deadline: i64,
    ) -> Result<crate::governance::GovernanceJobLeaseOutcome, StoreError> {
        let tenant = tenant_id.to_owned();
        self.run(&tenant, move |state| {
            state.renew_job_lease(tenant_id, fence, now, deadline)
        })
        .await
    }

    async fn release_job_lease(
        &self,
        tenant_id: &str,
        fence: crate::governance::GovernanceDestructiveFence,
    ) -> Result<crate::governance::GovernanceJobLeaseOutcome, StoreError> {
        let tenant = tenant_id.to_owned();
        self.run(&tenant, move |state| {
            state.release_job_lease(tenant_id, fence)
        })
        .await
    }

    async fn tenant_has_active_job_leases(
        &self,
        tenant_id: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        let tenant = tenant_id.to_owned();
        self.read(&tenant, move |state| {
            state.tenant_has_active_job_leases(tenant_id, now)
        })
        .await
    }

    async fn get_tenant_lifecycle(
        &self,
        tenant_id: &str,
    ) -> Result<Option<crate::governance::TenantLifecycleRecord>, StoreError> {
        let tenant = tenant_id.to_owned();
        self.read(&tenant, move |state| state.get_tenant_lifecycle(tenant_id))
            .await
    }

    async fn prepare_external_action(
        &self,
        record: crate::governance::GovernanceExternalActionRecord,
        fence: crate::governance::GovernanceExternalActionFence,
    ) -> Result<crate::governance::GovernanceExternalActionPutOutcome, StoreError> {
        let tenant = record.tenant_id.clone();
        self.run(&tenant, move |state| {
            state.prepare_external_action(record, fence)
        })
        .await
    }

    async fn get_external_action(
        &self,
        tenant_id: &str,
        job_id: &str,
        action_id: &str,
    ) -> Result<Option<crate::governance::GovernanceExternalActionRecord>, StoreError> {
        let tenant = tenant_id.to_owned();
        self.read(&tenant, move |state| {
            state.get_external_action(tenant_id, job_id, action_id)
        })
        .await
    }

    async fn list_external_actions(
        &self,
        tenant_id: &str,
        job_id: &str,
    ) -> Result<Vec<crate::governance::GovernanceExternalActionRecord>, StoreError> {
        let tenant = tenant_id.to_owned();
        self.read(&tenant, move |state| {
            state.list_external_actions(tenant_id, job_id)
        })
        .await
    }

    async fn list_tenant_external_actions(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<crate::governance::GovernanceExternalActionRecord>, StoreError> {
        let tenant = tenant_id.to_owned();
        self.read(&tenant, move |state| {
            state.list_tenant_external_actions(tenant_id)
        })
        .await
    }

    async fn update_external_action(
        &self,
        record: crate::governance::GovernanceExternalActionRecord,
        expected_revision: u64,
        fence: crate::governance::GovernanceExternalActionFence,
    ) -> Result<crate::governance::GovernanceExternalActionUpdateOutcome, StoreError> {
        let tenant = record.tenant_id.clone();
        self.run(&tenant, move |state| {
            state.update_external_action(record, expected_revision, fence)
        })
        .await
    }

    async fn reconcile_external_action(
        &self,
        record: crate::governance::GovernanceExternalActionRecord,
        expected_revision: u64,
        fence: crate::governance::GovernanceExternalActionReconcileFence,
    ) -> Result<crate::governance::GovernanceExternalActionUpdateOutcome, StoreError> {
        let tenant = record.tenant_id.clone();
        self.run(&tenant, move |state| {
            state.reconcile_external_action(record, expected_revision, fence)
        })
        .await
    }

    async fn put_evidence(
        &self,
        record: crate::governance::GovernanceEvidenceRecord,
    ) -> Result<crate::governance::GovernanceEvidencePutOutcome, StoreError> {
        let tenant = record.payload.tenant_id.clone();
        self.run(&tenant, move |state| state.put_evidence(record))
            .await
    }

    async fn latest_evidence(
        &self,
        tenant_id: &str,
        job_id: &str,
    ) -> Result<Option<crate::governance::GovernanceEvidenceRecord>, StoreError> {
        let tenant = tenant_id.to_owned();
        self.read(&tenant, move |state| {
            state.latest_evidence(tenant_id, job_id)
        })
        .await
    }

    async fn put_suppression(
        &self,
        record: GovernanceSuppressionRecord,
        fence: GovernanceDestructiveFence,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.database.pool.begin().await.map_err(db_error)?;
        let (_, mut state) = Self::lock(&mut transaction, &record.tenant_id).await?;
        // Fence validation precedes the append, and shares admission's lock.
        state.put_suppression(record.clone(), fence, now)?;
        let payload = serde_json::to_string(&record).map_err(|_| invalid())?;
        let inserted = sqlx::query(
            "INSERT INTO a_auth.governance_suppressions \
             (tenant, target_class, digest, epoch, record) VALUES ($1, $2, $3, $4::TEXT::NUMERIC, $5) \
             ON CONFLICT (tenant, target_class, digest, epoch) DO NOTHING",
        )
        .bind(record.tenant_id.as_bytes())
        .bind(record.target_class.as_bytes())
        .bind(record.digest.as_bytes())
        .bind(record.target_epoch.to_string())
        .bind(payload)
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?
        .rows_affected()
            == 1;
        if !inserted {
            let row = sqlx::query(
                "SELECT epoch::text AS epoch, record FROM a_auth.governance_suppressions \
                 WHERE tenant = $1 AND target_class = $2 AND digest = $3 AND epoch = $4::TEXT::NUMERIC",
            )
            .bind(record.tenant_id.as_bytes())
            .bind(record.target_class.as_bytes())
            .bind(record.digest.as_bytes())
            .bind(record.target_epoch.to_string())
            .fetch_one(&mut *transaction)
            .await
            .map_err(db_error)?;
            decode_suppression(row, &record.tenant_id, &record.target_class, &record.digest)?;
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(inserted)
    }

    async fn is_suppressed(
        &self,
        tenant_id: &str,
        target_class: &str,
        digest: &str,
    ) -> Result<bool, StoreError> {
        Ok(!self
            .suppression_epochs(tenant_id, target_class, digest)
            .await?
            .is_empty())
    }

    async fn latest_suppression_epoch(
        &self,
        tenant_id: &str,
        target_class: &str,
        digest: &str,
    ) -> Result<Option<u64>, StoreError> {
        Ok(self
            .suppression_epochs(tenant_id, target_class, digest)
            .await?
            .into_iter()
            .max())
    }
}
