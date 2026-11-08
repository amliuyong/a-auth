use super::{db_error, PostgresGovernanceStore};
use crate::{
    adapters::postgres::{PostgresSsfStore, PostgresUsersStore},
    governance_data::{GovernanceInventory, PostgresTenantPlane},
    governance_resources::{GovernanceRetentionRequest, GovernanceRetentionTarget},
    ports::StoreError,
};
use std::collections::BTreeMap;

impl PostgresGovernanceStore {
    pub(crate) async fn resource_inventory(
        &self,
        ssf: &PostgresSsfStore,
        request: &GovernanceRetentionRequest,
    ) -> Result<GovernanceInventory, StoreError> {
        if !ssf.belongs_to(&self.database) {
            return Err(StoreError::Permanent(
                "Portable governance pool mismatch".into(),
            ));
        }
        match &request.target {
            GovernanceRetentionTarget::User {
                tenant_id,
                user_id,
                aliases,
                ..
            } => {
                self.inventory_user_authority(
                    tenant_id,
                    &request.storage_tenant,
                    user_id,
                    aliases,
                    true,
                    true,
                )
                .await
            }
            GovernanceRetentionTarget::Tenant { tenant_id, .. } => {
                PostgresTenantPlane {
                    governance: self,
                    ssf,
                    grace: true,
                    jtis: true,
                    replay: true,
                    rate_limit: true,
                }
                .inventory(tenant_id, &request.storage_tenant)
                .await
            }
        }
    }

    pub(crate) async fn resource_retained_counts(
        &self,
        ssf: &PostgresSsfStore,
        request: &GovernanceRetentionRequest,
    ) -> Result<BTreeMap<String, u64>, StoreError> {
        let mut tx = self.database.pool.begin().await.map_err(db_error)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut tx, request.target.tenant_id()).await?;
        let hot = self
            .database
            .security_retention_count(&mut tx, request)
            .await?;
        let fallback = self
            .database
            .fallback_retention_count(&mut tx, request)
            .await?;
        let ssf_count = ssf
            .governance_retention_count(
                &mut tx,
                request.target.tenant_id(),
                request.retention_anchor_at,
            )
            .await?;
        tx.commit().await.map_err(db_error)?;
        Ok(BTreeMap::from([
            ("postgres_security_event_hot".into(), hot),
            ("postgres_security_event_fallback".into(), fallback),
            ("postgres_ssf_deliveries".into(), ssf_count),
        ]))
    }
}
