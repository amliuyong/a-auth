use super::{db_error, PostgresStore};
use crate::ports::{StoreError, WorkloadTrustEntry, WorkloadTrustStore};
use agent_auth_workload::TrustBinding;
use sqlx::types::Json;

impl WorkloadTrustStore for PostgresStore {
    async fn put(
        &self,
        tenant: &str,
        binding_id: String,
        binding: TrustBinding,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO a_auth.workload_trust (tenant, binding_id, record) VALUES ($1, $2, $3) \
             ON CONFLICT (tenant, binding_id) DO UPDATE SET record = EXCLUDED.record",
        )
        .bind(tenant)
        .bind(binding_id)
        .bind(Json(binding))
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn list_by_tenant(&self, tenant_id: &str) -> Result<Vec<WorkloadTrustEntry>, StoreError> {
        let records: Vec<(String, Json<TrustBinding>)> = sqlx::query_as(
            "SELECT binding_id, record FROM a_auth.workload_trust WHERE tenant = $1 ORDER BY binding_id",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(records
            .into_iter()
            .map(|(binding_id, Json(binding))| WorkloadTrustEntry {
                binding_id,
                binding,
            })
            .collect())
    }

    async fn delete(&self, tenant: &str, binding_id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM a_auth.workload_trust WHERE tenant = $1 AND binding_id = $2")
            .bind(tenant)
            .bind(binding_id)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let result = sqlx::query("DELETE FROM a_auth.workload_trust WHERE tenant = $1")
            .bind(tenant)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }
}
