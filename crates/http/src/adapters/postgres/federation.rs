use super::{db_error, PostgresStore};
use crate::ports::{FederationConfigStore, FederationFlowState, FederationFlowStore, StoreError};
use agent_auth_authn::federation::FederationConfig;
use sqlx::{types::Json, Row};

pub(super) fn validate_config_identity(
    config: &FederationConfig,
    tenant: &str,
    idp: &str,
) -> Result<(), StoreError> {
    if config.tenant_id != tenant || config.upstream_idp_id != idp {
        return Err(StoreError::Permanent(
            "Federation config identity mismatch".into(),
        ));
    }
    Ok(())
}

impl FederationConfigStore for PostgresStore {
    async fn get(
        &self,
        tenant_id: &str,
        upstream_idp_id: &str,
    ) -> Result<Option<FederationConfig>, StoreError> {
        let record: Option<Json<FederationConfig>> = sqlx::query_scalar(
            "SELECT record FROM a_auth.federation_configs WHERE tenant = $1 AND upstream_idp_id = $2",
        )
        .bind(tenant_id)
        .bind(upstream_idp_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        record
            .map(|Json(record)| {
                validate_config_identity(&record, tenant_id, upstream_idp_id)?;
                Ok(record)
            })
            .transpose()
    }

    async fn list_by_tenant(&self, tenant_id: &str) -> Result<Vec<FederationConfig>, StoreError> {
        let records = sqlx::query(
            "SELECT upstream_idp_id, record FROM a_auth.federation_configs \
             WHERE tenant = $1 ORDER BY upstream_idp_id",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        records
            .into_iter()
            .map(|row| {
                let idp: String = row.try_get("upstream_idp_id").map_err(db_error)?;
                let Json(record) = row.try_get("record").map_err(db_error)?;
                validate_config_identity(&record, tenant_id, &idp)?;
                Ok(record)
            })
            .collect()
    }

    async fn put(&self, config: FederationConfig) -> Result<(), StoreError> {
        // The record contains a secret reference, never a resolved client secret.
        sqlx::query(
            "INSERT INTO a_auth.federation_configs (tenant, upstream_idp_id, record) \
             VALUES ($1, $2, $3) ON CONFLICT (tenant, upstream_idp_id) \
             DO UPDATE SET record = EXCLUDED.record",
        )
        .bind(&config.tenant_id)
        .bind(&config.upstream_idp_id)
        .bind(Json(&config))
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn delete(&self, tenant_id: &str, upstream_idp_id: &str) -> Result<(), StoreError> {
        sqlx::query(
            "DELETE FROM a_auth.federation_configs WHERE tenant = $1 AND upstream_idp_id = $2",
        )
        .bind(tenant_id)
        .bind(upstream_idp_id)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        let result = sqlx::query("DELETE FROM a_auth.federation_configs WHERE tenant = $1")
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }
}

impl FederationFlowStore for PostgresStore {
    async fn put(&self, state: FederationFlowState) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO a_auth.federation_flows (state, tenant, expires_at, record) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (state) DO UPDATE SET tenant = EXCLUDED.tenant, \
             expires_at = EXCLUDED.expires_at, record = EXCLUDED.record",
        )
        .bind(&state.state)
        .bind(&state.tenant_id)
        .bind(state.expires_at)
        .bind(Json(&state))
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn consume(&self, state: &str) -> Result<Option<FederationFlowState>, StoreError> {
        let record: Option<Json<FederationFlowState>> = sqlx::query_scalar(
            "DELETE FROM a_auth.federation_flows WHERE state = $1 RETURNING record",
        )
        .bind(state)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        // Delete expired state as well. Check after waiting for the database so
        // lock contention cannot turn a stale callback into a valid one.
        Ok(record
            .map(|Json(record)| record)
            .filter(|record| record.expires_at > crate::current_unix_secs()))
    }

    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        let result = sqlx::query("DELETE FROM a_auth.federation_flows WHERE tenant = $1")
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }
}
