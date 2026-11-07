use super::{db_error, PostgresStore};
use crate::ports::{JtiRecord, JtiStore, StoreError};
use sqlx::types::Json;

impl JtiStore for PostgresStore {
    async fn put(&self, record: JtiRecord) -> Result<(), StoreError> {
        let delegated = record.delegation.is_some();
        let result = sqlx::query(
            "INSERT INTO a_auth.jti (tenant, jti, delegated, user_id, expires_at, record) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (tenant, jti, delegated) \
             DO UPDATE SET user_id = EXCLUDED.user_id, expires_at = EXCLUDED.expires_at, \
             record = EXCLUDED.record WHERE NOT a_auth.jti.delegated",
        )
        .bind(&record.tenant_id)
        .bind(&record.jti)
        .bind(delegated)
        .bind(&record.user_id)
        .bind(record.expires_at)
        .bind(Json(&record))
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::Permanent(
                "delegation authority is immutable".into(),
            ));
        }
        Ok(())
    }

    async fn get(&self, tenant_id: &str, jti: &str) -> Result<Option<JtiRecord>, StoreError> {
        let record: Option<Json<JtiRecord>> = sqlx::query_scalar(
            "SELECT record FROM a_auth.jti WHERE tenant = $1 AND jti = $2 \
             ORDER BY delegated LIMIT 1",
        )
        .bind(tenant_id)
        .bind(jti)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(record.map(|Json(record)| record))
    }

    async fn revoke_delegation(&self, tenant_id: &str, jti: &str) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE a_auth.jti SET record = jsonb_set(record, '{delegation,revoked}', 'true') \
             WHERE tenant = $1 AND jti = $2 AND delegated",
        )
        .bind(tenant_id)
        .bind(jti)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn delete_by_user(&self, tenant_id: &str, user_id: &str) -> Result<usize, StoreError> {
        let result = sqlx::query("DELETE FROM a_auth.jti WHERE tenant = $1 AND user_id = $2")
            .bind(tenant_id)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }

    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        let result = sqlx::query("DELETE FROM a_auth.jti WHERE tenant = $1")
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }
}
