use super::{db_error, PostgresStore};
use crate::ports::{DeviceAuthGrant, DeviceStore, StoreError};
use sqlx::types::Json;

impl DeviceStore for PostgresStore {
    async fn put(&self, tenant: &str, grant: DeviceAuthGrant) -> Result<(), StoreError> {
        // Whole-record writes are only for creation/nonconcurrent maintenance.
        // Poll, decision and signing paths use the field CAS methods below.
        sqlx::query(
            "INSERT INTO a_auth.device_grants (tenant, device_code, user_code, expires_at, record) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant, device_code) DO UPDATE \
             SET user_code = EXCLUDED.user_code, expires_at = EXCLUDED.expires_at, record = EXCLUDED.record",
        )
        .bind(tenant)
        .bind(&grant.device_code)
        .bind(&grant.user_code)
        .bind(grant.expires_at)
        .bind(Json(&grant))
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn get(
        &self,
        tenant: &str,
        device_code: &str,
    ) -> Result<Option<DeviceAuthGrant>, StoreError> {
        let record: Option<Json<DeviceAuthGrant>> = sqlx::query_scalar(
            "SELECT record FROM a_auth.device_grants WHERE tenant = $1 AND device_code = $2",
        )
        .bind(tenant)
        .bind(device_code)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(record.map(|Json(record)| record))
    }

    async fn get_by_user_code(
        &self,
        tenant: &str,
        user_code: &str,
    ) -> Result<Option<DeviceAuthGrant>, StoreError> {
        let record: Option<Json<DeviceAuthGrant>> = sqlx::query_scalar(
            "SELECT record FROM a_auth.device_grants WHERE tenant = $1 AND user_code = $2 \
             ORDER BY device_code LIMIT 1",
        )
        .bind(tenant)
        .bind(user_code)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(record.map(|Json(record)| record))
    }

    async fn update(&self, tenant: &str, grant: DeviceAuthGrant) -> Result<(), StoreError> {
        DeviceStore::put(self, tenant, grant).await
    }

    async fn consume(&self, tenant: &str, device_code: &str, now: i64) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE a_auth.device_grants SET record = jsonb_set(record, '{consumed}', 'true') \
             WHERE tenant = $1 AND device_code = $2 AND expires_at > $3 \
             AND record->>'consumed' = 'false'",
        )
        .bind(tenant)
        .bind(device_code)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn claim_poll(
        &self,
        tenant: &str,
        device_code: &str,
        observed_last_poll_at: Option<i64>,
        now: i64,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE a_auth.device_grants SET record = jsonb_set(record, '{last_poll_at}', to_jsonb($4::BIGINT)) \
             WHERE tenant = $1 AND device_code = $2 AND expires_at > $4 \
             AND (record->>'last_poll_at')::BIGINT IS NOT DISTINCT FROM $3",
        )
        .bind(tenant)
        .bind(device_code)
        .bind(observed_last_poll_at)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn decide(
        &self,
        tenant: &str,
        device_code: &str,
        user_id: &str,
        password_credential_version: Option<u64>,
        approve: bool,
        now: i64,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE a_auth.device_grants SET record = \
             jsonb_set(jsonb_set(jsonb_set(record, '{status}', to_jsonb($4::TEXT)), \
             '{user_id}', to_jsonb($3::TEXT)), '{password_credential_version}', \
             COALESCE(to_jsonb($5::TEXT::NUMERIC), 'null'::JSONB)) \
             WHERE tenant = $1 AND device_code = $2 AND expires_at > $6 \
             AND record->>'status' = 'pending'",
        )
        .bind(tenant)
        .bind(device_code)
        .bind(user_id)
        .bind(if approve { "approved" } else { "denied" })
        .bind(password_credential_version.map(|version| version.to_string()))
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn release_consume(
        &self,
        tenant: &str,
        device_code: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE a_auth.device_grants SET record = jsonb_set(record, '{consumed}', 'false') \
             WHERE tenant = $1 AND device_code = $2 AND expires_at > $3",
        )
        .bind(tenant)
        .bind(device_code)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        let result = sqlx::query(
            "DELETE FROM a_auth.device_grants WHERE tenant = $1 AND record->>'user_id' = $2",
        )
        .bind(tenant)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let result = sqlx::query("DELETE FROM a_auth.device_grants WHERE tenant = $1")
            .bind(tenant)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }
}
