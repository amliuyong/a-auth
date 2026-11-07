use super::{db_error, PostgresStore};
use crate::ports::{ReplayStore, StoreError};

impl ReplayStore for PostgresStore {
    async fn check_and_set(
        &self,
        tenant: &str,
        key: &str,
        expires_at: i64,
    ) -> Result<bool, StoreError> {
        // PostgreSQL rechecks the predicate while holding the conflicting row
        // lock. Exactly one connection can insert/replace expired authority.
        // Inclusive boundary matches memory and Dynamo: exp == now still rejects.
        let now = crate::token::current_unix_secs_pub();
        let result = sqlx::query(
            "INSERT INTO a_auth.replay (tenant, replay_key, expires_at) VALUES ($1, $2, $3) \
             ON CONFLICT (tenant, replay_key) DO UPDATE SET expires_at = EXCLUDED.expires_at \
             WHERE a_auth.replay.expires_at < $4",
        )
        .bind(tenant)
        .bind(key)
        .bind(expires_at)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let result = sqlx::query("DELETE FROM a_auth.replay WHERE tenant = $1")
            .bind(tenant)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }
}
