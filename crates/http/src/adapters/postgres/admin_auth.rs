use super::{db_error, PostgresStore};
use crate::ports::{
    AdminAuthStore, AdminOidcConfig, AdminOidcConfigDeleteOutcome, AdminOidcConfigPutOutcome,
    AdminOidcFlow, AdminSessionRecord, StoreError,
};
use sqlx::types::Json;

impl AdminAuthStore for PostgresStore {
    async fn get_config(&self, tenant_id: &str) -> Result<Option<AdminOidcConfig>, StoreError> {
        let record: Option<Json<AdminOidcConfig>> =
            sqlx::query_scalar("SELECT record FROM a_auth.admin_oidc_configs WHERE tenant = $1")
                .bind(tenant_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_error)?;
        Ok(record.map(|Json(record)| record))
    }

    async fn put_config(
        &self,
        config: AdminOidcConfig,
        expected_revision: u64,
    ) -> Result<AdminOidcConfigPutOutcome, StoreError> {
        if expected_revision.checked_add(1) != Some(config.revision) {
            return Ok(AdminOidcConfigPutOutcome::Conflict);
        }
        let result = if expected_revision == 0 {
            sqlx::query(
                "INSERT INTO a_auth.admin_oidc_configs (tenant, record) \
                 VALUES ($1, $2) ON CONFLICT (tenant) DO NOTHING",
            )
            .bind(&config.tenant_id)
            .bind(Json(&config))
            .execute(&self.pool)
            .await
        } else {
            sqlx::query(
                "UPDATE a_auth.admin_oidc_configs SET record = $2 \
                 WHERE tenant = $1 AND record->>'revision' = $3",
            )
            .bind(&config.tenant_id)
            .bind(Json(&config))
            .bind(expected_revision.to_string())
            .execute(&self.pool)
            .await
        }
        .map_err(db_error)?;
        Ok(if result.rows_affected() == 1 {
            AdminOidcConfigPutOutcome::Stored(config)
        } else {
            AdminOidcConfigPutOutcome::Conflict
        })
    }

    async fn delete_config(
        &self,
        tenant_id: &str,
        expected_revision: u64,
    ) -> Result<AdminOidcConfigDeleteOutcome, StoreError> {
        let result = sqlx::query(
            "DELETE FROM a_auth.admin_oidc_configs WHERE tenant = $1 AND record->>'revision' = $2",
        )
        .bind(tenant_id)
        .bind(expected_revision.to_string())
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(if result.rows_affected() == 1 {
            AdminOidcConfigDeleteOutcome::Deleted
        } else {
            AdminOidcConfigDeleteOutcome::Conflict
        })
    }

    async fn put_flow(&self, flow: AdminOidcFlow) -> Result<(), StoreError> {
        // A hashed browser binding may never overwrite a live flow.
        sqlx::query(
            "INSERT INTO a_auth.admin_oidc_flows (state_hash, tenant, expires_at, record) VALUES ($1, $2, $3, $4)",
        )
        .bind(&flow.state_hash)
        .bind(&flow.tenant_id)
        .bind(flow.expires_at)
        .bind(Json(&flow))
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn consume_flow(
        &self,
        state_hash: &str,
        now: i64,
    ) -> Result<Option<AdminOidcFlow>, StoreError> {
        let record: Option<Json<serde_json::Value>> = sqlx::query_scalar(
            "DELETE FROM a_auth.admin_oidc_flows WHERE state_hash = $1 RETURNING record",
        )
        .bind(state_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        // Even expired/malformed state is deleted; no later callback can reuse it.
        Ok(record
            .and_then(|Json(record)| serde_json::from_value::<AdminOidcFlow>(record).ok())
            .filter(|flow| flow.state_hash == state_hash && flow.expires_at > now))
    }

    async fn create_session(&self, session: AdminSessionRecord) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO a_auth.admin_sessions (session_hash, tenant, user_id, expires_at, record) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&session.session_hash)
        .bind(&session.tenant_id)
        .bind(&session.user_id)
        .bind(session.expires_at)
        .bind(Json(&session))
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn get_session(
        &self,
        session_hash: &str,
        now: i64,
    ) -> Result<Option<AdminSessionRecord>, StoreError> {
        let record: Option<Json<serde_json::Value>> = sqlx::query_scalar(
            "SELECT record FROM a_auth.admin_sessions WHERE session_hash = $1 AND expires_at > $2",
        )
        .bind(session_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(record
            .and_then(|Json(record)| serde_json::from_value::<AdminSessionRecord>(record).ok())
            .filter(|session| session.session_hash == session_hash && session.expires_at > now))
    }

    async fn delete_session(&self, tenant_id: &str, session_hash: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM a_auth.admin_sessions WHERE tenant = $1 AND session_hash = $2")
            .bind(tenant_id)
            .bind(session_hash)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let config = sqlx::query("DELETE FROM a_auth.admin_oidc_configs WHERE tenant = $1")
            .bind(tenant_id)
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
        let flows = sqlx::query("DELETE FROM a_auth.admin_oidc_flows WHERE tenant = $1")
            .bind(tenant_id)
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
        let sessions = sqlx::query("DELETE FROM a_auth.admin_sessions WHERE tenant = $1")
            .bind(tenant_id)
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok((config.rows_affected() + flows.rows_affected() + sessions.rows_affected()) as usize)
    }
}
