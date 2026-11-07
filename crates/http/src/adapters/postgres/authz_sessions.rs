use super::{db_error, PostgresStore};
use crate::ports::{AuthzSessionRecord, AuthzSessionStore, StoreError};
use agent_auth_authn::authz_session::AuthzState;
use sqlx::{types::Json, Postgres, Transaction};

impl PostgresStore {
    pub(super) async fn lock_authz_session(
        transaction: &mut Transaction<'_, Postgres>,
        tenant: &str,
        session_id: &str,
    ) -> Result<Option<AuthzSessionRecord>, StoreError> {
        let record: Option<Json<AuthzSessionRecord>> = sqlx::query_scalar(
            "SELECT record FROM a_auth.authz_sessions WHERE tenant = $1 AND session_id = $2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(session_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(db_error)?;
        Ok(record.map(|Json(record)| record))
    }

    pub(super) async fn persist_authz_session(
        transaction: &mut Transaction<'_, Postgres>,
        tenant: &str,
        record: &AuthzSessionRecord,
    ) -> Result<(), StoreError> {
        let result = sqlx::query(
            "UPDATE a_auth.authz_sessions SET user_id = $3, record = $4 \
             WHERE tenant = $1 AND session_id = $2",
        )
        .bind(tenant)
        .bind(&record.session_id)
        .bind(&record.user_id)
        .bind(Json(record))
        .execute(&mut **transaction)
        .await
        .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::Transient(
                "authorization session disappeared".into(),
            ));
        }
        Ok(())
    }
}

impl AuthzSessionStore for PostgresStore {
    async fn create(&self, tenant: &str, record: AuthzSessionRecord) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO a_auth.authz_sessions (tenant, session_id, client_id, user_id, expires_at, record) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (tenant, session_id) \
             DO UPDATE SET client_id = EXCLUDED.client_id, user_id = EXCLUDED.user_id, \
             expires_at = EXCLUDED.expires_at, record = EXCLUDED.record",
        )
        .bind(tenant)
        .bind(&record.session_id)
        .bind(&record.client_id)
        .bind(&record.user_id)
        .bind(record.expires_at)
        .bind(Json(&record))
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn get(
        &self,
        tenant: &str,
        session_id: &str,
    ) -> Result<Option<AuthzSessionRecord>, StoreError> {
        let record: Option<Json<AuthzSessionRecord>> = sqlx::query_scalar(
            "SELECT record FROM a_auth.authz_sessions WHERE tenant = $1 AND session_id = $2",
        )
        .bind(tenant)
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(record.map(|Json(record)| record))
    }

    async fn transition(
        &self,
        tenant: &str,
        session_id: &str,
        new_state: &str,
        last_error: Option<String>,
        now: i64,
    ) -> Result<Option<AuthzSessionRecord>, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let Some(mut record) =
            Self::lock_authz_session(&mut transaction, tenant, session_id).await?
        else {
            return Ok(None);
        };
        if record.expires_at <= now {
            return Ok(None);
        }
        let (Some(from), Some(to)) = (
            AuthzState::parse(&record.state),
            AuthzState::parse(new_state),
        ) else {
            return Ok(None);
        };
        if !from.can_transition_to(to) {
            return Ok(None);
        }
        record.sequence = record.sequence.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("authorization session sequence exhausted".into())
        })?;
        record.state = new_state.into();
        if last_error.is_some() {
            record.last_error = last_error;
        }
        Self::persist_authz_session(&mut transaction, tenant, &record).await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(Some(record))
    }

    async fn bind_user(
        &self,
        tenant: &str,
        session_id: &str,
        user_id: &str,
        now: i64,
    ) -> Result<Option<AuthzSessionRecord>, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let Some(mut record) =
            Self::lock_authz_session(&mut transaction, tenant, session_id).await?
        else {
            return Ok(None);
        };
        if record.expires_at <= now
            || record
                .user_id
                .as_deref()
                .is_some_and(|bound| bound != user_id)
        {
            return Ok(None);
        }
        if record.user_id.is_none() {
            record.user_id = Some(user_id.into());
            Self::persist_authz_session(&mut transaction, tenant, &record).await?;
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(Some(record))
    }

    async fn delete(&self, tenant: &str, session_id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM a_auth.authz_sessions WHERE tenant = $1 AND session_id = $2")
            .bind(tenant)
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn list_by_client(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> Result<Vec<String>, StoreError> {
        sqlx::query_scalar(
            "SELECT session_id FROM a_auth.authz_sessions WHERE tenant = $1 AND client_id = $2 ORDER BY session_id",
        )
        .bind(tenant)
        .bind(client_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)
    }

    async fn count_active(&self, tenant: &str, now: i64) -> Result<usize, StoreError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM a_auth.authz_sessions WHERE tenant = $1 AND expires_at > $2 \
             AND record->>'state' IN ('created', 'pending_user_authentication', 'pending_consent', 'code_issued_awaiting_exchange')",
        )
        .bind(tenant)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(count as usize)
    }

    async fn delete_by_client(&self, tenant: &str, client_id: &str) -> Result<usize, StoreError> {
        let result =
            sqlx::query("DELETE FROM a_auth.authz_sessions WHERE tenant = $1 AND client_id = $2")
                .bind(tenant)
                .bind(client_id)
                .execute(&self.pool)
                .await
                .map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let result = sqlx::query("DELETE FROM a_auth.authz_sessions WHERE tenant = $1")
            .bind(tenant)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }
}
