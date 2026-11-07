use super::{db_error, PostgresStore};
use crate::ports::{AuthzSessionRecord, CodeRecord, CodeStore, LeaseAcquire, StoreError};
use sqlx::{types::Json, Row};

/// Identity and fencing snapshot for one failed authorization-code exchange.
pub struct ExchangeFailureRequest<'a> {
    pub tenant: &'a str,
    pub code: &'a str,
    pub client_id: &'a str,
    pub expires_at: i64,
    pub now: i64,
    pub lease_owner: &'a str,
    pub authz_session_id: Option<&'a str>,
    pub last_error: String,
}

impl PostgresStore {
    /// Consume the code and make its bound session terminal in one transaction.
    /// No projection or network operation is included in the authority commit.
    pub async fn finalize_exchange_failure(
        &self,
        request: ExchangeFailureRequest<'_>,
    ) -> Result<Option<AuthzSessionRecord>, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let row = sqlx::query(
            "SELECT record, consumed, lease_owner FROM a_auth.codes \
             WHERE tenant = $1 AND code = $2 FOR UPDATE",
        )
        .bind(request.tenant)
        .bind(request.code)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(db_error)?;
        let Some(row) = row else {
            return Err(StoreError::Transient(
                "authorization code is unavailable".into(),
            ));
        };
        let Json(code): Json<CodeRecord> = row.try_get("record").map_err(db_error)?;
        if row.try_get::<bool, _>("consumed").map_err(db_error)?
            || row
                .try_get::<Option<String>, _>("lease_owner")
                .map_err(db_error)?
                .as_deref()
                != Some(request.lease_owner)
            || code.client_id != request.client_id
            || code.expires_at != request.expires_at
            || code.expires_at <= request.now
            || code.authz_session_id.as_deref() != request.authz_session_id
        {
            return Err(StoreError::Transient(
                "authorization code identity or lease ownership changed".into(),
            ));
        }
        let current = if let Some(session_id) = request.authz_session_id {
            let current = Self::lock_authz_session(&mut transaction, request.tenant, session_id)
                .await?
                .ok_or_else(|| {
                    StoreError::Transient("authorization session is unavailable".into())
                })?;
            Some(current)
        } else {
            None
        };
        let commit_now = request.now.max(crate::current_unix_secs());
        if code.expires_at <= commit_now
            || current.as_ref().is_some_and(|session| {
                session.expires_at <= commit_now || session.client_id != code.client_id
            })
        {
            return Err(StoreError::Transient(
                "authorization code or session expired or changed".into(),
            ));
        }
        let next = current
            .map(|current| {
                crate::authz_session::prepare_exchange_failure_transition(
                    current,
                    request.last_error,
                )
            })
            .transpose()?;
        sqlx::query(
            "UPDATE a_auth.codes SET consumed = TRUE, lease_owner = NULL, lease_until = NULL, \
             issued_grant_id = NULL WHERE tenant = $1 AND code = $2",
        )
        .bind(request.tenant)
        .bind(request.code)
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        if let Some(next) = &next {
            Self::persist_authz_session(&mut transaction, request.tenant, next).await?;
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(next)
    }
}

impl CodeStore for PostgresStore {
    async fn put(&self, tenant: &str, record: CodeRecord) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let result = sqlx::query(
            "INSERT INTO a_auth.codes (tenant, code, client_id, user_id, expires_at, record) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (tenant, code) DO NOTHING",
        )
        .bind(tenant)
        .bind(&record.code)
        .bind(&record.client_id)
        .bind(&record.user_id)
        .bind(record.expires_at)
        .bind(Json(&record))
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::Transient(
                "authorization code already exists".into(),
            ));
        }
        if record.cimd_snapshot.is_none() {
            Self::add_client_authority(&mut transaction, tenant, &record.client_id).await?;
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn acquire_lease(
        &self,
        tenant: &str,
        code: &str,
        lease_owner: &str,
        now: i64,
        lease_expires_at: i64,
    ) -> Result<LeaseAcquire, StoreError> {
        if lease_owner.is_empty() || lease_expires_at <= now {
            return Err(StoreError::Permanent(
                "invalid authorization code signing lease".into(),
            ));
        }
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let row = sqlx::query(
            "SELECT record, consumed, lease_until, issued_grant_id FROM a_auth.codes \
             WHERE tenant = $1 AND code = $2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(code)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(db_error)?;
        let Some(row) = row else {
            return Ok(LeaseAcquire::NotFound);
        };
        let Json(record): Json<CodeRecord> = row.try_get("record").map_err(db_error)?;
        if record.expires_at <= now {
            return Ok(LeaseAcquire::NotFound);
        }
        if row.try_get::<bool, _>("consumed").map_err(db_error)? {
            return Ok(LeaseAcquire::AlreadyConsumed {
                record,
                issued_grant_id: row.try_get("issued_grant_id").map_err(db_error)?,
            });
        }
        if row
            .try_get::<Option<i64>, _>("lease_until")
            .map_err(db_error)?
            .is_some_and(|until| until > now)
        {
            return Ok(LeaseAcquire::Locked);
        }
        sqlx::query(
            "UPDATE a_auth.codes SET lease_owner = $3, lease_until = $4 WHERE tenant = $1 AND code = $2",
        )
        .bind(tenant)
        .bind(code)
        .bind(lease_owner)
        .bind(lease_expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(LeaseAcquire::Acquired(record))
    }

    async fn finalize(
        &self,
        tenant: &str,
        code: &str,
        client_id: &str,
        expires_at: i64,
        now: i64,
        lease_owner: &str,
        issued_grant_id: Option<&str>,
    ) -> Result<(), StoreError> {
        let result = sqlx::query(
            "UPDATE a_auth.codes SET consumed = TRUE, lease_owner = NULL, lease_until = NULL, \
             issued_grant_id = $7 WHERE tenant = $1 AND code = $2 AND client_id = $3 \
             AND expires_at = $4 AND expires_at > $5 AND lease_owner = $6 AND NOT consumed",
        )
        .bind(tenant)
        .bind(code)
        .bind(client_id)
        .bind(expires_at)
        .bind(now)
        .bind(lease_owner)
        .bind(issued_grant_id)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::Transient(
                "authorization code lease ownership was lost".into(),
            ));
        }
        Ok(())
    }

    async fn release_lease(
        &self,
        tenant: &str,
        code: &str,
        lease_owner: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        let result = sqlx::query(
            "UPDATE a_auth.codes SET lease_owner = NULL, lease_until = NULL \
             WHERE tenant = $1 AND code = $2 AND lease_owner = $3 AND NOT consumed AND expires_at > $4",
        )
        .bind(tenant)
        .bind(code)
        .bind(lease_owner)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::Transient(
                "authorization code lease ownership was lost".into(),
            ));
        }
        Ok(())
    }

    async fn record_replay(&self, tenant: &str, code: &str, now: i64) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE a_auth.codes SET replay_detected = TRUE \
             WHERE tenant = $1 AND code = $2 AND consumed AND expires_at > $3",
        )
        .bind(tenant)
        .bind(code)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn replay_detected(&self, tenant: &str, code: &str) -> Result<bool, StoreError> {
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM a_auth.codes WHERE tenant = $1 AND code = $2 AND replay_detected)",
        )
        .bind(tenant)
        .bind(code)
        .fetch_one(&self.pool)
        .await
        .map_err(db_error)
    }

    async fn has_unexpired_by_client(
        &self,
        tenant: &str,
        client_id: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        // Read the primary authority table, not an eventually consistent index.
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM a_auth.codes \
             WHERE tenant = $1 AND client_id = $2 AND NOT consumed AND expires_at > $3)",
        )
        .bind(tenant)
        .bind(client_id)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(db_error)
    }

    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        let result = sqlx::query("DELETE FROM a_auth.codes WHERE tenant = $1 AND user_id = $2")
            .bind(tenant)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let result = sqlx::query("DELETE FROM a_auth.codes WHERE tenant = $1")
            .bind(tenant)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }
}
