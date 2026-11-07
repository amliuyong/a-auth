use super::{db_error, PostgresStore};
use crate::{
    credential::{CredentialStatus, InitialAccessTokenRecord},
    ports::{InitialAccessTokenStore, StoreError},
};
use sqlx::types::Json;

impl PostgresStore {
    /// Read/decision/write happens under a database row lock in one transaction.
    /// The callback cannot perform I/O or release the lock before the update.
    async fn mutate_initial_access_token(
        &self,
        tenant: &str,
        token_id: &str,
        mutation: impl FnOnce(&mut InitialAccessTokenRecord) -> bool + Send,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let record: Option<Json<InitialAccessTokenRecord>> = sqlx::query_scalar(
            "SELECT record FROM a_auth.initial_access_tokens \
             WHERE tenant = $1 AND token_id = $2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(token_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(db_error)?;
        let Some(Json(mut record)) = record else {
            return Ok(false);
        };
        if !mutation(&mut record) {
            return Ok(false);
        }
        sqlx::query(
            "UPDATE a_auth.initial_access_tokens SET record = $3 \
             WHERE tenant = $1 AND token_id = $2",
        )
        .bind(tenant)
        .bind(token_id)
        .bind(Json(record))
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(true)
    }
}

impl InitialAccessTokenStore for PostgresStore {
    async fn get(
        &self,
        tenant: &str,
        token_id: &str,
    ) -> Result<Option<InitialAccessTokenRecord>, StoreError> {
        let record: Option<Json<InitialAccessTokenRecord>> = sqlx::query_scalar(
            "SELECT record FROM a_auth.initial_access_tokens WHERE tenant = $1 AND token_id = $2",
        )
        .bind(tenant)
        .bind(token_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(record.map(|Json(record)| record))
    }

    async fn put_new(
        &self,
        tenant: &str,
        record: InitialAccessTokenRecord,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "INSERT INTO a_auth.initial_access_tokens (tenant, token_id, record) VALUES ($1, $2, $3) \
             ON CONFLICT (tenant, token_id) DO NOTHING",
        )
        .bind(tenant)
        .bind(&record.token_id)
        .bind(Json(&record))
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn list(&self, tenant: &str) -> Result<Vec<InitialAccessTokenRecord>, StoreError> {
        let records: Vec<Json<InitialAccessTokenRecord>> = sqlx::query_scalar(
            "SELECT record FROM a_auth.initial_access_tokens WHERE tenant = $1 ORDER BY token_id",
        )
        .bind(tenant)
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(records.into_iter().map(|Json(record)| record).collect())
    }

    async fn revoke(
        &self,
        tenant: &str,
        token_id: &str,
        expected_version: u64,
        revoked_at: i64,
    ) -> Result<bool, StoreError> {
        self.mutate_initial_access_token(tenant, token_id, move |record| {
            if record.credential.status == CredentialStatus::Revoked {
                return true;
            }
            if record.version != expected_version {
                return false;
            }
            record.credential.status = CredentialStatus::Revoked;
            record.credential.expires_at = record.credential.expires_at.min(revoked_at);
            record.version = record.version.saturating_add(1);
            true
        })
        .await
    }

    async fn consume_once(
        &self,
        tenant: &str,
        token_id: &str,
        expected_version: u64,
        used_at: i64,
    ) -> Result<bool, StoreError> {
        self.mutate_initial_access_token(tenant, token_id, move |record| {
            if record.version != expected_version
                || !record.one_time
                || record.used_at.is_some()
                || record.credential.status != CredentialStatus::Active
                || record.credential.expires_at <= used_at
            {
                return false;
            }
            record.used_at = Some(used_at);
            record.credential.status = CredentialStatus::Consumed;
            record.version = record.version.saturating_add(1);
            true
        })
        .await
    }

    async fn delete(&self, tenant: &str, token_id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM a_auth.initial_access_tokens WHERE tenant = $1 AND token_id = $2")
            .bind(tenant)
            .bind(token_id)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(())
    }
}
