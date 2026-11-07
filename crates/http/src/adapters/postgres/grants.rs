use super::{db_error, PostgresStore};
use crate::ports::{GrantStore, StoreError};
use agent_auth_grant::Grant;
use sqlx::types::Json;

impl PostgresStore {
    pub(crate) async fn put_grant_for_active_client(
        &self,
        tenant: &str,
        grant: Grant,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let Some(mut client) =
            Self::lock_client(&mut transaction, tenant, &grant.client_id).await?
        else {
            return Ok(false);
        };
        let today = crate::current_unix_secs().div_euclid(86_400);
        if client.is_tombstoned() || client.last_used_day.is_some_and(|day| day > today) {
            return Ok(false);
        }
        client.authority_revision = client
            .authority_revision
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("Client authority revision exhausted".into()))?;
        client.last_used_day = Some(today);
        Self::persist_client(&mut transaction, tenant, &client).await?;
        sqlx::query(
            "INSERT INTO a_auth.grants (tenant, grant_id, user_id, client_id, record) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant, grant_id) DO UPDATE \
             SET user_id = EXCLUDED.user_id, client_id = EXCLUDED.client_id, record = EXCLUDED.record",
        )
        .bind(tenant)
        .bind(&grant.grant_id)
        .bind(&grant.user_id)
        .bind(&grant.client_id)
        .bind(Json(&grant))
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(true)
    }
}

impl GrantStore for PostgresStore {
    async fn put(&self, tenant: &str, grant: Grant) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO a_auth.grants (tenant, grant_id, user_id, client_id, record) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant, grant_id) DO UPDATE \
             SET user_id = EXCLUDED.user_id, client_id = EXCLUDED.client_id, record = EXCLUDED.record",
        )
        .bind(tenant)
        .bind(&grant.grant_id)
        .bind(&grant.user_id)
        .bind(&grant.client_id)
        .bind(Json(&grant))
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn get(&self, tenant: &str, grant_id: &str) -> Result<Option<Grant>, StoreError> {
        let record: Option<Json<Grant>> = sqlx::query_scalar(
            "SELECT record FROM a_auth.grants WHERE tenant = $1 AND grant_id = $2",
        )
        .bind(tenant)
        .bind(grant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(record.map(|Json(record)| record))
    }

    async fn list_by_user(&self, tenant: &str, user_id: &str) -> Result<Vec<Grant>, StoreError> {
        let records: Vec<Json<Grant>> = sqlx::query_scalar(
            "SELECT record FROM a_auth.grants WHERE tenant = $1 AND user_id = $2 ORDER BY grant_id",
        )
        .bind(tenant)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(records.into_iter().map(|Json(record)| record).collect())
    }

    async fn revoke(&self, tenant: &str, grant_id: &str) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE a_auth.grants SET record = jsonb_set(jsonb_set(record, '{status}', '\"revoked\"'), \
             '{revision}', to_jsonb(LEAST((record->>'revision')::NUMERIC + 1, 18446744073709551615))) \
             WHERE tenant = $1 AND grant_id = $2",
        )
        .bind(tenant)
        .bind(grant_id)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn revoke_if_epoch_before(
        &self,
        tenant: &str,
        grant_id: &str,
        epoch: u64,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE a_auth.grants SET record = jsonb_set(jsonb_set(record, '{status}', '\"revoked\"'), \
             '{revision}', to_jsonb(LEAST((record->>'revision')::NUMERIC + 1, 18446744073709551615))) \
             WHERE tenant = $1 AND grant_id = $2 \
             AND (record->>'credential_epoch')::NUMERIC < $3::TEXT::NUMERIC",
        )
        .bind(tenant)
        .bind(grant_id)
        .bind(epoch.to_string())
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn revoke_if_revision(
        &self,
        tenant: &str,
        grant_id: &str,
        expected_revision: u64,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE a_auth.grants SET record = jsonb_set(jsonb_set(record, '{status}', '\"revoked\"'), \
             '{revision}', to_jsonb(LEAST((record->>'revision')::NUMERIC + 1, 18446744073709551615))) \
             WHERE tenant = $1 AND grant_id = $2 AND record->>'revision' = $3 \
             AND record->>'status' = 'active'",
        )
        .bind(tenant)
        .bind(grant_id)
        .bind(expected_revision.to_string())
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn put_conditional(
        &self,
        tenant: &str,
        mut grant: Grant,
        expected_revision: u64,
    ) -> Result<bool, StoreError> {
        grant.revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("Grant revision exhausted".into()))?;
        let result = sqlx::query(
            "UPDATE a_auth.grants SET user_id = $3, client_id = $4, record = $5 \
             WHERE tenant = $1 AND grant_id = $2 AND record->>'revision' = $6 \
             AND record->>'status' <> 'revoked'",
        )
        .bind(tenant)
        .bind(&grant.grant_id)
        .bind(&grant.user_id)
        .bind(&grant.client_id)
        .bind(Json(&grant))
        .bind(expected_revision.to_string())
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn list_stale(
        &self,
        tenant: &str,
        current_pv: u64,
    ) -> Result<Vec<(String, Grant)>, StoreError> {
        let records: Vec<(String, Json<Grant>)> = sqlx::query_as(
            "SELECT tenant, record FROM a_auth.grants WHERE ($1 = '' OR tenant = $1) \
             AND record->>'status' = 'active' \
             AND (record->>'effective_pv')::NUMERIC < $2::TEXT::NUMERIC ORDER BY tenant, grant_id",
        )
        .bind(tenant)
        .bind(current_pv.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(records
            .into_iter()
            .map(|(tenant, Json(record))| (tenant, record))
            .collect())
    }

    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        let result = sqlx::query("DELETE FROM a_auth.grants WHERE tenant = $1 AND user_id = $2")
            .bind(tenant)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }

    async fn delete_by_client(&self, tenant: &str, client_id: &str) -> Result<usize, StoreError> {
        let result = sqlx::query("DELETE FROM a_auth.grants WHERE tenant = $1 AND client_id = $2")
            .bind(tenant)
            .bind(client_id)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let result = sqlx::query("DELETE FROM a_auth.grants WHERE tenant = $1")
            .bind(tenant)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }
}
