use super::{db_error, PostgresStore};
use crate::{
    credential::{CredentialKind, CredentialSet},
    ports::{ClientRecord, ClientStore, StoreError},
};
use sqlx::{types::Json, Postgres, Row, Transaction};

fn validate_client(record: &ClientRecord) -> Result<(), StoreError> {
    if record.client_secret.is_some() || record.reg_token_hash.is_some() {
        return Err(StoreError::Permanent(
            "new PostgreSQL clients require versioned credential verifiers".into(),
        ));
    }
    Ok(())
}

fn decode_client(value: serde_json::Value, expected_id: &str) -> Result<ClientRecord, StoreError> {
    let invalid = || StoreError::Permanent("Invalid PostgreSQL client authority".into());
    let record: ClientRecord = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
    // Nullable authority fields must be present as explicit null, not omitted.
    // Otherwise a missing tombstone deserializes as an active client.
    if record.client_id != expected_id
        || serde_json::to_value(&record).map_err(|_| invalid())? != value
    {
        return Err(invalid());
    }
    validate_client(&record)?;
    Ok(record)
}

impl PostgresStore {
    pub(super) async fn lock_client(
        transaction: &mut Transaction<'_, Postgres>,
        tenant: &str,
        client_id: &str,
    ) -> Result<Option<ClientRecord>, StoreError> {
        let record: Option<Json<serde_json::Value>> = sqlx::query_scalar(
            "SELECT record FROM a_auth.clients WHERE tenant = $1 AND client_id = $2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(client_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(db_error)?;
        record
            .map(|Json(value)| decode_client(value, client_id))
            .transpose()
    }

    pub(super) async fn persist_client(
        transaction: &mut Transaction<'_, Postgres>,
        tenant: &str,
        record: &ClientRecord,
    ) -> Result<(), StoreError> {
        validate_client(record)?;
        let result = sqlx::query(
            "UPDATE a_auth.clients SET record = $3 WHERE tenant = $1 AND client_id = $2",
        )
        .bind(tenant)
        .bind(&record.client_id)
        .bind(Json(record))
        .execute(&mut **transaction)
        .await
        .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::Transient("Client authority changed".into()));
        }
        Ok(())
    }

    /// Called in the same transaction that creates a code/refresh family.
    /// Client reclaim and whole-record updates contend on this exact row.
    pub(super) async fn add_client_authority(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant: &str,
        client_id: &str,
    ) -> Result<(), StoreError> {
        let Some(mut record) = Self::lock_client(transaction, tenant, client_id).await? else {
            return Err(StoreError::Transient(
                "client authority changed or is unavailable".into(),
            ));
        };
        if record.is_tombstoned() {
            return Err(StoreError::Transient(
                "client authority changed or is unavailable".into(),
            ));
        }
        record.authority_revision = record.authority_revision.checked_add(1).ok_or_else(|| {
            StoreError::Transient("client authority changed or is unavailable".into())
        })?;
        Self::persist_client(transaction, tenant, &record).await
    }

    async fn mutate_client(
        &self,
        tenant: &str,
        client_id: &str,
        mutation: impl FnOnce(&mut ClientRecord) -> bool + Send,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let Some(mut record) = Self::lock_client(&mut transaction, tenant, client_id).await? else {
            return Ok(false);
        };
        if !mutation(&mut record) {
            return Ok(false);
        }
        Self::persist_client(&mut transaction, tenant, &record).await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(true)
    }
}

impl ClientStore for PostgresStore {
    async fn get(&self, tenant: &str, client_id: &str) -> Result<Option<ClientRecord>, StoreError> {
        let record: Option<Json<serde_json::Value>> = sqlx::query_scalar(
            "SELECT record FROM a_auth.clients WHERE tenant = $1 AND client_id = $2",
        )
        .bind(tenant)
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        record
            .map(|Json(value)| decode_client(value, client_id))
            .transpose()
    }

    async fn put(&self, tenant: &str, record: ClientRecord) -> Result<(), StoreError> {
        validate_client(&record)?;
        sqlx::query(
            "INSERT INTO a_auth.clients (tenant, client_id, record) VALUES ($1, $2, $3) \
             ON CONFLICT (tenant, client_id) DO UPDATE SET record = EXCLUDED.record",
        )
        .bind(tenant)
        .bind(&record.client_id)
        .bind(Json(&record))
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn put_if_credential_versions(
        &self,
        tenant: &str,
        record: ClientRecord,
        expected_client_secret_version: u64,
        expected_registration_token_version: u64,
    ) -> Result<bool, StoreError> {
        let client_id = record.client_id.clone();
        self.mutate_client(tenant, &client_id, move |stored| {
            if stored.is_tombstoned()
                || stored.client_secret_credentials.version != expected_client_secret_version
                || stored.registration_token_credentials.version
                    != expected_registration_token_version
                || stored.authority_revision != record.authority_revision
                || stored.last_used_day != record.last_used_day
            {
                return false;
            }
            *stored = record;
            true
        })
        .await
    }

    async fn replace_credential_set(
        &self,
        tenant: &str,
        client_id: &str,
        kind: CredentialKind,
        expected_version: u64,
        credentials: CredentialSet,
    ) -> Result<bool, StoreError> {
        self.mutate_client(tenant, client_id, move |record| {
            if record.is_tombstoned() {
                return false;
            }
            let target = match kind {
                CredentialKind::ClientSecret => &mut record.client_secret_credentials,
                CredentialKind::RegistrationAccessToken => {
                    &mut record.registration_token_credentials
                }
                CredentialKind::InitialAccessToken => return false,
            };
            if target.version != expected_version {
                return false;
            }
            *target = credentials;
            true
        })
        .await
    }

    async fn list(&self, tenant: &str) -> Result<Vec<ClientRecord>, StoreError> {
        let records = sqlx::query(
            "SELECT client_id, record FROM a_auth.clients WHERE tenant = $1 ORDER BY client_id",
        )
        .bind(tenant)
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        records
            .into_iter()
            .map(|row| {
                let id: String = row.try_get("client_id").map_err(db_error)?;
                let Json(value) = row.try_get("record").map_err(db_error)?;
                decode_client(value, &id)
            })
            .collect()
    }

    async fn delete(&self, tenant: &str, client_id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM a_auth.clients WHERE tenant = $1 AND client_id = $2")
            .bind(tenant)
            .bind(client_id)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn touch_last_used(
        &self,
        tenant: &str,
        client_id: &str,
        today: i64,
    ) -> Result<(), StoreError> {
        self.mutate_client(tenant, client_id, move |record| {
            if record.last_used_day.is_none_or(|day| day < today) {
                record.last_used_day = Some(today);
                true
            } else {
                false
            }
        })
        .await?;
        Ok(())
    }

    async fn convert_to_tombstone(
        &self,
        tenant: &str,
        client_id: &str,
        tombstoned_at: i64,
        snapshot_day: Option<i64>,
        snapshot_authority_revision: u64,
    ) -> Result<bool, StoreError> {
        self.mutate_client(tenant, client_id, move |record| {
            if record.is_tombstoned()
                || record.last_used_day > snapshot_day
                || record.authority_revision != snapshot_authority_revision
            {
                return false;
            }
            record.tombstoned_at = Some(tombstoned_at);
            true
        })
        .await
    }

    async fn list_reclaim_candidates(
        &self,
        tenant: &str,
        older_than_day: i64,
    ) -> Result<Vec<(String, ClientRecord)>, StoreError> {
        let records = sqlx::query(
            "SELECT tenant, client_id, record FROM a_auth.clients WHERE ($1 = '' OR tenant = $1) \
             AND (record->>'last_used_day')::BIGINT <= $2 ORDER BY tenant, client_id",
        )
        .bind(tenant)
        .bind(older_than_day)
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        records
            .into_iter()
            .map(|row| {
                let tenant: String = row.try_get("tenant").map_err(db_error)?;
                let id: String = row.try_get("client_id").map_err(db_error)?;
                let Json(value) = row.try_get("record").map_err(db_error)?;
                Ok((tenant, decode_client(value, &id)?))
            })
            .collect()
    }

    async fn hard_delete_with_audit(
        &self,
        tenant: &str,
        record: &ClientRecord,
        hard_deleted_at: i64,
    ) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        sqlx::query(
            "INSERT INTO a_auth.client_reclaim_audit \
             (tenant, client_id, created_at, tombstoned_at, hard_deleted_at, last_used_day) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (tenant, client_id) DO UPDATE \
             SET created_at = EXCLUDED.created_at, tombstoned_at = EXCLUDED.tombstoned_at, \
                 hard_deleted_at = EXCLUDED.hard_deleted_at, last_used_day = EXCLUDED.last_used_day",
        )
        .bind(tenant)
        .bind(&record.client_id)
        .bind(record.created_at)
        .bind(record.tombstoned_at)
        .bind(hard_deleted_at)
        .bind(record.last_used_day)
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        sqlx::query("DELETE FROM a_auth.clients WHERE tenant = $1 AND client_id = $2")
            .bind(tenant)
            .bind(&record.client_id)
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(())
    }
}
