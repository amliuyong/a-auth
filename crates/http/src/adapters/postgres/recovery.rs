use super::{db_error, users::PostgresUsersStore, PostgresStore};
use crate::{
    ports::{RecoveryConsume, RecoveryRecord, RecoveryStore, RecoverySuccessResult, StoreError},
    recovery_state::consume_recovery_record,
};
use sqlx::{Postgres, Transaction};

mod record;

pub(super) async fn get_locked(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &str,
    lookup: &str,
) -> Result<Option<RecoveryRecord>, StoreError> {
    sqlx::query(
        "SELECT user_lookup, user_id, activation_id, record FROM a_auth.recovery_codes \
         WHERE tenant = $1 AND user_lookup = $2 FOR UPDATE",
    )
    .bind(tenant.as_bytes())
    .bind(lookup.as_bytes())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(db_error)?
    .map(record::decode)
    .transpose()
}

pub(super) async fn write(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &str,
    record: &RecoveryRecord,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO a_auth.recovery_codes (tenant, user_lookup, user_id, activation_id, record) \
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant, user_lookup) DO UPDATE \
         SET user_id = EXCLUDED.user_id, activation_id = EXCLUDED.activation_id, \
             record = EXCLUDED.record",
    )
    .bind(tenant.as_bytes())
    .bind(record.user_lookup.as_bytes())
    .bind(record.user_id.as_bytes())
    .bind(record.activation_id.as_bytes())
    .bind(record::encode(record)?)
    .execute(&mut **transaction)
    .await
    .map_err(db_error)?;
    Ok(())
}

pub(super) async fn get_result_locked(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &str,
    operation_key: &str,
) -> Result<Option<RecoverySuccessResult>, StoreError> {
    sqlx::query(
        "SELECT operation_key, user_lookup, user_id, credential_epoch::TEXT AS credential_epoch, \
         session_id, created_at, expires_at, record FROM a_auth.recovery_success_results \
         WHERE tenant = $1 AND operation_key = $2 FOR UPDATE",
    )
    .bind(tenant.as_bytes())
    .bind(operation_key.as_bytes())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(db_error)?
    .map(record::decode_result)
    .transpose()
}

pub(super) async fn write_result(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &str,
    result: &RecoverySuccessResult,
) -> Result<(), StoreError> {
    let inserted = sqlx::query(
        "INSERT INTO a_auth.recovery_success_results \
         (tenant, operation_key, user_lookup, user_id, credential_epoch, session_id, \
          created_at, expires_at, record) \
         VALUES ($1, $2, $3, $4, $5::TEXT::NUMERIC, $6, $7, $8, $9) \
         ON CONFLICT (tenant, operation_key) DO NOTHING",
    )
    .bind(tenant.as_bytes())
    .bind(result.operation_key.as_bytes())
    .bind(result.user_lookup.as_bytes())
    .bind(result.user_id.as_bytes())
    .bind(result.credential_epoch.to_string())
    .bind(result.session_id.as_bytes())
    .bind(result.created_at)
    .bind(result.expires_at)
    .bind(record::encode_result(result)?)
    .execute(&mut **transaction)
    .await
    .map_err(db_error)?;
    if inserted.rows_affected() != 1 {
        return Err(StoreError::Transient(
            "Recovery operation already exists".into(),
        ));
    }
    Ok(())
}

impl RecoveryStore for PostgresStore {
    async fn put(&self, tenant: &str, record: RecoveryRecord) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        get_locked(&mut transaction, tenant, &record.user_lookup).await?;
        write(&mut transaction, tenant, &record).await?;
        transaction.commit().await.map_err(db_error)
    }

    async fn get(
        &self,
        tenant: &str,
        user_lookup: &str,
    ) -> Result<Option<RecoveryRecord>, StoreError> {
        sqlx::query(
            "SELECT user_lookup, user_id, activation_id, record FROM a_auth.recovery_codes \
             WHERE tenant = $1 AND user_lookup = $2",
        )
        .bind(tenant.as_bytes())
        .bind(user_lookup.as_bytes())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?
        .map(record::decode)
        .transpose()
    }

    async fn get_success_result(
        &self,
        tenant: &str,
        operation_key: &str,
    ) -> Result<Option<RecoverySuccessResult>, StoreError> {
        sqlx::query(
            "SELECT operation_key, user_lookup, user_id, credential_epoch::TEXT AS credential_epoch, \
             session_id, created_at, expires_at, record FROM a_auth.recovery_success_results \
             WHERE tenant = $1 AND operation_key = $2",
        )
        .bind(tenant.as_bytes())
        .bind(operation_key.as_bytes())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?
        .map(record::decode_result)
        .transpose()
    }

    async fn verify_and_consume(
        &self,
        tenant: &str,
        user_lookup: &str,
        presented_hash: &str,
        now: i64,
    ) -> Result<RecoveryConsume, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let Some(mut record) = get_locked(&mut transaction, tenant, user_lookup).await? else {
            return Ok(RecoveryConsume::NotFound);
        };
        let before = record.clone();
        let outcome = consume_recovery_record(&mut record, presented_hash, now);
        if record != before {
            write(&mut transaction, tenant, &record).await?;
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(outcome)
    }

    async fn delete_by_lookup(&self, tenant: &str, user_lookup: &str) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        sqlx::query("DELETE FROM a_auth.recovery_codes WHERE tenant = $1 AND user_lookup = $2")
            .bind(tenant.as_bytes())
            .bind(user_lookup.as_bytes())
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let records = sqlx::query("DELETE FROM a_auth.recovery_codes WHERE tenant = $1")
            .bind(tenant.as_bytes())
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
        let results = sqlx::query("DELETE FROM a_auth.recovery_success_results WHERE tenant = $1")
            .bind(tenant.as_bytes())
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
        let count = records
            .rows_affected()
            .checked_add(results.rows_affected())
            .and_then(|count| usize::try_from(count).ok())
            .ok_or_else(|| StoreError::Permanent("Recovery cleanup count exhausted".into()))?;
        transaction.commit().await.map_err(db_error)?;
        Ok(count)
    }
}
