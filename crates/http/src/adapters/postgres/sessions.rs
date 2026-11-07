use super::{db_error, users::PostgresUsersStore, PostgresStore};
use crate::ports::{SessionRecord, SessionStore, StoreError};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};

mod record;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSession {
    #[serde(with = "record")]
    record: SessionRecord,
    generation: u64,
}

const COLUMNS: &str = "s.session_id, s.user_id, s.credential_epoch::TEXT AS credential_epoch, \
    s.session_generation::TEXT AS session_generation, s.expires_at, s.last_used_at, s.record";

fn invalid() -> StoreError {
    StoreError::Permanent("Invalid login session authority".into())
}

fn decode(row: PgRow) -> Result<StoredSession, StoreError> {
    let payload: String = row.try_get("record").map_err(db_error)?;
    let stored: StoredSession = serde_json::from_str(&payload).map_err(|_| invalid())?;
    let id: Vec<u8> = row.try_get("session_id").map_err(db_error)?;
    let user: Vec<u8> = row.try_get("user_id").map_err(db_error)?;
    let epoch: String = row.try_get("credential_epoch").map_err(db_error)?;
    let generation: String = row.try_get("session_generation").map_err(db_error)?;
    let expiry: i64 = row.try_get("expires_at").map_err(db_error)?;
    let last_used: i64 = row.try_get("last_used_at").map_err(db_error)?;
    if id != stored.record.session_id.as_bytes()
        || user != stored.record.user_id.as_bytes()
        || epoch.parse::<u64>().map_err(|_| invalid())? != stored.record.credential_epoch
        || generation.parse::<u64>().map_err(|_| invalid())? != stored.generation
        || expiry != stored.record.expires_at
        || last_used != stored.record.last_used_at
    {
        return Err(invalid());
    }
    Ok(stored)
}

async fn lock_generation(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &str,
    user: &str,
) -> Result<u64, StoreError> {
    sqlx::query(
        "INSERT INTO a_auth.login_session_generations (tenant, user_id, generation) \
         VALUES ($1, $2, 0) ON CONFLICT (tenant, user_id) DO NOTHING",
    )
    .bind(tenant.as_bytes())
    .bind(user.as_bytes())
    .execute(&mut **transaction)
    .await
    .map_err(db_error)?;
    let value: String = sqlx::query_scalar(
        "SELECT generation::TEXT FROM a_auth.login_session_generations \
         WHERE tenant = $1 AND user_id = $2 FOR UPDATE",
    )
    .bind(tenant.as_bytes())
    .bind(user.as_bytes())
    .fetch_one(&mut **transaction)
    .await
    .map_err(db_error)?;
    value.parse().map_err(|_| invalid())
}

async fn get_locked(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &str,
    id: &str,
) -> Result<Option<StoredSession>, StoreError> {
    sqlx::query(&format!(
        "SELECT {COLUMNS} FROM a_auth.login_sessions s \
         WHERE s.tenant = $1 AND s.session_id = $2 FOR UPDATE"
    ))
    .bind(tenant.as_bytes())
    .bind(id.as_bytes())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(db_error)?
    .map(decode)
    .transpose()
}

async fn write(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &str,
    stored: &StoredSession,
    create: bool,
) -> Result<(), StoreError> {
    let statement = if create {
        "INSERT INTO a_auth.login_sessions \
         (tenant, session_id, user_id, credential_epoch, session_generation, \
          expires_at, last_used_at, record) \
         VALUES ($1, $2, $3, $4::TEXT::NUMERIC, $5::TEXT::NUMERIC, $6, $7, $8)"
    } else {
        "UPDATE a_auth.login_sessions SET user_id = $3, \
         credential_epoch = $4::TEXT::NUMERIC, session_generation = $5::TEXT::NUMERIC, \
         expires_at = $6, last_used_at = $7, record = $8 \
         WHERE tenant = $1 AND session_id = $2"
    };
    let payload = serde_json::to_string(stored)
        .map_err(|_| StoreError::Permanent("Login session encoding failed".into()))?;
    let result = sqlx::query(statement)
        .bind(tenant.as_bytes())
        .bind(stored.record.session_id.as_bytes())
        .bind(stored.record.user_id.as_bytes())
        .bind(stored.record.credential_epoch.to_string())
        .bind(stored.generation.to_string())
        .bind(stored.record.expires_at)
        .bind(stored.record.last_used_at)
        .bind(payload)
        .execute(&mut **transaction)
        .await
        .map_err(db_error)?;
    if result.rows_affected() != 1 {
        return Err(StoreError::Transient(
            "Login session authority changed".into(),
        ));
    }
    Ok(())
}

fn next_generation(current: u64) -> Result<u64, StoreError> {
    current
        .checked_add(1)
        .ok_or_else(|| StoreError::Permanent("Login session generation exhausted".into()))
}

async fn set_generation(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &str,
    user: &str,
    generation: u64,
) -> Result<(), StoreError> {
    let result = sqlx::query(
        "UPDATE a_auth.login_session_generations SET generation = $3::TEXT::NUMERIC \
         WHERE tenant = $1 AND user_id = $2",
    )
    .bind(tenant.as_bytes())
    .bind(user.as_bytes())
    .bind(generation.to_string())
    .execute(&mut **transaction)
    .await
    .map_err(db_error)?;
    if result.rows_affected() != 1 {
        return Err(StoreError::Transient(
            "Login session generation changed".into(),
        ));
    }
    Ok(())
}

pub(super) async fn create_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &str,
    record: SessionRecord,
) -> Result<(), StoreError> {
    let generation = lock_generation(transaction, tenant, &record.user_id).await?;
    write(
        transaction,
        tenant,
        &StoredSession { record, generation },
        true,
    )
    .await
}

impl SessionStore for PostgresStore {
    async fn create(&self, tenant: &str, record: SessionRecord) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        create_in_transaction(&mut transaction, tenant, record).await?;
        transaction.commit().await.map_err(db_error)
    }

    async fn get(
        &self,
        tenant: &str,
        session_id: &str,
    ) -> Result<Option<SessionRecord>, StoreError> {
        sqlx::query(&format!(
            "SELECT {COLUMNS} FROM a_auth.login_sessions s \
             JOIN a_auth.login_session_generations g \
             ON g.tenant = s.tenant AND g.user_id = s.user_id \
             WHERE s.tenant = $1 AND s.session_id = $2 \
             AND s.session_generation = g.generation"
        ))
        .bind(tenant.as_bytes())
        .bind(session_id.as_bytes())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?
        .map(decode)
        .transpose()
        .map(|stored| stored.map(|stored| stored.record))
    }

    async fn delete(&self, tenant: &str, session_id: &str) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        sqlx::query("DELETE FROM a_auth.login_sessions WHERE tenant = $1 AND session_id = $2")
            .bind(tenant.as_bytes())
            .bind(session_id.as_bytes())
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)
    }

    async fn list_by_user(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<Vec<SessionRecord>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {COLUMNS} FROM a_auth.login_sessions s \
             JOIN a_auth.login_session_generations g \
             ON g.tenant = s.tenant AND g.user_id = s.user_id \
             WHERE s.tenant = $1 AND s.user_id = $2 \
             AND s.session_generation = g.generation AND s.expires_at > $3 \
             ORDER BY s.session_id"
        ))
        .bind(tenant.as_bytes())
        .bind(user_id.as_bytes())
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        rows.into_iter()
            .map(|row| Ok(decode(row)?.record))
            .collect()
    }

    async fn delete_owned(
        &self,
        tenant: &str,
        user_id: &str,
        actor_session_id: &str,
        target_session_id: &str,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let generation = lock_generation(&mut transaction, tenant, user_id).await?;
        if !get_locked(&mut transaction, tenant, actor_session_id)
            .await?
            .is_some_and(|stored| {
                stored.record.user_id == user_id && stored.generation == generation
            })
        {
            return Ok(false);
        }
        if !get_locked(&mut transaction, tenant, target_session_id)
            .await?
            .is_some_and(|stored| {
                stored.record.user_id == user_id && stored.generation == generation
            })
        {
            return Ok(false);
        }
        sqlx::query("DELETE FROM a_auth.login_sessions WHERE tenant = $1 AND session_id = $2")
            .bind(tenant.as_bytes())
            .bind(target_session_id.as_bytes())
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(true)
    }

    async fn delete_others_by_user(
        &self,
        tenant: &str,
        user_id: &str,
        retained_session_id: &str,
    ) -> Result<Option<usize>, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let generation = lock_generation(&mut transaction, tenant, user_id).await?;
        let Some(mut retained) = get_locked(&mut transaction, tenant, retained_session_id)
            .await?
            .filter(|stored| stored.record.user_id == user_id && stored.generation == generation)
        else {
            return Ok(Some(0));
        };
        let affected: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM a_auth.login_sessions WHERE tenant = $1 AND user_id = $2 \
             AND session_id <> $3 AND session_generation = $4::TEXT::NUMERIC",
        )
        .bind(tenant.as_bytes())
        .bind(user_id.as_bytes())
        .bind(retained_session_id.as_bytes())
        .bind(generation.to_string())
        .fetch_one(&mut *transaction)
        .await
        .map_err(db_error)?;
        let affected = usize::try_from(affected).map_err(|_| invalid())?;
        retained.generation = next_generation(generation)?;
        set_generation(&mut transaction, tenant, user_id, retained.generation).await?;
        write(&mut transaction, tenant, &retained, false).await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(Some(affected))
    }

    async fn revoke_all_by_actor(
        &self,
        tenant: &str,
        user_id: &str,
        actor_session_id: &str,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let generation = lock_generation(&mut transaction, tenant, user_id).await?;
        if !get_locked(&mut transaction, tenant, actor_session_id)
            .await?
            .is_some_and(|stored| {
                stored.record.user_id == user_id && stored.generation == generation
            })
        {
            return Ok(false);
        }
        set_generation(
            &mut transaction,
            tenant,
            user_id,
            next_generation(generation)?,
        )
        .await?;
        sqlx::query("DELETE FROM a_auth.login_sessions WHERE tenant = $1 AND session_id = $2")
            .bind(tenant.as_bytes())
            .bind(actor_session_id.as_bytes())
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(true)
    }

    async fn touch_last_used(
        &self,
        tenant: &str,
        session_id: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let Some(mut stored) = get_locked(&mut transaction, tenant, session_id).await? else {
            return Ok(false);
        };
        let generation = lock_generation(&mut transaction, tenant, &stored.record.user_id).await?;
        if stored.generation != generation {
            return Ok(false);
        }
        if now > stored.record.last_used_at {
            stored.record.last_used_at = now;
            write(&mut transaction, tenant, &stored, false).await?;
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(true)
    }

    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let result =
            sqlx::query("DELETE FROM a_auth.login_sessions WHERE tenant = $1 AND user_id = $2")
                .bind(tenant.as_bytes())
                .bind(user_id.as_bytes())
                .execute(&mut *transaction)
                .await
                .map_err(db_error)?;
        let count = usize::try_from(result.rows_affected()).map_err(|_| invalid())?;
        transaction.commit().await.map_err(db_error)?;
        Ok(count)
    }

    async fn delete_by_user_before_epoch(
        &self,
        tenant: &str,
        user_id: &str,
        epoch: u64,
    ) -> Result<usize, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let result = sqlx::query(
            "DELETE FROM a_auth.login_sessions WHERE tenant = $1 AND user_id = $2 \
             AND credential_epoch < $3::TEXT::NUMERIC",
        )
        .bind(tenant.as_bytes())
        .bind(user_id.as_bytes())
        .bind(epoch.to_string())
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        let count = usize::try_from(result.rows_affected()).map_err(|_| invalid())?;
        transaction.commit().await.map_err(db_error)?;
        Ok(count)
    }

    async fn count_by_user(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<usize, StoreError> {
        Ok(self.list_by_user(tenant, user_id, now).await?.len())
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let sessions = sqlx::query("DELETE FROM a_auth.login_sessions WHERE tenant = $1")
            .bind(tenant.as_bytes())
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
        let generations =
            sqlx::query("DELETE FROM a_auth.login_session_generations WHERE tenant = $1")
                .bind(tenant.as_bytes())
                .execute(&mut *transaction)
                .await
                .map_err(db_error)?;
        let count = sessions
            .rows_affected()
            .checked_add(generations.rows_affected())
            .ok_or_else(invalid)?;
        let count = usize::try_from(count).map_err(|_| invalid())?;
        transaction.commit().await.map_err(db_error)?;
        Ok(count)
    }
}
