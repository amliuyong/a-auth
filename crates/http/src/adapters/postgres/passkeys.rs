use super::{db_error, users::PostgresUsersStore, PostgresStore};
use crate::ports::{PasskeyStore, StoreError};
use agent_auth_authn::passkey::PasskeyCredential;
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};

const COLUMNS: &str = "credential_id, user_id, sign_count, created_at, record";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCredential {
    credential_id: String,
    user_id: String,
    rp_id: String,
    public_key_sec1: Vec<u8>,
    sign_count: u32,
    name: String,
    created_at: i64,
}

fn invalid() -> StoreError {
    StoreError::Permanent("Invalid passkey authority".into())
}

fn encode(credential: &PasskeyCredential) -> Result<String, StoreError> {
    serde_json::to_string(&StoredCredential {
        credential_id: credential.credential_id.clone(),
        user_id: credential.user_id.clone(),
        rp_id: credential.rp_id.clone(),
        public_key_sec1: credential.public_key_sec1.clone(),
        sign_count: credential.sign_count,
        name: credential.name.clone(),
        created_at: credential.created_at,
    })
    .map_err(|_| StoreError::Permanent("Passkey authority encoding failed".into()))
}

fn decode(row: PgRow) -> Result<PasskeyCredential, StoreError> {
    let payload: String = row.try_get("record").map_err(db_error)?;
    let stored: StoredCredential = serde_json::from_str(&payload).map_err(|_| invalid())?;
    let id: Vec<u8> = row.try_get("credential_id").map_err(db_error)?;
    let user: Vec<u8> = row.try_get("user_id").map_err(db_error)?;
    let count: i64 = row.try_get("sign_count").map_err(db_error)?;
    let created: i64 = row.try_get("created_at").map_err(db_error)?;
    if id != stored.credential_id.as_bytes()
        || user != stored.user_id.as_bytes()
        || count != i64::from(stored.sign_count)
        || created != stored.created_at
    {
        return Err(invalid());
    }
    Ok(PasskeyCredential {
        credential_id: stored.credential_id,
        user_id: stored.user_id,
        rp_id: stored.rp_id,
        public_key_sec1: stored.public_key_sec1,
        sign_count: stored.sign_count,
        name: stored.name,
        created_at: stored.created_at,
    })
}

pub(super) async fn get_locked(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &str,
    id: &str,
) -> Result<Option<PasskeyCredential>, StoreError> {
    sqlx::query(&format!(
        "SELECT {COLUMNS} FROM a_auth.passkey_credentials \
         WHERE tenant = $1 AND credential_id = $2 FOR UPDATE"
    ))
    .bind(tenant.as_bytes())
    .bind(id.as_bytes())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(db_error)?
    .map(decode)
    .transpose()
}

async fn update(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &str,
    credential: &PasskeyCredential,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE a_auth.passkey_credentials SET sign_count = $3, record = $4 \
         WHERE tenant = $1 AND credential_id = $2",
    )
    .bind(tenant.as_bytes())
    .bind(credential.credential_id.as_bytes())
    .bind(i64::from(credential.sign_count))
    .bind(encode(credential)?)
    .execute(&mut **transaction)
    .await
    .map_err(db_error)?;
    Ok(())
}

pub(super) async fn insert(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &str,
    credential: &PasskeyCredential,
) -> Result<bool, StoreError> {
    let result = sqlx::query(
        "INSERT INTO a_auth.passkey_credentials \
         (tenant, credential_id, user_id, sign_count, created_at, record) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (tenant, credential_id) DO NOTHING",
    )
    .bind(tenant.as_bytes())
    .bind(credential.credential_id.as_bytes())
    .bind(credential.user_id.as_bytes())
    .bind(i64::from(credential.sign_count))
    .bind(credential.created_at)
    .bind(encode(credential)?)
    .execute(&mut **transaction)
    .await
    .map_err(db_error)?;
    Ok(result.rows_affected() == 1)
}

impl PasskeyStore for PostgresStore {
    async fn put_new(
        &self,
        tenant: &str,
        credential: PasskeyCredential,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        if get_locked(&mut transaction, tenant, &credential.credential_id)
            .await?
            .is_some()
        {
            return Ok(false);
        }
        let inserted = insert(&mut transaction, tenant, &credential).await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(inserted)
    }

    async fn get(
        &self,
        tenant: &str,
        credential_id: &str,
    ) -> Result<Option<PasskeyCredential>, StoreError> {
        sqlx::query(&format!(
            "SELECT {COLUMNS} FROM a_auth.passkey_credentials \
             WHERE tenant = $1 AND credential_id = $2"
        ))
        .bind(tenant.as_bytes())
        .bind(credential_id.as_bytes())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?
        .map(decode)
        .transpose()
    }

    async fn list_by_user(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<Vec<PasskeyCredential>, StoreError> {
        sqlx::query(&format!(
            "SELECT {COLUMNS} FROM a_auth.passkey_credentials \
             WHERE tenant = $1 AND user_id = $2 ORDER BY credential_id"
        ))
        .bind(tenant.as_bytes())
        .bind(user_id.as_bytes())
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?
        .into_iter()
        .map(decode)
        .collect()
    }

    async fn update_sign_count(
        &self,
        tenant: &str,
        credential_id: &str,
        new_count: u32,
        expected_prev: u32,
    ) -> Result<bool, StoreError> {
        if !agent_auth_authn::passkey::permits_sign_count_update(expected_prev, new_count) {
            return Ok(false);
        }
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let Some(mut credential) = get_locked(&mut transaction, tenant, credential_id).await?
        else {
            return Ok(false);
        };
        if credential.sign_count != expected_prev {
            return Ok(false);
        }
        credential.sign_count = new_count;
        update(&mut transaction, tenant, &credential).await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(true)
    }

    async fn rename_owned(
        &self,
        tenant: &str,
        user_id: &str,
        credential_id: &str,
        name: &str,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let Some(mut credential) = get_locked(&mut transaction, tenant, credential_id).await?
        else {
            return Ok(false);
        };
        if credential.user_id != user_id {
            return Ok(false);
        }
        credential.name = name.to_string();
        update(&mut transaction, tenant, &credential).await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(true)
    }

    async fn delete_owned(
        &self,
        tenant: &str,
        user_id: &str,
        credential_id: &str,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let Some(credential) = get_locked(&mut transaction, tenant, credential_id).await? else {
            return Ok(false);
        };
        if credential.user_id != user_id {
            return Ok(false);
        }
        sqlx::query(
            "DELETE FROM a_auth.passkey_credentials WHERE tenant = $1 AND credential_id = $2",
        )
        .bind(tenant.as_bytes())
        .bind(credential_id.as_bytes())
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(true)
    }

    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let deleted = sqlx::query(
            "DELETE FROM a_auth.passkey_credentials WHERE tenant = $1 AND user_id = $2",
        )
        .bind(tenant.as_bytes())
        .bind(user_id.as_bytes())
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        let count = usize::try_from(deleted.rows_affected()).map_err(|_| invalid())?;
        transaction.commit().await.map_err(db_error)?;
        Ok(count)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let deleted = sqlx::query("DELETE FROM a_auth.passkey_credentials WHERE tenant = $1")
            .bind(tenant.as_bytes())
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
        let count = usize::try_from(deleted.rows_affected()).map_err(|_| invalid())?;
        transaction.commit().await.map_err(db_error)?;
        Ok(count)
    }
}
