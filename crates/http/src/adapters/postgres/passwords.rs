use super::{db_error, PostgresStore, PostgresUsersStore};
use crate::ports::{PasswordCredential, PasswordStore, StoreError};
use agent_auth_authn::password::EncodedPasswordHash;
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};

const COLUMNS: &str = "user_id, password_hash, must_change, revocation_pending, \
    credential_change_id, version::TEXT AS version, updated_at";

fn decode(row: PgRow) -> Result<PasswordCredential, StoreError> {
    let encoded: String = row.try_get("password_hash").map_err(db_error)?;
    let password_hash = EncodedPasswordHash::from_storage(encoded)
        .map_err(|_| StoreError::Permanent("Invalid password hash profile".into()))?;
    let version: String = row.try_get("version").map_err(db_error)?;
    let version = version
        .parse()
        .map_err(|_| StoreError::Permanent("Invalid password credential version".into()))?;
    let owner: Option<Vec<u8>> = row.try_get("credential_change_id").map_err(db_error)?;
    let credential_change_id = owner
        .map(String::from_utf8)
        .transpose()
        .map_err(|_| StoreError::Permanent("Invalid password operation identity".into()))?;
    Ok(PasswordCredential {
        user_id: row.try_get("user_id").map_err(db_error)?,
        password_hash,
        must_change: row.try_get("must_change").map_err(db_error)?,
        revocation_pending: row.try_get("revocation_pending").map_err(db_error)?,
        credential_change_id,
        version,
        updated_at: row.try_get("updated_at").map_err(db_error)?,
    })
}

fn next_version(expected: u64) -> Result<u64, StoreError> {
    expected
        .checked_add(1)
        .ok_or_else(|| StoreError::Permanent("Password version exhausted".into()))
}

impl PostgresStore {
    pub(super) async fn lock_password(
        transaction: &mut Transaction<'_, Postgres>,
        tenant: &str,
        user_id: &str,
    ) -> Result<Option<PasswordCredential>, StoreError> {
        sqlx::query(&format!(
            "SELECT {COLUMNS} FROM a_auth.password_credentials \
             WHERE tenant = $1 AND user_id = $2 FOR UPDATE"
        ))
        .bind(tenant)
        .bind(user_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(db_error)?
        .map(decode)
        .transpose()
    }

    pub(super) async fn write_password(
        transaction: &mut Transaction<'_, Postgres>,
        tenant: &str,
        credential: &PasswordCredential,
        expected_version: Option<u64>,
    ) -> Result<bool, StoreError> {
        let statement = if expected_version.is_some() {
            "UPDATE a_auth.password_credentials SET password_hash = $3, \
             must_change = $4, revocation_pending = $5, credential_change_id = $6, \
             version = $7::TEXT::NUMERIC, updated_at = $8 \
             WHERE tenant = $1 AND user_id = $2 AND version = $9::TEXT::NUMERIC"
        } else {
            "INSERT INTO a_auth.password_credentials \
             (tenant, user_id, password_hash, must_change, revocation_pending, \
              credential_change_id, version, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7::TEXT::NUMERIC, $8) \
             ON CONFLICT (tenant, user_id) DO NOTHING"
        };
        let query = sqlx::query(statement)
            .bind(tenant)
            .bind(&credential.user_id)
            .bind(credential.password_hash.expose())
            .bind(credential.must_change)
            .bind(credential.revocation_pending)
            .bind(
                credential
                    .credential_change_id
                    .as_deref()
                    .map(str::as_bytes),
            )
            .bind(credential.version.to_string())
            .bind(credential.updated_at);
        let query = if let Some(version) = expected_version {
            query.bind(version.to_string())
        } else {
            query
        };
        let result = query.execute(&mut **transaction).await.map_err(db_error)?;
        Ok(result.rows_affected() == 1)
    }
}

impl PasswordStore for PostgresStore {
    async fn get(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<Option<PasswordCredential>, StoreError> {
        sqlx::query(&format!(
            "SELECT {COLUMNS} FROM a_auth.password_credentials WHERE tenant = $1 AND user_id = $2"
        ))
        .bind(tenant)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?
        .map(decode)
        .transpose()
    }

    async fn create_if_absent(
        &self,
        tenant: &str,
        credential: PasswordCredential,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let result = sqlx::query(
            "INSERT INTO a_auth.password_credentials \
             (tenant, user_id, password_hash, must_change, revocation_pending, \
              credential_change_id, version, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7::TEXT::NUMERIC, $8) \
             ON CONFLICT (tenant, user_id) DO NOTHING",
        )
        .bind(tenant)
        .bind(&credential.user_id)
        .bind(credential.password_hash.expose())
        .bind(credential.must_change)
        .bind(credential.revocation_pending)
        .bind(
            credential
                .credential_change_id
                .as_deref()
                .map(str::as_bytes),
        )
        .bind(credential.version.to_string())
        .bind(credential.updated_at)
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn delete_if_version(
        &self,
        tenant: &str,
        user_id: &str,
        expected_version: u64,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "DELETE FROM a_auth.password_credentials \
             WHERE tenant = $1 AND user_id = $2 AND version = $3::TEXT::NUMERIC",
        )
        .bind(tenant)
        .bind(user_id)
        .bind(expected_version.to_string())
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn replace_if_version_and_temporary(
        &self,
        tenant: &str,
        user_id: &str,
        new_hash: EncodedPasswordHash,
        expected_version: u64,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        let next = next_version(expected_version)?;
        let result = sqlx::query(
            "UPDATE a_auth.password_credentials SET password_hash = $3, \
             must_change = false, credential_change_id = NULL, \
             version = $4::TEXT::NUMERIC, updated_at = $5 \
             WHERE tenant = $1 AND user_id = $2 AND version = $6::TEXT::NUMERIC \
             AND must_change AND NOT revocation_pending",
        )
        .bind(tenant)
        .bind(user_id)
        .bind(new_hash.expose())
        .bind(next.to_string())
        .bind(updated_at)
        .bind(expected_version.to_string())
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn reset_temporary(
        &self,
        tenant: &str,
        user_id: &str,
        new_hash: EncodedPasswordHash,
        expected_version: Option<u64>,
        updated_at: i64,
    ) -> Result<Option<u64>, StoreError> {
        let next = expected_version.map(next_version).transpose()?.unwrap_or(1);
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let result = match expected_version {
            Some(expected) => sqlx::query(
                "UPDATE a_auth.password_credentials SET password_hash = $3, \
                     must_change = true, revocation_pending = true, credential_change_id = NULL, \
                     version = $4::TEXT::NUMERIC, updated_at = $5 \
                     WHERE tenant = $1 AND user_id = $2 AND version = $6::TEXT::NUMERIC",
            )
            .bind(tenant)
            .bind(user_id)
            .bind(new_hash.expose())
            .bind(next.to_string())
            .bind(updated_at)
            .bind(expected.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?,
            None => sqlx::query(
                "INSERT INTO a_auth.password_credentials \
                     (tenant, user_id, password_hash, must_change, revocation_pending, \
                      version, updated_at) VALUES ($1, $2, $3, true, true, 1, $4) \
                     ON CONFLICT (tenant, user_id) DO NOTHING",
            )
            .bind(tenant)
            .bind(user_id)
            .bind(new_hash.expose())
            .bind(updated_at)
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?,
        };
        transaction.commit().await.map_err(db_error)?;
        Ok((result.rows_affected() == 1).then_some(next))
    }

    async fn complete_reset_revocation(
        &self,
        tenant: &str,
        user_id: &str,
        expected_version: u64,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE a_auth.password_credentials SET revocation_pending = false, \
             credential_change_id = NULL WHERE tenant = $1 AND user_id = $2 \
             AND version = $3::TEXT::NUMERIC AND must_change AND revocation_pending",
        )
        .bind(tenant)
        .bind(user_id)
        .bind(expected_version.to_string())
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn delete(&self, tenant: &str, user_id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM a_auth.password_credentials WHERE tenant = $1 AND user_id = $2")
            .bind(tenant)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let result = sqlx::query("DELETE FROM a_auth.password_credentials WHERE tenant = $1")
            .bind(tenant)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }
}
