use super::{db_error, PostgresStore};
use crate::ports::{PolicyArtifactStore, PolicyVersionStore, StoreError};

impl PolicyVersionStore for PostgresStore {
    async fn get(&self, tenant: &str) -> Result<u64, StoreError> {
        let version: Option<String> = sqlx::query_scalar(
            "SELECT version::TEXT FROM a_auth.policy_versions WHERE tenant = $1",
        )
        .bind(tenant)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        version.map_or(Ok(0), |version| {
            version
                .parse()
                .map_err(|_| StoreError::Permanent("invalid policy version".into()))
        })
    }

    async fn bump(&self, tenant: &str) -> Result<u64, StoreError> {
        let version: Option<String> = sqlx::query_scalar(
            "INSERT INTO a_auth.policy_versions (tenant, version) VALUES ($1, 1) \
             ON CONFLICT (tenant) DO UPDATE SET version = a_auth.policy_versions.version + 1 \
             WHERE a_auth.policy_versions.version < 18446744073709551615 RETURNING version::TEXT",
        )
        .bind(tenant)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        version
            .ok_or_else(|| StoreError::Permanent("policy version exhausted".into()))?
            .parse()
            .map_err(|_| StoreError::Permanent("invalid policy version".into()))
    }

    async fn delete(&self, tenant: &str) -> Result<usize, StoreError> {
        let result = sqlx::query("DELETE FROM a_auth.policy_versions WHERE tenant = $1")
            .bind(tenant)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }
}

impl PolicyArtifactStore for PostgresStore {
    async fn put(
        &self,
        tenant: &str,
        version: u64,
        text: String,
        digest: String,
    ) -> Result<(), StoreError> {
        let result = sqlx::query(
            "INSERT INTO a_auth.policy_artifacts (tenant, version, policy_text, policy_digest) \
             VALUES ($1, $2::NUMERIC, $3, $4) ON CONFLICT (tenant, version) \
             DO UPDATE SET policy_text = a_auth.policy_artifacts.policy_text \
             WHERE a_auth.policy_artifacts.policy_text = EXCLUDED.policy_text \
             AND a_auth.policy_artifacts.policy_digest = EXCLUDED.policy_digest",
        )
        .bind(tenant)
        .bind(version.to_string())
        .bind(text)
        .bind(digest)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::Permanent("policy artifact is immutable".into()));
        }
        Ok(())
    }

    async fn get(
        &self,
        tenant: &str,
        version: u64,
    ) -> Result<Option<(String, String)>, StoreError> {
        sqlx::query_as(
            "SELECT policy_text, policy_digest FROM a_auth.policy_artifacts \
             WHERE tenant = $1 AND version = $2::NUMERIC",
        )
        .bind(tenant)
        .bind(version.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let result = sqlx::query("DELETE FROM a_auth.policy_artifacts WHERE tenant = $1")
            .bind(tenant)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }
}
