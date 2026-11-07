use super::{db_error, PostgresStore};
use crate::ports::{PasskeyCeremony, PasskeyChallenge, PasskeyChallengeStore, StoreError};
use sqlx::Row;

impl PasskeyChallengeStore for PostgresStore {
    async fn put(&self, challenge: PasskeyChallenge) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO a_auth.passkey_challenges \
             (challenge, tenant, user_id, ceremony, rp_id, origin, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (challenge) DO UPDATE \
             SET tenant = EXCLUDED.tenant, user_id = EXCLUDED.user_id, ceremony = EXCLUDED.ceremony, \
             rp_id = EXCLUDED.rp_id, origin = EXCLUDED.origin, expires_at = EXCLUDED.expires_at",
        )
        .bind(challenge.challenge_b64url)
        .bind(challenge.tenant)
        .bind(challenge.user_id)
        .bind(challenge.ceremony.as_str())
        .bind(challenge.rp_id)
        .bind(challenge.origin)
        .bind(challenge.expires_at)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn consume(
        &self,
        tenant: &str,
        challenge_b64url: &str,
    ) -> Result<Option<PasskeyChallenge>, StoreError> {
        // A foreign tenant must not consume the authentic browser's ceremony.
        let row = sqlx::query(
            "DELETE FROM a_auth.passkey_challenges WHERE challenge = $1 AND tenant = $2 \
             RETURNING challenge, tenant, user_id, ceremony, rp_id, origin, expires_at",
        )
        .bind(challenge_b64url)
        .bind(tenant)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        let Some(row) = row else { return Ok(None) };
        let expires_at = row.try_get("expires_at").map_err(db_error)?;
        if expires_at <= crate::current_unix_secs() {
            return Ok(None);
        }
        let ceremony: String = row.try_get("ceremony").map_err(db_error)?;
        let ceremony = PasskeyCeremony::parse(&ceremony)
            .ok_or_else(|| StoreError::Permanent("Invalid passkey ceremony".into()))?;
        Ok(Some(PasskeyChallenge {
            challenge_b64url: row.try_get("challenge").map_err(db_error)?,
            tenant: row.try_get("tenant").map_err(db_error)?,
            user_id: row.try_get("user_id").map_err(db_error)?,
            ceremony,
            rp_id: row.try_get("rp_id").map_err(db_error)?,
            origin: row.try_get("origin").map_err(db_error)?,
            expires_at,
        }))
    }

    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        let result =
            sqlx::query("DELETE FROM a_auth.passkey_challenges WHERE tenant = $1 AND user_id = $2")
                .bind(tenant)
                .bind(user_id)
                .execute(&self.pool)
                .await
                .map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let result = sqlx::query("DELETE FROM a_auth.passkey_challenges WHERE tenant = $1")
            .bind(tenant)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }
}
