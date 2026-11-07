use super::{db_error, PostgresStore};
use crate::ports::{MagicLinkRecord, MagicLinkStore, StoreError};
use sqlx::types::Json;

impl MagicLinkStore for PostgresStore {
    async fn put(&self, tenant: &str, link: MagicLinkRecord) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO a_auth.magic_links (tenant, link_id, user_id, session_nonce, expires_at, record) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (tenant, link_id) \
             DO UPDATE SET user_id = EXCLUDED.user_id, session_nonce = EXCLUDED.session_nonce, \
             expires_at = EXCLUDED.expires_at, record = EXCLUDED.record",
        )
        .bind(tenant)
        .bind(&link.link_id)
        .bind(&link.user_id)
        .bind(&link.session_nonce)
        .bind(link.expires_at)
        .bind(Json(&link))
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn get(
        &self,
        tenant: &str,
        link_id: &str,
    ) -> Result<Option<MagicLinkRecord>, StoreError> {
        let record: Option<Json<MagicLinkRecord>> = sqlx::query_scalar(
            "SELECT record FROM a_auth.magic_links WHERE tenant = $1 AND link_id = $2",
        )
        .bind(tenant)
        .bind(link_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(record.map(|Json(record)| record))
    }

    async fn consume_bound(
        &self,
        tenant: &str,
        link_id: &str,
        expected_session_nonce: &str,
    ) -> Result<Option<MagicLinkRecord>, StoreError> {
        let record: Option<Json<MagicLinkRecord>> = sqlx::query_scalar(
            "DELETE FROM a_auth.magic_links WHERE tenant = $1 AND link_id = $2 \
             AND session_nonce = $3 RETURNING record",
        )
        .bind(tenant)
        .bind(link_id)
        .bind(expected_session_nonce)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(record.map(|Json(record)| record))
    }

    async fn last_sent_at(&self, tenant: &str, email: &str) -> Result<Option<i64>, StoreError> {
        sqlx::query_scalar(
            "SELECT last_sent_at FROM a_auth.magic_link_cooldowns WHERE tenant = $1 AND email = $2",
        )
        .bind(tenant)
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)
    }

    async fn mark_sent(&self, tenant: &str, email: &str, now: i64) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO a_auth.magic_link_cooldowns (tenant, email, last_sent_at) VALUES ($1, $2, $3) \
             ON CONFLICT (tenant, email) DO UPDATE SET last_sent_at = EXCLUDED.last_sent_at",
        )
        .bind(tenant)
        .bind(email)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn delete_by_user(
        &self,
        tenant: &str,
        user_id: &str,
        aliases: &[String],
    ) -> Result<usize, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let links =
            sqlx::query("DELETE FROM a_auth.magic_links WHERE tenant = $1 AND user_id = $2")
                .bind(tenant)
                .bind(user_id)
                .execute(&mut *transaction)
                .await
                .map_err(db_error)?;
        sqlx::query(
            "DELETE FROM a_auth.magic_link_cooldowns WHERE tenant = $1 AND email = ANY($2)",
        )
        .bind(tenant)
        .bind(aliases)
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(links.rows_affected() as usize)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let links = sqlx::query("DELETE FROM a_auth.magic_links WHERE tenant = $1")
            .bind(tenant)
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
        let cooldowns = sqlx::query("DELETE FROM a_auth.magic_link_cooldowns WHERE tenant = $1")
            .bind(tenant)
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok((links.rows_affected() + cooldowns.rows_affected()) as usize)
    }
}
