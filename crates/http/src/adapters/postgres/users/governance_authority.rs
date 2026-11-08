//! Canonical identity mutations used only inside the governance transaction.

use super::{db_error, PostgresUsersStore};
use crate::{
    governance::{classify_user_erasure_fence_transition, UserErasureFenceTransition},
    ports::{StoreError, UserRecord, UserStatus},
};
use sqlx::{Postgres, Transaction};

impl PostgresUsersStore {
    pub(crate) async fn governance_identity_locked(
        transaction: &mut Transaction<'_, Postgres>,
        tenant: &str,
        user_id: &str,
    ) -> Result<Option<UserRecord>, StoreError> {
        Ok(Self::lock_user(transaction, tenant, user_id)
            .await?
            .map(|user| user.record))
    }

    pub(crate) async fn governance_fence_identity(
        transaction: &mut Transaction<'_, Postgres>,
        tenant: &str,
        user_id: &str,
        target_epoch: u64,
        now: i64,
    ) -> Result<Option<UserRecord>, StoreError> {
        let Some(mut user) = Self::lock_user(transaction, tenant, user_id).await? else {
            return Ok(None);
        };
        if classify_user_erasure_fence_transition(
            user.record.status,
            user.record.credential_epoch,
            target_epoch,
        )? != UserErasureFenceTransition::AlreadyFenced
        {
            user.record.status = UserStatus::Tombstoned;
            user.record.credential_epoch = target_epoch;
            user.record.revocation_pending = true;
            user.record.attributes.clear();
            user.record.updated_at = now;
            Self::write_user(transaction, tenant, &user, false).await?;
        }
        Ok(Some(user.record))
    }

    pub(crate) async fn governance_delete_identity(
        transaction: &mut Transaction<'_, Postgres>,
        tenant: &str,
        user_id: &str,
        target_epoch: u64,
    ) -> Result<bool, StoreError> {
        if let Some(user) = Self::lock_user(transaction, tenant, user_id).await? {
            if user.record.status != UserStatus::Tombstoned
                || user.record.credential_epoch != target_epoch
            {
                return Err(StoreError::Permanent(
                    "user identity is not fenced for this erasure epoch".into(),
                ));
            }
            sqlx::query("DELETE FROM a_auth.users WHERE tenant = $1 AND user_id = $2")
                .bind(tenant.as_bytes())
                .bind(user_id.as_bytes())
                .execute(&mut **transaction)
                .await
                .map_err(db_error)?;
        }
        // Historical SCIM POST claims must disappear even on an idempotent retry.
        sqlx::query("DELETE FROM a_auth.scim_create_claims WHERE tenant = $1 AND user_id = $2")
            .bind(tenant.as_bytes())
            .bind(user_id.as_bytes())
            .execute(&mut **transaction)
            .await
            .map_err(db_error)?;
        Ok(true)
    }
}
