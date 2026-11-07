use super::{
    super::{passkeys, sessions},
    db_error, PostgresUsersStore,
};
use crate::ports::{
    CredentialChangeOwner, PasskeyRegistrationOutcome, SessionRecord, StoreError, UserStatus,
};
use agent_auth_authn::passkey::PasskeyCredential;

impl PostgresUsersStore {
    pub(crate) async fn put_passkey_authorized(
        &self,
        tenant: &str,
        session: &SessionRecord,
        credential: PasskeyCredential,
        now: i64,
    ) -> Result<PasskeyRegistrationOutcome, StoreError> {
        let now = crate::current_unix_secs().max(now);
        if credential.user_id != session.user_id
            || !crate::account_credentials::session_is_reauthenticated(session, now)
            || session.expires_at <= now
        {
            return Ok(PasskeyRegistrationOutcome::AuthorityChanged);
        }
        let mut transaction = self.base.pool.begin().await.map_err(db_error)?;
        Self::lock_directory(&mut transaction, tenant).await?;
        let Some(user) = Self::lock_user(&mut transaction, tenant, &session.user_id).await? else {
            return Ok(PasskeyRegistrationOutcome::AuthorityChanged);
        };
        if user.record.status != UserStatus::Active
            || user.record.revocation_pending
            || user.record.credential_epoch != session.credential_epoch
        {
            return Ok(PasskeyRegistrationOutcome::AuthorityChanged);
        }
        let generation =
            sessions::lock_generation(&mut transaction, tenant, &session.user_id).await?;
        let Some(stored) =
            sessions::get_locked(&mut transaction, tenant, &session.session_id).await?
        else {
            return Ok(PasskeyRegistrationOutcome::AuthorityChanged);
        };
        let now = crate::current_unix_secs().max(now);
        if stored.record.user_id != session.user_id
            || stored.record.credential_epoch != session.credential_epoch
            || stored.record.expires_at <= now
            || !crate::account_credentials::session_is_reauthenticated(&stored.record, now)
            || stored.generation != generation
            || session.expires_at <= now
            || !crate::account_credentials::session_is_reauthenticated(session, now)
        {
            return Ok(PasskeyRegistrationOutcome::AuthorityChanged);
        }
        if passkeys::get_locked(&mut transaction, tenant, &credential.credential_id)
            .await?
            .is_some()
        {
            return Ok(PasskeyRegistrationOutcome::CredentialExists);
        }
        if !passkeys::insert(&mut transaction, tenant, &credential).await? {
            return Ok(PasskeyRegistrationOutcome::CredentialExists);
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(PasskeyRegistrationOutcome::Created)
    }

    pub(crate) async fn delete_passkey_and_complete(
        &self,
        tenant: &str,
        user_id: &str,
        credential_id: &str,
        owner: CredentialChangeOwner<'_>,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.base.pool.begin().await.map_err(db_error)?;
        Self::lock_directory(&mut transaction, tenant).await?;
        let Some(mut user) = Self::lock_user(&mut transaction, tenant, user_id).await? else {
            return Ok(false);
        };
        if user.record.status != UserStatus::Active
            || !user.record.revocation_pending
            || user.record.credential_epoch != owner.epoch
            || user.operation_id.as_deref() != Some(owner.operation_id)
        {
            return Ok(false);
        }
        if passkeys::get_locked(&mut transaction, tenant, credential_id)
            .await?
            .is_none_or(|credential| credential.user_id != user_id)
        {
            return Ok(false);
        }
        let removed = sqlx::query(
            "DELETE FROM a_auth.passkey_credentials \
             WHERE tenant = $1 AND credential_id = $2 AND user_id = $3",
        )
        .bind(tenant.as_bytes())
        .bind(credential_id.as_bytes())
        .bind(user_id.as_bytes())
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        if removed.rows_affected() != 1 {
            return Ok(false);
        }
        user.record.revocation_pending = false;
        user.record.updated_at = updated_at;
        user.operation_id = None;
        Self::write_user(&mut transaction, tenant, &user, false).await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(true)
    }
}
