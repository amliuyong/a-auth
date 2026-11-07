use super::{db_error, record::LockedUser, PostgresStore, PostgresUsersStore};
use crate::ports::{
    CredentialChangeOwner, FencedPasswordMutation, PasswordCredential, StoreError, UserStatus,
};

fn owns_fence(user: &LockedUser, owner: CredentialChangeOwner<'_>, allow_disabled: bool) -> bool {
    (user.record.status == UserStatus::Active
        || (allow_disabled && user.record.status == UserStatus::Disabled))
        && user.record.revocation_pending
        && user.record.credential_epoch == owner.epoch
        && user.operation_id.as_deref() == Some(owner.operation_id)
}

fn next_version(version: Option<u64>) -> Result<u64, StoreError> {
    version
        .map(|version| {
            version
                .checked_add(1)
                .ok_or_else(|| StoreError::Permanent("Password version exhausted".into()))
        })
        .transpose()
        .map(|version| version.unwrap_or(1))
}

impl PostgresUsersStore {
    pub(crate) async fn commit_credential_change(
        &self,
        mutation: FencedPasswordMutation<'_>,
        owner: CredentialChangeOwner<'_>,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.base.pool.begin().await.map_err(db_error)?;
        // Follow directory -> user -> credential ordering used by provisioning
        // and identity cleanup, including the absent-credential case.
        Self::lock_directory(&mut transaction, mutation.tenant).await?;
        let Some(mut user) =
            Self::lock_user(&mut transaction, mutation.tenant, mutation.user_id).await?
        else {
            return Ok(false);
        };
        if mutation.credential_epoch != owner.epoch || !owns_fence(&user, owner, false) {
            return Ok(false);
        }
        let existing =
            PostgresStore::lock_password(&mut transaction, mutation.tenant, mutation.user_id)
                .await?;
        match (&existing, mutation.expected_version) {
            (None, None) => {}
            (Some(credential), Some(expected))
                if credential.version == expected
                    && !credential.must_change
                    && !credential.revocation_pending => {}
            _ => return Ok(false),
        }
        let credential = PasswordCredential {
            user_id: mutation.user_id.into(),
            password_hash: mutation.password_hash,
            must_change: false,
            revocation_pending: false,
            credential_change_id: None,
            version: next_version(mutation.expected_version)?,
            updated_at: mutation.updated_at,
        };
        if !PostgresStore::write_password(
            &mut transaction,
            mutation.tenant,
            &credential,
            mutation.expected_version,
        )
        .await?
        {
            return Ok(false);
        }
        user.record.revocation_pending = false;
        user.record.updated_at = mutation.updated_at;
        user.operation_id = None;
        Self::write_user(&mut transaction, mutation.tenant, &user, false).await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(true)
    }

    pub(crate) async fn stage_admin_reset(
        &self,
        mutation: FencedPasswordMutation<'_>,
        owner: CredentialChangeOwner<'_>,
    ) -> Result<Option<u64>, StoreError> {
        let mut transaction = self.base.pool.begin().await.map_err(db_error)?;
        Self::lock_directory(&mut transaction, mutation.tenant).await?;
        let Some(user) =
            Self::lock_user(&mut transaction, mutation.tenant, mutation.user_id).await?
        else {
            return Ok(None);
        };
        if mutation.credential_epoch != owner.epoch || !owns_fence(&user, owner, true) {
            return Ok(None);
        }
        let existing =
            PostgresStore::lock_password(&mut transaction, mutation.tenant, mutation.user_id)
                .await?;
        match (&existing, mutation.expected_version) {
            (None, None) => {}
            (Some(credential), Some(expected)) if credential.version == expected => {}
            _ => return Ok(None),
        }
        let version = next_version(mutation.expected_version)?;
        let credential = PasswordCredential {
            user_id: mutation.user_id.into(),
            password_hash: mutation.password_hash,
            must_change: true,
            revocation_pending: true,
            credential_change_id: Some(owner.operation_id.into()),
            version,
            updated_at: mutation.updated_at,
        };
        if !PostgresStore::write_password(
            &mut transaction,
            mutation.tenant,
            &credential,
            mutation.expected_version,
        )
        .await?
        {
            return Ok(None);
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(Some(version))
    }

    pub(crate) async fn complete_admin_reset(
        &self,
        tenant: &str,
        user_id: &str,
        expected_version: u64,
        owner: CredentialChangeOwner<'_>,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.base.pool.begin().await.map_err(db_error)?;
        Self::lock_directory(&mut transaction, tenant).await?;
        let Some(mut user) = Self::lock_user(&mut transaction, tenant, user_id).await? else {
            return Ok(false);
        };
        if !owns_fence(&user, owner, true) {
            return Ok(false);
        }
        let Some(mut credential) =
            PostgresStore::lock_password(&mut transaction, tenant, user_id).await?
        else {
            return Ok(false);
        };
        if credential.version != expected_version
            || !credential.must_change
            || !credential.revocation_pending
            || credential.credential_change_id.as_deref() != Some(owner.operation_id)
        {
            return Ok(false);
        }
        credential.revocation_pending = false;
        credential.credential_change_id = None;
        if !PostgresStore::write_password(
            &mut transaction,
            tenant,
            &credential,
            Some(expected_version),
        )
        .await?
        {
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
