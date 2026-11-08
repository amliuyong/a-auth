use super::{
    super::{recovery, sessions},
    db_error, PostgresStore, PostgresUsersStore,
};
use crate::{
    ports::{
        CredentialChangeOwner, RecoveryAuthorityConsume, RecoveryConsume, RecoveryConsumeRequest,
        RecoveryRecord, RecoverySuccessResult, SessionRecord, StoreError, UserStatus,
    },
    recovery_state::consume_recovery_record,
};

fn validate_result(
    request: RecoveryConsumeRequest<'_>,
    session: &SessionRecord,
    result: &RecoverySuccessResult,
    next_epoch: u64,
) -> Result<(), StoreError> {
    if session.user_id != request.user_id
        || session.credential_epoch != next_epoch
        || result.operation_key.is_empty()
        || result.user_lookup != request.user_lookup
        || result.user_id != request.user_id
        || !agent_auth_authn::recovery::hash_eq_b64(&result.presented_hash, request.presented_hash)
        || result.credential_epoch != next_epoch
        || result.session_id != session.session_id
        || result.created_at != session.created_at
        || result.created_at > request.now
        || result.expires_at <= request.now
        || result.expires_at > session.expires_at
    {
        return Err(StoreError::Permanent(
            "Recovery result does not match recovery authority".into(),
        ));
    }
    Ok(())
}

impl PostgresUsersStore {
    pub(crate) async fn commit_recovery_rotation(
        &self,
        tenant: &str,
        record: RecoveryRecord,
        expected_email: &str,
        owner: CredentialChangeOwner<'_>,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.base.pool.begin().await.map_err(db_error)?;
        Self::lock_directory(&mut transaction, tenant).await?;
        let Some(mut user) = Self::lock_user(&mut transaction, tenant, &record.user_id).await?
        else {
            return Ok(false);
        };
        if user.record.status != UserStatus::Active
            || !user.record.revocation_pending
            || user.record.credential_epoch != owner.epoch
            || user.operation_id.as_deref() != Some(owner.operation_id)
            || user.record.email != expected_email
        {
            return Ok(false);
        }
        recovery::get_locked(&mut transaction, tenant, &record.user_lookup).await?;
        recovery::write(&mut transaction, tenant, &record).await?;
        user.record.revocation_pending = false;
        user.record.updated_at = updated_at;
        user.operation_id = None;
        Self::write_user(&mut transaction, tenant, &user, false).await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(true)
    }

    pub(crate) async fn consume_recovery_at_epoch(
        &self,
        request: RecoveryConsumeRequest<'_>,
        session: SessionRecord,
        result: RecoverySuccessResult,
    ) -> Result<RecoveryAuthorityConsume, StoreError> {
        let next_epoch = request
            .expected_epoch
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("User credential epoch exhausted".into()))?;
        validate_result(request, &session, &result, next_epoch)?;
        let mut transaction = self.base.pool.begin().await.map_err(db_error)?;
        Self::lock_directory(&mut transaction, request.tenant).await?;
        let mut user = Self::lock_user(&mut transaction, request.tenant, request.user_id).await?;
        let password =
            PostgresStore::lock_password(&mut transaction, request.tenant, request.user_id).await?;
        let generation =
            sessions::lock_generation(&mut transaction, request.tenant, request.user_id).await?;
        let existing =
            recovery::get_result_locked(&mut transaction, request.tenant, &result.operation_key)
                .await?;
        let password_ready = password
            .as_ref()
            .is_none_or(|credential| !credential.must_change && !credential.revocation_pending);
        // Lease/expiry decisions use the clock after waiting for authority locks.
        let now = crate::current_unix_secs().max(request.now);
        if let Some(existing) = existing {
            if existing.user_lookup != request.user_lookup
                || existing.user_id != request.user_id
                || !agent_auth_authn::recovery::hash_eq_b64(
                    &existing.presented_hash,
                    request.presented_hash,
                )
                || existing.expires_at <= now
            {
                return Ok(RecoveryAuthorityConsume::Invalid);
            }
            if !password_ready {
                return Ok(RecoveryAuthorityConsume::PasswordChangeRequired);
            }
            let stored =
                sessions::get_locked(&mut transaction, request.tenant, &existing.session_id)
                    .await?;
            let authoritative = user.as_ref().is_some_and(|user| {
                user.record.status == UserStatus::Active
                    && !user.record.revocation_pending
                    && user.record.credential_epoch == existing.credential_epoch
                    && user.record.email == request.expected_email
            }) && stored.is_some_and(|stored| {
                stored.record.user_id == existing.user_id
                    && stored.record.credential_epoch == existing.credential_epoch
                    && stored.record.created_at == existing.created_at
                    && stored.record.expires_at > now
                    && existing.expires_at <= stored.record.expires_at
                    && stored.generation == generation
            });
            return Ok(if authoritative {
                RecoveryAuthorityConsume::Replayed { result: existing }
            } else {
                RecoveryAuthorityConsume::AuthorityChanged
            });
        }
        let Some(user) = user.as_mut() else {
            return Ok(RecoveryAuthorityConsume::AuthorityChanged);
        };
        if user.record.status != UserStatus::Active
            || user.record.revocation_pending
            || user.record.credential_epoch != request.expected_epoch
            || user.record.email != request.expected_email
            || result.expires_at <= now
        {
            return Ok(RecoveryAuthorityConsume::AuthorityChanged);
        }
        let Some(mut record) =
            recovery::get_locked(&mut transaction, request.tenant, request.user_lookup).await?
        else {
            return Ok(RecoveryAuthorityConsume::NotFound);
        };
        if record.user_id != request.user_id {
            return Ok(RecoveryAuthorityConsume::AuthorityChanged);
        }
        let valid = !agent_auth_authn::recovery::is_locked(record.locked_until, now)
            && record.code_hashes.iter().any(|code| {
                !code.consumed
                    && agent_auth_authn::recovery::hash_eq_b64(
                        &code.hash_b64,
                        request.presented_hash,
                    )
            });
        if valid && !password_ready {
            return Ok(RecoveryAuthorityConsume::PasswordChangeRequired);
        }
        let next_generation = if valid {
            if sessions::get_locked(&mut transaction, request.tenant, &session.session_id)
                .await?
                .is_some()
            {
                return Err(StoreError::Transient(
                    "Recovered session ID collision".into(),
                ));
            }
            Some(sessions::next_generation(generation)?)
        } else {
            None
        };
        let before = record.clone();
        let outcome = consume_recovery_record(&mut record, request.presented_hash, now);
        if record != before {
            recovery::write(&mut transaction, request.tenant, &record).await?;
        }
        let outcome = match outcome {
            RecoveryConsume::Valid => {
                user.record.credential_epoch = next_epoch;
                user.record.updated_at = now;
                Self::write_user(&mut transaction, request.tenant, user, false).await?;
                sessions::set_generation(
                    &mut transaction,
                    request.tenant,
                    request.user_id,
                    next_generation.expect("valid consumption computed generation"),
                )
                .await?;
                sessions::create_in_transaction(&mut transaction, request.tenant, session).await?;
                recovery::write_result(&mut transaction, request.tenant, &result).await?;
                RecoveryAuthorityConsume::Valid {
                    credential_epoch: next_epoch,
                }
            }
            RecoveryConsume::Invalid => RecoveryAuthorityConsume::Invalid,
            RecoveryConsume::Locked { retry_after_secs } => {
                RecoveryAuthorityConsume::Locked { retry_after_secs }
            }
            RecoveryConsume::NotFound => RecoveryAuthorityConsume::NotFound,
            RecoveryConsume::AuthorityChanged => RecoveryAuthorityConsume::AuthorityChanged,
        };
        transaction.commit().await.map_err(db_error)?;
        Ok(outcome)
    }
}
