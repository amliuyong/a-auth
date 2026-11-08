use super::*;

struct Claim {
    user_id: String,
    pending: Option<u64>,
}

fn invalid_claim() -> StoreError {
    StoreError::Permanent("Invalid SCIM creation authority".into())
}

impl PostgresUsersStore {
    async fn scim_claim(
        transaction: &mut Transaction<'_, Postgres>,
        tenant: &str,
        external_id: &str,
        user_name: &str,
    ) -> Result<Option<Claim>, StoreError> {
        sqlx::query(
            "SELECT user_id, pending_initial_epoch::TEXT AS pending \
             FROM a_auth.scim_create_claims \
             WHERE tenant = $1 AND external_id = $2 AND user_name = $3",
        )
        .bind(tenant.as_bytes())
        .bind(external_id.as_bytes())
        .bind(user_name.as_bytes())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(db_error)?
        .map(|row| {
            let id: Vec<u8> = row.try_get("user_id").map_err(db_error)?;
            let pending: Option<String> = row.try_get("pending").map_err(db_error)?;
            Ok(Claim {
                user_id: String::from_utf8(id).map_err(|_| invalid_claim())?,
                pending: pending
                    .map(|value| value.parse().map_err(|_| invalid_claim()))
                    .transpose()?,
            })
        })
        .transpose()
    }

    async fn insert_scim_claim(
        transaction: &mut Transaction<'_, Postgres>,
        tenant: &str,
        external_id: &str,
        user_name: &str,
        user_id: &str,
        pending: Option<u64>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO a_auth.scim_create_claims \
             (tenant, external_id, user_name, user_id, pending_initial_epoch) \
             VALUES ($1, $2, $3, $4, $5::TEXT::NUMERIC)",
        )
        .bind(tenant.as_bytes())
        .bind(external_id.as_bytes())
        .bind(user_name.as_bytes())
        .bind(user_id.as_bytes())
        .bind(pending.map(|value| value.to_string()))
        .execute(&mut **transaction)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    pub(super) async fn scim_create(
        &self,
        tenant: &str,
        input: ScimUserInput,
    ) -> Result<ScimCreateOutcome, StoreError> {
        let name = input.user_name.trim().to_lowercase();
        let mut transaction = self.base.pool.begin().await.map_err(db_error)?;
        Self::lock_directory(&mut transaction, tenant).await?;
        self.admit_aliases(
            &mut transaction,
            tenant,
            &[
                (GovernanceAliasKind::CanonicalId, &input.user_id),
                (GovernanceAliasKind::ScimExternalId, &input.external_id),
                (GovernanceAliasKind::ScimUserName, &name),
                (GovernanceAliasKind::Email, &name),
            ],
        )
        .await?;
        if let Some(claim) =
            Self::scim_claim(&mut transaction, tenant, &input.external_id, &name).await?
        {
            let user = Self::lock_user(&mut transaction, tenant, &claim.user_id)
                .await?
                .ok_or_else(invalid_claim)?;
            transaction.commit().await.map_err(db_error)?;
            return Ok(if user.record.status == UserStatus::Tombstoned {
                ScimCreateOutcome::Tombstoned
            } else {
                ScimCreateOutcome::Existing {
                    record: user.record,
                    pending_initial_epoch: claim.pending,
                }
            });
        }
        let external = Self::alias_user(
            &mut transaction,
            tenant,
            "scim_external_id",
            &input.external_id,
        )
        .await?;
        let named = Self::alias_user(&mut transaction, tenant, "scim_user_name", &name).await?;
        match (external, named) {
            (Some(left), Some(right)) if left.record.user_id == right.record.user_id => {
                // A per-user mutation may race the initial alias read. Lock and
                // read the canonical record before returning a current receipt.
                let user = Self::lock_user(&mut transaction, tenant, &left.record.user_id)
                    .await?
                    .ok_or_else(invalid_claim)?;
                if user.record.status == UserStatus::Tombstoned {
                    return Ok(ScimCreateOutcome::Tombstoned);
                }
                self.admit_aliases(
                    &mut transaction,
                    tenant,
                    &[(GovernanceAliasKind::CanonicalId, &user.record.user_id)],
                )
                .await?;
                Self::insert_scim_claim(
                    &mut transaction,
                    tenant,
                    &input.external_id,
                    &name,
                    &user.record.user_id,
                    None,
                )
                .await?;
                transaction.commit().await.map_err(db_error)?;
                return Ok(ScimCreateOutcome::Existing {
                    record: user.record,
                    pending_initial_epoch: None,
                });
            }
            (Some(_), _) | (_, Some(_)) => return Ok(ScimCreateOutcome::Conflict),
            (None, None) => {}
        }
        let adopted = if name.is_empty() {
            None
        } else {
            Self::alias_user(&mut transaction, tenant, "email", &name).await?
        };
        let id = adopted
            .map(|user| user.record.user_id)
            .unwrap_or(input.user_id);
        // Email adoption can choose an existing canonical identity instead of
        // the proposed ID. Its suppression must fence the actual write.
        self.admit_aliases(
            &mut transaction,
            tenant,
            &[(GovernanceAliasKind::CanonicalId, &id)],
        )
        .await?;
        let existing = Self::lock_user(&mut transaction, tenant, &id).await?;
        let create = existing.is_none();
        let mut user = existing.unwrap_or_else(|| LockedUser {
            record: initial_record(&id, &name, input.now),
            operation_id: None,
        });
        if user.record.status == UserStatus::Tombstoned {
            return Ok(ScimCreateOutcome::Tombstoned);
        }
        if user.record.scim_external_id.is_some() || user.record.scim_user_name.is_some() {
            return Ok(ScimCreateOutcome::Conflict);
        }
        let initial_epoch = user.record.credential_epoch;
        let disable_epoch = (!input.active)
            .then(|| next_disable_epoch(user.record.status, user.record.credential_epoch))
            .transpose()?;
        user.record.email = name.clone();
        user.record.updated_at = input.now;
        user.record.scim_external_id = Some(input.external_id.clone());
        user.record.scim_user_name = Some(name.clone());
        user.record.scim_display_name = input.display_name;
        if let Some(epoch) = disable_epoch {
            user.record.credential_epoch = epoch;
            user.record.status = UserStatus::Disabled;
            user.record.revocation_pending = true;
        }
        Self::write_user(&mut transaction, tenant, &user, create).await?;
        Self::insert_scim_claim(
            &mut transaction,
            tenant,
            &input.external_id,
            &name,
            &id,
            (!input.active).then_some(initial_epoch),
        )
        .await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(ScimCreateOutcome::Created(user.record))
    }

    pub(super) async fn scim_begin_lifecycle(
        &self,
        tenant: &str,
        external_id: &str,
        user_name: &str,
        user_id: &str,
        now: i64,
    ) -> Result<ScimCreateLifecycleStart, StoreError> {
        let mut transaction = self.base.pool.begin().await.map_err(db_error)?;
        Self::lock_directory(&mut transaction, tenant).await?;
        let Some(claim) = Self::scim_claim(
            &mut transaction,
            tenant,
            external_id,
            &user_name.trim().to_lowercase(),
        )
        .await?
        else {
            return Ok(ScimCreateLifecycleStart::Complete);
        };
        if claim.user_id != user_id {
            return Err(invalid_claim());
        }
        let Some(initial) = claim.pending else {
            return Ok(ScimCreateLifecycleStart::Complete);
        };
        let mut user = Self::lock_user(&mut transaction, tenant, user_id)
            .await?
            .ok_or_else(invalid_claim)?;
        if user.record.status == UserStatus::Tombstoned {
            return Ok(ScimCreateLifecycleStart::Tombstoned);
        }
        if !user.record.revocation_pending
            && (user.record.credential_epoch != initial
                || (user.record.status == UserStatus::Disabled
                    && user.record.credential_epoch != 0))
        {
            return Ok(ScimCreateLifecycleStart::Complete);
        }
        let epoch = next_disable_epoch(user.record.status, user.record.credential_epoch)?;
        user.record.credential_epoch = epoch;
        user.record.status = UserStatus::Disabled;
        user.record.revocation_pending = true;
        user.record.updated_at = now;
        Self::write_user(&mut transaction, tenant, &user, false).await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(ScimCreateLifecycleStart::Ready {
            record: user.record,
            epoch,
        })
    }

    pub(super) async fn scim_complete_lifecycle(
        &self,
        tenant: &str,
        external_id: &str,
        user_name: &str,
        user_id: &str,
    ) -> Result<(), StoreError> {
        let mut transaction = self.base.pool.begin().await.map_err(db_error)?;
        Self::lock_directory(&mut transaction, tenant).await?;
        let name = user_name.trim().to_lowercase();
        let Some(claim) = Self::scim_claim(&mut transaction, tenant, external_id, &name).await?
        else {
            return Ok(());
        };
        if claim.user_id != user_id {
            return Err(invalid_claim());
        }
        sqlx::query(
            "UPDATE a_auth.scim_create_claims SET pending_initial_epoch = NULL \
             WHERE tenant = $1 AND external_id = $2 AND user_name = $3",
        )
        .bind(tenant.as_bytes())
        .bind(external_id.as_bytes())
        .bind(name.as_bytes())
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)
    }

    pub(super) async fn scim_lookup(
        &self,
        tenant: &str,
        column: &'static str,
        value: &str,
    ) -> Result<Option<UserRecord>, StoreError> {
        let mut transaction = self.base.pool.begin().await.map_err(db_error)?;
        let user = Self::alias_user(&mut transaction, tenant, column, value).await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(user.map(|user| user.record))
    }

    pub(super) async fn scim_list(
        &self,
        tenant: &str,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<UserRecord>, usize), StoreError> {
        // The page and its count must describe one statement snapshot.
        let rows = sqlx::query(&format!(
            "WITH candidates AS MATERIALIZED \
             (SELECT {COLUMNS} FROM a_auth.users WHERE tenant = $1 \
              AND scim_external_id IS NOT NULL AND status <> 'tombstoned'), \
             tally AS (SELECT count(*) AS total FROM candidates), \
             page AS (SELECT * FROM candidates ORDER BY user_id OFFSET $2 LIMIT $3) \
             SELECT tally.total, page.* FROM tally LEFT JOIN page ON TRUE ORDER BY page.user_id"
        ))
        .bind(tenant.as_bytes())
        .bind(i64::try_from(offset).unwrap_or(i64::MAX))
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.base.pool)
        .await
        .map_err(db_error)?;
        let mut total = 0;
        let mut records = Vec::new();
        for row in rows {
            let count: i64 = row.try_get("total").map_err(db_error)?;
            total = usize::try_from(count).map_err(|_| invalid_claim())?;
            let id: Option<Vec<u8>> = row.try_get("user_id").map_err(db_error)?;
            if id.is_some() {
                records.push(decode(row)?.record);
            }
        }
        Ok((records, total))
    }

    pub(super) async fn scim_replace(
        &self,
        tenant: &str,
        user_id: &str,
        input: ScimReplaceInput,
    ) -> Result<ScimReplaceOutcome, StoreError> {
        let name = input.user_name.trim().to_lowercase();
        let mut transaction = self.base.pool.begin().await.map_err(db_error)?;
        Self::lock_directory(&mut transaction, tenant).await?;
        self.admit_aliases(
            &mut transaction,
            tenant,
            &[
                (GovernanceAliasKind::ScimExternalId, &input.external_id),
                (GovernanceAliasKind::ScimUserName, &name),
                (GovernanceAliasKind::Email, &name),
            ],
        )
        .await?;
        let conflict: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM a_auth.users WHERE tenant = $1 AND user_id <> $2 \
             AND (email = $3 OR scim_external_id = $4 OR scim_user_name = $3))",
        )
        .bind(tenant.as_bytes())
        .bind(user_id.as_bytes())
        .bind(name.as_bytes())
        .bind(input.external_id.as_bytes())
        .fetch_one(&mut *transaction)
        .await
        .map_err(db_error)?;
        if conflict {
            return Ok(ScimReplaceOutcome::Conflict);
        }
        let Some(mut user) = Self::lock_user(&mut transaction, tenant, user_id).await? else {
            return Ok(ScimReplaceOutcome::NotFound);
        };
        if user.record.scim_external_id.is_none() {
            return Ok(ScimReplaceOutcome::NotFound);
        }
        if user.record.status == UserStatus::Tombstoned {
            return Ok(ScimReplaceOutcome::Tombstoned);
        }
        let disable_epoch = (!input.active
            && (user.record.status == UserStatus::Active || user.record.credential_epoch == 0))
            .then(|| next_disable_epoch(user.record.status, user.record.credential_epoch))
            .transpose()?;
        user.record.email = name.clone();
        user.record.scim_external_id = Some(input.external_id);
        user.record.scim_user_name = Some(name);
        user.record.scim_display_name = input.display_name;
        user.record.updated_at = input.now;
        if let Some(epoch) = disable_epoch {
            user.record.credential_epoch = epoch;
            user.record.status = UserStatus::Disabled;
            user.record.revocation_pending = true;
        }
        Self::write_user(&mut transaction, tenant, &user, false).await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(ScimReplaceOutcome::Updated(user.record))
    }
}
