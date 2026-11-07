//! A claimed governance lease and all user erasure effects share one transaction.
//! Physical ownership columns let delete-only workers erase encrypted authority
//! without access to the wrapping keys.

use super::{db_error, GovernanceState, PostgresGovernanceStore, PostgresUsersStore};
use crate::{
    adapters::{
        governance_state::governance_destructive_fence_matches,
        postgres::scim_groups::remove_member_in_transaction,
    },
    governance::{GovernanceAliasKind, GovernanceDestructiveFence, GovernanceJobKind},
    governance_data::GovernanceInventory,
    ports::{StoreError, UserRecord, UserStatus},
};
use sqlx::{Postgres, Row, Transaction};

fn conflict() -> StoreError {
    StoreError::Transient("governance destructive fence conflict".into())
}

pub(super) fn validate_tenant(logical: &str, data: &str) -> Result<(), StoreError> {
    if logical != if data.is_empty() { "default" } else { data } {
        return Err(StoreError::Permanent(
            "governance logical and data tenants do not match".into(),
        ));
    }
    Ok(())
}

fn target_epoch(fence: &GovernanceDestructiveFence) -> Result<u64, StoreError> {
    fence
        .target_epoch
        .ok_or_else(|| StoreError::Permanent("user erasure fence is missing target epoch".into()))
}

pub(super) fn check_fence(
    authority: &GovernanceState,
    tenant: &str,
    fence: &GovernanceDestructiveFence,
    now: i64,
) -> Result<(), StoreError> {
    if !governance_destructive_fence_matches(
        authority,
        tenant,
        fence,
        crate::current_unix_secs().max(now),
    ) {
        return Err(conflict());
    }
    Ok(())
}

fn check_user_target(
    authority: &GovernanceState,
    tenant: &str,
    fence: &GovernanceDestructiveFence,
    user_id: &str,
    aliases: Option<&[String]>,
) -> Result<(), StoreError> {
    let Some(job) = authority.jobs.get(&(tenant.into(), fence.job_id.clone())) else {
        return Err(conflict());
    };
    if job.kind != GovernanceJobKind::UserErasure || job.target_id.as_deref() != Some(user_id) {
        return Err(conflict());
    }
    if let Some(aliases) = aliases {
        let expected = job
            .target_aliases
            .iter()
            .filter(|alias| alias.kind != GovernanceAliasKind::CanonicalId)
            .map(|alias| alias.normalized_value.as_str())
            .collect::<Vec<_>>();
        if expected != aliases.iter().map(String::as_str).collect::<Vec<_>>() {
            return Err(conflict());
        }
    }
    Ok(())
}

// Fixed statements only. Each predicate selects physical authority owned by this
// user; associated authorization state is selected before its code is deleted.
// login_session_generations follows login_sessions because of the foreign key.
const TEXT_USER_AUTHORITY: &[(&str, &str)] = &[
    (
        "authz_sessions",
        "authz_sessions WHERE tenant = $1 AND (user_id = $2 OR session_id IN \
         (SELECT record->>'authz_session_id' FROM a_auth.codes WHERE tenant = $1 AND user_id = $2))",
    ),
    ("codes", "codes WHERE tenant = $1 AND user_id = $2"),
    (
        "refresh_families",
        "refresh_families WHERE tenant = $1 AND user_id = $2",
    ),
    (
        "passkey_challenges",
        "passkey_challenges WHERE tenant = $1 AND user_id = $2",
    ),
    ("grants", "grants WHERE tenant = $1 AND user_id = $2"),
    (
        "device_grants",
        "device_grants WHERE tenant = $1 AND record->>'user_id' = $2",
    ),
    (
        "passwords",
        "password_credentials WHERE tenant = $1 AND user_id = $2",
    ),
    ("magic_links", "magic_links WHERE tenant = $1 AND user_id = $2"),
];
const BYTE_USER_AUTHORITY: &[(&str, &str)] = &[
    (
        "sessions",
        "login_sessions WHERE tenant = $1 AND user_id = $2",
    ),
    (
        "session_generations",
        "login_session_generations WHERE tenant = $1 AND user_id = $2",
    ),
    (
        "passkeys",
        "passkey_credentials WHERE tenant = $1 AND user_id = $2",
    ),
    (
        "ciba_requests",
        "ciba_requests WHERE tenant = $1 AND user_id = $2",
    ),
    (
        "ciba_throttles",
        "ciba_throttle WHERE tenant = $1 AND user_id = $2",
    ),
    (
        "recovery",
        "recovery_codes WHERE tenant = $1 AND user_id = $2",
    ),
    (
        "recovery_results",
        "recovery_success_results WHERE tenant = $1 AND user_id = $2",
    ),
    (
        "invitations",
        "invitations WHERE tenant = $1 AND user_id = $2",
    ),
];

async fn count(
    transaction: &mut Transaction<'_, Postgres>,
    predicate: &str,
    tenant: &str,
    user_id: &str,
    bytes: bool,
) -> Result<u64, StoreError> {
    let statement = format!("SELECT count(*) AS total FROM a_auth.{predicate}");
    let query = sqlx::query(&statement);
    let query = if bytes {
        query.bind(tenant.as_bytes()).bind(user_id.as_bytes())
    } else {
        query.bind(tenant).bind(user_id)
    };
    let total: i64 = query
        .fetch_one(&mut **transaction)
        .await
        .map_err(db_error)?
        .try_get("total")
        .map_err(db_error)?;
    u64::try_from(total)
        .map_err(|_| StoreError::Permanent("governance inventory count exceeds u64".into()))
}

async fn delete(
    transaction: &mut Transaction<'_, Postgres>,
    predicate: &str,
    tenant: &str,
    user_id: &str,
    bytes: bool,
) -> Result<u64, StoreError> {
    let statement = format!("DELETE FROM a_auth.{predicate}");
    let query = sqlx::query(&statement);
    let query = if bytes {
        query.bind(tenant.as_bytes()).bind(user_id.as_bytes())
    } else {
        query.bind(tenant).bind(user_id)
    };
    Ok(query
        .execute(&mut **transaction)
        .await
        .map_err(db_error)?
        .rows_affected())
}

async fn alias_authority(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &str,
    aliases: &[String],
    remove: bool,
) -> Result<(u64, u64), StoreError> {
    let mut counts = [0, 0];
    for (index, (table, column, bytes)) in [
        ("magic_link_cooldowns", "email", false),
        ("message_outbox", "recipient", true),
    ]
    .into_iter()
    .enumerate()
    {
        let statement = format!(
            "{} FROM a_auth.{table} WHERE tenant = $1 AND {column} = ANY($2)",
            if remove {
                "DELETE"
            } else {
                "SELECT count(*) AS total"
            }
        );
        let query = sqlx::query(&statement);
        let query = if bytes {
            query.bind(tenant.as_bytes()).bind(
                aliases
                    .iter()
                    .map(|alias| alias.as_bytes().to_vec())
                    .collect::<Vec<_>>(),
            )
        } else {
            query.bind(tenant).bind(aliases)
        };
        counts[index] = if remove {
            query
                .execute(&mut **transaction)
                .await
                .map_err(db_error)?
                .rows_affected()
        } else {
            let total: i64 = query
                .fetch_one(&mut **transaction)
                .await
                .map_err(db_error)?
                .try_get("total")
                .map_err(db_error)?;
            u64::try_from(total).map_err(|_| {
                StoreError::Permanent("governance inventory count exceeds u64".into())
            })?
        };
    }
    Ok((counts[0], counts[1]))
}

impl PostgresGovernanceStore {
    pub(super) async fn begin_destructive<'a>(
        &'a self,
        logical: &str,
        data: &str,
        fence: &GovernanceDestructiveFence,
        now: i64,
    ) -> Result<(Transaction<'a, Postgres>, GovernanceState), StoreError> {
        validate_tenant(logical, data)?;
        let mut transaction = self.database.pool.begin().await.map_err(db_error)?;
        let (_, authority) = Self::lock(&mut transaction, logical).await?;
        check_fence(&authority, logical, fence, now)?;
        Ok((transaction, authority))
    }

    pub(crate) async fn fence_user_identity(
        &self,
        logical: &str,
        data: &str,
        user_id: &str,
        fence: &GovernanceDestructiveFence,
        now: i64,
    ) -> Result<Option<UserRecord>, StoreError> {
        let epoch = target_epoch(fence)?;
        let (mut transaction, authority) =
            self.begin_destructive(logical, data, fence, now).await?;
        check_user_target(&authority, logical, fence, user_id, None)?;
        let record = PostgresUsersStore::governance_fence_identity(
            &mut transaction,
            data,
            user_id,
            epoch,
            crate::current_unix_secs().max(now),
        )
        .await?;
        // A later data-row lock may have consumed the lease. Roll back every
        // tentative effect if the current clock no longer permits this commit.
        check_fence(&authority, logical, fence, now)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn cleanup_user_authority(
        &self,
        logical: &str,
        data: &str,
        user_id: &str,
        aliases: &[String],
        grace: bool,
        jtis: bool,
        fence: &GovernanceDestructiveFence,
        now: i64,
    ) -> Result<u64, StoreError> {
        let epoch = target_epoch(fence)?;
        let (mut transaction, authority) =
            self.begin_destructive(logical, data, fence, now).await?;
        check_user_target(&authority, logical, fence, user_id, Some(aliases))?;
        let identity =
            PostgresUsersStore::governance_identity_locked(&mut transaction, data, user_id).await?;
        if identity.is_none_or(|user| {
            user.status != UserStatus::Tombstoned || user.credential_epoch != epoch
        }) {
            return Err(conflict());
        }
        let mut removed = 0u64;
        // Remove grace while the refresh family ownership is still available.
        if grace {
            removed += delete(
                &mut transaction,
                "grace_responses WHERE family_id IN (SELECT convert_to(family_id, 'UTF8') \
                 FROM a_auth.refresh_families WHERE tenant = $1 AND user_id = $2)",
                data,
                user_id,
                false,
            )
            .await?;
        }
        for (_, predicate) in TEXT_USER_AUTHORITY {
            removed += delete(&mut transaction, predicate, data, user_id, false).await?;
        }
        for (_, predicate) in BYTE_USER_AUTHORITY {
            removed += delete(&mut transaction, predicate, data, user_id, true).await?;
        }
        if jtis {
            removed += delete(
                &mut transaction,
                "jti WHERE tenant = $1 AND user_id = $2",
                logical,
                user_id,
                false,
            )
            .await?;
        }
        removed += delete(
            &mut transaction,
            "admin_sessions WHERE tenant = $1 AND user_id = $2",
            logical,
            user_id,
            false,
        )
        .await?;
        let (cooldowns, messages) = alias_authority(&mut transaction, data, aliases, true).await?;
        removed += cooldowns + messages;
        removed += u64::try_from(
            remove_member_in_transaction(
                &mut transaction,
                data,
                user_id,
                crate::current_unix_secs().max(now),
            )
            .await?,
        )
        .map_err(|_| StoreError::Permanent("user cleanup count exceeds u64".into()))?;
        check_fence(&authority, logical, fence, now)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(removed)
    }

    pub(crate) async fn delete_user_identity(
        &self,
        logical: &str,
        data: &str,
        user_id: &str,
        fence: &GovernanceDestructiveFence,
        now: i64,
    ) -> Result<bool, StoreError> {
        let epoch = target_epoch(fence)?;
        let (mut transaction, authority) =
            self.begin_destructive(logical, data, fence, now).await?;
        check_user_target(&authority, logical, fence, user_id, None)?;
        let outcome =
            PostgresUsersStore::governance_delete_identity(&mut transaction, data, user_id, epoch)
                .await?;
        check_fence(&authority, logical, fence, now)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(outcome)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn inventory_user_authority(
        &self,
        logical: &str,
        data: &str,
        user_id: &str,
        aliases: &[String],
        grace: bool,
        jtis: bool,
    ) -> Result<GovernanceInventory, StoreError> {
        validate_tenant(logical, data)?;
        let mut transaction = self.database.pool.begin().await.map_err(db_error)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, logical).await?;
        let identity =
            PostgresUsersStore::governance_identity_locked(&mut transaction, data, user_id).await?;
        let mut inventory = GovernanceInventory::default();
        let live = &mut inventory.live_counts;
        live.insert("identity".into(), u64::from(identity.is_some()));
        let identity_aliases = identity.as_ref().map_or(0, |user| {
            u64::from(!user.email.is_empty())
                + u64::from(user.scim_external_id.is_some())
                + u64::from(user.scim_user_name.is_some())
        }) + count(
            &mut transaction,
            "scim_create_claims WHERE tenant = $1 AND user_id = $2",
            data,
            user_id,
            true,
        )
        .await?;
        live.insert("identity_aliases".into(), identity_aliases);
        for (category, predicate) in TEXT_USER_AUTHORITY {
            live.insert(
                (*category).into(),
                count(&mut transaction, predicate, data, user_id, false).await?,
            );
        }
        for (category, predicate) in BYTE_USER_AUTHORITY {
            live.insert(
                (*category).into(),
                count(&mut transaction, predicate, data, user_id, true).await?,
            );
        }
        live.insert(
            "refresh_grace".into(),
            if grace {
                count(
                    &mut transaction,
                    "grace_responses WHERE family_id IN (SELECT convert_to(family_id, 'UTF8') \
                 FROM a_auth.refresh_families WHERE tenant = $1 AND user_id = $2)",
                    data,
                    user_id,
                    false,
                )
                .await?
            } else {
                0
            },
        );
        live.insert(
            "jtis".into(),
            if jtis {
                count(
                    &mut transaction,
                    "jti WHERE tenant = $1 AND user_id = $2",
                    logical,
                    user_id,
                    false,
                )
                .await?
            } else {
                0
            },
        );
        live.insert(
            "admin_sessions".into(),
            count(
                &mut transaction,
                "admin_sessions WHERE tenant = $1 AND user_id = $2",
                logical,
                user_id,
                false,
            )
            .await?,
        );
        live.insert(
            "scim_memberships".into(),
            count(
                &mut transaction,
                "scim_groups WHERE tenant = $1 AND NOT deleted AND $2 = ANY(members)",
                data,
                user_id,
                true,
            )
            .await?,
        );
        let (cooldowns, messages) = alias_authority(&mut transaction, data, aliases, false).await?;
        live.insert("magic_cooldowns".into(), cooldowns);
        live.insert("messages".into(), messages);
        transaction.commit().await.map_err(db_error)?;
        Ok(inventory)
    }
}
