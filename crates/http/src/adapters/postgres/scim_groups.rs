use super::{db_error, serialization::required_option, users::PostgresUsersStore, PostgresStore};
use crate::ports::*;
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};

mod record;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupState {
    #[serde(with = "record")]
    record: ScimGroupRecord,
    #[serde(deserialize_with = "required_option")]
    role: Option<TenantRole>,
    #[serde(deserialize_with = "required_option")]
    role_updated_at: Option<i64>,
    deleted: bool,
}

const COLUMNS: &str = "group_id, external_id, members, role, deleted, record";

fn invalid() -> StoreError {
    StoreError::Permanent("Invalid SCIM group authority".into())
}

fn role_name(role: TenantRole) -> &'static str {
    match role {
        TenantRole::Member => "member",
        TenantRole::Auditor => "auditor",
        TenantRole::Admin => "admin",
        TenantRole::Owner => "owner",
    }
}

fn next_version(version: u64) -> Result<u64, StoreError> {
    version
        .checked_add(1)
        .ok_or_else(|| StoreError::Permanent("SCIM group version exhausted".into()))
}

fn decode(row: PgRow) -> Result<GroupState, StoreError> {
    let payload: String = row.try_get("record").map_err(db_error)?;
    let state: GroupState = serde_json::from_str(&payload).map_err(|_| invalid())?;
    let id: Vec<u8> = row.try_get("group_id").map_err(db_error)?;
    let external: Vec<u8> = row.try_get("external_id").map_err(db_error)?;
    let members: Vec<Vec<u8>> = row.try_get("members").map_err(db_error)?;
    let role: Option<String> = row.try_get("role").map_err(db_error)?;
    let deleted: bool = row.try_get("deleted").map_err(db_error)?;
    if id != state.record.group_id.as_bytes()
        || external != state.record.external_id.as_bytes()
        || members
            != state
                .record
                .members
                .iter()
                .map(|member| member.as_bytes().to_vec())
                .collect::<Vec<_>>()
        || role.as_deref() != state.role.map(role_name)
        || deleted != state.deleted
        || state.record.version == 0
        || state.record.members.len() > SCIM_GROUP_MAX_MEMBERS
        || state
            .record
            .members
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || state.role.is_some() != state.role_updated_at.is_some()
        || (state.deleted && (!state.record.members.is_empty() || state.role.is_some()))
    {
        return Err(invalid());
    }
    Ok(state)
}

fn mapping(state: &GroupState) -> Option<ScimGroupRoleMapping> {
    state
        .role
        .zip(state.role_updated_at)
        .map(|(role, updated_at)| ScimGroupRoleMapping {
            group_id: state.record.group_id.clone(),
            external_id: state.record.external_id.clone(),
            role,
            updated_at,
        })
}

async fn get_locked(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &str,
    group_id: &str,
) -> Result<Option<GroupState>, StoreError> {
    sqlx::query(&format!(
        "SELECT {COLUMNS} FROM a_auth.scim_groups WHERE tenant = $1 AND group_id = $2 FOR UPDATE"
    ))
    .bind(tenant.as_bytes())
    .bind(group_id.as_bytes())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(db_error)?
    .map(decode)
    .transpose()
}

async fn get_alias_locked(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &str,
    external: &str,
) -> Result<Option<GroupState>, StoreError> {
    sqlx::query(&format!(
        "SELECT {COLUMNS} FROM a_auth.scim_groups \
         WHERE tenant = $1 AND external_id = $2 AND NOT deleted FOR UPDATE"
    ))
    .bind(tenant.as_bytes())
    .bind(external.as_bytes())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(db_error)?
    .map(decode)
    .transpose()
}

async fn write(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &str,
    state: &GroupState,
    create: bool,
) -> Result<(), StoreError> {
    let statement = if create {
        "INSERT INTO a_auth.scim_groups \
         (tenant, group_id, external_id, members, role, deleted, record) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)"
    } else {
        "UPDATE a_auth.scim_groups SET external_id = $3, members = $4, role = $5, \
         deleted = $6, record = $7 WHERE tenant = $1 AND group_id = $2"
    };
    let payload = serde_json::to_string(state)
        .map_err(|_| StoreError::Permanent("SCIM group encoding failed".into()))?;
    let result = sqlx::query(statement)
        .bind(tenant.as_bytes())
        .bind(state.record.group_id.as_bytes())
        .bind(state.record.external_id.as_bytes())
        .bind(
            state
                .record
                .members
                .iter()
                .map(|member| member.as_bytes().to_vec())
                .collect::<Vec<_>>(),
        )
        .bind(state.role.map(role_name))
        .bind(state.deleted)
        .bind(payload)
        .execute(&mut **transaction)
        .await
        .map_err(db_error)?;
    if result.rows_affected() != 1 {
        return Err(StoreError::Transient("SCIM group authority changed".into()));
    }
    Ok(())
}

impl ScimGroupsStore for PostgresStore {
    async fn create(
        &self,
        tenant: &str,
        input: ScimGroupCreateInput,
    ) -> Result<ScimGroupCreateOutcome, StoreError> {
        let members = canonical_scim_group_members(input.members);
        if members.len() > SCIM_GROUP_MAX_MEMBERS {
            return Err(StoreError::Permanent(
                "SCIM group exceeds the member limit".into(),
            ));
        }
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        if let Some(state) = get_alias_locked(&mut transaction, tenant, &input.external_id).await? {
            transaction.commit().await.map_err(db_error)?;
            return Ok(ScimGroupCreateOutcome::Existing(state.record));
        }
        if get_locked(&mut transaction, tenant, &input.group_id)
            .await?
            .is_some()
        {
            return Err(StoreError::Permanent(
                "SCIM group ID is already bound".into(),
            ));
        }
        let state = GroupState {
            record: ScimGroupRecord {
                group_id: input.group_id,
                external_id: input.external_id,
                display_name: input.display_name,
                members,
                version: 1,
                created_at: input.now,
                updated_at: input.now,
            },
            role: None,
            role_updated_at: None,
            deleted: false,
        };
        write(&mut transaction, tenant, &state, true).await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(ScimGroupCreateOutcome::Created(state.record))
    }

    async fn get(
        &self,
        tenant: &str,
        group_id: &str,
    ) -> Result<Option<ScimGroupRecord>, StoreError> {
        sqlx::query(&format!(
            "SELECT {COLUMNS} FROM a_auth.scim_groups WHERE tenant = $1 AND group_id = $2"
        ))
        .bind(tenant.as_bytes())
        .bind(group_id.as_bytes())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?
        .map(decode)
        .transpose()
        .map(|state| {
            state
                .filter(|state| !state.deleted)
                .map(|state| state.record)
        })
    }

    async fn get_by_external_id(
        &self,
        tenant: &str,
        external_id: &str,
    ) -> Result<Option<ScimGroupRecord>, StoreError> {
        sqlx::query(&format!(
            "SELECT {COLUMNS} FROM a_auth.scim_groups \
             WHERE tenant = $1 AND external_id = $2 AND NOT deleted"
        ))
        .bind(tenant.as_bytes())
        .bind(external_id.as_bytes())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?
        .map(decode)
        .transpose()
        .map(|state| state.map(|state| state.record))
    }

    async fn list(
        &self,
        tenant: &str,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<ScimGroupRecord>, usize), StoreError> {
        let rows = sqlx::query(&format!(
            "WITH candidates AS MATERIALIZED \
             (SELECT {COLUMNS} FROM a_auth.scim_groups WHERE tenant = $1 AND NOT deleted), \
             tally AS (SELECT count(*) AS total FROM candidates), \
             page AS (SELECT * FROM candidates ORDER BY group_id OFFSET $2 LIMIT $3) \
             SELECT tally.total, page.* FROM tally LEFT JOIN page ON TRUE ORDER BY page.group_id"
        ))
        .bind(tenant.as_bytes())
        .bind(i64::try_from(offset).unwrap_or(i64::MAX))
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        let mut total = 0;
        let mut records = Vec::new();
        for row in rows {
            let count: i64 = row.try_get("total").map_err(db_error)?;
            total = usize::try_from(count).map_err(|_| invalid())?;
            let id: Option<Vec<u8>> = row.try_get("group_id").map_err(db_error)?;
            if id.is_some() {
                records.push(decode(row)?.record);
            }
        }
        Ok((records, total))
    }

    async fn mutate(
        &self,
        tenant: &str,
        group_id: &str,
        mutation: ScimGroupMutation,
    ) -> Result<ScimGroupMutationOutcome, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let Some(mut state) = get_locked(&mut transaction, tenant, group_id)
            .await?
            .filter(|state| !state.deleted)
        else {
            return Ok(ScimGroupMutationOutcome::NotFound);
        };
        let (mut next, now) = apply_scim_group_mutation(&state.record, mutation);
        if next.members.len() > SCIM_GROUP_MAX_MEMBERS {
            return Ok(ScimGroupMutationOutcome::TooManyMembers);
        }
        if next.display_name == state.record.display_name && next.members == state.record.members {
            return Ok(ScimGroupMutationOutcome::Updated(state.record));
        }
        next.version = next_version(state.record.version)?;
        next.updated_at = now;
        state.record = next;
        write(&mut transaction, tenant, &state, false).await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(ScimGroupMutationOutcome::Updated(state.record))
    }

    async fn delete(
        &self,
        tenant: &str,
        group_id: &str,
        now: i64,
    ) -> Result<ScimGroupDeleteOutcome, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let Some(mut state) = get_locked(&mut transaction, tenant, group_id).await? else {
            return Ok(ScimGroupDeleteOutcome::NotFound);
        };
        if state.deleted {
            return Ok(ScimGroupDeleteOutcome::Deleted);
        }
        state.record.version = next_version(state.record.version)?;
        state.record.updated_at = now;
        state.record.members.clear();
        state.role = None;
        state.role_updated_at = None;
        state.deleted = true;
        write(&mut transaction, tenant, &state, false).await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(ScimGroupDeleteOutcome::Deleted)
    }

    async fn set_role_mapping(
        &self,
        tenant: &str,
        external_id: &str,
        role: Option<TenantRole>,
        now: i64,
    ) -> Result<ScimRoleMappingOutcome, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let Some(mut state) = get_alias_locked(&mut transaction, tenant, external_id).await? else {
            return Ok(ScimRoleMappingOutcome::GroupNotFound);
        };
        if state.role != role {
            state.record.version = next_version(state.record.version)?;
            state.record.updated_at = now;
            state.role = role;
            state.role_updated_at = role.map(|_| now);
            write(&mut transaction, tenant, &state, false).await?;
        }
        let outcome = mapping(&state).map_or(
            ScimRoleMappingOutcome::Removed,
            ScimRoleMappingOutcome::Updated,
        );
        transaction.commit().await.map_err(db_error)?;
        Ok(outcome)
    }

    async fn list_role_mappings(
        &self,
        tenant: &str,
    ) -> Result<Vec<ScimGroupRoleMapping>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {COLUMNS} FROM a_auth.scim_groups \
             WHERE tenant = $1 AND NOT deleted AND role IS NOT NULL ORDER BY external_id"
        ))
        .bind(tenant.as_bytes())
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        rows.into_iter()
            .map(|row| decode(row)?.into_mapping())
            .collect()
    }

    async fn mapped_role_for_member(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<MappedTenantRole, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {COLUMNS} FROM a_auth.scim_groups WHERE tenant = $1 AND NOT deleted \
             AND role IS NOT NULL AND $2 = ANY(members) ORDER BY external_id"
        ))
        .bind(tenant.as_bytes())
        .bind(user_id.as_bytes())
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        let mappings: Vec<_> = rows
            .into_iter()
            .map(|row| decode(row)?.into_mapping())
            .collect::<Result<_, _>>()?;
        let role = mappings.iter().map(|mapping| mapping.role).max();
        Ok(MappedTenantRole { role, mappings })
    }

    async fn remove_member_from_all(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<usize, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let rows = sqlx::query(&format!(
            "SELECT {COLUMNS} FROM a_auth.scim_groups WHERE tenant = $1 AND NOT deleted \
             AND $2 = ANY(members) ORDER BY group_id FOR UPDATE"
        ))
        .bind(tenant.as_bytes())
        .bind(user_id.as_bytes())
        .fetch_all(&mut *transaction)
        .await
        .map_err(db_error)?;
        let mut states = rows
            .into_iter()
            .map(decode)
            .collect::<Result<Vec<_>, _>>()?;
        for state in &mut states {
            state.record.version = next_version(state.record.version)?;
            state.record.members.retain(|member| member != user_id);
            state.record.updated_at = now;
        }
        for state in &states {
            write(&mut transaction, tenant, state, false).await?;
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(states.len())
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let result = sqlx::query("DELETE FROM a_auth.scim_groups WHERE tenant = $1")
            .bind(tenant.as_bytes())
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
        let removed = usize::try_from(result.rows_affected()).map_err(|_| invalid())?;
        transaction.commit().await.map_err(db_error)?;
        Ok(removed)
    }
}

impl GroupState {
    fn into_mapping(self) -> Result<ScimGroupRoleMapping, StoreError> {
        mapping(&self).ok_or_else(invalid)
    }
}
