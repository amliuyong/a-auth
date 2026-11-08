use super::{db_error, PostgresGraceStore, PostgresStore};
use crate::ports::{
    GraceCacheEntry, RefreshFamilyRecord, RefreshLeaseAcquire, RefreshStore, StoreError,
};
use sqlx::{types::Json, PgConnection, Row};

/// The leased refresh version and its already-signed response commit together.
pub struct RefreshRotationRequest<'a> {
    pub tenant: &'a str,
    pub family_id: &'a str,
    pub expected_version: u64,
    pub lease_owner: &'a str,
    pub now: i64,
    pub grace_entry: Option<GraceCacheEntry>,
}

async fn advance_version(
    connection: &mut PgConnection,
    request: &RefreshRotationRequest<'_>,
) -> Result<bool, StoreError> {
    let result = sqlx::query(
        "UPDATE a_auth.refresh_families SET record = jsonb_set(record, '{current_version}', \
         to_jsonb((record->>'current_version')::NUMERIC + 1)), \
         lease_owner = NULL, lease_until = NULL, lease_version = NULL \
         WHERE tenant = $1 AND family_id = $2 AND record->>'current_version' = $3 \
         AND lease_version = $3::TEXT::NUMERIC AND lease_owner = $4 AND lease_until > $5 \
         AND NOT (record->>'revoked')::BOOLEAN \
         AND (record->>'current_version')::NUMERIC < 18446744073709551615",
    )
    .bind(request.tenant)
    .bind(request.family_id)
    .bind(request.expected_version.to_string())
    .bind(request.lease_owner)
    .bind(request.now)
    .execute(connection)
    .await
    .map_err(db_error)?;
    Ok(result.rows_affected() == 1)
}

impl PostgresStore {
    pub async fn finalize_refresh_rotation(
        &self,
        grace: Option<&PostgresGraceStore>,
        mut request: RefreshRotationRequest<'_>,
    ) -> Result<bool, StoreError> {
        if grace.is_some() != request.grace_entry.is_some()
            || grace.is_some_and(|grace| !grace.belongs_to(self))
        {
            return Err(StoreError::Permanent(
                "Refresh finalization requires matching store and grace configuration".into(),
            ));
        }
        if request.grace_entry.as_ref().is_some_and(|entry| {
            entry.family_id != request.family_id || entry.version != request.expected_version
        }) {
            return Err(StoreError::Permanent(
                "Refresh grace response does not match the leased version".into(),
            ));
        }
        let prepared = match (grace, request.grace_entry.take()) {
            (Some(grace), Some(entry)) => Some(grace.prepare(entry)?),
            _ => None,
        };
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let exists: Option<String> = sqlx::query_scalar(
            "SELECT family_id FROM a_auth.refresh_families \
             WHERE tenant = $1 AND family_id = $2 FOR UPDATE",
        )
        .bind(request.tenant)
        .bind(request.family_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(db_error)?;
        if exists.is_none() {
            return Ok(false);
        }
        // Check the real commit clock after acquiring the authority lock. A
        // delayed request cannot reuse its earlier timestamp to extend a lease.
        request.now = request.now.max(crate::current_unix_secs());
        if !advance_version(&mut transaction, &request).await? {
            return Ok(false);
        }
        if let Some(prepared) = prepared {
            PostgresGraceStore::persist(&mut transaction, &prepared).await?;
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(true)
    }
}

impl RefreshStore for PostgresStore {
    async fn create(&self, tenant: &str, record: RefreshFamilyRecord) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let result = sqlx::query(
            "INSERT INTO a_auth.refresh_families (tenant, family_id, client_id, user_id, record) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant, family_id) DO NOTHING",
        )
        .bind(tenant)
        .bind(&record.family_id)
        .bind(&record.client_id)
        .bind(&record.user_id)
        .bind(Json(&record))
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::Transient(
                "refresh family already exists".into(),
            ));
        }
        if !record.revoked && record.cimd_snapshot.is_none() {
            Self::add_client_authority(&mut transaction, tenant, &record.client_id).await?;
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn get(
        &self,
        tenant: &str,
        family_id: &str,
    ) -> Result<Option<RefreshFamilyRecord>, StoreError> {
        let record: Option<Json<RefreshFamilyRecord>> = sqlx::query_scalar(
            "SELECT record FROM a_auth.refresh_families WHERE tenant = $1 AND family_id = $2",
        )
        .bind(tenant)
        .bind(family_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(record.map(|Json(record)| record))
    }

    async fn acquire_lease(
        &self,
        tenant: &str,
        family_id: &str,
        expected_version: u64,
        lease_owner: &str,
        now: i64,
        lease_expires_at: i64,
    ) -> Result<RefreshLeaseAcquire, StoreError> {
        if lease_owner.is_empty() || lease_expires_at <= now {
            return Err(StoreError::Permanent(
                "invalid refresh signing lease request".into(),
            ));
        }
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let row = sqlx::query(
            "SELECT record, lease_until FROM a_auth.refresh_families \
             WHERE tenant = $1 AND family_id = $2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(family_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(db_error)?;
        let Some(row) = row else {
            return Ok(RefreshLeaseAcquire::NotFound);
        };
        let Json(record): Json<RefreshFamilyRecord> = row.try_get("record").map_err(db_error)?;
        if record.revoked {
            return Ok(RefreshLeaseAcquire::Revoked);
        }
        if record.current_version != expected_version {
            return Ok(RefreshLeaseAcquire::VersionMismatch);
        }
        if let Some(until) = row
            .try_get::<Option<i64>, _>("lease_until")
            .map_err(db_error)?
        {
            if until > now {
                return Ok(RefreshLeaseAcquire::Locked {
                    retry_after_secs: until.saturating_sub(now).max(1) as u64,
                });
            }
        }
        sqlx::query(
            "UPDATE a_auth.refresh_families SET lease_owner = $3, lease_until = $4, \
             lease_version = $5::TEXT::NUMERIC WHERE tenant = $1 AND family_id = $2",
        )
        .bind(tenant)
        .bind(family_id)
        .bind(lease_owner)
        .bind(lease_expires_at)
        .bind(expected_version.to_string())
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(RefreshLeaseAcquire::Acquired)
    }

    async fn finalize_rotation(
        &self,
        tenant: &str,
        family_id: &str,
        expected_version: u64,
        lease_owner: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut connection = self.pool.acquire().await.map_err(db_error)?;
        advance_version(
            &mut connection,
            &RefreshRotationRequest {
                tenant,
                family_id,
                expected_version,
                lease_owner,
                now,
                grace_entry: None,
            },
        )
        .await
    }

    async fn release_lease(
        &self,
        tenant: &str,
        family_id: &str,
        expected_version: u64,
        lease_owner: &str,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE a_auth.refresh_families SET lease_owner = NULL, lease_until = NULL, lease_version = NULL \
             WHERE tenant = $1 AND family_id = $2 AND record->>'current_version' = $3 \
             AND lease_version = $3::TEXT::NUMERIC AND lease_owner = $4",
        )
        .bind(tenant)
        .bind(family_id)
        .bind(expected_version.to_string())
        .bind(lease_owner)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn revoke(&self, tenant: &str, family_id: &str) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE a_auth.refresh_families SET record = jsonb_set(record, '{revoked}', 'true'::JSONB) \
             WHERE tenant = $1 AND family_id = $2",
        )
        .bind(tenant)
        .bind(family_id)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn revoke_by_user(&self, tenant: &str, user_id: &str) -> Result<Vec<String>, StoreError> {
        let mut ids: Vec<String> = sqlx::query_scalar(
            "UPDATE a_auth.refresh_families SET record = jsonb_set(record, '{revoked}', 'true'::JSONB) \
             WHERE tenant = $1 AND user_id = $2 RETURNING family_id",
        )
        .bind(tenant)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        ids.sort();
        Ok(ids)
    }

    async fn revoke_by_user_before_epoch(
        &self,
        tenant: &str,
        user_id: &str,
        epoch: u64,
    ) -> Result<Vec<String>, StoreError> {
        let mut ids: Vec<String> = sqlx::query_scalar(
            "UPDATE a_auth.refresh_families SET record = jsonb_set(record, '{revoked}', 'true'::JSONB) \
             WHERE tenant = $1 AND user_id = $2 \
             AND (record->>'credential_epoch')::NUMERIC < $3::TEXT::NUMERIC RETURNING family_id",
        )
        .bind(tenant)
        .bind(user_id)
        .bind(epoch.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        ids.sort();
        Ok(ids)
    }

    async fn revoke_by_client(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> Result<Vec<String>, StoreError> {
        let mut ids: Vec<String> = sqlx::query_scalar(
            "UPDATE a_auth.refresh_families SET record = jsonb_set(record, '{revoked}', 'true'::JSONB) \
             WHERE tenant = $1 AND client_id = $2 RETURNING family_id",
        )
        .bind(tenant)
        .bind(client_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        ids.sort();
        Ok(ids)
    }

    async fn has_active_family_by_client(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> Result<bool, StoreError> {
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM a_auth.refresh_families \
             WHERE tenant = $1 AND client_id = $2 AND NOT (record->>'revoked')::BOOLEAN)",
        )
        .bind(tenant)
        .bind(client_id)
        .fetch_one(&self.pool)
        .await
        .map_err(db_error)
    }

    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<Vec<String>, StoreError> {
        let mut ids: Vec<String> = sqlx::query_scalar(
            "DELETE FROM a_auth.refresh_families WHERE tenant = $1 AND user_id = $2 RETURNING family_id",
        )
        .bind(tenant)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        ids.sort();
        Ok(ids)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<Vec<String>, StoreError> {
        let mut ids: Vec<String> = sqlx::query_scalar(
            "DELETE FROM a_auth.refresh_families WHERE tenant = $1 RETURNING family_id",
        )
        .bind(tenant)
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        ids.sort();
        Ok(ids)
    }
}
