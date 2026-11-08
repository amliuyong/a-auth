use super::{db_error, PostgresStore};
use crate::ports::{DomainBinding, DomainMapStore, StoreError};
use sqlx::Row;

fn binding(row: sqlx::postgres::PgRow) -> Result<DomainBinding, StoreError> {
    Ok(DomainBinding {
        domain: row.try_get("domain").map_err(db_error)?,
        resource_id: row.try_get("resource_id").map_err(db_error)?,
        tenant_id: row.try_get("tenant").map_err(db_error)?,
        client_id: row.try_get("client_id").map_err(db_error)?,
    })
}

impl DomainMapStore for PostgresStore {
    async fn get(&self, domain: &str) -> Result<Option<DomainBinding>, StoreError> {
        let row = sqlx::query(
            "SELECT domain, resource_id, tenant, client_id FROM a_auth.domain_bindings WHERE domain = $1",
        )
        .bind(domain.to_ascii_lowercase())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        row.map(binding).transpose()
    }

    async fn put_if_absent(&self, record: DomainBinding) -> Result<bool, StoreError> {
        // This key is deliberately global: tenant partitioning would admit two
        // owners for the same resource hostname.
        let result = sqlx::query(
            "INSERT INTO a_auth.domain_bindings (domain, resource_id, tenant, client_id) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (domain) DO NOTHING",
        )
        .bind(record.domain.to_ascii_lowercase())
        .bind(record.resource_id)
        .bind(record.tenant_id)
        .bind(record.client_id)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn delete_if_owner(&self, domain: &str, client_id: &str) -> Result<bool, StoreError> {
        let result =
            sqlx::query("DELETE FROM a_auth.domain_bindings WHERE domain = $1 AND client_id = $2")
                .bind(domain.to_ascii_lowercase())
                .bind(client_id)
                .execute(&self.pool)
                .await
                .map_err(db_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn list_by_client(&self, client_id: &str) -> Result<Vec<DomainBinding>, StoreError> {
        let rows = sqlx::query(
            "SELECT domain, resource_id, tenant, client_id FROM a_auth.domain_bindings \
             WHERE client_id = $1 ORDER BY domain",
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        rows.into_iter().map(binding).collect()
    }

    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        let result = sqlx::query("DELETE FROM a_auth.domain_bindings WHERE tenant = $1")
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }
}
