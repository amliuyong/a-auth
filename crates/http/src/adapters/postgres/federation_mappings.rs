use super::{db_error, PostgresStore};
use crate::{
    federation_attributes::{
        catalog::{MappingCatalog, MappingCatalogSnapshot},
        FederationAttributeMappingsStore, MappingChange, MappingChangeOutcome, MappingRegistry,
    },
    ports::StoreError,
};
use sqlx::{Postgres, Transaction};

fn decode(tenant: &str, record: &str) -> Result<MappingCatalog, StoreError> {
    let snapshot = serde_json::from_str(record)
        .map_err(|_| StoreError::Permanent("Invalid federation mapping snapshot".into()))?;
    MappingCatalog::from_snapshot(tenant, snapshot)
}

fn encode(snapshot: &MappingCatalogSnapshot) -> Result<String, StoreError> {
    serde_json::to_string(snapshot)
        .map_err(|_| StoreError::Permanent("Federation mapping encoding failed".into()))
}

impl PostgresStore {
    /// Cross-port reconciliation must lock mapping authority before the user
    /// row, so absent or changing ownership cannot escape its commit fence.
    pub(super) async fn lock_mapping_catalog(
        transaction: &mut Transaction<'_, Postgres>,
        tenant: &str,
    ) -> Result<MappingCatalog, StoreError> {
        sqlx::query(
            "INSERT INTO a_auth.federation_mapping_catalogs (tenant, record) VALUES ($1, $2) \
             ON CONFLICT (tenant) DO NOTHING",
        )
        .bind(tenant)
        .bind(encode(&MappingCatalogSnapshot::default())?)
        .execute(&mut **transaction)
        .await
        .map_err(db_error)?;
        let record: String = sqlx::query_scalar(
            "SELECT record FROM a_auth.federation_mapping_catalogs \
             WHERE tenant = $1 FOR UPDATE",
        )
        .bind(tenant)
        .fetch_one(&mut **transaction)
        .await
        .map_err(db_error)?;
        decode(tenant, &record)
    }

    async fn mapping_catalog(&self, tenant: &str) -> Result<MappingCatalog, StoreError> {
        let record: Option<String> = sqlx::query_scalar(
            "SELECT record FROM a_auth.federation_mapping_catalogs WHERE tenant = $1",
        )
        .bind(tenant)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        match record {
            Some(record) => decode(tenant, &record),
            None => Ok(MappingCatalog::default()),
        }
    }

    async fn persist_mapping_catalog(
        transaction: &mut Transaction<'_, Postgres>,
        tenant: &str,
        catalog: &MappingCatalog,
    ) -> Result<(), StoreError> {
        let result = sqlx::query(
            "UPDATE a_auth.federation_mapping_catalogs SET record = $2 WHERE tenant = $1",
        )
        .bind(tenant)
        .bind(encode(&catalog.snapshot(tenant))?)
        .execute(&mut **transaction)
        .await
        .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::Transient(
                "Federation mapping catalog changed".into(),
            ));
        }
        Ok(())
    }
}

impl FederationAttributeMappingsStore for PostgresStore {
    async fn get_registry(
        &self,
        tenant_id: &str,
        upstream_idp_id: &str,
    ) -> Result<Option<MappingRegistry>, StoreError> {
        self.mapping_catalog(tenant_id)
            .await?
            .get_registry(tenant_id, upstream_idp_id)
    }

    async fn change(
        &self,
        tenant_id: &str,
        upstream_idp_id: &str,
        upstream_issuer: &str,
        change: MappingChange,
    ) -> Result<MappingChangeOutcome, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let mut catalog = Self::lock_mapping_catalog(&mut transaction, tenant_id).await?;
        let outcome = catalog.change(tenant_id, upstream_idp_id, upstream_issuer, change)?;
        Self::persist_mapping_catalog(&mut transaction, tenant_id, &catalog).await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(outcome)
    }

    async fn list_by_tenant(&self, tenant_id: &str) -> Result<Vec<MappingRegistry>, StoreError> {
        self.mapping_catalog(tenant_id)
            .await?
            .list_by_tenant(tenant_id)
    }

    async fn governance_count_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        self.mapping_catalog(tenant_id)
            .await?
            .governance_count_all_by_tenant(tenant_id)
    }

    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let mut catalog = Self::lock_mapping_catalog(&mut transaction, tenant_id).await?;
        let removed = catalog.delete_all_by_tenant(tenant_id)?;
        Self::persist_mapping_catalog(&mut transaction, tenant_id, &catalog).await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(removed)
    }
}
