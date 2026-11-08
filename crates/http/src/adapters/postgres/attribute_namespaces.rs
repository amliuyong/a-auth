use super::{db_error, PostgresStore};
use crate::{
    attribute_namespace::{
        catalog::{NamespaceCatalog, NamespaceCatalogSnapshot},
        AttributeNamespaceStore, AttributeWriteResolution, AudienceResolution,
        BeginNamespaceChange, BeginNamespaceChangeOutcome, NamespaceChangeOutcome,
        NamespaceOperationCheckpoint, NamespaceRegistration,
    },
    ports::StoreError,
};
use sqlx::{Postgres, Transaction};

fn decode(tenant: &str, record: &str) -> Result<NamespaceCatalog, StoreError> {
    let snapshot: NamespaceCatalogSnapshot = serde_json::from_str(record)
        .map_err(|_| StoreError::Permanent("Invalid namespace catalog snapshot".into()))?;
    NamespaceCatalog::from_snapshot(tenant, snapshot)
}

fn encode(snapshot: &NamespaceCatalogSnapshot) -> Result<String, StoreError> {
    serde_json::to_string(snapshot)
        .map_err(|_| StoreError::Permanent("Namespace catalog encoding failed".into()))
}

impl PostgresStore {
    /// The tenant row also fences names that do not exist yet. Transactions
    /// authorizing user attributes must lock this row before the user row so
    /// an unbound namespace cannot become bound during its authority check.
    pub(super) async fn lock_namespace_catalog(
        transaction: &mut Transaction<'_, Postgres>,
        tenant: &str,
    ) -> Result<NamespaceCatalog, StoreError> {
        sqlx::query(
            "INSERT INTO a_auth.namespace_catalogs (tenant, record) VALUES ($1, $2) \
             ON CONFLICT (tenant) DO NOTHING",
        )
        .bind(tenant)
        .bind(encode(&NamespaceCatalogSnapshot::default())?)
        .execute(&mut **transaction)
        .await
        .map_err(db_error)?;
        let record: String = sqlx::query_scalar(
            "SELECT record FROM a_auth.namespace_catalogs WHERE tenant = $1 FOR UPDATE",
        )
        .bind(tenant)
        .fetch_one(&mut **transaction)
        .await
        .map_err(db_error)?;
        decode(tenant, &record)
    }

    async fn namespace_catalog(&self, tenant: &str) -> Result<NamespaceCatalog, StoreError> {
        let record: Option<String> =
            sqlx::query_scalar("SELECT record FROM a_auth.namespace_catalogs WHERE tenant = $1")
                .bind(tenant)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_error)?;
        match record {
            Some(record) => decode(tenant, &record),
            None => Ok(NamespaceCatalog::default()),
        }
    }

    async fn persist_namespace_catalog(
        transaction: &mut Transaction<'_, Postgres>,
        tenant: &str,
        catalog: &NamespaceCatalog,
    ) -> Result<(), StoreError> {
        let record = encode(&catalog.snapshot(tenant))?;
        let result =
            sqlx::query("UPDATE a_auth.namespace_catalogs SET record = $2 WHERE tenant = $1")
                .bind(tenant)
                .bind(record)
                .execute(&mut **transaction)
                .await
                .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::Transient(
                "Namespace catalog disappeared".into(),
            ));
        }
        Ok(())
    }
}

impl AttributeNamespaceStore for PostgresStore {
    async fn resolve(
        &self,
        tenant: &str,
        verified_aud: &str,
    ) -> Result<AudienceResolution, StoreError> {
        self.namespace_catalog(tenant)
            .await?
            .resolve(tenant, verified_aud)
    }

    async fn resolve_write_authority(
        &self,
        tenant: &str,
        namespace: &str,
    ) -> Result<AttributeWriteResolution, StoreError> {
        self.namespace_catalog(tenant)
            .await?
            .resolve_write_authority(tenant, namespace)
    }

    async fn get(
        &self,
        tenant: &str,
        canonical_namespace: &str,
    ) -> Result<Option<NamespaceRegistration>, StoreError> {
        self.namespace_catalog(tenant)
            .await?
            .get(tenant, canonical_namespace)
    }

    async fn list(&self, tenant: &str) -> Result<Vec<NamespaceRegistration>, StoreError> {
        self.namespace_catalog(tenant).await?.list(tenant)
    }

    async fn begin_change(
        &self,
        tenant: &str,
        request: BeginNamespaceChange,
    ) -> Result<BeginNamespaceChangeOutcome, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let mut catalog = Self::lock_namespace_catalog(&mut transaction, tenant).await?;
        let outcome = catalog.begin_change(tenant, request)?;
        Self::persist_namespace_catalog(&mut transaction, tenant, &catalog).await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(outcome)
    }

    async fn checkpoint(
        &self,
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
        checkpoint: NamespaceOperationCheckpoint,
    ) -> Result<NamespaceChangeOutcome, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let mut catalog = Self::lock_namespace_catalog(&mut transaction, tenant).await?;
        let outcome = catalog.checkpoint(tenant, canonical_namespace, operation_id, checkpoint)?;
        Self::persist_namespace_catalog(&mut transaction, tenant, &catalog).await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(outcome)
    }

    async fn activate(
        &self,
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
        expected_operation_revision: u64,
    ) -> Result<NamespaceChangeOutcome, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let mut catalog = Self::lock_namespace_catalog(&mut transaction, tenant).await?;
        let outcome = catalog.activate(
            tenant,
            canonical_namespace,
            operation_id,
            expected_operation_revision,
        )?;
        Self::persist_namespace_catalog(&mut transaction, tenant, &catalog).await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(outcome)
    }

    async fn cancel(
        &self,
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
        expected_operation_revision: u64,
    ) -> Result<NamespaceChangeOutcome, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let mut catalog = Self::lock_namespace_catalog(&mut transaction, tenant).await?;
        let outcome = catalog.cancel(
            tenant,
            canonical_namespace,
            operation_id,
            expected_operation_revision,
        )?;
        Self::persist_namespace_catalog(&mut transaction, tenant, &catalog).await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(outcome)
    }
}
