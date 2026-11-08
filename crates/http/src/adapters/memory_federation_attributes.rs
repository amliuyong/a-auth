use std::sync::Arc;

use tokio::sync::Mutex;

use crate::{
    federation_attributes::{
        catalog::MappingCatalog, FederationAttributeMappingsStore, MappingChange,
        MappingChangeOutcome, MappingRegistry,
    },
    ports::StoreError,
};

#[derive(Clone, Default)]
pub struct MemoryFederationAttributeMappingsStore {
    state: Arc<Mutex<MappingCatalog>>,
}

impl FederationAttributeMappingsStore for MemoryFederationAttributeMappingsStore {
    async fn get_registry(
        &self,
        tenant_id: &str,
        upstream_idp_id: &str,
    ) -> Result<Option<MappingRegistry>, StoreError> {
        self.state
            .lock()
            .await
            .get_registry(tenant_id, upstream_idp_id)
    }

    async fn change(
        &self,
        tenant_id: &str,
        upstream_idp_id: &str,
        upstream_issuer: &str,
        change: MappingChange,
    ) -> Result<MappingChangeOutcome, StoreError> {
        self.state
            .lock()
            .await
            .change(tenant_id, upstream_idp_id, upstream_issuer, change)
    }

    async fn list_by_tenant(&self, tenant_id: &str) -> Result<Vec<MappingRegistry>, StoreError> {
        self.state.lock().await.list_by_tenant(tenant_id)
    }

    async fn governance_count_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        self.state
            .lock()
            .await
            .governance_count_all_by_tenant(tenant_id)
    }

    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        self.state.lock().await.delete_all_by_tenant(tenant_id)
    }
}
