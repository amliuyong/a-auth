use crate::attribute_namespace::{
    catalog::NamespaceCatalog, AttributeNamespaceStore, AttributeWriteResolution,
    AudienceResolution, BeginNamespaceChange, BeginNamespaceChangeOutcome, NamespaceChangeOutcome,
    NamespaceOperationCheckpoint, NamespaceRegistration,
};
use crate::ports::StoreError;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Default)]
pub struct MemoryAttributeNamespaceStore {
    state: Arc<Mutex<NamespaceCatalog>>,
}

impl AttributeNamespaceStore for MemoryAttributeNamespaceStore {
    async fn resolve(
        &self,
        tenant: &str,
        verified_aud: &str,
    ) -> Result<AudienceResolution, StoreError> {
        let state = self.state.lock().await;
        state.resolve(tenant, verified_aud)
    }

    async fn resolve_write_authority(
        &self,
        tenant: &str,
        namespace: &str,
    ) -> Result<AttributeWriteResolution, StoreError> {
        let state = self.state.lock().await;
        state.resolve_write_authority(tenant, namespace)
    }

    async fn get(
        &self,
        tenant: &str,
        canonical_namespace: &str,
    ) -> Result<Option<NamespaceRegistration>, StoreError> {
        let state = self.state.lock().await;
        state.get(tenant, canonical_namespace)
    }

    async fn list(&self, tenant: &str) -> Result<Vec<NamespaceRegistration>, StoreError> {
        let state = self.state.lock().await;
        state.list(tenant)
    }

    async fn begin_change(
        &self,
        tenant: &str,
        request: BeginNamespaceChange,
    ) -> Result<BeginNamespaceChangeOutcome, StoreError> {
        let mut state = self.state.lock().await;
        state.begin_change(tenant, request)
    }

    async fn checkpoint(
        &self,
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
        checkpoint: NamespaceOperationCheckpoint,
    ) -> Result<NamespaceChangeOutcome, StoreError> {
        let mut state = self.state.lock().await;
        state.checkpoint(tenant, canonical_namespace, operation_id, checkpoint)
    }

    async fn activate(
        &self,
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
        expected_operation_revision: u64,
    ) -> Result<NamespaceChangeOutcome, StoreError> {
        let mut state = self.state.lock().await;
        state.activate(
            tenant,
            canonical_namespace,
            operation_id,
            expected_operation_revision,
        )
    }

    async fn cancel(
        &self,
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
        expected_operation_revision: u64,
    ) -> Result<NamespaceChangeOutcome, StoreError> {
        let mut state = self.state.lock().await;
        state.cancel(
            tenant,
            canonical_namespace,
            operation_id,
            expected_operation_revision,
        )
    }
}
