use super::{db_error, PostgresStore, PostgresUsersStore};
use crate::{
    attribute_namespace::{AttributeWriteAuthority, AttributeWriteResolution},
    federation_attributes::{
        federated_attribute_owner_is_active, plan_federated_attribute_owner_purge,
        plan_federated_user_reconciliation, DesiredFederatedAttributes,
        FederationAttributeOwnerPurgeOutcome, FederationAttributeReconciliationOutcome,
        FederationAttributeReconciliationRequest, MappingRegistry,
    },
    ports::{FederatedAttributeOwner, StoreError},
};
use std::collections::BTreeMap;

impl PostgresUsersStore {
    pub(crate) async fn reconcile_federated_attributes_authorized(
        &self,
        request: &FederationAttributeReconciliationRequest,
        expected_registry: Option<&MappingRegistry>,
        desired: &DesiredFederatedAttributes,
        expected_namespaces: &BTreeMap<String, AttributeWriteAuthority>,
    ) -> Result<FederationAttributeReconciliationOutcome, StoreError> {
        let mut transaction = self.base.pool.begin().await.map_err(db_error)?;
        let namespaces =
            PostgresStore::lock_namespace_catalog(&mut transaction, &request.storage_tenant_id)
                .await?;
        let mappings =
            PostgresStore::lock_mapping_catalog(&mut transaction, &request.logical_tenant_id)
                .await?;
        let current_registry =
            mappings.get_registry(&request.logical_tenant_id, &request.upstream_idp_id)?;
        if current_registry.as_ref() != expected_registry {
            return Ok(FederationAttributeReconciliationOutcome::AuthorityChanged);
        }
        for (namespace, expected) in expected_namespaces {
            if namespaces.resolve_write_authority(&request.storage_tenant_id, namespace)?
                != AttributeWriteResolution::Authorized(expected.clone())
            {
                return Ok(FederationAttributeReconciliationOutcome::AuthorityChanged);
            }
        }
        let Some(mut locked) = Self::lock_user(
            &mut transaction,
            &request.storage_tenant_id,
            &request.user_id,
        )
        .await?
        else {
            return Ok(FederationAttributeReconciliationOutcome::UserNotFound);
        };
        let outcome = plan_federated_user_reconciliation(
            &locked.record,
            &request.upstream_idp_id,
            desired,
            current_registry
                .as_ref()
                .map_or(0, |registry| registry.revision),
        )?;
        if let FederationAttributeReconciliationOutcome::Applied {
            user,
            changed: true,
            ..
        } = &outcome
        {
            locked.record = user.as_ref().clone();
            Self::write_user(&mut transaction, &request.storage_tenant_id, &locked, false).await?;
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(outcome)
    }

    // Keep the complete owner/revision/registry fence at this transaction seam.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn purge_federated_attribute_owner_authorized(
        &self,
        logical_tenant: &str,
        data_tenant: &str,
        user_id: &str,
        namespace: &str,
        key: &str,
        expected_revision: u64,
        expected_owner: &FederatedAttributeOwner,
        expected_registry: Option<&MappingRegistry>,
    ) -> Result<FederationAttributeOwnerPurgeOutcome, StoreError> {
        let mut transaction = self.base.pool.begin().await.map_err(db_error)?;
        let mappings =
            PostgresStore::lock_mapping_catalog(&mut transaction, logical_tenant).await?;
        let registry = mappings.get_registry(logical_tenant, &expected_owner.upstream_idp_id)?;
        if registry.as_ref() != expected_registry {
            return Ok(FederationAttributeOwnerPurgeOutcome::AuthorityChanged);
        }
        if federated_attribute_owner_is_active(registry.as_ref(), expected_owner, namespace, key) {
            return Ok(FederationAttributeOwnerPurgeOutcome::ActiveOwner {
                owner: expected_owner.clone(),
            });
        }
        let Some(mut locked) = Self::lock_user(&mut transaction, data_tenant, user_id).await?
        else {
            return Ok(FederationAttributeOwnerPurgeOutcome::NotFound);
        };
        let outcome = plan_federated_attribute_owner_purge(
            &locked.record,
            namespace,
            key,
            expected_revision,
            expected_owner,
        )?;
        if let FederationAttributeOwnerPurgeOutcome::Purged { user, .. } = &outcome {
            locked.record = user.as_ref().clone();
            Self::write_user(&mut transaction, data_tenant, &locked, false).await?;
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(outcome)
    }
}
