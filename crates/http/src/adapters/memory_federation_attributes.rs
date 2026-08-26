use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::federation_attributes::{
    AttributeMapping, FederationAttributeMappingsStore, MappingChange, MappingChangeOutcome,
    MappingRegistry, MAPPINGS_MAX_PER_IDP, MAPPING_REGISTRY_MAX_BYTES,
};
use crate::ports::StoreError;

#[derive(Debug, Clone, PartialEq, Eq)]
struct TargetOwner {
    upstream_idp_id: String,
    mapping_id: String,
    mapping_revision: u64,
}

#[derive(Default)]
struct MemoryState {
    registries: BTreeMap<(String, String), MappingRegistry>,
    target_owners: BTreeMap<(String, String, String), TargetOwner>,
    retired_mapping_ids: BTreeSet<(String, String)>,
}

#[derive(Clone, Default)]
pub struct MemoryFederationAttributeMappingsStore {
    state: Arc<Mutex<MemoryState>>,
}

fn next_revision(revision: u64) -> Result<u64, StoreError> {
    revision
        .checked_add(1)
        .ok_or_else(|| StoreError::Permanent("federation mapping revision exhausted".into()))
}

fn target_key(tenant_id: &str, mapping: &AttributeMapping) -> (String, String, String) {
    (
        tenant_id.to_string(),
        mapping.target_namespace.clone(),
        mapping.target_key.clone(),
    )
}

impl FederationAttributeMappingsStore for MemoryFederationAttributeMappingsStore {
    async fn get_registry(
        &self,
        tenant_id: &str,
        upstream_idp_id: &str,
    ) -> Result<Option<MappingRegistry>, StoreError> {
        Ok(self
            .state
            .lock()
            .await
            .registries
            .get(&(tenant_id.to_string(), upstream_idp_id.to_string()))
            .cloned())
    }

    async fn change(
        &self,
        tenant_id: &str,
        upstream_idp_id: &str,
        upstream_issuer: &str,
        change: MappingChange,
    ) -> Result<MappingChangeOutcome, StoreError> {
        let mut state = self.state.lock().await;
        let registry_key = (tenant_id.to_string(), upstream_idp_id.to_string());
        let current_registry_revision = state
            .registries
            .get(&registry_key)
            .map_or(0, |registry| registry.revision);

        match change {
            MappingChange::Create {
                mapping_id,
                expected_registry_revision,
                spec,
            } => {
                if current_registry_revision != expected_registry_revision {
                    return Ok(MappingChangeOutcome::Conflict);
                }
                if let Err(error) =
                    AttributeMapping::validate_id(&mapping_id).and_then(|_| spec.validate())
                {
                    return Ok(MappingChangeOutcome::Invalid(error));
                }
                if state
                    .retired_mapping_ids
                    .contains(&(tenant_id.to_string(), mapping_id.clone()))
                {
                    return Ok(MappingChangeOutcome::MappingIdRetired);
                }
                if state.registries.get(&registry_key).is_some_and(|registry| {
                    (!registry.mappings.is_empty() && registry.upstream_issuer != upstream_issuer)
                        || registry
                            .mappings
                            .iter()
                            .any(|mapping| mapping.mapping_id == mapping_id)
                }) {
                    return Ok(MappingChangeOutcome::Conflict);
                }
                if state
                    .registries
                    .get(&registry_key)
                    .is_some_and(|registry| registry.mappings.len() >= MAPPINGS_MAX_PER_IDP)
                {
                    return Ok(MappingChangeOutcome::LimitExceeded);
                }

                let mapping = AttributeMapping::from_spec(mapping_id.clone(), 1, true, spec);
                let owner_key = target_key(tenant_id, &mapping);
                if state.target_owners.contains_key(&owner_key) {
                    return Ok(MappingChangeOutcome::TargetConflict);
                }
                let next_registry_revision = next_revision(current_registry_revision)?;
                let mut registry =
                    state
                        .registries
                        .get(&registry_key)
                        .cloned()
                        .unwrap_or(MappingRegistry {
                            tenant_id: tenant_id.to_string(),
                            upstream_idp_id: upstream_idp_id.to_string(),
                            upstream_issuer: upstream_issuer.to_string(),
                            revision: 0,
                            mappings: Vec::new(),
                        });
                if registry.mappings.is_empty() {
                    registry.upstream_issuer = upstream_issuer.to_string();
                }
                registry.revision = next_registry_revision;
                registry.mappings.push(mapping.clone());
                registry
                    .mappings
                    .sort_by(|left, right| left.mapping_id.cmp(&right.mapping_id));
                if serde_json::to_vec(&registry)
                    .map_or(true, |json| json.len() > MAPPING_REGISTRY_MAX_BYTES)
                {
                    return Ok(MappingChangeOutcome::LimitExceeded);
                }
                let output = registry.clone();
                state.registries.insert(registry_key, registry);
                state.target_owners.insert(
                    owner_key,
                    TargetOwner {
                        upstream_idp_id: upstream_idp_id.to_string(),
                        mapping_id: mapping_id.clone(),
                        mapping_revision: 1,
                    },
                );
                state
                    .retired_mapping_ids
                    .insert((tenant_id.to_string(), mapping_id));
                Ok(MappingChangeOutcome::Applied(output))
            }
            MappingChange::Update {
                mapping_id,
                expected_registry_revision,
                expected_mapping_revision,
                enabled,
                spec,
            } => {
                if current_registry_revision != expected_registry_revision {
                    return Ok(MappingChangeOutcome::Conflict);
                }
                if let Err(error) = spec.validate() {
                    return Ok(MappingChangeOutcome::Invalid(error));
                }
                let Some(current_registry) = state.registries.get(&registry_key).cloned() else {
                    return Ok(MappingChangeOutcome::NotFound);
                };
                if current_registry.upstream_issuer != upstream_issuer {
                    return Ok(MappingChangeOutcome::Conflict);
                }
                let Some(current_mapping) = current_registry
                    .mappings
                    .iter()
                    .find(|mapping| mapping.mapping_id == mapping_id)
                    .cloned()
                else {
                    return Ok(MappingChangeOutcome::NotFound);
                };
                if current_mapping.revision != expected_mapping_revision {
                    return Ok(MappingChangeOutcome::Conflict);
                }

                let current_owner = TargetOwner {
                    upstream_idp_id: upstream_idp_id.to_string(),
                    mapping_id: mapping_id.clone(),
                    mapping_revision: current_mapping.revision,
                };
                let current_owner_key = target_key(tenant_id, &current_mapping);
                if current_mapping.enabled
                    && state.target_owners.get(&current_owner_key) != Some(&current_owner)
                {
                    return Ok(MappingChangeOutcome::Conflict);
                }

                let next_mapping_revision = next_revision(current_mapping.revision)?;
                let updated_mapping = AttributeMapping::from_spec(
                    mapping_id.clone(),
                    next_mapping_revision,
                    enabled,
                    spec,
                );
                let updated_owner_key = target_key(tenant_id, &updated_mapping);
                if enabled
                    && state
                        .target_owners
                        .get(&updated_owner_key)
                        .is_some_and(|owner| {
                            updated_owner_key != current_owner_key || owner != &current_owner
                        })
                {
                    return Ok(MappingChangeOutcome::TargetConflict);
                }

                let mut updated_registry = current_registry;
                updated_registry.revision = next_revision(updated_registry.revision)?;
                let mapping = updated_registry
                    .mappings
                    .iter_mut()
                    .find(|mapping| mapping.mapping_id == mapping_id)
                    .expect("mapping was checked above");
                *mapping = updated_mapping.clone();
                if serde_json::to_vec(&updated_registry)
                    .map_or(true, |json| json.len() > MAPPING_REGISTRY_MAX_BYTES)
                {
                    return Ok(MappingChangeOutcome::LimitExceeded);
                }

                if current_mapping.enabled {
                    state.target_owners.remove(&current_owner_key);
                }
                if enabled {
                    state.target_owners.insert(
                        updated_owner_key,
                        TargetOwner {
                            upstream_idp_id: upstream_idp_id.to_string(),
                            mapping_id,
                            mapping_revision: updated_mapping.revision,
                        },
                    );
                }
                let output = updated_registry.clone();
                state.registries.insert(registry_key, updated_registry);
                Ok(MappingChangeOutcome::Applied(output))
            }
            MappingChange::SetEnabled {
                mapping_id,
                expected_registry_revision,
                expected_mapping_revision,
                enabled,
            } => {
                if current_registry_revision != expected_registry_revision {
                    return Ok(MappingChangeOutcome::Conflict);
                }
                let Some(current_registry) = state.registries.get(&registry_key).cloned() else {
                    return Ok(MappingChangeOutcome::NotFound);
                };
                if current_registry.upstream_issuer != upstream_issuer {
                    return Ok(MappingChangeOutcome::Conflict);
                }
                let Some(current_mapping) = current_registry
                    .mappings
                    .iter()
                    .find(|mapping| mapping.mapping_id == mapping_id)
                    .cloned()
                else {
                    return Ok(MappingChangeOutcome::NotFound);
                };
                if current_mapping.revision != expected_mapping_revision {
                    return Ok(MappingChangeOutcome::Conflict);
                }
                if current_mapping.enabled == enabled {
                    return Ok(MappingChangeOutcome::Applied(current_registry));
                }
                let owner_key = target_key(tenant_id, &current_mapping);
                if enabled && state.target_owners.contains_key(&owner_key) {
                    return Ok(MappingChangeOutcome::TargetConflict);
                }

                if !enabled {
                    let expected_owner = TargetOwner {
                        upstream_idp_id: upstream_idp_id.to_string(),
                        mapping_id: mapping_id.clone(),
                        mapping_revision: current_mapping.revision,
                    };
                    if state.target_owners.get(&owner_key) != Some(&expected_owner) {
                        return Ok(MappingChangeOutcome::Conflict);
                    }
                    state.target_owners.remove(&owner_key);
                }

                let next_mapping_revision = next_revision(current_mapping.revision)?;
                let next_registry_revision = next_revision(current_registry.revision)?;
                let registry = state
                    .registries
                    .get_mut(&registry_key)
                    .expect("registry was checked above");
                let mapping = registry
                    .mappings
                    .iter_mut()
                    .find(|mapping| mapping.mapping_id == mapping_id)
                    .expect("mapping was checked above");
                mapping.enabled = enabled;
                mapping.revision = next_mapping_revision;
                let updated_mapping = mapping.clone();
                registry.revision = next_registry_revision;
                let output = registry.clone();
                if enabled {
                    state.target_owners.insert(
                        owner_key,
                        TargetOwner {
                            upstream_idp_id: upstream_idp_id.to_string(),
                            mapping_id,
                            mapping_revision: updated_mapping.revision,
                        },
                    );
                }
                Ok(MappingChangeOutcome::Applied(output))
            }
            MappingChange::Delete {
                mapping_id,
                expected_registry_revision,
                expected_mapping_revision,
            } => {
                if current_registry_revision != expected_registry_revision {
                    return Ok(MappingChangeOutcome::Conflict);
                }
                let Some(current_registry) = state.registries.get(&registry_key).cloned() else {
                    return Ok(MappingChangeOutcome::NotFound);
                };
                if current_registry.upstream_issuer != upstream_issuer {
                    return Ok(MappingChangeOutcome::Conflict);
                }
                let Some(current_mapping) = current_registry
                    .mappings
                    .iter()
                    .find(|mapping| mapping.mapping_id == mapping_id)
                    .cloned()
                else {
                    return Ok(MappingChangeOutcome::NotFound);
                };
                if current_mapping.revision != expected_mapping_revision {
                    return Ok(MappingChangeOutcome::Conflict);
                }
                let owner_key = target_key(tenant_id, &current_mapping);
                if current_mapping.enabled {
                    let expected_owner = TargetOwner {
                        upstream_idp_id: upstream_idp_id.to_string(),
                        mapping_id: mapping_id.clone(),
                        mapping_revision: current_mapping.revision,
                    };
                    if state.target_owners.get(&owner_key) != Some(&expected_owner) {
                        return Ok(MappingChangeOutcome::Conflict);
                    }
                    state.target_owners.remove(&owner_key);
                }
                let next_registry_revision = next_revision(current_registry.revision)?;
                let registry = state
                    .registries
                    .get_mut(&registry_key)
                    .expect("registry was checked above");
                registry
                    .mappings
                    .retain(|mapping| mapping.mapping_id != mapping_id);
                registry.revision = next_registry_revision;
                let output = registry.clone();
                state
                    .retired_mapping_ids
                    .insert((tenant_id.to_string(), mapping_id));
                Ok(MappingChangeOutcome::Applied(output))
            }
        }
    }

    async fn list_by_tenant(&self, tenant_id: &str) -> Result<Vec<MappingRegistry>, StoreError> {
        let state = self.state.lock().await;
        let mut registries = state
            .registries
            .iter()
            .filter(|((tenant, _), _)| tenant == tenant_id)
            .map(|(_, registry)| registry.clone())
            .collect::<Vec<_>>();
        registries.sort_by(|left, right| left.upstream_idp_id.cmp(&right.upstream_idp_id));
        Ok(registries)
    }

    async fn governance_count_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        let state = self.state.lock().await;
        Ok(state
            .registries
            .keys()
            .filter(|(tenant, _)| tenant == tenant_id)
            .count()
            .saturating_add(
                state
                    .target_owners
                    .keys()
                    .filter(|(tenant, _, _)| tenant == tenant_id)
                    .count(),
            )
            .saturating_add(
                state
                    .retired_mapping_ids
                    .iter()
                    .filter(|(tenant, _)| tenant == tenant_id)
                    .count(),
            ))
    }

    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        let mut state = self.state.lock().await;
        let before_registries = state.registries.len();
        state
            .registries
            .retain(|(tenant, _), _| tenant != tenant_id);
        let before_targets = state.target_owners.len();
        state
            .target_owners
            .retain(|(tenant, _, _), _| tenant != tenant_id);
        let before_markers = state.retired_mapping_ids.len();
        state
            .retired_mapping_ids
            .retain(|(tenant, _)| tenant != tenant_id);
        Ok(before_registries
            .saturating_sub(state.registries.len())
            .saturating_add(before_targets.saturating_sub(state.target_owners.len()))
            .saturating_add(before_markers.saturating_sub(state.retired_mapping_ids.len())))
    }
}
