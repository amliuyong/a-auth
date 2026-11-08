//! Pure tenant-wide federation mapping authority, shared by storage adapters.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    AttributeMapping, MappingChange, MappingChangeOutcome, MappingRegistry, MAPPINGS_MAX_PER_IDP,
    MAPPING_REGISTRY_MAX_BYTES,
};
use crate::ports::StoreError;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "postgres", derive(serde::Serialize, serde::Deserialize))]
struct TargetOwner {
    upstream_idp_id: String,
    mapping_id: String,
    mapping_revision: u64,
}

#[derive(Default)]
pub(crate) struct MappingCatalog {
    registries: BTreeMap<(String, String), MappingRegistry>,
    target_owners: BTreeMap<(String, String, String), TargetOwner>,
    retired_mapping_ids: BTreeSet<(String, String)>,
}

/// Required fields keep a truncated authority row from becoming an empty,
/// permissive registry. Tuple map keys use a list in the persistence format.
#[cfg(feature = "postgres")]
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MappingCatalogSnapshot {
    registries: BTreeMap<String, MappingRegistry>,
    target_owners: Vec<(String, String, TargetOwner)>,
    retired_mapping_ids: BTreeSet<String>,
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

impl MappingCatalog {
    #[cfg(feature = "postgres")]
    pub(crate) fn from_snapshot(
        tenant: &str,
        snapshot: MappingCatalogSnapshot,
    ) -> Result<Self, StoreError> {
        let invalid = || StoreError::Permanent("Invalid federation mapping catalog".into());
        let mut expected_owners = BTreeMap::new();
        let mut present_ids = BTreeSet::new();
        if snapshot
            .retired_mapping_ids
            .iter()
            .any(|id| AttributeMapping::validate_id(id).is_err())
        {
            return Err(invalid());
        }
        for (idp, registry) in &snapshot.registries {
            if registry.tenant_id != tenant
                || &registry.upstream_idp_id != idp
                || registry.revision == 0
                || registry.mappings.len() > MAPPINGS_MAX_PER_IDP
                || serde_json::to_vec(registry)
                    .map_or(true, |json| json.len() > MAPPING_REGISTRY_MAX_BYTES)
            {
                return Err(invalid());
            }
            for mapping in &registry.mappings {
                let spec = super::MappingSpec {
                    source_claim: mapping.source_claim.clone(),
                    target_namespace: mapping.target_namespace.clone(),
                    target_key: mapping.target_key.clone(),
                    mode: mapping.mode.clone(),
                };
                if mapping.revision == 0
                    || AttributeMapping::validate_id(&mapping.mapping_id).is_err()
                    || spec.validate().is_err()
                    || !snapshot.retired_mapping_ids.contains(&mapping.mapping_id)
                    || !present_ids.insert(mapping.mapping_id.clone())
                {
                    return Err(invalid());
                }
                if mapping.enabled {
                    let owner = TargetOwner {
                        upstream_idp_id: idp.clone(),
                        mapping_id: mapping.mapping_id.clone(),
                        mapping_revision: mapping.revision,
                    };
                    if expected_owners
                        .insert(
                            (mapping.target_namespace.clone(), mapping.target_key.clone()),
                            owner,
                        )
                        .is_some()
                    {
                        return Err(invalid());
                    }
                }
            }
        }
        let mut owners = BTreeMap::new();
        for (namespace, key, owner) in snapshot.target_owners {
            if owners.insert((namespace, key), owner).is_some() {
                return Err(invalid());
            }
        }
        if owners != expected_owners {
            return Err(invalid());
        }
        Ok(Self {
            registries: snapshot
                .registries
                .into_iter()
                .map(|(idp, registry)| ((tenant.to_owned(), idp), registry))
                .collect(),
            target_owners: owners
                .into_iter()
                .map(|((namespace, key), owner)| ((tenant.to_owned(), namespace, key), owner))
                .collect(),
            retired_mapping_ids: snapshot
                .retired_mapping_ids
                .into_iter()
                .map(|id| (tenant.to_owned(), id))
                .collect(),
        })
    }

    #[cfg(feature = "postgres")]
    pub(crate) fn snapshot(&self, tenant: &str) -> MappingCatalogSnapshot {
        MappingCatalogSnapshot {
            registries: self
                .registries
                .iter()
                .filter(|((owner, _), _)| owner == tenant)
                .map(|((_, idp), registry)| (idp.clone(), registry.clone()))
                .collect(),
            target_owners: self
                .target_owners
                .iter()
                .filter(|((owner, _, _), _)| owner == tenant)
                .map(|((_, namespace, key), owner)| (namespace.clone(), key.clone(), owner.clone()))
                .collect(),
            retired_mapping_ids: self
                .retired_mapping_ids
                .iter()
                .filter(|(owner, _)| owner == tenant)
                .map(|(_, id)| id.clone())
                .collect(),
        }
    }

    pub(crate) fn get_registry(
        &self,
        tenant_id: &str,
        upstream_idp_id: &str,
    ) -> Result<Option<MappingRegistry>, StoreError> {
        Ok(self
            .registries
            .get(&(tenant_id.to_string(), upstream_idp_id.to_string()))
            .cloned())
    }

    pub(crate) fn change(
        &mut self,
        tenant_id: &str,
        upstream_idp_id: &str,
        upstream_issuer: &str,
        change: MappingChange,
    ) -> Result<MappingChangeOutcome, StoreError> {
        let state = self;
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
                }

                let next_mapping_revision = next_revision(current_mapping.revision)?;
                let next_registry_revision = next_revision(current_registry.revision)?;
                if !enabled {
                    state.target_owners.remove(&owner_key);
                }
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
                }
                let next_registry_revision = next_revision(current_registry.revision)?;
                if current_mapping.enabled {
                    state.target_owners.remove(&owner_key);
                }
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

    pub(crate) fn list_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<MappingRegistry>, StoreError> {
        let state = self;
        let mut registries = state
            .registries
            .iter()
            .filter(|((tenant, _), _)| tenant == tenant_id)
            .map(|(_, registry)| registry.clone())
            .collect::<Vec<_>>();
        registries.sort_by(|left, right| left.upstream_idp_id.cmp(&right.upstream_idp_id));
        Ok(registries)
    }

    pub(crate) fn governance_count_all_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<usize, StoreError> {
        let state = self;
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

    pub(crate) fn delete_all_by_tenant(&mut self, tenant_id: &str) -> Result<usize, StoreError> {
        let state = self;
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
#[cfg(test)]
mod tests {
    use super::*;

    fn exhausted_catalog() -> MappingCatalog {
        let mut catalog = MappingCatalog::default();
        let result = catalog
            .change(
                "tenant",
                "primary",
                "https://identity.example.test",
                MappingChange::Create {
                    mapping_id: "fm_primary".into(),
                    expected_registry_revision: 0,
                    spec: super::super::MappingSpec {
                        source_claim: "department".into(),
                        target_namespace: "https://resource.example.test/attributes".into(),
                        target_key: "department".into(),
                        mode: super::super::MappingMode::CopyString,
                    },
                },
            )
            .unwrap();
        assert!(matches!(result, MappingChangeOutcome::Applied(_)));
        let registry = catalog
            .registries
            .get_mut(&("tenant".into(), "primary".into()))
            .unwrap();
        registry.revision = u64::MAX;
        registry.mappings[0].revision = u64::MAX;
        catalog
            .target_owners
            .values_mut()
            .next()
            .unwrap()
            .mapping_revision = u64::MAX;
        catalog
    }

    fn assert_preserved_after_failure(change: MappingChange) {
        let mut catalog = exhausted_catalog();
        assert!(matches!(
            catalog.change("tenant", "primary", "https://identity.example.test", change),
            Err(StoreError::Permanent(_))
        ));
        let registry = catalog.get_registry("tenant", "primary").unwrap().unwrap();
        assert_eq!(registry.revision, u64::MAX);
        assert_eq!(registry.mappings[0].revision, u64::MAX);
        assert!(registry.mappings[0].enabled);
        assert_eq!(
            catalog.governance_count_all_by_tenant("tenant").unwrap(),
            3,
            "a rejected transition must preserve registry, target ownership and permanent marker"
        );
    }

    #[test]
    fn mapping_disable_exhaustion_preserves_target_authority() {
        assert_preserved_after_failure(MappingChange::SetEnabled {
            mapping_id: "fm_primary".into(),
            expected_registry_revision: u64::MAX,
            expected_mapping_revision: u64::MAX,
            enabled: false,
        });
    }

    #[test]
    fn mapping_delete_exhaustion_preserves_target_authority() {
        assert_preserved_after_failure(MappingChange::Delete {
            mapping_id: "fm_primary".into(),
            expected_registry_revision: u64::MAX,
            expected_mapping_revision: u64::MAX,
        });
    }
}
