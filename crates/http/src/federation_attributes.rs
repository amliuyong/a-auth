use std::{collections::BTreeMap, future::Future};

use serde::{Deserialize, Serialize};

use crate::ports::StoreError;

pub const MAPPINGS_MAX_PER_IDP: usize = 32;
pub const MAPPING_REGISTRY_MAX_BYTES: usize = 65_536;
const MAPPING_ID_MAX_BYTES: usize = 128;
const SOURCE_CLAIM_MAX_BYTES: usize = 256;
const TARGET_KEY_MAX_BYTES: usize = 128;
const MAPPING_VALUE_MAX_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MappingMode {
    CopyString,
    ExactMembership {
        source_value: String,
        target_value: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributeMapping {
    pub mapping_id: String,
    pub revision: u64,
    pub enabled: bool,
    pub source_claim: String,
    pub target_namespace: String,
    pub target_key: String,
    pub mode: MappingMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingSpec {
    pub source_claim: String,
    pub target_namespace: String,
    pub target_key: String,
    pub mode: MappingMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappingValidationError {
    InvalidMappingId,
    InvalidSourceClaim,
    InvalidTargetNamespace,
    InvalidTargetKey,
    ReservedTargetKey,
    InvalidModeValue,
}

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && !value.chars().any(char::is_control)
        && value.trim() == value
}

fn reserved_target_key(value: &str) -> bool {
    matches!(
        value,
        "iss"
            | "sub"
            | "aud"
            | "exp"
            | "nbf"
            | "iat"
            | "jti"
            | "nonce"
            | "sid"
            | "acr"
            | "amr"
            | "auth_time"
            | "tenant_id"
            | "user_id"
            | "status"
            | "credential_epoch"
            | "sub_type"
            | "auth_grant"
            | "actor_types"
            | "tenant_role"
            | "platform_role"
    )
}

impl MappingSpec {
    pub fn validate(&self) -> Result<(), MappingValidationError> {
        if !valid_text(&self.source_claim, SOURCE_CLAIM_MAX_BYTES) {
            return Err(MappingValidationError::InvalidSourceClaim);
        }
        if !crate::attribute_namespace::validate_namespace_uri(&self.target_namespace) {
            return Err(MappingValidationError::InvalidTargetNamespace);
        }
        if !valid_text(&self.target_key, TARGET_KEY_MAX_BYTES) {
            return Err(MappingValidationError::InvalidTargetKey);
        }
        if reserved_target_key(&self.target_key) {
            return Err(MappingValidationError::ReservedTargetKey);
        }
        if let MappingMode::ExactMembership {
            source_value,
            target_value,
        } = &self.mode
        {
            if !valid_text(source_value, MAPPING_VALUE_MAX_BYTES)
                || !valid_text(target_value, MAPPING_VALUE_MAX_BYTES)
            {
                return Err(MappingValidationError::InvalidModeValue);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingRegistry {
    pub tenant_id: String,
    pub upstream_idp_id: String,
    pub upstream_issuer: String,
    pub revision: u64,
    pub mappings: Vec<AttributeMapping>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappingChange {
    Create {
        mapping_id: String,
        expected_registry_revision: u64,
        spec: MappingSpec,
    },
    Update {
        mapping_id: String,
        expected_registry_revision: u64,
        expected_mapping_revision: u64,
        enabled: bool,
        spec: MappingSpec,
    },
    SetEnabled {
        mapping_id: String,
        expected_registry_revision: u64,
        expected_mapping_revision: u64,
        enabled: bool,
    },
    Delete {
        mapping_id: String,
        expected_registry_revision: u64,
        expected_mapping_revision: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappingChangeOutcome {
    Applied(MappingRegistry),
    Conflict,
    TargetConflict,
    MappingIdRetired,
    NotFound,
    Invalid(MappingValidationError),
    LimitExceeded,
}

pub trait FederationAttributeMappingsStore: Send + Sync {
    fn get_registry(
        &self,
        tenant_id: &str,
        upstream_idp_id: &str,
    ) -> impl Future<Output = Result<Option<MappingRegistry>, StoreError>> + Send;

    fn change(
        &self,
        tenant_id: &str,
        upstream_idp_id: &str,
        upstream_issuer: &str,
        change: MappingChange,
    ) -> impl Future<Output = Result<MappingChangeOutcome, StoreError>> + Send;

    fn list_by_tenant(
        &self,
        tenant_id: &str,
    ) -> impl Future<Output = Result<Vec<MappingRegistry>, StoreError>> + Send;

    fn governance_count_all_by_tenant(
        &self,
        tenant_id: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;

    fn delete_all_by_tenant(
        &self,
        tenant_id: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappingEvaluation {
    Present(String),
    Absent,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FederationAttributeReconciliationRequest {
    pub operation_id: String,
    pub logical_tenant_id: String,
    pub storage_tenant_id: String,
    pub upstream_idp_id: String,
    pub upstream_issuer: String,
    pub user_id: String,
    pub verified_claims: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationAttributeReconciliationOutcome {
    Applied {
        previous_user: Box<crate::ports::UserRecord>,
        user: Box<crate::ports::UserRecord>,
        registry_revision: u64,
        changed: bool,
    },
    UserNotFound,
    UserDisabled,
    UserTombstoned,
    OwnershipConflict {
        namespace: String,
        key: String,
    },
    NamespaceBlocked {
        namespace: String,
    },
    AuthorityChanged,
    TooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationAttributeOwnerPurgeOutcome {
    Purged {
        user: Box<crate::ports::UserRecord>,
        owner: crate::ports::FederatedAttributeOwner,
        previous_value: String,
    },
    NotFound,
    Tombstoned,
    OwnerNotFound,
    ActiveOwner {
        owner: crate::ports::FederatedAttributeOwner,
    },
    RevisionConflict {
        current: u64,
    },
    AuthorityChanged,
}

pub fn federated_attribute_owner_is_active(
    registry: Option<&MappingRegistry>,
    owner: &crate::ports::FederatedAttributeOwner,
    namespace: &str,
    key: &str,
) -> bool {
    registry.is_some_and(|registry| {
        registry.upstream_idp_id == owner.upstream_idp_id
            && registry.upstream_issuer == owner.upstream_issuer
            && registry.mappings.iter().any(|mapping| {
                mapping.mapping_id == owner.mapping_id
                    && mapping.revision == owner.mapping_revision
                    && mapping.enabled
                    && mapping.target_namespace == namespace
                    && mapping.target_key == key
            })
    })
}

pub(crate) fn plan_federated_attribute_owner_purge(
    current: &crate::ports::UserRecord,
    namespace: &str,
    key: &str,
    expected_revision: u64,
    expected_owner: &crate::ports::FederatedAttributeOwner,
) -> Result<FederationAttributeOwnerPurgeOutcome, StoreError> {
    if current.status == crate::ports::UserStatus::Tombstoned {
        return Ok(FederationAttributeOwnerPurgeOutcome::Tombstoned);
    }
    let Some(attributes) = current.attributes.get(namespace) else {
        return Ok(FederationAttributeOwnerPurgeOutcome::OwnerNotFound);
    };
    if attributes.revision != expected_revision {
        return Ok(FederationAttributeOwnerPurgeOutcome::RevisionConflict {
            current: attributes.revision,
        });
    }
    if attributes.federation_owners.get(key) != Some(expected_owner) {
        return Ok(FederationAttributeOwnerPurgeOutcome::AuthorityChanged);
    }

    let mut next = current.clone();
    let previous_value =
        attributes.kv.get(key).cloned().ok_or_else(|| {
            StoreError::Permanent("federation owner has no attribute value".into())
        })?;
    let next_attributes = next
        .attributes
        .get_mut(namespace)
        .expect("checked namespace above");
    next_attributes.kv.remove(key);
    next_attributes.federation_owners.remove(key);
    next_attributes.revision = next_attributes.revision.checked_add(1).ok_or_else(|| {
        StoreError::Permanent("namespace attributes revision exhausted during owner purge".into())
    })?;
    next.attributes_generation = next
        .attributes_generation
        .checked_add(1)
        .ok_or_else(|| StoreError::Permanent("user attributes generation exhausted".into()))?;
    Ok(FederationAttributeOwnerPurgeOutcome::Purged {
        user: Box::new(next),
        owner: expected_owner.clone(),
        previous_value,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DesiredFederatedAttribute {
    pub namespace: String,
    pub key: String,
    pub value: String,
    pub owner: crate::ports::FederatedAttributeOwner,
}

pub(crate) type DesiredFederatedAttributes = BTreeMap<(String, String), DesiredFederatedAttribute>;

#[cfg(feature = "aws")]
pub(crate) fn reconciliation_fingerprint(
    request: &FederationAttributeReconciliationRequest,
    registry: Option<&MappingRegistry>,
    desired: &DesiredFederatedAttributes,
) -> Result<String, StoreError> {
    use base64::Engine as _;
    use sha2::Digest as _;

    let payload = serde_json::to_vec(&serde_json::json!({
        "logical_tenant_id": request.logical_tenant_id,
        "storage_tenant_id": request.storage_tenant_id,
        "upstream_idp_id": request.upstream_idp_id,
        "upstream_issuer": request.upstream_issuer,
        "user_id": request.user_id,
        "registry": registry,
        "desired": desired.values().map(|value| serde_json::json!({
            "namespace": value.namespace,
            "key": value.key,
            "value": value.value,
            "owner": value.owner,
        })).collect::<Vec<_>>(),
    }))
    .map_err(|error| {
        StoreError::Permanent(format!(
            "serialize federation reconciliation fingerprint: {error}"
        ))
    })?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(payload)))
}

pub(crate) fn plan_federated_user_reconciliation(
    current: &crate::ports::UserRecord,
    upstream_idp_id: &str,
    desired: &DesiredFederatedAttributes,
    registry_revision: u64,
) -> Result<FederationAttributeReconciliationOutcome, StoreError> {
    if current.status == crate::ports::UserStatus::Tombstoned {
        return Ok(FederationAttributeReconciliationOutcome::UserTombstoned);
    }
    if current.status == crate::ports::UserStatus::Disabled {
        return Ok(FederationAttributeReconciliationOutcome::UserDisabled);
    }

    for desired_value in desired.values() {
        let Some(current_namespace) = current.attributes.get(&desired_value.namespace) else {
            continue;
        };
        if !current_namespace.kv.contains_key(&desired_value.key) {
            continue;
        }
        match current_namespace.federation_owners.get(&desired_value.key) {
            Some(owner) if owner.upstream_idp_id == upstream_idp_id => {}
            _ => {
                return Ok(
                    FederationAttributeReconciliationOutcome::OwnershipConflict {
                        namespace: desired_value.namespace.clone(),
                        key: desired_value.key.clone(),
                    },
                );
            }
        }
    }

    let mut user = current.clone();
    let mut touched_namespaces = std::collections::BTreeSet::new();
    for (namespace, attributes) in &mut user.attributes {
        let stale_keys: Vec<String> = attributes
            .federation_owners
            .iter()
            .filter(|(_, owner)| owner.upstream_idp_id == upstream_idp_id)
            .map(|(key, _)| key.clone())
            .collect();
        for key in stale_keys {
            attributes.federation_owners.remove(&key);
            attributes.kv.remove(&key);
            touched_namespaces.insert(namespace.clone());
        }
    }
    for desired_value in desired.values() {
        let attributes = user
            .attributes
            .entry(desired_value.namespace.clone())
            .or_default();
        attributes
            .kv
            .insert(desired_value.key.clone(), desired_value.value.clone());
        attributes
            .federation_owners
            .insert(desired_value.key.clone(), desired_value.owner.clone());
        touched_namespaces.insert(desired_value.namespace.clone());
    }

    let mut changed = false;
    for namespace in touched_namespaces {
        let next = user
            .attributes
            .get_mut(&namespace)
            .expect("touched namespace must exist");
        let previous = current.attributes.get(&namespace);
        if previous.is_some_and(|previous| {
            previous.kv == next.kv && previous.federation_owners == next.federation_owners
        }) {
            next.revision = previous.expect("checked above").revision;
            continue;
        }
        next.revision = previous
            .map(|previous| previous.revision)
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| {
                StoreError::Permanent(
                    "namespace attributes revision exhausted during reconciliation".into(),
                )
            })?;
        changed = true;
    }
    if !changed {
        return Ok(FederationAttributeReconciliationOutcome::Applied {
            previous_user: Box::new(current.clone()),
            user: Box::new(user),
            registry_revision,
            changed: false,
        });
    }
    if crate::adapters::memory::attributes_serialized_len(&user.attributes)
        > crate::ports::ATTRIBUTES_MAX_BYTES
    {
        return Ok(FederationAttributeReconciliationOutcome::TooLarge);
    }
    user.attributes_generation = user
        .attributes_generation
        .checked_add(1)
        .ok_or_else(|| StoreError::Permanent("user attributes generation exhausted".into()))?;
    Ok(FederationAttributeReconciliationOutcome::Applied {
        previous_user: Box::new(current.clone()),
        user: Box::new(user),
        registry_revision,
        changed: true,
    })
}

impl AttributeMapping {
    pub fn evaluate(&self, verified_claims: &serde_json::Value) -> MappingEvaluation {
        if !self.enabled {
            return MappingEvaluation::Absent;
        }
        let Some(value) = verified_claims.get(&self.source_claim) else {
            return MappingEvaluation::Absent;
        };
        match &self.mode {
            MappingMode::CopyString => value
                .as_str()
                .map(|value| MappingEvaluation::Present(value.to_string()))
                .unwrap_or(MappingEvaluation::Absent),
            MappingMode::ExactMembership {
                source_value,
                target_value,
            } => {
                let matched = match value {
                    serde_json::Value::String(value) => value == source_value,
                    serde_json::Value::Array(values) => {
                        values.iter().all(serde_json::Value::is_string)
                            && values
                                .iter()
                                .any(|value| value.as_str() == Some(source_value))
                    }
                    _ => false,
                };
                if matched {
                    MappingEvaluation::Present(target_value.clone())
                } else {
                    MappingEvaluation::Absent
                }
            }
        }
    }

    pub(crate) fn from_spec(
        mapping_id: String,
        revision: u64,
        enabled: bool,
        spec: MappingSpec,
    ) -> Self {
        Self {
            mapping_id,
            revision,
            enabled,
            source_claim: spec.source_claim,
            target_namespace: spec.target_namespace,
            target_key: spec.target_key,
            mode: spec.mode,
        }
    }

    pub(crate) fn validate_id(mapping_id: &str) -> Result<(), MappingValidationError> {
        if !valid_text(mapping_id, MAPPING_ID_MAX_BYTES) || !mapping_id.starts_with("fm_") {
            return Err(MappingValidationError::InvalidMappingId);
        }
        Ok(())
    }
}
