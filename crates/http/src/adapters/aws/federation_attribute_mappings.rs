use std::collections::HashMap;

use aws_sdk_dynamodb::types::{AttributeValue, ConditionCheck, Delete, Put, TransactWriteItem};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::federation_attributes::{
    AttributeMapping, FederationAttributeMappingsStore, MappingChange, MappingChangeOutcome,
    MappingRegistry, MappingSpec, MAPPINGS_MAX_PER_IDP, MAPPING_REGISTRY_MAX_BYTES,
};
use crate::ports::StoreError;

use super::{ddb_err, send_idempotent_transaction};

const TENANT_KEY: &str = "tenant_id";
const LOOKUP_KEY: &str = "lookup_key";
const REGISTRY_PREFIX: &str = "registry#";
const TARGET_PREFIX: &str = "target#";
const MARKER_PREFIX: &str = "marker#";

fn tenant_key(tenant_id: &str) -> String {
    if tenant_id.is_empty() {
        "default".to_string()
    } else {
        tenant_id.to_string()
    }
}

fn framed_digest(values: &[&str]) -> String {
    let mut digest = Sha256::new();
    for value in values {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

fn next_revision(revision: u64) -> Result<u64, StoreError> {
    revision
        .checked_add(1)
        .ok_or_else(|| StoreError::Permanent("federation mapping revision exhausted".into()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TargetOwner {
    upstream_idp_id: String,
    mapping_id: String,
    mapping_revision: u64,
    target_namespace: String,
    target_key: String,
}

struct MappingUpdate {
    mapping_id: String,
    expected_registry_revision: u64,
    expected_mapping_revision: u64,
    enabled: bool,
    spec: MappingSpec,
}

struct MappingCreate {
    mapping_id: String,
    expected_registry_revision: u64,
    spec: MappingSpec,
}

struct MappingDelete {
    mapping_id: String,
    expected_registry_revision: u64,
    expected_mapping_revision: u64,
}

#[derive(Clone)]
pub struct DynamoFederationAttributeMappingsStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
}

impl DynamoFederationAttributeMappingsStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        Self {
            db,
            table: table.into(),
        }
    }

    pub(crate) fn reconciliation_authority_condition(
        &self,
        tenant_id: &str,
        upstream_idp_id: &str,
        registry: Option<&MappingRegistry>,
    ) -> Result<TransactWriteItem, StoreError> {
        let check = match registry {
            Some(registry) => {
                let payload = serde_json::to_string(registry).map_err(|error| {
                    StoreError::Permanent(format!(
                        "serialize reconciliation mapping registry: {error}"
                    ))
                })?;
                ConditionCheck::builder()
                    .table_name(&self.table)
                    .set_key(Some(Self::registry_key(
                        tenant_id,
                        &registry.upstream_idp_id,
                    )))
                    .condition_expression(
                        "upstream_idp_id = :idp AND upstream_issuer = :issuer \
                         AND revision = :revision AND payload = :payload",
                    )
                    .expression_attribute_values(
                        ":idp",
                        AttributeValue::S(registry.upstream_idp_id.clone()),
                    )
                    .expression_attribute_values(
                        ":issuer",
                        AttributeValue::S(registry.upstream_issuer.clone()),
                    )
                    .expression_attribute_values(
                        ":revision",
                        AttributeValue::N(registry.revision.to_string()),
                    )
                    .expression_attribute_values(":payload", AttributeValue::S(payload))
            }
            None => ConditionCheck::builder()
                .table_name(&self.table)
                .set_key(Some(Self::registry_key(tenant_id, upstream_idp_id)))
                .condition_expression(
                    "attribute_not_exists(tenant_id) AND attribute_not_exists(lookup_key)",
                ),
        };
        Ok(TransactWriteItem::builder()
            .condition_check(check.build().map_err(|error| {
                StoreError::Permanent(format!(
                    "build reconciliation mapping authority check: {error}"
                ))
            })?)
            .build())
    }

    fn key(tenant_id: &str, lookup_key: String) -> HashMap<String, AttributeValue> {
        HashMap::from([
            (
                TENANT_KEY.to_string(),
                AttributeValue::S(tenant_key(tenant_id)),
            ),
            (LOOKUP_KEY.to_string(), AttributeValue::S(lookup_key)),
        ])
    }

    fn registry_key(tenant_id: &str, upstream_idp_id: &str) -> HashMap<String, AttributeValue> {
        Self::key(
            tenant_id,
            format!("{REGISTRY_PREFIX}{}", framed_digest(&[upstream_idp_id])),
        )
    }

    fn target_key(
        tenant_id: &str,
        target_namespace: &str,
        target_key: &str,
    ) -> HashMap<String, AttributeValue> {
        Self::key(
            tenant_id,
            format!(
                "{TARGET_PREFIX}{}",
                framed_digest(&[target_namespace, target_key])
            ),
        )
    }

    fn marker_key(tenant_id: &str, mapping_id: &str) -> HashMap<String, AttributeValue> {
        Self::key(
            tenant_id,
            format!("{MARKER_PREFIX}{}", framed_digest(&[mapping_id])),
        )
    }

    fn registry_item(
        tenant_id: &str,
        registry: &MappingRegistry,
    ) -> Result<HashMap<String, AttributeValue>, StoreError> {
        let mut item = Self::registry_key(tenant_id, &registry.upstream_idp_id);
        item.insert("row_type".into(), AttributeValue::S("registry".into()));
        item.insert(
            "upstream_idp_id".into(),
            AttributeValue::S(registry.upstream_idp_id.clone()),
        );
        item.insert(
            "upstream_issuer".into(),
            AttributeValue::S(registry.upstream_issuer.clone()),
        );
        item.insert(
            "revision".into(),
            AttributeValue::N(registry.revision.to_string()),
        );
        item.insert(
            "payload".into(),
            AttributeValue::S(serde_json::to_string(registry).map_err(|error| {
                StoreError::Permanent(format!("serialize federation mapping registry: {error}"))
            })?),
        );
        Ok(item)
    }

    fn target_item(tenant_id: &str, owner: &TargetOwner) -> HashMap<String, AttributeValue> {
        let mut item = Self::target_key(tenant_id, &owner.target_namespace, &owner.target_key);
        item.insert("row_type".into(), AttributeValue::S("target".into()));
        item.insert(
            "target_namespace".into(),
            AttributeValue::S(owner.target_namespace.clone()),
        );
        item.insert(
            "target_key".into(),
            AttributeValue::S(owner.target_key.clone()),
        );
        item.insert(
            "upstream_idp_id".into(),
            AttributeValue::S(owner.upstream_idp_id.clone()),
        );
        item.insert(
            "mapping_id".into(),
            AttributeValue::S(owner.mapping_id.clone()),
        );
        item.insert(
            "mapping_revision".into(),
            AttributeValue::N(owner.mapping_revision.to_string()),
        );
        item
    }

    fn marker_item(
        tenant_id: &str,
        upstream_idp_id: &str,
        mapping_id: &str,
    ) -> HashMap<String, AttributeValue> {
        let mut item = Self::marker_key(tenant_id, mapping_id);
        item.insert("row_type".into(), AttributeValue::S("marker".into()));
        item.insert(
            "upstream_idp_id".into(),
            AttributeValue::S(upstream_idp_id.to_string()),
        );
        item.insert(
            "mapping_id".into(),
            AttributeValue::S(mapping_id.to_string()),
        );
        item
    }

    fn decode_registry(
        item: &HashMap<String, AttributeValue>,
        requested_tenant_id: &str,
        requested_idp_id: &str,
    ) -> Result<MappingRegistry, StoreError> {
        let original_idp_id = item
            .get("upstream_idp_id")
            .and_then(|value| value.as_s().ok())
            .ok_or_else(|| {
                StoreError::Permanent("federation mapping registry idp is missing".into())
            })?;
        if original_idp_id != requested_idp_id {
            return Err(StoreError::Permanent(
                "federation mapping registry hash collision".into(),
            ));
        }
        let payload = item
            .get("payload")
            .and_then(|value| value.as_s().ok())
            .ok_or_else(|| {
                StoreError::Permanent("federation mapping registry payload is missing".into())
            })?;
        let registry: MappingRegistry = serde_json::from_str(payload).map_err(|error| {
            StoreError::Permanent(format!("decode federation mapping registry: {error}"))
        })?;
        if registry.tenant_id != requested_tenant_id
            || registry.upstream_idp_id != requested_idp_id
            || registry.upstream_issuer
                != item
                    .get("upstream_issuer")
                    .and_then(|value| value.as_s().ok())
                    .cloned()
                    .unwrap_or_default()
        {
            return Err(StoreError::Permanent(
                "federation mapping registry original value mismatch".into(),
            ));
        }
        Ok(registry)
    }

    async fn query_tenant_rows(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<HashMap<String, AttributeValue>>, StoreError> {
        let mut rows = Vec::new();
        let mut cursor = None;
        loop {
            let response = self
                .db
                .query()
                .table_name(&self.table)
                .key_condition_expression("#tenant = :tenant")
                .expression_attribute_names("#tenant", TENANT_KEY)
                .expression_attribute_values(":tenant", AttributeValue::S(tenant_key(tenant_id)))
                .consistent_read(true)
                .set_exclusive_start_key(cursor)
                .send()
                .await
                .map_err(ddb_err)?;
            rows.extend(response.items.unwrap_or_default());
            cursor = response.last_evaluated_key;
            if cursor.as_ref().is_none_or(HashMap::is_empty) {
                return Ok(rows);
            }
        }
    }

    fn decode_target(
        item: &HashMap<String, AttributeValue>,
        target_namespace: &str,
        target_key: &str,
    ) -> Result<TargetOwner, StoreError> {
        let owner = TargetOwner {
            upstream_idp_id: item
                .get("upstream_idp_id")
                .and_then(|value| value.as_s().ok())
                .cloned()
                .ok_or_else(|| StoreError::Permanent("target owner idp is missing".into()))?,
            mapping_id: item
                .get("mapping_id")
                .and_then(|value| value.as_s().ok())
                .cloned()
                .ok_or_else(|| StoreError::Permanent("target owner mapping is missing".into()))?,
            mapping_revision: item
                .get("mapping_revision")
                .and_then(|value| value.as_n().ok())
                .and_then(|value| value.parse().ok())
                .ok_or_else(|| {
                    StoreError::Permanent("target owner mapping revision is missing".into())
                })?,
            target_namespace: item
                .get("target_namespace")
                .and_then(|value| value.as_s().ok())
                .cloned()
                .ok_or_else(|| StoreError::Permanent("target namespace is missing".into()))?,
            target_key: item
                .get("target_key")
                .and_then(|value| value.as_s().ok())
                .cloned()
                .ok_or_else(|| StoreError::Permanent("target key is missing".into()))?,
        };
        if owner.target_namespace != target_namespace || owner.target_key != target_key {
            return Err(StoreError::Permanent(
                "federation mapping target hash collision".into(),
            ));
        }
        Ok(owner)
    }

    async fn marker_owner(
        &self,
        tenant_id: &str,
        mapping_id: &str,
    ) -> Result<Option<String>, StoreError> {
        let item = self
            .db
            .get_item()
            .table_name(&self.table)
            .set_key(Some(Self::marker_key(tenant_id, mapping_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?
            .item;
        let Some(item) = item else {
            return Ok(None);
        };
        if item
            .get("mapping_id")
            .and_then(|value| value.as_s().ok())
            .map(String::as_str)
            != Some(mapping_id)
        {
            return Err(StoreError::Permanent(
                "federation mapping marker hash collision".into(),
            ));
        }
        item.get("upstream_idp_id")
            .and_then(|value| value.as_s().ok())
            .cloned()
            .map(Some)
            .ok_or_else(|| StoreError::Permanent("federation mapping marker idp is missing".into()))
    }

    async fn marker_exists(&self, tenant_id: &str, mapping_id: &str) -> Result<bool, StoreError> {
        Ok(self.marker_owner(tenant_id, mapping_id).await?.is_some())
    }

    async fn marker_belongs_to(
        &self,
        tenant_id: &str,
        mapping_id: &str,
        upstream_idp_id: &str,
    ) -> Result<bool, StoreError> {
        Ok(self
            .marker_owner(tenant_id, mapping_id)
            .await?
            .is_some_and(|owner| owner == upstream_idp_id))
    }

    async fn get_target(
        &self,
        tenant_id: &str,
        target_namespace: &str,
        target_key: &str,
    ) -> Result<Option<TargetOwner>, StoreError> {
        self.db
            .get_item()
            .table_name(&self.table)
            .set_key(Some(Self::target_key(
                tenant_id,
                target_namespace,
                target_key,
            )))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?
            .item()
            .map(|item| Self::decode_target(item, target_namespace, target_key))
            .transpose()
    }

    fn registry_put(
        &self,
        tenant_id: &str,
        current: Option<&MappingRegistry>,
        next: &MappingRegistry,
    ) -> Result<TransactWriteItem, StoreError> {
        let mut put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(Self::registry_item(tenant_id, next)?));
        put = if let Some(current) = current {
            put.condition_expression(
                "upstream_idp_id = :idp AND upstream_issuer = :issuer AND revision = :revision",
            )
            .expression_attribute_values(":idp", AttributeValue::S(current.upstream_idp_id.clone()))
            .expression_attribute_values(
                ":issuer",
                AttributeValue::S(current.upstream_issuer.clone()),
            )
            .expression_attribute_values(
                ":revision",
                AttributeValue::N(current.revision.to_string()),
            )
        } else {
            put.condition_expression(
                "attribute_not_exists(tenant_id) AND attribute_not_exists(lookup_key)",
            )
        };
        Ok(TransactWriteItem::builder()
            .put(put.build().map_err(|error| {
                StoreError::Permanent(format!("build mapping registry put: {error}"))
            })?)
            .build())
    }

    fn target_put_absent(
        &self,
        tenant_id: &str,
        owner: &TargetOwner,
    ) -> Result<TransactWriteItem, StoreError> {
        Ok(TransactWriteItem::builder()
            .put(
                Put::builder()
                    .table_name(&self.table)
                    .set_item(Some(Self::target_item(tenant_id, owner)))
                    .condition_expression(
                        "attribute_not_exists(tenant_id) AND attribute_not_exists(lookup_key)",
                    )
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!("build mapping target put: {error}"))
                    })?,
            )
            .build())
    }

    fn target_put_owned(
        &self,
        tenant_id: &str,
        current: &TargetOwner,
        next: &TargetOwner,
    ) -> Result<TransactWriteItem, StoreError> {
        Ok(TransactWriteItem::builder()
            .put(
                Put::builder()
                    .table_name(&self.table)
                    .set_item(Some(Self::target_item(tenant_id, next)))
                    .condition_expression(
                        "target_namespace = :namespace AND target_key = :key \
                         AND upstream_idp_id = :idp AND mapping_id = :mapping \
                         AND mapping_revision = :revision",
                    )
                    .expression_attribute_values(
                        ":namespace",
                        AttributeValue::S(current.target_namespace.clone()),
                    )
                    .expression_attribute_values(
                        ":key",
                        AttributeValue::S(current.target_key.clone()),
                    )
                    .expression_attribute_values(
                        ":idp",
                        AttributeValue::S(current.upstream_idp_id.clone()),
                    )
                    .expression_attribute_values(
                        ":mapping",
                        AttributeValue::S(current.mapping_id.clone()),
                    )
                    .expression_attribute_values(
                        ":revision",
                        AttributeValue::N(current.mapping_revision.to_string()),
                    )
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!("build owned mapping target put: {error}"))
                    })?,
            )
            .build())
    }

    fn target_delete(
        &self,
        tenant_id: &str,
        owner: &TargetOwner,
    ) -> Result<TransactWriteItem, StoreError> {
        Ok(TransactWriteItem::builder()
            .delete(
                Delete::builder()
                    .table_name(&self.table)
                    .set_key(Some(Self::target_key(
                        tenant_id,
                        &owner.target_namespace,
                        &owner.target_key,
                    )))
                    .condition_expression(
                        "target_namespace = :namespace AND target_key = :key \
                         AND upstream_idp_id = :idp AND mapping_id = :mapping \
                         AND mapping_revision = :revision",
                    )
                    .expression_attribute_values(
                        ":namespace",
                        AttributeValue::S(owner.target_namespace.clone()),
                    )
                    .expression_attribute_values(
                        ":key",
                        AttributeValue::S(owner.target_key.clone()),
                    )
                    .expression_attribute_values(
                        ":idp",
                        AttributeValue::S(owner.upstream_idp_id.clone()),
                    )
                    .expression_attribute_values(
                        ":mapping",
                        AttributeValue::S(owner.mapping_id.clone()),
                    )
                    .expression_attribute_values(
                        ":revision",
                        AttributeValue::N(owner.mapping_revision.to_string()),
                    )
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!("build mapping target delete: {error}"))
                    })?,
            )
            .build())
    }

    fn owner(upstream_idp_id: &str, mapping: &AttributeMapping) -> TargetOwner {
        TargetOwner {
            upstream_idp_id: upstream_idp_id.to_string(),
            mapping_id: mapping.mapping_id.clone(),
            mapping_revision: mapping.revision,
            target_namespace: mapping.target_namespace.clone(),
            target_key: mapping.target_key.clone(),
        }
    }

    fn validate_registry_size(registry: &MappingRegistry) -> bool {
        serde_json::to_vec(registry)
            .is_ok_and(|payload| payload.len() <= MAPPING_REGISTRY_MAX_BYTES)
    }

    async fn create(
        &self,
        config_condition: Option<TransactWriteItem>,
        tenant_id: &str,
        upstream_idp_id: &str,
        upstream_issuer: &str,
        create: MappingCreate,
    ) -> Result<MappingChangeOutcome, StoreError> {
        let MappingCreate {
            mapping_id,
            expected_registry_revision,
            spec,
        } = create;
        let current = self.get_registry(tenant_id, upstream_idp_id).await?;
        let current_revision = current.as_ref().map_or(0, |registry| registry.revision);
        if current_revision != expected_registry_revision {
            return Ok(MappingChangeOutcome::Conflict);
        }
        if let Err(error) = AttributeMapping::validate_id(&mapping_id).and_then(|_| spec.validate())
        {
            return Ok(MappingChangeOutcome::Invalid(error));
        }
        if current.as_ref().is_some_and(|registry| {
            (!registry.mappings.is_empty() && registry.upstream_issuer != upstream_issuer)
                || registry
                    .mappings
                    .iter()
                    .any(|mapping| mapping.mapping_id == mapping_id)
        }) {
            return Ok(MappingChangeOutcome::Conflict);
        }
        if current
            .as_ref()
            .is_some_and(|registry| registry.mappings.len() >= MAPPINGS_MAX_PER_IDP)
        {
            return Ok(MappingChangeOutcome::LimitExceeded);
        }
        if self.marker_exists(tenant_id, &mapping_id).await? {
            return Ok(MappingChangeOutcome::MappingIdRetired);
        }

        let mapping = AttributeMapping::from_spec(mapping_id.clone(), 1, true, spec);
        if self
            .get_target(tenant_id, &mapping.target_namespace, &mapping.target_key)
            .await?
            .is_some()
        {
            return Ok(MappingChangeOutcome::TargetConflict);
        }
        let mut registry = current.clone().unwrap_or(MappingRegistry {
            tenant_id: tenant_id.to_string(),
            upstream_idp_id: upstream_idp_id.to_string(),
            upstream_issuer: upstream_issuer.to_string(),
            revision: 0,
            mappings: Vec::new(),
        });
        if registry.mappings.is_empty() {
            registry.upstream_issuer = upstream_issuer.to_string();
        }
        registry.revision = next_revision(registry.revision)?;
        registry.mappings.push(mapping.clone());
        registry
            .mappings
            .sort_by(|left, right| left.mapping_id.cmp(&right.mapping_id));
        if !Self::validate_registry_size(&registry) {
            return Ok(MappingChangeOutcome::LimitExceeded);
        }
        let owner = Self::owner(upstream_idp_id, &mapping);
        let marker = TransactWriteItem::builder()
            .put(
                Put::builder()
                    .table_name(&self.table)
                    .set_item(Some(Self::marker_item(
                        tenant_id,
                        upstream_idp_id,
                        &mapping_id,
                    )))
                    .condition_expression(
                        "attribute_not_exists(tenant_id) AND attribute_not_exists(lookup_key)",
                    )
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!("build mapping marker put: {error}"))
                    })?,
            )
            .build();
        let mut request = self.db.transact_write_items();
        if let Some(condition) = config_condition {
            request = request.transact_items(condition);
        }
        let request = request
            .transact_items(self.registry_put(tenant_id, current.as_ref(), &registry)?)
            .transact_items(self.target_put_absent(tenant_id, &owner)?)
            .transact_items(marker);
        match send_idempotent_transaction(request).await {
            Ok(true) => return Ok(MappingChangeOutcome::Applied(registry)),
            Ok(false) => {}
            Err(error) => {
                if matches!(error, StoreError::Transient(_))
                    && self
                        .get_registry(tenant_id, upstream_idp_id)
                        .await?
                        .as_ref()
                        == Some(&registry)
                    && self
                        .marker_belongs_to(tenant_id, &mapping_id, upstream_idp_id)
                        .await?
                    && self
                        .get_target(tenant_id, &mapping.target_namespace, &mapping.target_key)
                        .await?
                        .as_ref()
                        == Some(&owner)
                {
                    return Ok(MappingChangeOutcome::Applied(registry));
                }
                return Err(error);
            }
        }
        if self.marker_exists(tenant_id, &mapping_id).await? {
            return Ok(MappingChangeOutcome::MappingIdRetired);
        }
        if self
            .get_target(tenant_id, &mapping.target_namespace, &mapping.target_key)
            .await?
            .is_some()
        {
            return Ok(MappingChangeOutcome::TargetConflict);
        }
        Ok(MappingChangeOutcome::Conflict)
    }

    async fn update(
        &self,
        config_condition: Option<TransactWriteItem>,
        tenant_id: &str,
        upstream_idp_id: &str,
        upstream_issuer: &str,
        update: MappingUpdate,
    ) -> Result<MappingChangeOutcome, StoreError> {
        let MappingUpdate {
            mapping_id,
            expected_registry_revision,
            expected_mapping_revision,
            enabled,
            spec,
        } = update;
        let Some(current_registry) = self.get_registry(tenant_id, upstream_idp_id).await? else {
            return Ok(MappingChangeOutcome::NotFound);
        };
        if current_registry.revision != expected_registry_revision
            || current_registry.upstream_issuer != upstream_issuer
        {
            return Ok(MappingChangeOutcome::Conflict);
        }
        if let Err(error) = spec.validate() {
            return Ok(MappingChangeOutcome::Invalid(error));
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
        let current_owner = Self::owner(upstream_idp_id, &current_mapping);
        if current_mapping.enabled
            && self
                .get_target(
                    tenant_id,
                    &current_mapping.target_namespace,
                    &current_mapping.target_key,
                )
                .await?
                .as_ref()
                != Some(&current_owner)
        {
            return Ok(MappingChangeOutcome::Conflict);
        }

        let updated_mapping = AttributeMapping::from_spec(
            mapping_id.clone(),
            next_revision(current_mapping.revision)?,
            enabled,
            spec,
        );
        let updated_owner = Self::owner(upstream_idp_id, &updated_mapping);
        let same_target = current_owner.target_namespace == updated_owner.target_namespace
            && current_owner.target_key == updated_owner.target_key;
        if enabled
            && !same_target
            && self
                .get_target(
                    tenant_id,
                    &updated_mapping.target_namespace,
                    &updated_mapping.target_key,
                )
                .await?
                .is_some()
        {
            return Ok(MappingChangeOutcome::TargetConflict);
        }

        let mut updated_registry = current_registry.clone();
        updated_registry.revision = next_revision(updated_registry.revision)?;
        *updated_registry
            .mappings
            .iter_mut()
            .find(|mapping| mapping.mapping_id == mapping_id)
            .expect("mapping was checked above") = updated_mapping.clone();
        if !Self::validate_registry_size(&updated_registry) {
            return Ok(MappingChangeOutcome::LimitExceeded);
        }

        let mut request = self.db.transact_write_items();
        if let Some(condition) = config_condition {
            request = request.transact_items(condition);
        }
        request = request.transact_items(self.registry_put(
            tenant_id,
            Some(&current_registry),
            &updated_registry,
        )?);
        if current_mapping.enabled && (!enabled || !same_target) {
            request = request.transact_items(self.target_delete(tenant_id, &current_owner)?);
        }
        if enabled {
            request = if current_mapping.enabled && same_target {
                request.transact_items(self.target_put_owned(
                    tenant_id,
                    &current_owner,
                    &updated_owner,
                )?)
            } else {
                request.transact_items(self.target_put_absent(tenant_id, &updated_owner)?)
            };
        }
        match send_idempotent_transaction(request).await {
            Ok(true) => return Ok(MappingChangeOutcome::Applied(updated_registry)),
            Ok(false) => {}
            Err(error) => {
                let registry_matches = self
                    .get_registry(tenant_id, upstream_idp_id)
                    .await?
                    .as_ref()
                    == Some(&updated_registry);
                let old_target_released = if current_mapping.enabled && (!enabled || !same_target) {
                    self.get_target(
                        tenant_id,
                        &current_owner.target_namespace,
                        &current_owner.target_key,
                    )
                    .await?
                    .is_none()
                } else {
                    true
                };
                let new_target_matches = if enabled {
                    self.get_target(
                        tenant_id,
                        &updated_owner.target_namespace,
                        &updated_owner.target_key,
                    )
                    .await?
                    .as_ref()
                        == Some(&updated_owner)
                } else {
                    self.get_target(
                        tenant_id,
                        &updated_owner.target_namespace,
                        &updated_owner.target_key,
                    )
                    .await?
                    .is_none()
                };
                if matches!(error, StoreError::Transient(_))
                    && registry_matches
                    && old_target_released
                    && new_target_matches
                    && self
                        .marker_belongs_to(tenant_id, &mapping_id, upstream_idp_id)
                        .await?
                {
                    return Ok(MappingChangeOutcome::Applied(updated_registry));
                }
                return Err(error);
            }
        }
        if enabled
            && self
                .get_target(
                    tenant_id,
                    &updated_mapping.target_namespace,
                    &updated_mapping.target_key,
                )
                .await?
                .is_some_and(|owner| owner != updated_owner)
        {
            return Ok(MappingChangeOutcome::TargetConflict);
        }
        Ok(MappingChangeOutcome::Conflict)
    }

    async fn delete(
        &self,
        config_condition: Option<TransactWriteItem>,
        tenant_id: &str,
        upstream_idp_id: &str,
        upstream_issuer: &str,
        delete: MappingDelete,
    ) -> Result<MappingChangeOutcome, StoreError> {
        let MappingDelete {
            mapping_id,
            expected_registry_revision,
            expected_mapping_revision,
        } = delete;
        let Some(current_registry) = self.get_registry(tenant_id, upstream_idp_id).await? else {
            return Ok(MappingChangeOutcome::NotFound);
        };
        if current_registry.revision != expected_registry_revision
            || current_registry.upstream_issuer != upstream_issuer
        {
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
        let owner = Self::owner(upstream_idp_id, &current_mapping);
        if current_mapping.enabled
            && self
                .get_target(
                    tenant_id,
                    &current_mapping.target_namespace,
                    &current_mapping.target_key,
                )
                .await?
                .as_ref()
                != Some(&owner)
        {
            return Ok(MappingChangeOutcome::Conflict);
        }
        let mut updated_registry = current_registry.clone();
        updated_registry.revision = next_revision(updated_registry.revision)?;
        updated_registry
            .mappings
            .retain(|mapping| mapping.mapping_id != mapping_id);

        let mut request = self.db.transact_write_items();
        if let Some(condition) = config_condition {
            request = request.transact_items(condition);
        }
        request = request.transact_items(self.registry_put(
            tenant_id,
            Some(&current_registry),
            &updated_registry,
        )?);
        if current_mapping.enabled {
            request = request.transact_items(self.target_delete(tenant_id, &owner)?);
        }
        match send_idempotent_transaction(request).await {
            Ok(true) => Ok(MappingChangeOutcome::Applied(updated_registry)),
            Ok(false) => Ok(MappingChangeOutcome::Conflict),
            Err(error) => {
                let registry_matches = self
                    .get_registry(tenant_id, upstream_idp_id)
                    .await?
                    .as_ref()
                    == Some(&updated_registry);
                let target_released = if current_mapping.enabled {
                    self.get_target(tenant_id, &owner.target_namespace, &owner.target_key)
                        .await?
                        .is_none()
                } else {
                    true
                };
                if matches!(error, StoreError::Transient(_))
                    && registry_matches
                    && target_released
                    && self
                        .marker_belongs_to(tenant_id, &mapping_id, upstream_idp_id)
                        .await?
                {
                    Ok(MappingChangeOutcome::Applied(updated_registry))
                } else {
                    Err(error)
                }
            }
        }
    }
    async fn change_with_condition(
        &self,
        config_condition: Option<TransactWriteItem>,
        tenant_id: &str,
        upstream_idp_id: &str,
        upstream_issuer: &str,
        change: MappingChange,
    ) -> Result<MappingChangeOutcome, StoreError> {
        match change {
            MappingChange::Create {
                mapping_id,
                expected_registry_revision,
                spec,
            } => {
                self.create(
                    config_condition,
                    tenant_id,
                    upstream_idp_id,
                    upstream_issuer,
                    MappingCreate {
                        mapping_id,
                        expected_registry_revision,
                        spec,
                    },
                )
                .await
            }
            MappingChange::Update {
                mapping_id,
                expected_registry_revision,
                expected_mapping_revision,
                enabled,
                spec,
            } => {
                self.update(
                    config_condition,
                    tenant_id,
                    upstream_idp_id,
                    upstream_issuer,
                    MappingUpdate {
                        mapping_id,
                        expected_registry_revision,
                        expected_mapping_revision,
                        enabled,
                        spec,
                    },
                )
                .await
            }
            MappingChange::SetEnabled {
                mapping_id,
                expected_registry_revision,
                expected_mapping_revision,
                enabled,
            } => {
                let Some(registry) = self.get_registry(tenant_id, upstream_idp_id).await? else {
                    return Ok(MappingChangeOutcome::NotFound);
                };
                let Some(mapping) = registry
                    .mappings
                    .iter()
                    .find(|mapping| mapping.mapping_id == mapping_id)
                else {
                    return Ok(MappingChangeOutcome::NotFound);
                };
                self.update(
                    config_condition,
                    tenant_id,
                    upstream_idp_id,
                    upstream_issuer,
                    MappingUpdate {
                        mapping_id,
                        expected_registry_revision,
                        expected_mapping_revision,
                        enabled,
                        spec: MappingSpec {
                            source_claim: mapping.source_claim.clone(),
                            target_namespace: mapping.target_namespace.clone(),
                            target_key: mapping.target_key.clone(),
                            mode: mapping.mode.clone(),
                        },
                    },
                )
                .await
            }
            MappingChange::Delete {
                mapping_id,
                expected_registry_revision,
                expected_mapping_revision,
            } => {
                self.delete(
                    config_condition,
                    tenant_id,
                    upstream_idp_id,
                    upstream_issuer,
                    MappingDelete {
                        mapping_id,
                        expected_registry_revision,
                        expected_mapping_revision,
                    },
                )
                .await
            }
        }
    }

    pub(crate) async fn change_authorized(
        &self,
        config_condition: TransactWriteItem,
        tenant_id: &str,
        upstream_idp_id: &str,
        upstream_issuer: &str,
        change: MappingChange,
    ) -> Result<MappingChangeOutcome, StoreError> {
        self.change_with_condition(
            Some(config_condition),
            tenant_id,
            upstream_idp_id,
            upstream_issuer,
            change,
        )
        .await
    }
}

impl FederationAttributeMappingsStore for DynamoFederationAttributeMappingsStore {
    async fn get_registry(
        &self,
        tenant_id: &str,
        upstream_idp_id: &str,
    ) -> Result<Option<MappingRegistry>, StoreError> {
        self.db
            .get_item()
            .table_name(&self.table)
            .set_key(Some(Self::registry_key(tenant_id, upstream_idp_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?
            .item()
            .map(|item| Self::decode_registry(item, tenant_id, upstream_idp_id))
            .transpose()
    }

    async fn change(
        &self,
        tenant_id: &str,
        upstream_idp_id: &str,
        upstream_issuer: &str,
        change: MappingChange,
    ) -> Result<MappingChangeOutcome, StoreError> {
        self.change_with_condition(None, tenant_id, upstream_idp_id, upstream_issuer, change)
            .await
    }

    async fn list_by_tenant(&self, tenant_id: &str) -> Result<Vec<MappingRegistry>, StoreError> {
        let mut registries = self
            .query_tenant_rows(tenant_id)
            .await?
            .into_iter()
            .filter(|item| {
                item.get("row_type")
                    .and_then(|value| value.as_s().ok())
                    .is_some_and(|row_type| row_type == "registry")
            })
            .map(|item| {
                let upstream_idp_id = item
                    .get("upstream_idp_id")
                    .and_then(|value| value.as_s().ok())
                    .cloned()
                    .ok_or_else(|| {
                        StoreError::Permanent("federation mapping registry idp is missing".into())
                    })?;
                Self::decode_registry(&item, tenant_id, &upstream_idp_id)
            })
            .collect::<Result<Vec<_>, _>>()?;
        registries.sort_by(|left, right| left.upstream_idp_id.cmp(&right.upstream_idp_id));
        Ok(registries)
    }

    async fn governance_count_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        Ok(self.query_tenant_rows(tenant_id).await?.len())
    }

    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        let rows = self.query_tenant_rows(tenant_id).await?;
        let mut removed = 0usize;
        for row in rows {
            let lookup_key = row
                .get(LOOKUP_KEY)
                .and_then(|value| value.as_s().ok())
                .cloned()
                .ok_or_else(|| {
                    StoreError::Permanent(
                        "federation mapping authority lookup key is missing".into(),
                    )
                })?;
            self.db
                .delete_item()
                .table_name(&self.table)
                .set_key(Some(Self::key(tenant_id, lookup_key)))
                .send()
                .await
                .map_err(ddb_err)?;
            removed = removed.saturating_add(1);
        }
        Ok(removed)
    }
}
