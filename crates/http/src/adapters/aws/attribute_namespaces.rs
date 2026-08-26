use std::collections::{BTreeMap, BTreeSet, HashMap};

use aws_sdk_dynamodb::types::{
    AttributeValue, ConditionCheck, Delete, Get, Put, TransactGetItem, TransactWriteItem,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::attribute_namespace::{
    invalid_inflight_checkpoint, resolve_exact, validate_exact_audiences, validate_namespace_uri,
    AttributeNamespaceStore, AttributeWriteAuthority, AttributeWriteResolution, AudienceBinding,
    AudienceResolution, AudienceState, BeginNamespaceChange, BeginNamespaceChangeOutcome,
    CancelledNamespaceOperation, NamespaceChangeKind, NamespaceChangeOutcome,
    NamespaceMigrationOperation, NamespaceMigrationPhase, NamespaceOperationCheckpoint,
    NamespaceRegistration, RegistrationSnapshot, RegistrationState,
};
use crate::ports::StoreError;

use super::{ddb_err, send_idempotent_transaction};

const TENANT_KEY: &str = "tenant_id";
const LOOKUP_KEY: &str = "lookup_key";
const REGISTRATION_PREFIX: &str = "ns#";
const AUDIENCE_PREFIX: &str = "aud#";
const CANCELLATION_PREFIX: &str = "cancel#";
const OPERATION_PREFIX: &str = "op#";

fn tenant_key(tenant: &str) -> String {
    if tenant.is_empty() {
        "default".to_string()
    } else {
        tenant.to_string()
    }
}

fn hashed_key(prefix: &str, value: &str) -> String {
    format!(
        "{prefix}{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
    )
}

fn operation_lookup_key(canonical_namespace: &str, operation_id: &str) -> String {
    let mut digest = Sha256::new();
    for value in [canonical_namespace, operation_id] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    format!(
        "{OPERATION_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(digest.finalize())
    )
}

fn audience_state(value: AudienceState) -> &'static str {
    match value {
        AudienceState::Active => "active",
        AudienceState::Blocked => "blocked",
        AudienceState::Retired => "retired",
        AudienceState::CanonicalOnly => "canonical_only",
    }
}

fn registration_state(value: RegistrationState) -> &'static str {
    match value {
        RegistrationState::Pending => "pending",
        RegistrationState::Active => "active",
        RegistrationState::Retired => "retired",
    }
}

#[derive(Clone)]
pub struct DynamoAttributeNamespaceStore {
    db: aws_sdk_dynamodb::Client,
    table: String,
}

impl DynamoAttributeNamespaceStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        Self {
            db,
            table: table.into(),
        }
    }

    pub(crate) fn write_authority_condition(
        &self,
        tenant: &str,
        authority: &AttributeWriteAuthority,
    ) -> Result<TransactWriteItem, StoreError> {
        let mut check = ConditionCheck::builder().table_name(&self.table);
        check = match authority {
            AttributeWriteAuthority::Unbound { namespace } => check
                .set_key(Some(Self::audience_key(tenant, namespace)))
                .condition_expression(
                    "attribute_not_exists(tenant_id) AND attribute_not_exists(lookup_key)",
                ),
            AttributeWriteAuthority::ActiveCanonical {
                canonical_namespace,
                registration_revision,
            } => check
                .set_key(Some(Self::registration_key(tenant, canonical_namespace)))
                .condition_expression(
                    "#canonical = :canonical AND revision = :revision AND #state = :active \
                     AND attribute_not_exists(operation_id)",
                )
                .expression_attribute_names("#canonical", "canonical_namespace")
                .expression_attribute_names("#state", "state")
                .expression_attribute_values(
                    ":canonical",
                    AttributeValue::S(canonical_namespace.clone()),
                )
                .expression_attribute_values(
                    ":revision",
                    AttributeValue::N(registration_revision.to_string()),
                )
                .expression_attribute_values(":active", AttributeValue::S("active".into())),
            AttributeWriteAuthority::ActiveAudience {
                audience,
                canonical_namespace,
                registration_revision,
            } => check
                .set_key(Some(Self::audience_key(tenant, audience)))
                .condition_expression(
                    "#audience = :audience AND #canonical = :canonical \
                     AND registration_revision = :revision AND #state = :active \
                     AND attribute_not_exists(operation_id)",
                )
                .expression_attribute_names("#audience", "audience")
                .expression_attribute_names("#canonical", "canonical_namespace")
                .expression_attribute_names("#state", "state")
                .expression_attribute_values(":audience", AttributeValue::S(audience.clone()))
                .expression_attribute_values(
                    ":canonical",
                    AttributeValue::S(canonical_namespace.clone()),
                )
                .expression_attribute_values(
                    ":revision",
                    AttributeValue::N(registration_revision.to_string()),
                )
                .expression_attribute_values(":active", AttributeValue::S("active".into())),
        };
        Ok(TransactWriteItem::builder()
            .condition_check(check.build().map_err(|error| {
                StoreError::Permanent(format!("build namespace write authority check: {error}"))
            })?)
            .build())
    }

    fn key(tenant: &str, lookup_key: String) -> HashMap<String, AttributeValue> {
        HashMap::from([
            (
                TENANT_KEY.to_string(),
                AttributeValue::S(tenant_key(tenant)),
            ),
            (LOOKUP_KEY.to_string(), AttributeValue::S(lookup_key)),
        ])
    }

    fn registration_key(
        tenant: &str,
        canonical_namespace: &str,
    ) -> HashMap<String, AttributeValue> {
        Self::key(tenant, hashed_key(REGISTRATION_PREFIX, canonical_namespace))
    }

    fn audience_key(tenant: &str, audience: &str) -> HashMap<String, AttributeValue> {
        Self::key(tenant, hashed_key(AUDIENCE_PREFIX, audience))
    }

    fn cancellation_key(
        tenant: &str,
        canonical_namespace: &str,
    ) -> HashMap<String, AttributeValue> {
        Self::key(tenant, hashed_key(CANCELLATION_PREFIX, canonical_namespace))
    }

    fn operation_key(
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
    ) -> HashMap<String, AttributeValue> {
        Self::key(
            tenant,
            operation_lookup_key(canonical_namespace, operation_id),
        )
    }

    fn operation_item(
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
    ) -> HashMap<String, AttributeValue> {
        let mut item = Self::operation_key(tenant, canonical_namespace, operation_id);
        item.insert("row_type".into(), AttributeValue::S("operation".into()));
        item.insert(
            "canonical_namespace".into(),
            AttributeValue::S(canonical_namespace.to_string()),
        );
        item.insert(
            "operation_id".into(),
            AttributeValue::S(operation_id.to_string()),
        );
        item
    }

    fn registration_item(
        tenant: &str,
        registration: &NamespaceRegistration,
    ) -> Result<HashMap<String, AttributeValue>, StoreError> {
        let mut item = Self::registration_key(tenant, &registration.canonical_namespace);
        item.insert("row_type".into(), AttributeValue::S("registration".into()));
        item.insert(
            "canonical_namespace".into(),
            AttributeValue::S(registration.canonical_namespace.clone()),
        );
        item.insert(
            "revision".into(),
            AttributeValue::N(registration.revision.to_string()),
        );
        item.insert(
            "state".into(),
            AttributeValue::S(registration_state(registration.state).into()),
        );
        item.insert(
            "payload".into(),
            AttributeValue::S(serde_json::to_string(registration).map_err(|error| {
                StoreError::Permanent(format!("serialize namespace registration: {error}"))
            })?),
        );
        if let Some(operation) = &registration.operation {
            item.insert(
                "operation_id".into(),
                AttributeValue::S(operation.operation_id.clone()),
            );
            item.insert(
                "operation_revision".into(),
                AttributeValue::N(operation.revision.to_string()),
            );
        }
        if let Some(operation_id) = &registration.last_operation_id {
            item.insert(
                "last_operation_id".into(),
                AttributeValue::S(operation_id.clone()),
            );
        }
        Ok(item)
    }

    fn audience_item(
        tenant: &str,
        binding: &AudienceBinding,
    ) -> Result<HashMap<String, AttributeValue>, StoreError> {
        let mut item = Self::audience_key(tenant, &binding.audience);
        item.insert("row_type".into(), AttributeValue::S("audience".into()));
        item.insert(
            "audience".into(),
            AttributeValue::S(binding.audience.clone()),
        );
        item.insert(
            "canonical_namespace".into(),
            AttributeValue::S(binding.canonical_namespace.clone()),
        );
        item.insert(
            "registration_revision".into(),
            AttributeValue::N(binding.registration_revision.to_string()),
        );
        item.insert(
            "state".into(),
            AttributeValue::S(audience_state(binding.state).into()),
        );
        item.insert(
            "payload".into(),
            AttributeValue::S(serde_json::to_string(binding).map_err(|error| {
                StoreError::Permanent(format!("serialize namespace audience binding: {error}"))
            })?),
        );
        if let Some(operation_id) = &binding.operation_id {
            item.insert(
                "operation_id".into(),
                AttributeValue::S(operation_id.clone()),
            );
        }
        Ok(item)
    }

    fn cancellation_item(
        tenant: &str,
        cancellation: &CancelledNamespaceOperation,
    ) -> Result<HashMap<String, AttributeValue>, StoreError> {
        let mut item = Self::cancellation_key(tenant, &cancellation.canonical_namespace);
        item.insert("row_type".into(), AttributeValue::S("cancellation".into()));
        item.insert(
            "canonical_namespace".into(),
            AttributeValue::S(cancellation.canonical_namespace.clone()),
        );
        item.insert(
            "operation_id".into(),
            AttributeValue::S(cancellation.operation_id.clone()),
        );
        item.insert(
            "operation_revision".into(),
            AttributeValue::N(cancellation.operation_revision.to_string()),
        );
        item.insert(
            "payload".into(),
            AttributeValue::S(serde_json::to_string(cancellation).map_err(|error| {
                StoreError::Permanent(format!("serialize namespace cancellation: {error}"))
            })?),
        );
        Ok(item)
    }

    fn decode_registration(
        item: &HashMap<String, AttributeValue>,
    ) -> Result<NamespaceRegistration, StoreError> {
        let payload = item
            .get("payload")
            .and_then(|value| value.as_s().ok())
            .ok_or_else(|| {
                StoreError::Permanent("namespace registration payload is missing".into())
            })?;
        let registration: NamespaceRegistration =
            serde_json::from_str(payload).map_err(|error| {
                StoreError::Permanent(format!("decode namespace registration: {error}"))
            })?;
        if item
            .get("canonical_namespace")
            .and_then(|value| value.as_s().ok())
            != Some(&registration.canonical_namespace)
        {
            return Err(StoreError::Permanent(
                "namespace registration original URI mismatch".into(),
            ));
        }
        Ok(registration)
    }

    fn decode_audience(
        item: &HashMap<String, AttributeValue>,
    ) -> Result<AudienceBinding, StoreError> {
        let payload = item
            .get("payload")
            .and_then(|value| value.as_s().ok())
            .ok_or_else(|| StoreError::Permanent("namespace audience payload is missing".into()))?;
        let binding: AudienceBinding = serde_json::from_str(payload).map_err(|error| {
            StoreError::Permanent(format!("decode namespace audience binding: {error}"))
        })?;
        if item.get("audience").and_then(|value| value.as_s().ok()) != Some(&binding.audience) {
            return Err(StoreError::Permanent(
                "namespace audience original URI mismatch".into(),
            ));
        }
        Ok(binding)
    }

    fn decode_cancellation(
        item: &HashMap<String, AttributeValue>,
    ) -> Result<CancelledNamespaceOperation, StoreError> {
        let payload = item
            .get("payload")
            .and_then(|value| value.as_s().ok())
            .ok_or_else(|| {
                StoreError::Permanent("namespace cancellation payload is missing".into())
            })?;
        let cancellation: CancelledNamespaceOperation =
            serde_json::from_str(payload).map_err(|error| {
                StoreError::Permanent(format!("decode namespace cancellation: {error}"))
            })?;
        if item
            .get("canonical_namespace")
            .and_then(|value| value.as_s().ok())
            != Some(&cancellation.canonical_namespace)
        {
            return Err(StoreError::Permanent(
                "namespace cancellation original URI mismatch".into(),
            ));
        }
        Ok(cancellation)
    }

    async fn get_registration(
        &self,
        tenant: &str,
        canonical_namespace: &str,
    ) -> Result<Option<NamespaceRegistration>, StoreError> {
        let registration = self
            .db
            .get_item()
            .table_name(&self.table)
            .set_key(Some(Self::registration_key(tenant, canonical_namespace)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?
            .item()
            .map(Self::decode_registration)
            .transpose()?;
        if registration
            .as_ref()
            .is_some_and(|registration| registration.canonical_namespace != canonical_namespace)
        {
            return Err(StoreError::Permanent(
                "namespace registration hash collision".into(),
            ));
        }
        Ok(registration)
    }

    async fn get_cancellation(
        &self,
        tenant: &str,
        canonical_namespace: &str,
    ) -> Result<Option<CancelledNamespaceOperation>, StoreError> {
        let cancellation = self
            .db
            .get_item()
            .table_name(&self.table)
            .set_key(Some(Self::cancellation_key(tenant, canonical_namespace)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?
            .item()
            .map(Self::decode_cancellation)
            .transpose()?;
        if cancellation
            .as_ref()
            .is_some_and(|cancellation| cancellation.canonical_namespace != canonical_namespace)
        {
            return Err(StoreError::Permanent(
                "namespace cancellation hash collision".into(),
            ));
        }
        Ok(cancellation)
    }

    async fn operation_id_used(
        &self,
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
    ) -> Result<bool, StoreError> {
        let output = self
            .db
            .get_item()
            .table_name(&self.table)
            .set_key(Some(Self::operation_key(
                tenant,
                canonical_namespace,
                operation_id,
            )))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        let Some(item) = output.item() else {
            return Ok(false);
        };
        if item
            .get("canonical_namespace")
            .and_then(|value| value.as_s().ok())
            .map(String::as_str)
            != Some(canonical_namespace)
            || item
                .get("operation_id")
                .and_then(|value| value.as_s().ok())
                .map(String::as_str)
                != Some(operation_id)
        {
            return Err(StoreError::Permanent(
                "namespace operation marker hash collision".into(),
            ));
        }
        Ok(true)
    }

    fn operation_put(
        &self,
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
    ) -> Result<Put, StoreError> {
        Put::builder()
            .table_name(&self.table)
            .set_item(Some(Self::operation_item(
                tenant,
                canonical_namespace,
                operation_id,
            )))
            .condition_expression(
                "attribute_not_exists(tenant_id) AND attribute_not_exists(lookup_key)",
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build namespace operation marker: {error}"))
            })
    }

    async fn get_binding(
        &self,
        tenant: &str,
        audience: &str,
    ) -> Result<Option<AudienceBinding>, StoreError> {
        let binding = self
            .db
            .get_item()
            .table_name(&self.table)
            .set_key(Some(Self::audience_key(tenant, audience)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?
            .item()
            .map(Self::decode_audience)
            .transpose()?;
        if binding
            .as_ref()
            .is_some_and(|binding| binding.audience != audience)
        {
            return Err(StoreError::Permanent(
                "namespace audience hash collision".into(),
            ));
        }
        Ok(binding)
    }

    async fn read_bindings(
        &self,
        tenant: &str,
        audiences: &BTreeSet<String>,
    ) -> Result<BTreeMap<String, Option<AudienceBinding>>, StoreError> {
        let mut request = self.db.transact_get_items();
        for audience in audiences {
            let get = Get::builder()
                .table_name(&self.table)
                .set_key(Some(Self::audience_key(tenant, audience)))
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!("build namespace audience read: {error}"))
                })?;
            request = request.transact_items(TransactGetItem::builder().get(get).build());
        }
        let output = request.send().await.map_err(ddb_err)?;
        if output.responses().len() != audiences.len() {
            return Err(StoreError::Transient(
                "namespace audience snapshot was incomplete".into(),
            ));
        }
        audiences
            .iter()
            .zip(output.responses())
            .map(|(audience, response)| {
                let binding = response
                    .item
                    .as_ref()
                    .map(Self::decode_audience)
                    .transpose()?;
                if binding
                    .as_ref()
                    .is_some_and(|binding| binding.audience != *audience)
                {
                    return Err(StoreError::Permanent(
                        "namespace audience hash collision".into(),
                    ));
                }
                Ok((audience.clone(), binding))
            })
            .collect()
    }

    fn registration_put(
        &self,
        tenant: &str,
        next: &NamespaceRegistration,
        previous: Option<&NamespaceRegistration>,
    ) -> Result<Put, StoreError> {
        let mut put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(Self::registration_item(tenant, next)?));
        put = match previous {
            None => put.condition_expression(
                "attribute_not_exists(tenant_id) AND attribute_not_exists(lookup_key)",
            ),
            Some(previous) => {
                let mut condition =
                    "#canonical = :canonical AND revision = :revision AND #state = :state"
                        .to_string();
                put = put
                    .expression_attribute_names("#canonical", "canonical_namespace")
                    .expression_attribute_names("#state", "state")
                    .expression_attribute_values(
                        ":canonical",
                        AttributeValue::S(previous.canonical_namespace.clone()),
                    )
                    .expression_attribute_values(
                        ":revision",
                        AttributeValue::N(previous.revision.to_string()),
                    )
                    .expression_attribute_values(
                        ":state",
                        AttributeValue::S(registration_state(previous.state).into()),
                    );
                if let Some(operation) = &previous.operation {
                    condition.push_str(
                        " AND operation_id = :operation_id AND operation_revision = :operation_revision",
                    );
                    put = put
                        .expression_attribute_values(
                            ":operation_id",
                            AttributeValue::S(operation.operation_id.clone()),
                        )
                        .expression_attribute_values(
                            ":operation_revision",
                            AttributeValue::N(operation.revision.to_string()),
                        );
                } else {
                    condition.push_str(" AND attribute_not_exists(operation_id)");
                }
                put.condition_expression(condition)
            }
        };
        put.build().map_err(|error| {
            StoreError::Permanent(format!("build namespace registration put: {error}"))
        })
    }

    fn audience_put(
        &self,
        tenant: &str,
        next: &AudienceBinding,
        previous: Option<&AudienceBinding>,
    ) -> Result<Put, StoreError> {
        let mut put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(Self::audience_item(tenant, next)?));
        put = match previous {
            None => put.condition_expression(
                "attribute_not_exists(tenant_id) AND attribute_not_exists(lookup_key)",
            ),
            Some(previous) => {
                let mut condition = "#audience = :audience AND #canonical = :canonical \
                    AND registration_revision = :registration_revision AND #state = :state"
                    .to_string();
                put = put
                    .expression_attribute_names("#audience", "audience")
                    .expression_attribute_names("#canonical", "canonical_namespace")
                    .expression_attribute_names("#state", "state")
                    .expression_attribute_values(
                        ":audience",
                        AttributeValue::S(previous.audience.clone()),
                    )
                    .expression_attribute_values(
                        ":canonical",
                        AttributeValue::S(previous.canonical_namespace.clone()),
                    )
                    .expression_attribute_values(
                        ":registration_revision",
                        AttributeValue::N(previous.registration_revision.to_string()),
                    )
                    .expression_attribute_values(
                        ":state",
                        AttributeValue::S(audience_state(previous.state).into()),
                    );
                if let Some(operation_id) = &previous.operation_id {
                    condition.push_str(" AND operation_id = :operation_id");
                    put = put.expression_attribute_values(
                        ":operation_id",
                        AttributeValue::S(operation_id.clone()),
                    );
                } else {
                    condition.push_str(" AND attribute_not_exists(operation_id)");
                }
                put.condition_expression(condition)
            }
        };
        put.build().map_err(|error| {
            StoreError::Permanent(format!("build namespace audience put: {error}"))
        })
    }

    fn registration_delete(
        &self,
        tenant: &str,
        previous: &NamespaceRegistration,
    ) -> Result<Delete, StoreError> {
        let operation = previous.operation.as_ref().ok_or_else(|| {
            StoreError::Permanent("namespace registration delete requires an operation".into())
        })?;
        Delete::builder()
            .table_name(&self.table)
            .set_key(Some(Self::registration_key(
                tenant,
                &previous.canonical_namespace,
            )))
            .condition_expression(
                "#canonical = :canonical AND revision = :revision AND #state = :state \
                 AND operation_id = :operation_id AND operation_revision = :operation_revision",
            )
            .expression_attribute_names("#canonical", "canonical_namespace")
            .expression_attribute_names("#state", "state")
            .expression_attribute_values(
                ":canonical",
                AttributeValue::S(previous.canonical_namespace.clone()),
            )
            .expression_attribute_values(
                ":revision",
                AttributeValue::N(previous.revision.to_string()),
            )
            .expression_attribute_values(
                ":state",
                AttributeValue::S(registration_state(previous.state).into()),
            )
            .expression_attribute_values(
                ":operation_id",
                AttributeValue::S(operation.operation_id.clone()),
            )
            .expression_attribute_values(
                ":operation_revision",
                AttributeValue::N(operation.revision.to_string()),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build namespace registration delete: {error}"))
            })
    }

    fn audience_delete(
        &self,
        tenant: &str,
        previous: &AudienceBinding,
    ) -> Result<Delete, StoreError> {
        let operation_id = previous.operation_id.as_ref().ok_or_else(|| {
            StoreError::Permanent("namespace audience delete requires an operation".into())
        })?;
        Delete::builder()
            .table_name(&self.table)
            .set_key(Some(Self::audience_key(tenant, &previous.audience)))
            .condition_expression(
                "#audience = :audience AND #canonical = :canonical \
                 AND registration_revision = :registration_revision AND #state = :state \
                 AND operation_id = :operation_id",
            )
            .expression_attribute_names("#audience", "audience")
            .expression_attribute_names("#canonical", "canonical_namespace")
            .expression_attribute_names("#state", "state")
            .expression_attribute_values(":audience", AttributeValue::S(previous.audience.clone()))
            .expression_attribute_values(
                ":canonical",
                AttributeValue::S(previous.canonical_namespace.clone()),
            )
            .expression_attribute_values(
                ":registration_revision",
                AttributeValue::N(previous.registration_revision.to_string()),
            )
            .expression_attribute_values(
                ":state",
                AttributeValue::S(audience_state(previous.state).into()),
            )
            .expression_attribute_values(":operation_id", AttributeValue::S(operation_id.clone()))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build namespace audience delete: {error}"))
            })
    }

    fn cancellation_put(
        &self,
        tenant: &str,
        cancellation: &CancelledNamespaceOperation,
    ) -> Result<Put, StoreError> {
        Put::builder()
            .table_name(&self.table)
            .set_item(Some(Self::cancellation_item(tenant, cancellation)?))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build namespace cancellation put: {error}"))
            })
    }

    fn cancellation_delete(
        &self,
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
    ) -> Result<Delete, StoreError> {
        Delete::builder()
            .table_name(&self.table)
            .set_key(Some(Self::cancellation_key(tenant, canonical_namespace)))
            .condition_expression(
                "attribute_not_exists(operation_id) OR operation_id <> :operation_id",
            )
            .expression_attribute_values(
                ":operation_id",
                AttributeValue::S(operation_id.to_string()),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build namespace cancellation delete: {error}"))
            })
    }

    async fn replayed_cancellation(
        &self,
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
        operation_revision: u64,
    ) -> Result<Option<NamespaceChangeOutcome>, StoreError> {
        Ok(self
            .get_cancellation(tenant, canonical_namespace)
            .await?
            .filter(|cancellation| {
                cancellation.operation_id == operation_id
                    && cancellation.operation_revision == operation_revision
            })
            .map(|cancellation| {
                NamespaceChangeOutcome::Cancelled(cancellation.restored_registration)
            }))
    }

    fn operation_conflict(registration: NamespaceRegistration) -> NamespaceChangeOutcome {
        match registration.operation {
            Some(operation) => NamespaceChangeOutcome::OperationConflict {
                operation_id: operation.operation_id,
                revision: operation.revision,
            },
            None => NamespaceChangeOutcome::InvalidState,
        }
    }
}

impl AttributeNamespaceStore for DynamoAttributeNamespaceStore {
    async fn resolve(
        &self,
        tenant: &str,
        verified_aud: &str,
    ) -> Result<AudienceResolution, StoreError> {
        let binding = self.get_binding(tenant, verified_aud).await?;
        Ok(resolve_exact(binding.as_ref(), verified_aud))
    }

    async fn resolve_write_authority(
        &self,
        tenant: &str,
        namespace: &str,
    ) -> Result<AttributeWriteResolution, StoreError> {
        if let Some(registration) = self.get_registration(tenant, namespace).await? {
            return Ok(match registration.state {
                RegistrationState::Active => {
                    AttributeWriteResolution::Authorized(AttributeWriteAuthority::ActiveCanonical {
                        canonical_namespace: registration.canonical_namespace,
                        registration_revision: registration.revision,
                    })
                }
                RegistrationState::Pending | RegistrationState::Retired => {
                    AttributeWriteResolution::Blocked
                }
            });
        }
        Ok(match self.get_binding(tenant, namespace).await? {
            Some(binding) if binding.state == AudienceState::Active => {
                AttributeWriteResolution::Authorized(AttributeWriteAuthority::ActiveAudience {
                    audience: namespace.to_string(),
                    canonical_namespace: binding.canonical_namespace,
                    registration_revision: binding.registration_revision,
                })
            }
            Some(_) => AttributeWriteResolution::Blocked,
            None => AttributeWriteResolution::Authorized(AttributeWriteAuthority::Unbound {
                namespace: namespace.to_string(),
            }),
        })
    }

    async fn get(
        &self,
        tenant: &str,
        canonical_namespace: &str,
    ) -> Result<Option<NamespaceRegistration>, StoreError> {
        self.get_registration(tenant, canonical_namespace).await
    }

    async fn list(&self, tenant: &str) -> Result<Vec<NamespaceRegistration>, StoreError> {
        let mut registrations = Vec::new();
        let mut start_key = None;
        loop {
            let output = self
                .db
                .query()
                .table_name(&self.table)
                .key_condition_expression(
                    "tenant_id = :tenant AND begins_with(lookup_key, :prefix)",
                )
                .expression_attribute_values(":tenant", AttributeValue::S(tenant_key(tenant)))
                .expression_attribute_values(
                    ":prefix",
                    AttributeValue::S(REGISTRATION_PREFIX.into()),
                )
                .set_exclusive_start_key(start_key)
                .consistent_read(true)
                .send()
                .await
                .map_err(ddb_err)?;
            for item in output.items() {
                registrations.push(Self::decode_registration(item)?);
            }
            match output.last_evaluated_key() {
                Some(key) if !key.is_empty() => start_key = Some(key.clone()),
                _ => break,
            }
        }
        registrations
            .sort_by(|left, right| left.canonical_namespace.cmp(&right.canonical_namespace));
        Ok(registrations)
    }

    async fn begin_change(
        &self,
        tenant: &str,
        request: BeginNamespaceChange,
    ) -> Result<BeginNamespaceChangeOutcome, StoreError> {
        if request.operation_id.is_empty() || request.operation_id.len() > 256 {
            return Err(StoreError::Permanent(
                "namespace operation id must be 1..=256 bytes".into(),
            ));
        }
        match request.kind {
            NamespaceChangeKind::Upsert => {
                let exact: Vec<String> = request.exact_audiences.iter().cloned().collect();
                validate_exact_audiences(&request.canonical_namespace, &exact)
                    .map_err(|message| StoreError::Permanent(message.into()))?;
            }
            NamespaceChangeKind::Delete => {
                if !validate_namespace_uri(&request.canonical_namespace)
                    || !request.exact_audiences.is_empty()
                {
                    return Err(StoreError::Permanent(
                        "delete requires a valid canonical namespace and no audiences".into(),
                    ));
                }
            }
        }

        for _ in 0..5 {
            let current = self
                .get_registration(tenant, &request.canonical_namespace)
                .await?;
            if let Some(registration) = &current {
                if registration.state == RegistrationState::Pending {
                    let operation = registration.operation.as_ref().ok_or_else(|| {
                        StoreError::Permanent("pending registration has no operation".into())
                    })?;
                    if operation.operation_id == request.operation_id
                        && operation.expected_registration_revision == request.expected_revision
                        && operation.kind == request.kind
                        && operation.desired_exact_audiences == request.exact_audiences
                    {
                        return Ok(BeginNamespaceChangeOutcome::Started(Box::new(
                            registration.clone(),
                        )));
                    }
                    return Ok(BeginNamespaceChangeOutcome::Busy {
                        operation_id: operation.operation_id.clone(),
                    });
                }
            }
            if self
                .operation_id_used(tenant, &request.canonical_namespace, &request.operation_id)
                .await?
            {
                return Ok(BeginNamespaceChangeOutcome::Busy {
                    operation_id: request.operation_id,
                });
            }
            if current
                .as_ref()
                .and_then(|registration| registration.last_operation_id.as_deref())
                == Some(request.operation_id.as_str())
                || self
                    .get_cancellation(tenant, &request.canonical_namespace)
                    .await?
                    .is_some_and(|cancellation| cancellation.operation_id == request.operation_id)
            {
                return Ok(BeginNamespaceChangeOutcome::Busy {
                    operation_id: request.operation_id,
                });
            }
            let current_revision = current
                .as_ref()
                .map(|registration| registration.revision)
                .unwrap_or(0);
            if current_revision != request.expected_revision {
                return Ok(BeginNamespaceChangeOutcome::RevisionConflict {
                    current: current_revision,
                });
            }
            if request.kind == NamespaceChangeKind::Delete
                && current
                    .as_ref()
                    .is_none_or(|registration| registration.state == RegistrationState::Retired)
            {
                return Ok(BeginNamespaceChangeOutcome::NotFound);
            }

            let mut affected = request.exact_audiences.clone();
            affected.insert(request.canonical_namespace.clone());
            if let Some(registration) = &current {
                affected.extend(registration.exact_audiences.iter().cloned());
            }
            let bindings = self.read_bindings(tenant, &affected).await?;
            for (audience, previous) in &bindings {
                if let Some(binding) = previous {
                    if binding.canonical_namespace != request.canonical_namespace
                        && matches!(
                            binding.state,
                            AudienceState::Active
                                | AudienceState::Blocked
                                | AudienceState::CanonicalOnly
                        )
                    {
                        return Ok(BeginNamespaceChangeOutcome::AudienceConflict {
                            audience: audience.clone(),
                            canonical_namespace: binding.canonical_namespace.clone(),
                        });
                    }
                    if binding.state == AudienceState::Blocked
                        && binding.operation_id.as_deref() != Some(request.operation_id.as_str())
                    {
                        return Ok(BeginNamespaceChangeOutcome::Busy {
                            operation_id: binding.operation_id.clone().unwrap_or_default(),
                        });
                    }
                }
            }

            let operation = NamespaceMigrationOperation {
                operation_id: request.operation_id.clone(),
                expected_registration_revision: request.expected_revision,
                revision: 1,
                kind: request.kind,
                desired_exact_audiences: request.exact_audiences.clone(),
                source_namespaces: affected.clone(),
                previous_registration: current.as_ref().map(|registration| RegistrationSnapshot {
                    revision: registration.revision,
                    exact_audiences: registration.exact_audiences.clone(),
                    state: registration.state,
                    last_operation_id: registration.last_operation_id.clone(),
                }),
                previous_bindings: bindings.clone(),
                phase: NamespaceMigrationPhase::Validating,
                cursor: None,
                scan_complete: false,
                started_mutation: false,
                inflight_user_id: None,
                users_scanned: 0,
                users_completed: 0,
                conflict_count: 0,
                conflict_user_ids: Vec::new(),
            };
            let registration = NamespaceRegistration {
                canonical_namespace: request.canonical_namespace.clone(),
                revision: current_revision,
                exact_audiences: current
                    .as_ref()
                    .map(|registration| registration.exact_audiences.clone())
                    .unwrap_or_default(),
                state: RegistrationState::Pending,
                last_operation_id: current
                    .as_ref()
                    .and_then(|registration| registration.last_operation_id.clone()),
                operation: Some(operation),
            };
            let mut transaction = self.db.transact_write_items().transact_items(
                TransactWriteItem::builder()
                    .put(self.registration_put(tenant, &registration, current.as_ref())?)
                    .build(),
            );
            transaction = transaction.transact_items(
                TransactWriteItem::builder()
                    .put(self.operation_put(
                        tenant,
                        &request.canonical_namespace,
                        &request.operation_id,
                    )?)
                    .build(),
            );
            transaction = transaction.transact_items(
                TransactWriteItem::builder()
                    .delete(self.cancellation_delete(
                        tenant,
                        &request.canonical_namespace,
                        &request.operation_id,
                    )?)
                    .build(),
            );
            for audience in &affected {
                let blocked = AudienceBinding {
                    audience: audience.clone(),
                    canonical_namespace: request.canonical_namespace.clone(),
                    registration_revision: current_revision,
                    state: AudienceState::Blocked,
                    operation_id: Some(request.operation_id.clone()),
                };
                transaction = transaction.transact_items(
                    TransactWriteItem::builder()
                        .put(self.audience_put(
                            tenant,
                            &blocked,
                            bindings.get(audience).and_then(Option::as_ref),
                        )?)
                        .build(),
                );
            }
            if send_idempotent_transaction(transaction).await? {
                return Ok(BeginNamespaceChangeOutcome::Started(Box::new(registration)));
            }
        }
        Err(StoreError::Transient(
            "namespace begin did not converge after conditional conflicts".into(),
        ))
    }

    async fn checkpoint(
        &self,
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
        checkpoint: NamespaceOperationCheckpoint,
    ) -> Result<NamespaceChangeOutcome, StoreError> {
        if checkpoint.conflict_user_ids.len() > 20 {
            return Err(StoreError::Permanent(
                "namespace conflict sample exceeds 20 users".into(),
            ));
        }
        let Some(mut registration) = self.get_registration(tenant, canonical_namespace).await?
        else {
            return Ok(NamespaceChangeOutcome::NotFound);
        };
        let previous = registration.clone();
        let Some(mut operation) = registration.operation.clone() else {
            return Ok(NamespaceChangeOutcome::InvalidState);
        };
        if operation.operation_id != operation_id
            || operation.revision != checkpoint.expected_revision
        {
            return Ok(NamespaceChangeOutcome::OperationConflict {
                operation_id: operation.operation_id,
                revision: operation.revision,
            });
        }
        let invalid = (operation.phase == NamespaceMigrationPhase::Migrating
            && checkpoint.phase == NamespaceMigrationPhase::Validating)
            || checkpoint.users_scanned < operation.users_scanned
            || checkpoint.users_completed < operation.users_completed
            || checkpoint.conflict_count < operation.conflict_count
            || invalid_inflight_checkpoint(&operation, &checkpoint)
            || (operation.started_mutation && !checkpoint.started_mutation)
            || (operation.phase == NamespaceMigrationPhase::Validating
                && checkpoint.phase == NamespaceMigrationPhase::Migrating
                && checkpoint.conflict_count != 0);
        if invalid {
            return Ok(NamespaceChangeOutcome::InvalidState);
        }
        operation.revision = operation.revision.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("namespace operation revision exhausted".into())
        })?;
        operation.phase = checkpoint.phase;
        operation.cursor = checkpoint.cursor;
        operation.scan_complete = checkpoint.scan_complete;
        operation.started_mutation = checkpoint.started_mutation;
        operation.inflight_user_id = checkpoint.inflight_user_id;
        operation.users_scanned = checkpoint.users_scanned;
        operation.users_completed = checkpoint.users_completed;
        operation.conflict_count = checkpoint.conflict_count;
        operation.conflict_user_ids = checkpoint.conflict_user_ids;
        registration.operation = Some(operation);
        let request = self.db.transact_write_items().transact_items(
            TransactWriteItem::builder()
                .put(self.registration_put(tenant, &registration, Some(&previous))?)
                .build(),
        );
        if send_idempotent_transaction(request).await? {
            return Ok(NamespaceChangeOutcome::Updated(registration));
        }
        Ok(
            match self.get_registration(tenant, canonical_namespace).await? {
                Some(current) => Self::operation_conflict(current),
                None => NamespaceChangeOutcome::NotFound,
            },
        )
    }

    async fn activate(
        &self,
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
        expected_operation_revision: u64,
    ) -> Result<NamespaceChangeOutcome, StoreError> {
        for _ in 0..3 {
            let Some(mut registration) = self.get_registration(tenant, canonical_namespace).await?
            else {
                return Ok(NamespaceChangeOutcome::NotFound);
            };
            let previous = registration.clone();
            let Some(operation) = registration.operation.clone() else {
                if registration.last_operation_id.as_deref() == Some(operation_id) {
                    return Ok(NamespaceChangeOutcome::Updated(registration));
                }
                return Ok(NamespaceChangeOutcome::InvalidState);
            };
            if operation.operation_id != operation_id
                || operation.revision != expected_operation_revision
            {
                return Ok(NamespaceChangeOutcome::OperationConflict {
                    operation_id: operation.operation_id,
                    revision: operation.revision,
                });
            }
            if operation.phase != NamespaceMigrationPhase::Migrating
                || !operation.scan_complete
                || operation.inflight_user_id.is_some()
                || operation.conflict_count != 0
            {
                return Ok(NamespaceChangeOutcome::InvalidState);
            }
            let revision = registration.revision.checked_add(1).ok_or_else(|| {
                StoreError::Permanent("namespace registration revision exhausted".into())
            })?;
            registration.revision = revision;
            registration.last_operation_id = Some(operation.operation_id.clone());
            registration.operation = None;
            match operation.kind {
                NamespaceChangeKind::Upsert => {
                    registration.exact_audiences = operation.desired_exact_audiences.clone();
                    registration.state = RegistrationState::Active;
                }
                NamespaceChangeKind::Delete => {
                    registration.exact_audiences.clear();
                    registration.state = RegistrationState::Retired;
                }
            }
            let mut transaction = self.db.transact_write_items().transact_items(
                TransactWriteItem::builder()
                    .put(self.registration_put(tenant, &registration, Some(&previous))?)
                    .build(),
            );
            for audience in &operation.source_namespaces {
                let next_state = match operation.kind {
                    NamespaceChangeKind::Delete => AudienceState::Retired,
                    NamespaceChangeKind::Upsert
                        if operation.desired_exact_audiences.contains(audience) =>
                    {
                        AudienceState::Active
                    }
                    NamespaceChangeKind::Upsert if audience == canonical_namespace => {
                        AudienceState::CanonicalOnly
                    }
                    NamespaceChangeKind::Upsert => AudienceState::Retired,
                };
                let blocked = AudienceBinding {
                    audience: audience.clone(),
                    canonical_namespace: canonical_namespace.to_string(),
                    registration_revision: previous.revision,
                    state: AudienceState::Blocked,
                    operation_id: Some(operation_id.to_string()),
                };
                let next = AudienceBinding {
                    audience: audience.clone(),
                    canonical_namespace: canonical_namespace.to_string(),
                    registration_revision: revision,
                    state: next_state,
                    operation_id: None,
                };
                transaction = transaction.transact_items(
                    TransactWriteItem::builder()
                        .put(self.audience_put(tenant, &next, Some(&blocked))?)
                        .build(),
                );
            }
            if send_idempotent_transaction(transaction).await? {
                return Ok(NamespaceChangeOutcome::Updated(registration));
            }
        }
        Ok(
            match self.get_registration(tenant, canonical_namespace).await? {
                Some(current) if current.last_operation_id.as_deref() == Some(operation_id) => {
                    NamespaceChangeOutcome::Updated(current)
                }
                Some(current) => Self::operation_conflict(current),
                None => NamespaceChangeOutcome::NotFound,
            },
        )
    }

    async fn cancel(
        &self,
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
        expected_operation_revision: u64,
    ) -> Result<NamespaceChangeOutcome, StoreError> {
        let Some(registration) = self.get_registration(tenant, canonical_namespace).await? else {
            if let Some(outcome) = self
                .replayed_cancellation(
                    tenant,
                    canonical_namespace,
                    operation_id,
                    expected_operation_revision,
                )
                .await?
            {
                return Ok(outcome);
            }
            return Ok(NamespaceChangeOutcome::NotFound);
        };
        let Some(operation) = registration.operation.clone() else {
            if let Some(outcome) = self
                .replayed_cancellation(
                    tenant,
                    canonical_namespace,
                    operation_id,
                    expected_operation_revision,
                )
                .await?
            {
                return Ok(outcome);
            }
            return Ok(NamespaceChangeOutcome::InvalidState);
        };
        if operation.operation_id != operation_id
            || operation.revision != expected_operation_revision
        {
            return Ok(NamespaceChangeOutcome::OperationConflict {
                operation_id: operation.operation_id,
                revision: operation.revision,
            });
        }
        if operation.started_mutation {
            return Ok(NamespaceChangeOutcome::CannotCancel);
        }

        let mut transaction = self.db.transact_write_items();
        for (audience, previous) in &operation.previous_bindings {
            let blocked = AudienceBinding {
                audience: audience.clone(),
                canonical_namespace: canonical_namespace.to_string(),
                registration_revision: registration.revision,
                state: AudienceState::Blocked,
                operation_id: Some(operation_id.to_string()),
            };
            transaction = match previous {
                Some(previous) => transaction.transact_items(
                    TransactWriteItem::builder()
                        .put(self.audience_put(tenant, previous, Some(&blocked))?)
                        .build(),
                ),
                None => transaction.transact_items(
                    TransactWriteItem::builder()
                        .delete(self.audience_delete(tenant, &blocked)?)
                        .build(),
                ),
            };
        }
        let restored = operation
            .previous_registration
            .map(|snapshot| NamespaceRegistration {
                canonical_namespace: canonical_namespace.to_string(),
                revision: snapshot.revision,
                exact_audiences: snapshot.exact_audiences,
                state: snapshot.state,
                last_operation_id: snapshot.last_operation_id,
                operation: None,
            });
        let cancellation = CancelledNamespaceOperation {
            canonical_namespace: canonical_namespace.to_string(),
            operation_id: operation_id.to_string(),
            operation_revision: expected_operation_revision,
            restored_registration: restored.clone(),
        };
        transaction = transaction.transact_items(
            TransactWriteItem::builder()
                .put(self.cancellation_put(tenant, &cancellation)?)
                .build(),
        );
        transaction = match &restored {
            Some(restored) => transaction.transact_items(
                TransactWriteItem::builder()
                    .put(self.registration_put(tenant, restored, Some(&registration))?)
                    .build(),
            ),
            None => transaction.transact_items(
                TransactWriteItem::builder()
                    .delete(self.registration_delete(tenant, &registration)?)
                    .build(),
            ),
        };
        if send_idempotent_transaction(transaction).await? {
            return Ok(NamespaceChangeOutcome::Cancelled(restored));
        }
        if let Some(outcome) = self
            .replayed_cancellation(
                tenant,
                canonical_namespace,
                operation_id,
                expected_operation_revision,
            )
            .await?
        {
            return Ok(outcome);
        }
        Ok(
            match self.get_registration(tenant, canonical_namespace).await? {
                Some(current) => Self::operation_conflict(current),
                None => NamespaceChangeOutcome::Cancelled(None),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_keys_hash_exact_uri_bytes_without_normalization() {
        let base = hashed_key(AUDIENCE_PREFIX, "https://finance.example.com");
        assert_ne!(
            base,
            hashed_key(AUDIENCE_PREFIX, "https://finance.example.com/")
        );
        assert_ne!(
            base,
            hashed_key(AUDIENCE_PREFIX, "https://FINANCE.example.com")
        );
        assert_ne!(
            base,
            hashed_key(REGISTRATION_PREFIX, "https://finance.example.com")
        );
    }

    #[test]
    fn operation_markers_frame_both_identifiers_and_preserve_originals() {
        assert_ne!(
            operation_lookup_key("urn:example:ab", "c"),
            operation_lookup_key("urn:example:a", "bc")
        );

        let canonical = "urn:example:finance";
        let operation_id = "operation-a";
        let item =
            DynamoAttributeNamespaceStore::operation_item("tenant-a", canonical, operation_id);
        assert_eq!(item["canonical_namespace"].as_s().unwrap(), canonical);
        assert_eq!(item["operation_id"].as_s().unwrap(), operation_id);

        let store = DynamoAttributeNamespaceStore::new(
            aws_sdk_dynamodb::Client::from_conf(
                aws_sdk_dynamodb::Config::builder()
                    .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
                    .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                    .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                    .build(),
            ),
            "attribute-namespaces",
        );
        let put = store
            .operation_put("tenant-a", canonical, operation_id)
            .unwrap();
        assert_eq!(
            put.condition_expression(),
            Some("attribute_not_exists(tenant_id) AND attribute_not_exists(lookup_key)")
        );
    }

    #[test]
    fn audience_decode_rejects_original_uri_mismatch() {
        let binding = AudienceBinding {
            audience: "https://finance.example.com".into(),
            canonical_namespace: "https://resources.example.com/finance".into(),
            registration_revision: 1,
            state: AudienceState::Active,
            operation_id: None,
        };
        let mut item = DynamoAttributeNamespaceStore::audience_item("", &binding).unwrap();
        item.insert(
            "audience".into(),
            AttributeValue::S("https://finance.example.com/".into()),
        );
        assert!(DynamoAttributeNamespaceStore::decode_audience(&item).is_err());
    }

    #[test]
    fn attribute_write_authority_checks_fence_unbound_alias_and_canonical_states() {
        let store = DynamoAttributeNamespaceStore::new(
            aws_sdk_dynamodb::Client::from_conf(
                aws_sdk_dynamodb::Config::builder()
                    .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
                    .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                    .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                    .build(),
            ),
            "attribute-namespaces",
        );
        let unbound = store
            .write_authority_condition(
                "tenant-a",
                &AttributeWriteAuthority::Unbound {
                    namespace: "https://unbound.example.com".into(),
                },
            )
            .unwrap()
            .condition_check()
            .unwrap()
            .clone();
        assert_eq!(
            unbound.condition_expression(),
            "attribute_not_exists(tenant_id) AND attribute_not_exists(lookup_key)"
        );

        let alias = store
            .write_authority_condition(
                "tenant-a",
                &AttributeWriteAuthority::ActiveAudience {
                    audience: "https://finance.example.com".into(),
                    canonical_namespace: "https://resources.example.com/finance".into(),
                    registration_revision: 7,
                },
            )
            .unwrap()
            .condition_check()
            .unwrap()
            .clone();
        let alias_condition = alias.condition_expression();
        assert!(alias_condition.contains("registration_revision = :revision"));
        assert!(alias_condition.contains("#state = :active"));
        assert!(alias_condition.contains("attribute_not_exists(operation_id)"));
        assert_eq!(
            alias.expression_attribute_values().unwrap()[":audience"]
                .as_s()
                .unwrap(),
            "https://finance.example.com"
        );

        let canonical = store
            .write_authority_condition(
                "tenant-a",
                &AttributeWriteAuthority::ActiveCanonical {
                    canonical_namespace: "https://resources.example.com/finance".into(),
                    registration_revision: 7,
                },
            )
            .unwrap()
            .condition_check()
            .unwrap()
            .clone();
        let canonical_condition = canonical.condition_expression();
        assert!(canonical_condition.contains("revision = :revision"));
        assert!(canonical_condition.contains("attribute_not_exists(operation_id)"));
    }
}
