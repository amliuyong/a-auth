use super::*;

pub(crate) struct AuthorizedFederatedReconciliation<'a> {
    pub tenant: &'a str,
    pub user_id: &'a str,
    pub upstream_idp_id: &'a str,
    pub desired: &'a crate::federation_attributes::DesiredFederatedAttributes,
    pub registry_revision: u64,
    pub operation_id: &'a str,
    pub fingerprint: &'a str,
    pub authority_conditions: Vec<aws_sdk_dynamodb::types::TransactWriteItem>,
}

/// DynamoDB 用户目录(spec 003 §1.4)。表 pk=`user_id` + GSI `email-index`(email→user_id lookup)
/// + sparse GSI `scim_tenant-index`(tenant→SCIM canonical users)。
///
/// **持久身份不挂 TTL**(C10.5)。`create_or_get_by_email` 幂等:先 GSI 查 email、无则条件 PutItem
/// (`attribute_not_exists(user_id)`,并发一方成功,另一方 ConditionalCheckFailed → 重查复用)。
const TOUCH_LAST_LOGIN_UPDATE_EXPRESSION: &str = "SET last_login_at = :now";
const TOUCH_LAST_LOGIN_CONDITION_EXPRESSION: &str = "attribute_exists(user_id) AND \
     (attribute_not_exists(#status) OR #status = :active) AND \
     (attribute_not_exists(last_login_at) OR last_login_at < :now)";
const ATTRIBUTE_USER_EXISTS_CONDITION: &str = "attribute_exists(user_id)";
const USER_LIST_CONSISTENT_READ: bool = true;
const SCIM_ALIAS_RECORD_TYPE: &str = "scim_alias";
const SCIM_CREATE_RECORD_TYPE: &str = "scim_create";
const SCIM_ALIAS_EXTERNAL: &str = "external";
const SCIM_ALIAS_USERNAME: &str = "username";

struct ScimCreateClaim {
    user_id: String,
    pending_initial_epoch: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttributeTransactionOutcome {
    Applied,
    AuthorityConflict,
    UserConflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GovernanceUserIdentityInventory {
    pub canonical_exists: bool,
    pub canonical_tombstoned: bool,
    pub canonical_epoch: Option<u64>,
    pub scim_aliases_remaining: usize,
    pub scim_create_claims_remaining: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct GovernanceTenantIdentityInventory {
    pub canonical_rows: usize,
    pub scim_alias_rows: usize,
    pub scim_create_claim_rows: usize,
}

fn disable_status_condition(status: crate::ports::UserStatus) -> (&'static str, bool) {
    if status == crate::ports::UserStatus::Active {
        ("(attribute_not_exists(#status) OR #status = :active)", true)
    } else {
        ("#status = :disabled", false)
    }
}

#[derive(Clone)]
pub struct DynamoUsersStore {
    db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
    email_index: String,
    scim_tenant_index: String,
    governance_suppression: Option<(String, Vec<u8>)>,
}

impl DynamoUsersStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        Self {
            db,
            table: table.into(),
            email_index: "email-index".to_string(),
            scim_tenant_index: "scim_tenant-index".to_string(),
            governance_suppression: None,
        }
    }

    pub(crate) fn federation_reconciliation_user_item(
        &self,
        tenant: &str,
        current: &crate::ports::UserRecord,
        next: &crate::ports::UserRecord,
        changed: bool,
        operation_id: &str,
        fingerprint: &str,
    ) -> Result<aws_sdk_dynamodb::types::TransactWriteItem, StoreError> {
        use aws_sdk_dynamodb::types::{AttributeValue, TransactWriteItem, Update};

        let generation_condition = if current.attributes_generation == 0 {
            "(attribute_not_exists(#generation) OR #generation = :expected_generation)"
        } else {
            "#generation = :expected_generation"
        };
        let attributes_condition = if current.attributes.is_empty() {
            "(attribute_not_exists(#attrs) OR #attrs = :expected_attributes)"
        } else {
            "#attrs = :expected_attributes"
        };
        let condition = format!(
            "{ATTRIBUTE_USER_EXISTS_CONDITION} AND \
             (attribute_not_exists(#status) OR #status = :active) AND \
             {generation_condition} AND {attributes_condition}"
        );
        let key = HashMap::from([(
            "user_id".to_string(),
            AttributeValue::S(tpk(tenant, &current.user_id)),
        )]);
        let mut update = Update::builder()
            .table_name(&self.table)
            .set_key(Some(key))
            .condition_expression(condition)
            .expression_attribute_names("#status", "status")
            .expression_attribute_names("#attrs", "attributes")
            .expression_attribute_names("#generation", "attributes_generation")
            .expression_attribute_names("#reconciliation_id", "federation_reconciliation_id")
            .expression_attribute_names(
                "#reconciliation_fingerprint",
                "federation_reconciliation_fingerprint",
            )
            .expression_attribute_values(":active", AttributeValue::S("active".into()))
            .expression_attribute_values(
                ":expected_generation",
                AttributeValue::N(current.attributes_generation.to_string()),
            )
            .expression_attribute_values(
                ":expected_attributes",
                Self::attributes_to_av(&current.attributes),
            )
            .expression_attribute_values(
                ":reconciliation_id",
                AttributeValue::S(operation_id.to_string()),
            )
            .expression_attribute_values(
                ":reconciliation_fingerprint",
                AttributeValue::S(fingerprint.to_string()),
            );
        if changed {
            update = update
                .update_expression(
                    "SET #attrs = :next_attributes, #generation = :next_generation, \
                     #reconciliation_id = :reconciliation_id, \
                     #reconciliation_fingerprint = :reconciliation_fingerprint",
                )
                .expression_attribute_values(
                    ":next_generation",
                    AttributeValue::N(next.attributes_generation.to_string()),
                )
                .expression_attribute_values(
                    ":next_attributes",
                    Self::attributes_to_av(&next.attributes),
                );
        } else {
            update = update.update_expression(
                "SET #reconciliation_id = :reconciliation_id, \
                 #reconciliation_fingerprint = :reconciliation_fingerprint",
            );
        }
        let update = update.build().map_err(|error| {
            StoreError::Permanent(format!(
                "build federation reconciliation user update: {error}"
            ))
        })?;
        Ok(TransactWriteItem::builder().update(update).build())
    }

    pub(crate) fn federation_owner_purge_user_item(
        &self,
        tenant: &str,
        current: &crate::ports::UserRecord,
        next: &crate::ports::UserRecord,
    ) -> Result<aws_sdk_dynamodb::types::TransactWriteItem, StoreError> {
        use aws_sdk_dynamodb::types::{AttributeValue, TransactWriteItem, Update};

        let generation_condition = if current.attributes_generation == 0 {
            "(attribute_not_exists(#generation) OR #generation = :expected_generation)"
        } else {
            "#generation = :expected_generation"
        };
        let attributes_condition = if current.attributes.is_empty() {
            "(attribute_not_exists(#attrs) OR #attrs = :expected_attributes)"
        } else {
            "#attrs = :expected_attributes"
        };
        let condition = format!(
            "{ATTRIBUTE_USER_EXISTS_CONDITION} AND \
             (attribute_not_exists(#status) OR #status <> :tombstoned) AND \
             {generation_condition} AND {attributes_condition}"
        );
        let update = Update::builder()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, &current.user_id)))
            .condition_expression(condition)
            .update_expression("SET #attrs = :next_attributes, #generation = :next_generation")
            .expression_attribute_names("#status", "status")
            .expression_attribute_names("#attrs", "attributes")
            .expression_attribute_names("#generation", "attributes_generation")
            .expression_attribute_values(":tombstoned", AttributeValue::S("tombstoned".into()))
            .expression_attribute_values(
                ":expected_generation",
                AttributeValue::N(current.attributes_generation.to_string()),
            )
            .expression_attribute_values(
                ":expected_attributes",
                Self::attributes_to_av(&current.attributes),
            )
            .expression_attribute_values(
                ":next_generation",
                AttributeValue::N(next.attributes_generation.to_string()),
            )
            .expression_attribute_values(
                ":next_attributes",
                Self::attributes_to_av(&next.attributes),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build federation owner purge user update: {error}"))
            })?;
        Ok(TransactWriteItem::builder().update(update).build())
    }

    async fn federation_reconciliation_marker_matches(
        &self,
        tenant: &str,
        user_id: &str,
        operation_id: &str,
        fingerprint: &str,
    ) -> Result<bool, StoreError> {
        let item = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?
            .item;
        Ok(item.is_some_and(|item| {
            item.get("federation_reconciliation_id")
                .and_then(|value| value.as_s().ok())
                .is_some_and(|value| value == operation_id)
                && item
                    .get("federation_reconciliation_fingerprint")
                    .and_then(|value| value.as_s().ok())
                    .is_some_and(|value| value == fingerprint)
        }))
    }

    pub(crate) async fn reconcile_federated_attributes_authorized(
        &self,
        request: AuthorizedFederatedReconciliation<'_>,
    ) -> Result<
        Option<crate::federation_attributes::FederationAttributeReconciliationOutcome>,
        StoreError,
    > {
        use crate::federation_attributes::{
            plan_federated_user_reconciliation, FederationAttributeReconciliationOutcome,
        };
        let AuthorizedFederatedReconciliation {
            tenant,
            user_id,
            upstream_idp_id,
            desired,
            registry_revision,
            operation_id,
            fingerprint,
            authority_conditions,
        } = request;

        for _ in 0..5 {
            let Some(current) = self.get_by_id(tenant, user_id).await? else {
                return Ok(Some(FederationAttributeReconciliationOutcome::UserNotFound));
            };
            let outcome = plan_federated_user_reconciliation(
                &current,
                upstream_idp_id,
                desired,
                registry_revision,
            )?;
            let FederationAttributeReconciliationOutcome::Applied {
                user: next,
                changed,
                ..
            } = &outcome
            else {
                return Ok(Some(outcome));
            };
            let mut request = self.db.transact_write_items();
            for condition in authority_conditions.iter().cloned() {
                request = request.transact_items(condition);
            }
            request = request.transact_items(self.federation_reconciliation_user_item(
                tenant,
                &current,
                next,
                *changed,
                operation_id,
                fingerprint,
            )?);
            match super::send_idempotent_transaction(request).await {
                Ok(true) => return Ok(Some(outcome)),
                Ok(false) => {}
                Err(error @ StoreError::Transient(_)) => {
                    if self
                        .federation_reconciliation_marker_matches(
                            tenant,
                            user_id,
                            operation_id,
                            fingerprint,
                        )
                        .await?
                    {
                        let latest = self.get_by_id(tenant, user_id).await?;
                        if latest.as_ref().is_some_and(|latest| {
                            latest.attributes_generation == next.attributes_generation
                                && latest.attributes == next.attributes
                        }) {
                            return Ok(Some(outcome));
                        }
                    }
                    return Err(error);
                }
                Err(error) => return Err(error),
            }

            let Some(latest) = self.get_by_id(tenant, user_id).await? else {
                return Ok(Some(FederationAttributeReconciliationOutcome::UserNotFound));
            };
            if latest.attributes_generation == current.attributes_generation
                && latest.status == current.status
                && latest.attributes == current.attributes
            {
                return Ok(None);
            }
        }
        Err(StoreError::Transient(
            "federation attribute reconciliation did not converge".into(),
        ))
    }

    pub(crate) async fn purge_federated_attribute_owner_authorized(
        &self,
        tenant: &str,
        current: &crate::ports::UserRecord,
        next: &crate::ports::UserRecord,
        authority_condition: aws_sdk_dynamodb::types::TransactWriteItem,
    ) -> Result<bool, StoreError> {
        let request = self
            .db
            .transact_write_items()
            .transact_items(authority_condition)
            .transact_items(self.federation_owner_purge_user_item(tenant, current, next)?);
        match super::send_idempotent_transaction(request).await {
            Ok(applied) => Ok(applied),
            Err(error @ StoreError::Transient(_)) => {
                let latest = self.get_by_id(tenant, &current.user_id).await?;
                if latest.as_ref().is_some_and(|latest| {
                    latest.attributes_generation == next.attributes_generation
                        && latest.attributes == next.attributes
                }) {
                    Ok(true)
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }

    pub fn with_governance_suppression(
        mut self,
        table: impl Into<String>,
        hmac_key: impl Into<Vec<u8>>,
    ) -> Self {
        self.governance_suppression = Some((table.into(), hmac_key.into()));
        self
    }

    async fn send_attribute_transaction(
        request: aws_sdk_dynamodb::operation::transact_write_items::builders::TransactWriteItemsFluentBuilder,
        has_authority: bool,
    ) -> Result<AttributeTransactionOutcome, StoreError> {
        use aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError;

        let request = request.client_request_token(super::transaction_request_token());
        for attempt in 0..super::IDEMPOTENT_TRANSACTION_REPLAY_ATTEMPTS {
            match request.clone().send().await {
                Ok(_) => return Ok(AttributeTransactionOutcome::Applied),
                Err(error) => {
                    if let Some(TransactWriteItemsError::TransactionCanceledException(cancelled)) =
                        error.as_service_error()
                    {
                        match super::classify_transaction_cancellation(cancelled) {
                            super::TransactionCancelAction::RetryCondition => {
                                let reasons = cancelled.cancellation_reasons();
                                let failed = |index: usize| {
                                    reasons
                                        .get(index)
                                        .and_then(|reason| reason.code())
                                        .is_some_and(|code| code == "ConditionalCheckFailed")
                                };
                                if has_authority && failed(0) {
                                    return Ok(AttributeTransactionOutcome::AuthorityConflict);
                                }
                                if failed(usize::from(has_authority)) {
                                    return Ok(AttributeTransactionOutcome::UserConflict);
                                }
                                return Err(StoreError::Transient(
                                    "attribute transaction condition failure was ambiguous".into(),
                                ));
                            }
                            super::TransactionCancelAction::Permanent => {
                                return Err(super::transaction_cancellation_error(
                                    cancelled,
                                    super::TransactionCancelAction::Permanent,
                                ));
                            }
                            super::TransactionCancelAction::Transient => {}
                        }
                    }
                    let classified = ddb_err(error);
                    if !matches!(classified, StoreError::Transient(_))
                        || attempt + 1 == super::IDEMPOTENT_TRANSACTION_REPLAY_ATTEMPTS
                    {
                        return Err(classified);
                    }
                }
            }
        }
        unreachable!("attribute transaction replay loop always returns")
    }

    fn attribute_replay_condition(
        &self,
        pk: &str,
        namespace: &str,
        attributes_generation: u64,
        attributes: &crate::ports::NamespaceAttrs,
    ) -> Result<aws_sdk_dynamodb::types::TransactWriteItem, StoreError> {
        use aws_sdk_dynamodb::types::{AttributeValue, ConditionCheck, TransactWriteItem};

        let generation_condition = if attributes_generation == 0 {
            "(attribute_not_exists(#generation) OR #generation = :expected_generation)"
        } else {
            "#generation = :expected_generation"
        };
        let condition = ConditionCheck::builder()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(pk.to_string()))
            .condition_expression(format!(
                "{ATTRIBUTE_USER_EXISTS_CONDITION} AND \
                 (attribute_not_exists(#status) OR #status <> :tombstone) AND \
                 {generation_condition} AND #attrs.#namespace = :namespace_value"
            ))
            .expression_attribute_names("#status", "status")
            .expression_attribute_names("#generation", "attributes_generation")
            .expression_attribute_names("#attrs", "attributes")
            .expression_attribute_names("#namespace", namespace)
            .expression_attribute_values(":tombstone", AttributeValue::S("tombstoned".into()))
            .expression_attribute_values(
                ":expected_generation",
                AttributeValue::N(attributes_generation.to_string()),
            )
            .expression_attribute_values(
                ":namespace_value",
                Self::namespace_attrs_to_av(attributes),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build attribute replay condition: {error}"))
            })?;
        Ok(TransactWriteItem::builder()
            .condition_check(condition)
            .build())
    }

    async fn verify_attribute_replay(
        &self,
        authority_condition: Option<aws_sdk_dynamodb::types::TransactWriteItem>,
        user_condition: aws_sdk_dynamodb::types::TransactWriteItem,
    ) -> Result<AttributeTransactionOutcome, StoreError> {
        let has_authority = authority_condition.is_some();
        let mut transaction = self.db.transact_write_items();
        if let Some(condition) = authority_condition {
            transaction = transaction.transact_items(condition);
        }
        transaction = transaction.transact_items(user_condition);
        Self::send_attribute_transaction(transaction, has_authority).await
    }

    async fn put_attributes_conditioned(
        &self,
        tenant: &str,
        user_id: &str,
        namespace: &str,
        kv: std::collections::BTreeMap<String, String>,
        expected_revision: u64,
        authority_condition: Option<aws_sdk_dynamodb::types::TransactWriteItem>,
    ) -> Result<Option<crate::ports::PutAttrOutcome>, StoreError> {
        use crate::ports::{NamespaceAttrs, PutAttrOutcome};
        use aws_sdk_dynamodb::types::{AttributeValue, TransactWriteItem, Update};

        let pk = tpk(tenant, user_id);
        for _ in 0..5 {
            let out = self
                .db
                .get_item()
                .table_name(&self.table)
                .key("user_id", AttributeValue::S(pk.clone()))
                .consistent_read(true)
                .send()
                .await
                .map_err(ddb_err)?;
            let Some(rec) = out.item().and_then(Self::to_record) else {
                return Ok(Some(PutAttrOutcome::NotFound));
            };
            if rec.status == crate::ports::UserStatus::Tombstoned {
                return Ok(Some(PutAttrOutcome::Tombstoned));
            }
            let current = rec
                .attributes
                .get(namespace)
                .map(|attributes| attributes.revision)
                .unwrap_or(0);
            if current != expected_revision {
                if expected_revision.checked_add(1) == Some(current)
                    && rec
                        .attributes
                        .get(namespace)
                        .is_some_and(|attributes| attributes.kv == kv)
                {
                    let attributes = rec
                        .attributes
                        .get(namespace)
                        .expect("idempotent replay requires the observed namespace");
                    let user_condition = self.attribute_replay_condition(
                        &pk,
                        namespace,
                        rec.attributes_generation,
                        attributes,
                    )?;
                    match self
                        .verify_attribute_replay(authority_condition.clone(), user_condition)
                        .await?
                    {
                        AttributeTransactionOutcome::Applied => {
                            return Ok(Some(PutAttrOutcome::Ok { revision: current }));
                        }
                        AttributeTransactionOutcome::AuthorityConflict => return Ok(None),
                        AttributeTransactionOutcome::UserConflict => continue,
                    }
                }
                return Ok(Some(PutAttrOutcome::RevisionConflict { current }));
            }
            let next_generation = rec.attributes_generation.checked_add(1).ok_or_else(|| {
                StoreError::Permanent("user attributes generation exhausted".into())
            })?;
            let next_revision = current.checked_add(1).ok_or_else(|| {
                StoreError::Permanent("namespace attributes revision exhausted".into())
            })?;
            let federation_owners = rec
                .attributes
                .get(namespace)
                .map(|attributes| attributes.federation_owners.clone())
                .unwrap_or_default();
            if federation_owners.keys().any(|key| {
                rec.attributes
                    .get(namespace)
                    .and_then(|attributes| attributes.kv.get(key))
                    != kv.get(key)
            }) {
                return Ok(Some(PutAttrOutcome::OwnershipConflict));
            }
            let mut candidate = rec.attributes.clone();
            candidate.insert(
                namespace.to_string(),
                NamespaceAttrs {
                    revision: next_revision,
                    kv: kv.clone(),
                    federation_owners: federation_owners.clone(),
                },
            );
            if crate::adapters::memory::attributes_serialized_len(&candidate)
                > crate::ports::ATTRIBUTES_MAX_BYTES
            {
                return Ok(Some(PutAttrOutcome::TooLarge));
            }

            let mut update = Update::builder()
                .table_name(&self.table)
                .key("user_id", AttributeValue::S(pk.clone()))
                .expression_attribute_names("#status", "status")
                .expression_attribute_names("#attrs", "attributes")
                .expression_attribute_names("#namespace", namespace)
                .expression_attribute_names("#generation", "attributes_generation")
                .expression_attribute_values(":tombstone", AttributeValue::S("tombstoned".into()))
                .expression_attribute_values(
                    ":expected_generation",
                    AttributeValue::N(rec.attributes_generation.to_string()),
                )
                .expression_attribute_values(
                    ":next_generation",
                    AttributeValue::N(next_generation.to_string()),
                );
            if rec.attributes.is_empty() {
                update = update
                    .update_expression("SET #attrs = :attributes, #generation = :next_generation")
                    .expression_attribute_values(":attributes", Self::attributes_to_av(&candidate));
            } else {
                update = update
                    .update_expression(
                        "SET #attrs.#namespace = :namespace_value, #generation = :next_generation",
                    )
                    .expression_attribute_values(
                        ":namespace_value",
                        Self::namespace_attrs_to_av(&NamespaceAttrs {
                            revision: next_revision,
                            kv: kv.clone(),
                            federation_owners,
                        }),
                    );
            }
            let mut condition = String::from(
                "attribute_exists(user_id) AND \
                 (attribute_not_exists(#status) OR #status <> :tombstone)",
            );
            if rec.attributes_generation == 0 {
                condition.push_str(
                    " AND (attribute_not_exists(#generation) OR #generation = :expected_generation)",
                );
            } else {
                condition.push_str(" AND #generation = :expected_generation");
            }
            if expected_revision == 0 {
                condition.push_str(
                    " AND (attribute_not_exists(#attrs) OR attribute_not_exists(#attrs.#namespace))",
                );
            } else {
                condition.push_str(" AND #attrs.#namespace.#revision = :expected_revision");
                update = update
                    .expression_attribute_names("#revision", "rev")
                    .expression_attribute_values(
                        ":expected_revision",
                        AttributeValue::N(expected_revision.to_string()),
                    );
            }
            let update = update
                .condition_expression(condition)
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!("build attribute user update: {error}"))
                })?;
            let has_authority = authority_condition.is_some();
            let mut transaction = self.db.transact_write_items();
            if let Some(condition) = authority_condition.clone() {
                transaction = transaction.transact_items(condition);
            }
            transaction =
                transaction.transact_items(TransactWriteItem::builder().update(update).build());
            match Self::send_attribute_transaction(transaction, has_authority).await? {
                AttributeTransactionOutcome::Applied => {
                    return Ok(Some(PutAttrOutcome::Ok {
                        revision: next_revision,
                    }));
                }
                AttributeTransactionOutcome::AuthorityConflict => return Ok(None),
                AttributeTransactionOutcome::UserConflict => {
                    match self.get_by_id(tenant, user_id).await? {
                        None => return Ok(Some(PutAttrOutcome::NotFound)),
                        Some(record) if record.status == crate::ports::UserStatus::Tombstoned => {
                            return Ok(Some(PutAttrOutcome::Tombstoned));
                        }
                        Some(record) => {
                            let observed = record
                                .attributes
                                .get(namespace)
                                .map(|attributes| attributes.revision)
                                .unwrap_or(0);
                            if expected_revision.checked_add(1) == Some(observed)
                                && record
                                    .attributes
                                    .get(namespace)
                                    .is_some_and(|attributes| attributes.kv == kv)
                            {
                                continue;
                            }
                            if observed != expected_revision {
                                return Ok(Some(PutAttrOutcome::RevisionConflict {
                                    current: observed,
                                }));
                            }
                        }
                    }
                }
            }
        }
        Err(StoreError::Transient(
            "attribute write did not converge after generation conflicts".into(),
        ))
    }

    pub(crate) async fn put_attributes_authorized(
        &self,
        tenant: &str,
        user_id: &str,
        namespace: &str,
        kv: std::collections::BTreeMap<String, String>,
        expected_revision: u64,
        authority_condition: aws_sdk_dynamodb::types::TransactWriteItem,
    ) -> Result<Option<crate::ports::PutAttrOutcome>, StoreError> {
        self.put_attributes_conditioned(
            tenant,
            user_id,
            namespace,
            kv,
            expected_revision,
            Some(authority_condition),
        )
        .await
    }

    fn suppression_condition(
        &self,
        tenant: &str,
        kind: crate::governance::GovernanceAliasKind,
        normalized_value: &str,
    ) -> Result<Option<aws_sdk_dynamodb::types::TransactWriteItem>, StoreError> {
        use aws_sdk_dynamodb::types::{AttributeValue, ConditionCheck, TransactWriteItem};

        let Some((table, hmac_key)) = &self.governance_suppression else {
            return Ok(None);
        };
        let logical_tenant = if tenant.is_empty() { "default" } else { tenant };
        let digest = crate::governance::suppression_digest(
            hmac_key,
            logical_tenant,
            "user",
            kind.as_str(),
            crate::governance::SUPPRESSION_NORMALIZATION_VERSION,
            normalized_value,
        );
        let condition = ConditionCheck::builder()
            .table_name(table)
            .key(
                "pk",
                AttributeValue::S(crate::governance::suppression_partition_key(
                    logical_tenant,
                    "user",
                    &digest,
                )),
            )
            .key("epoch", AttributeValue::N("0".into()))
            .condition_expression("attribute_not_exists(pk) AND attribute_not_exists(epoch)")
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build user suppression condition: {error}"))
            })?;
        Ok(Some(
            TransactWriteItem::builder()
                .condition_check(condition)
                .build(),
        ))
    }

    pub(crate) async fn begin_admin_credential_change(
        &self,
        tenant: &str,
        user_id: &str,
        expected_epoch: u64,
        operation_id: &str,
        now: i64,
    ) -> Result<crate::ports::CredentialChangeStart, StoreError> {
        use crate::ports::{CredentialChangeStart, UserStatus};

        let next_epoch = expected_epoch
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("user credential_epoch exhausted".to_string()))?;
        let epoch_condition = if expected_epoch == 0 {
            "(attribute_not_exists(credential_epoch) OR credential_epoch = :expected)"
        } else {
            "credential_epoch = :expected"
        };
        let result = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .update_expression(
                "SET credential_epoch = :next, revocation_pending = :true, \
                 credential_change_id = :operation, updated_at = :now",
            )
            .condition_expression(format!(
                "attribute_exists(user_id) AND \
                 (attribute_not_exists(#status) OR #status <> :tomb) AND \
                 (attribute_not_exists(revocation_pending) OR revocation_pending = :false) AND \
                 {epoch_condition}"
            ))
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":tomb", AttributeValue::S("tombstoned".to_string()))
            .expression_attribute_values(":false", AttributeValue::Bool(false))
            .expression_attribute_values(":true", AttributeValue::Bool(true))
            .expression_attribute_values(":expected", AttributeValue::N(expected_epoch.to_string()))
            .expression_attribute_values(":next", AttributeValue::N(next_epoch.to_string()))
            .expression_attribute_values(":operation", AttributeValue::S(operation_id.to_string()))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .send()
            .await;
        match result {
            Ok(_) => Ok(CredentialChangeStart::Started { epoch: next_epoch }),
            Err(error) => {
                let conditional = error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed"));
                let classified = if conditional {
                    None
                } else {
                    let classified = ddb_err(error);
                    if !matches!(classified, StoreError::Transient(_)) {
                        return Err(classified);
                    }
                    Some(classified)
                };
                let observed = self
                    .db
                    .get_item()
                    .table_name(&self.table)
                    .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
                    .consistent_read(true)
                    .send()
                    .await
                    .map_err(ddb_err)?;
                let committed = observed.item().is_some_and(|item| {
                    s(item.get("credential_change_id")).as_deref() == Some(operation_id)
                        && n_u64(item.get("credential_epoch")) == Some(next_epoch)
                        && item
                            .get("revocation_pending")
                            .and_then(|value| value.as_bool().ok())
                            .copied()
                            == Some(true)
                });
                if committed {
                    Ok(CredentialChangeStart::Started { epoch: next_epoch })
                } else if observed.item().is_some_and(|item| {
                    Self::to_record(item).is_some_and(|record| {
                        record.status != UserStatus::Tombstoned && record.revocation_pending
                    }) && s(item.get("credential_change_id")).as_deref() != Some(operation_id)
                }) {
                    Ok(CredentialChangeStart::ConcurrentChange)
                } else if conditional {
                    match observed.item().and_then(Self::to_record) {
                        None => Ok(CredentialChangeStart::NotFound),
                        Some(record) if record.status == UserStatus::Tombstoned => {
                            Ok(CredentialChangeStart::Ineligible)
                        }
                        Some(_) => Ok(CredentialChangeStart::ConcurrentChange),
                    }
                } else {
                    Err(classified.expect("non-conditional failures are classified"))
                }
            }
        }
    }

    pub(crate) async fn abort_admin_credential_change(
        &self,
        tenant: &str,
        user_id: &str,
        owner: crate::ports::CredentialChangeOwner<'_>,
        now: i64,
    ) -> Result<bool, StoreError> {
        let result = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .update_expression(
                "SET revocation_pending = :false, updated_at = :now REMOVE credential_change_id",
            )
            .condition_expression(
                "attribute_exists(user_id) AND \
                 (attribute_not_exists(#status) OR #status <> :tomb) AND \
                 credential_epoch = :epoch AND revocation_pending = :true AND \
                 credential_change_id = :operation",
            )
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":tomb", AttributeValue::S("tombstoned".to_string()))
            .expression_attribute_values(":false", AttributeValue::Bool(false))
            .expression_attribute_values(":true", AttributeValue::Bool(true))
            .expression_attribute_values(":epoch", AttributeValue::N(owner.epoch.to_string()))
            .expression_attribute_values(
                ":operation",
                AttributeValue::S(owner.operation_id.to_string()),
            )
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                Ok(false)
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    pub(crate) async fn credential_change_is_owned(
        &self,
        tenant: &str,
        user_id: &str,
        owner: crate::ports::CredentialChangeOwner<'_>,
    ) -> Result<bool, StoreError> {
        use crate::ports::UserStatus;

        let observed = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(observed.item().is_some_and(|item| {
            Self::to_record(item).is_some_and(|record| {
                record.status != UserStatus::Tombstoned
                    && record.revocation_pending
                    && record.credential_epoch == owner.epoch
            }) && s(item.get("credential_change_id")).as_deref() == Some(owner.operation_id)
        }))
    }

    fn to_record(
        item: &std::collections::HashMap<String, AttributeValue>,
    ) -> Option<crate::ports::UserRecord> {
        if item.contains_key("record_type") {
            return None;
        }
        let created_at = item.get("created_at")?.as_n().ok()?.parse().ok()?;
        Some(crate::ports::UserRecord {
            // 物理 pk / GSI email 值可能带 tenant 前缀 → strip 回逻辑值(空 tenant 无前缀,零变化)。
            user_id: strip_tpk(item.get("user_id")?.as_s().ok()?),
            // email 可缺(canonical-user 审计 K:联邦用户 `user:fed:*` 无 email attr)→ 空串,
            // **绝不因缺 email 令 to_record 返 None**(否则联邦用户在 list/get 隐形、无法管理)。
            email: item
                .get("email")
                .and_then(|v| v.as_s().ok())
                .map(|s| strip_tpk(s))
                .unwrap_or_default(),
            created_at,
            updated_at: item
                .get("updated_at")
                .and_then(|value| value.as_n().ok())
                .and_then(|value| value.parse().ok())
                .unwrap_or(created_at),
            last_login_at: item
                .get("last_login_at")
                .and_then(|v| v.as_n().ok())
                .and_then(|n| n.parse().ok()),
            // status:缺 attr → Active(既有记录无痛,§1.4 兼容;非 serde,手工 marshaling)。
            status: match item
                .get("status")
                .and_then(|v| v.as_s().ok())
                .map(String::as_str)
            {
                Some("disabled") => crate::ports::UserStatus::Disabled,
                Some("tombstoned") => crate::ports::UserStatus::Tombstoned,
                _ => crate::ports::UserStatus::Active,
            },
            credential_epoch: n_u64(item.get("credential_epoch")).unwrap_or(0),
            revocation_pending: item
                .get("revocation_pending")
                .and_then(|value| value.as_bool().ok())
                .copied()
                .unwrap_or(false),
            scim_external_id: s(item.get("scim_external_id")),
            scim_user_name: s(item.get("scim_user_name")),
            scim_display_name: s(item.get("scim_display_name")),
            attributes_generation: n_u64(item.get("attributes_generation")).unwrap_or(0),
            // attributes(spec 007):Dynamo Map `{namespace: {rev:N, kv:{k:S}}}`;缺 attr → 空 map(向后兼容)。
            attributes: Self::attributes_from_item(item)?,
        })
    }

    /// 从 Dynamo item 解 attributes(spec 007)。缺 `attributes` attr 或结构异常的条目 → 空 map(向后兼容,
    /// 不 panic)。形状:`attributes` = M{ namespace → M{ "rev": N, "kv": M{ key → S } } }。
    fn attributes_from_item(
        item: &std::collections::HashMap<String, AttributeValue>,
    ) -> Option<std::collections::BTreeMap<String, crate::ports::NamespaceAttrs>> {
        let mut out = std::collections::BTreeMap::new();
        let Some(Ok(ns_map)) = item.get("attributes").map(|v| v.as_m()) else {
            return Some(out); // 缺 attr / 非 Map → 空(既有记录无痛)
        };
        for (ns, nv) in ns_map {
            let Ok(nm) = nv.as_m() else { continue };
            let revision = nm
                .get("rev")
                .and_then(|v| v.as_n().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let mut kv = std::collections::BTreeMap::new();
            if let Some(Ok(kvm)) = nm.get("kv").map(|v| v.as_m()) {
                for (k, val) in kvm {
                    if let Ok(s) = val.as_s() {
                        kv.insert(k.clone(), s.clone());
                    }
                }
            }
            let mut federation_owners = std::collections::BTreeMap::new();
            if let Some(owners) = nm.get("owners") {
                let owners = owners.as_m().ok()?;
                for (key, owner) in owners {
                    let owner = owner.as_m().ok()?;
                    let upstream_idp_id = owner.get("idp")?.as_s().ok()?.clone();
                    let upstream_issuer = owner.get("iss")?.as_s().ok()?.clone();
                    let mapping_id = owner.get("mapping")?.as_s().ok()?.clone();
                    let mapping_revision = owner.get("rev")?.as_n().ok()?.parse().ok()?;
                    if !kv.contains_key(key) {
                        return None;
                    }
                    federation_owners.insert(
                        key.clone(),
                        crate::ports::FederatedAttributeOwner {
                            upstream_idp_id,
                            upstream_issuer,
                            mapping_id,
                            mapping_revision,
                        },
                    );
                }
            }
            out.insert(
                ns.clone(),
                crate::ports::NamespaceAttrs {
                    revision,
                    kv,
                    federation_owners,
                },
            );
        }
        Some(out)
    }

    /// `NamespaceAttrs` → Dynamo Map AttributeValue(与 attributes_from_item 对称)。
    fn namespace_attrs_to_av(n: &crate::ports::NamespaceAttrs) -> AttributeValue {
        let kv_map: std::collections::HashMap<String, AttributeValue> =
            n.kv.iter()
                .map(|(k, v)| (k.clone(), AttributeValue::S(v.clone())))
                .collect();
        let owner_map: std::collections::HashMap<String, AttributeValue> = n
            .federation_owners
            .iter()
            .map(|(key, owner)| {
                (
                    key.clone(),
                    AttributeValue::M(std::collections::HashMap::from([
                        (
                            "idp".to_string(),
                            AttributeValue::S(owner.upstream_idp_id.clone()),
                        ),
                        (
                            "iss".to_string(),
                            AttributeValue::S(owner.upstream_issuer.clone()),
                        ),
                        (
                            "mapping".to_string(),
                            AttributeValue::S(owner.mapping_id.clone()),
                        ),
                        (
                            "rev".to_string(),
                            AttributeValue::N(owner.mapping_revision.to_string()),
                        ),
                    ])),
                )
            })
            .collect();
        AttributeValue::M(std::collections::HashMap::from([
            ("rev".to_string(), AttributeValue::N(n.revision.to_string())),
            ("kv".to_string(), AttributeValue::M(kv_map)),
            ("owners".to_string(), AttributeValue::M(owner_map)),
        ]))
    }

    fn attributes_to_av(
        attributes: &std::collections::BTreeMap<String, crate::ports::NamespaceAttrs>,
    ) -> AttributeValue {
        AttributeValue::M(
            attributes
                .iter()
                .map(|(namespace, attrs)| (namespace.clone(), Self::namespace_attrs_to_av(attrs)))
                .collect(),
        )
    }

    /// UserStatus → DynamoDB attr 值(与 to_record 解析对称)。
    fn status_str(s: crate::ports::UserStatus) -> &'static str {
        match s {
            crate::ports::UserStatus::Active => "active",
            crate::ports::UserStatus::Disabled => "disabled",
            crate::ports::UserStatus::Tombstoned => "tombstoned",
        }
    }

    fn scim_alias_key(tenant: &str, kind: &str, value: &str) -> String {
        let digest = Sha256::digest(value.as_bytes());
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
        tpk(tenant, &format!("scim-alias:{kind}:{encoded}"))
    }

    fn scim_tenant_key(tenant: &str) -> String {
        tpk(tenant, "scim-users")
    }

    fn scim_alias_item(
        tenant: &str,
        kind: &str,
        value: &str,
        user_id: &str,
    ) -> HashMap<String, AttributeValue> {
        HashMap::from([
            (
                "user_id".to_string(),
                AttributeValue::S(Self::scim_alias_key(tenant, kind, value)),
            ),
            (
                "record_type".to_string(),
                AttributeValue::S(SCIM_ALIAS_RECORD_TYPE.to_string()),
            ),
            (
                "alias_kind".to_string(),
                AttributeValue::S(kind.to_string()),
            ),
            (
                "alias_value".to_string(),
                AttributeValue::S(value.to_string()),
            ),
            (
                "canonical_user_id".to_string(),
                AttributeValue::S(tpk(tenant, user_id)),
            ),
        ])
    }

    fn scim_create_claim_key(tenant: &str, external_id: &str, user_name: &str) -> String {
        let mut digest = Sha256::new();
        digest.update((external_id.len() as u64).to_be_bytes());
        digest.update(external_id.as_bytes());
        digest.update((user_name.len() as u64).to_be_bytes());
        digest.update(user_name.as_bytes());
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.finalize());
        tpk(tenant, &format!("scim-create:{encoded}"))
    }

    fn scim_create_claim_item(
        tenant: &str,
        external_id: &str,
        user_name: &str,
        user_id: &str,
        pending_initial_epoch: Option<u64>,
    ) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::from([
            (
                "user_id".to_string(),
                AttributeValue::S(Self::scim_create_claim_key(tenant, external_id, user_name)),
            ),
            (
                "record_type".to_string(),
                AttributeValue::S(SCIM_CREATE_RECORD_TYPE.to_string()),
            ),
            (
                "canonical_user_id".to_string(),
                AttributeValue::S(tpk(tenant, user_id)),
            ),
        ]);
        if let Some(epoch) = pending_initial_epoch {
            item.insert(
                "initial_lifecycle_epoch".to_string(),
                AttributeValue::N(epoch.to_string()),
            );
        }
        item
    }

    async fn lookup_scim_create_claim(
        &self,
        tenant: &str,
        external_id: &str,
        user_name: &str,
    ) -> Result<Option<ScimCreateClaim>, StoreError> {
        let output = self
            .db
            .get_item()
            .table_name(&self.table)
            .key(
                "user_id",
                AttributeValue::S(Self::scim_create_claim_key(tenant, external_id, user_name)),
            )
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        let Some(item) = output.item() else {
            return Ok(None);
        };
        if item
            .get("record_type")
            .and_then(|item| item.as_s().ok())
            .is_none_or(|record_type| record_type != SCIM_CREATE_RECORD_TYPE)
        {
            return Err(StoreError::Permanent("malformed SCIM create claim".into()));
        }
        let user_id = item
            .get("canonical_user_id")
            .and_then(|item| item.as_s().ok())
            .map(|user_id| strip_tpk(user_id))
            .ok_or_else(|| StoreError::Permanent("malformed SCIM create claim".into()))?;
        let pending_initial_epoch = match item.get("initial_lifecycle_epoch") {
            Some(value) => Some(
                value
                    .as_n()
                    .ok()
                    .and_then(|value| value.parse().ok())
                    .ok_or_else(|| StoreError::Permanent("malformed SCIM create claim".into()))?,
            ),
            None => None,
        };
        Ok(Some(ScimCreateClaim {
            user_id,
            pending_initial_epoch,
        }))
    }

    async fn ensure_scim_create_claim(
        &self,
        tenant: &str,
        external_id: &str,
        user_name: &str,
        user_id: &str,
    ) -> Result<(), StoreError> {
        let result = self
            .db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(Self::scim_create_claim_item(
                tenant,
                external_id,
                user_name,
                user_id,
                None,
            )))
            .condition_expression("attribute_not_exists(user_id)")
            .send()
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                match self
                    .lookup_scim_create_claim(tenant, external_id, user_name)
                    .await?
                {
                    Some(existing) if existing.user_id == user_id => Ok(()),
                    Some(_) => Err(StoreError::Permanent(
                        "SCIM create claim is bound to another canonical user".into(),
                    )),
                    None => Err(StoreError::Transient(
                        "SCIM create claim contention did not converge".into(),
                    )),
                }
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn lookup_scim_alias(
        &self,
        tenant: &str,
        kind: &str,
        value: &str,
    ) -> Result<Option<String>, StoreError> {
        let output = self
            .db
            .get_item()
            .table_name(&self.table)
            .key(
                "user_id",
                AttributeValue::S(Self::scim_alias_key(tenant, kind, value)),
            )
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        let Some(item) = output.item() else {
            return Ok(None);
        };
        if item
            .get("record_type")
            .and_then(|item| item.as_s().ok())
            .is_none_or(|record_type| record_type != SCIM_ALIAS_RECORD_TYPE)
            || item
                .get("alias_kind")
                .and_then(|item| item.as_s().ok())
                .is_none_or(|alias_kind| alias_kind != kind)
            || item
                .get("alias_value")
                .and_then(|item| item.as_s().ok())
                .is_none_or(|alias_value| alias_value != value)
        {
            return Err(StoreError::Permanent(
                "SCIM alias hash collision or malformed alias record".into(),
            ));
        }
        Ok(item
            .get("canonical_user_id")
            .and_then(|item| item.as_s().ok())
            .map(|user_id| strip_tpk(user_id)))
    }

    async fn classify_scim_aliases(
        &self,
        tenant: &str,
        external_id: &str,
        user_name: &str,
    ) -> Result<(Option<String>, Option<String>), StoreError> {
        let external = self
            .lookup_scim_alias(tenant, SCIM_ALIAS_EXTERNAL, external_id)
            .await?;
        let user_name = self
            .lookup_scim_alias(tenant, SCIM_ALIAS_USERNAME, user_name)
            .await?;
        Ok((external, user_name))
    }

    async fn lookup_by_email(
        &self,
        tenant: &str,
        email: &str,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        // GSI email 值 tenant 化 → 只命中本租户(同一 email 跨租户是不同用户,codex B1)。
        let q = self
            .db
            .query()
            .table_name(&self.table)
            .index_name(&self.email_index)
            .key_condition_expression("email = :e")
            .expression_attribute_values(":e", AttributeValue::S(tpk(tenant, email)))
            .send()
            .await
            .map_err(ddb_err)?;
        for candidate in q.items().iter().filter_map(Self::to_record) {
            let Some(current) = self.get_by_id(tenant, &candidate.user_id).await? else {
                continue;
            };
            if current.email == email {
                return Ok(Some(current));
            }
        }
        Ok(None)
    }

    async fn lookup_local_by_email(
        &self,
        tenant: &str,
        email: &str,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        if let Some(record) = self.lookup_by_email(tenant, email).await? {
            return Ok(Some(record));
        }
        // The email GSI is eventually consistent. SCIM writes its normalized
        // userName alias in the same transaction as the canonical record update,
        // so use that primary-key claim before the legacy deterministic-id fallback.
        if let Some(user_id) = self
            .lookup_scim_alias(tenant, SCIM_ALIAS_USERNAME, email)
            .await?
        {
            return self.get_by_id(tenant, &user_id).await;
        }
        let deterministic_id = format!("user:{email}");
        Ok(self
            .get_by_id(tenant, &deterministic_id)
            .await?
            .filter(|record| record.email == email))
    }
}

impl crate::ports::UsersStore for DynamoUsersStore {
    async fn create_or_get_by_email(
        &self,
        tenant: &str,
        email: &str,
        user_id: &str,
        now: i64,
    ) -> Result<crate::ports::UserRecord, StoreError> {
        use aws_sdk_dynamodb::types::{ConditionCheck, Put, TransactWriteItem};

        let email = email.trim().to_lowercase();
        // 1. 先 GSI 查(命中即复用,不覆盖 created_at)。
        if let Some(rec) = self.lookup_local_by_email(tenant, &email).await? {
            return Ok(rec);
        }
        // GSI 可能尚未传播；SCIM userName alias 是强一致 canonical identity lock。
        if let Some(canonical_id) = self
            .lookup_scim_alias(tenant, SCIM_ALIAS_USERNAME, &email)
            .await?
        {
            return self.get_by_id(tenant, &canonical_id).await?.ok_or_else(|| {
                StoreError::Permanent(
                    "SCIM userName alias references a missing canonical user".into(),
                )
            });
        }
        // 2. 未命中 → 在同一事务中确认 SCIM alias 仍空并创建本地 canonical user。
        let rec = crate::ports::UserRecord {
            user_id: user_id.to_string(),
            email: email.clone(),
            created_at: now,
            updated_at: now,
            last_login_at: None,
            status: crate::ports::UserStatus::Active, // 首建 Active(§1.4)
            credential_epoch: 0,
            revocation_pending: false,
            scim_external_id: None,
            scim_user_name: None,
            scim_display_name: None,
            attributes_generation: 0,
            attributes: Default::default(), // 首建空属性(spec 007;不写 attr,缺省=空)
        };
        let item = HashMap::from([
            (
                "user_id".to_string(),
                AttributeValue::S(tpk(tenant, &rec.user_id)),
            ),
            (
                "email".to_string(),
                AttributeValue::S(tpk(tenant, &rec.email)),
            ),
            (
                "created_at".to_string(),
                AttributeValue::N(rec.created_at.to_string()),
            ),
            (
                "updated_at".to_string(),
                AttributeValue::N(rec.updated_at.to_string()),
            ),
            (
                "credential_epoch".to_string(),
                AttributeValue::N("0".to_string()),
            ),
            (
                "revocation_pending".to_string(),
                AttributeValue::Bool(false),
            ),
            (
                "status".to_string(),
                AttributeValue::S(Self::status_str(rec.status).to_string()),
            ),
        ]);
        let put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(user_id)")
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build local canonical user put: {error}"))
            })?;
        let alias_check = ConditionCheck::builder()
            .table_name(&self.table)
            .key(
                "user_id",
                AttributeValue::S(Self::scim_alias_key(tenant, SCIM_ALIAS_USERNAME, &email)),
            )
            .condition_expression("attribute_not_exists(user_id)")
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build SCIM userName alias condition: {error}"))
            })?;
        let result = self
            .db
            .transact_write_items()
            .set_transact_items(Some(
                [
                    self.suppression_condition(
                        tenant,
                        crate::governance::GovernanceAliasKind::Email,
                        &email,
                    )?,
                    self.suppression_condition(
                        tenant,
                        crate::governance::GovernanceAliasKind::CanonicalId,
                        user_id,
                    )?,
                ]
                .into_iter()
                .flatten()
                .chain([
                    TransactWriteItem::builder()
                        .condition_check(alias_check)
                        .build(),
                    TransactWriteItem::builder().put(put).build(),
                ])
                .collect(),
            ))
            .send()
            .await;
        match result {
            Ok(_) => Ok(rec),
            Err(error) => {
                match classify_transact_write_error(&error) {
                    Some((TransactionCancelAction::RetryCondition, _)) => {}
                    Some((_, classified)) => return Err(classified),
                    None => return Err(ddb_err(error)),
                }
                if let Some(canonical_id) = self
                    .lookup_scim_alias(tenant, SCIM_ALIAS_USERNAME, &email)
                    .await?
                {
                    return self.get_by_id(tenant, &canonical_id).await?.ok_or_else(|| {
                        StoreError::Permanent(
                            "SCIM userName alias references a missing canonical user".into(),
                        )
                    });
                }
                if let Some(existing) = self.get_by_id(tenant, user_id).await? {
                    if existing.email == email {
                        Ok(existing)
                    } else {
                        Err(StoreError::Permanent(
                            "canonical user id is already bound to a different email".into(),
                        ))
                    }
                } else {
                    Err(StoreError::Transient(
                        "local/SCIM canonical identity transaction did not converge".into(),
                    ))
                }
            }
        }
    }

    async fn create_or_get_by_id(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<crate::ports::UserRecord, StoreError> {
        // canonical-user(审计 K):按 user_id **主键**幂等 upsert(联邦用户;email 空,不写 email GSI)。
        // 1. 先强一致读主键(命中即复用,不覆盖 created_at/status/attributes)。
        let out = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        if let Some(rec) = out.item().and_then(Self::to_record) {
            return Ok(rec);
        }
        // 2. 未命中 → 条件 create(attribute_not_exists(user_id) 防并发)。**不写 email attr**(联邦无 email)。
        let rec = crate::ports::UserRecord {
            user_id: user_id.to_string(),
            email: String::new(),
            created_at: now,
            updated_at: now,
            last_login_at: None,
            status: crate::ports::UserStatus::Active,
            credential_epoch: 0,
            revocation_pending: false,
            scim_external_id: None,
            scim_user_name: None,
            scim_display_name: None,
            attributes_generation: 0,
            attributes: Default::default(),
        };
        use aws_sdk_dynamodb::types::{Put, TransactWriteItem};
        let put = Put::builder()
            .table_name(&self.table)
            .item("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .item("created_at", AttributeValue::N(now.to_string()))
            .item("updated_at", AttributeValue::N(now.to_string()))
            .item("credential_epoch", AttributeValue::N("0".to_string()))
            .item("revocation_pending", AttributeValue::Bool(false))
            .item(
                "status",
                AttributeValue::S(Self::status_str(rec.status).to_string()),
            )
            .condition_expression("attribute_not_exists(user_id)")
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build federated canonical user put: {error}"))
            })?;
        let mut items = Vec::new();
        if let Some(condition) = self.suppression_condition(
            tenant,
            crate::governance::GovernanceAliasKind::CanonicalId,
            user_id,
        )? {
            items.push(condition);
        }
        items.push(TransactWriteItem::builder().put(put).build());
        let res = self
            .db
            .transact_write_items()
            .set_transact_items(Some(items))
            .send()
            .await;
        match res {
            Ok(_) => Ok(rec),
            // 并发已被别人 create → 强一致读复用胜者。
            Err(e)
                if e.code()
                    .is_some_and(|code| code.contains("TransactionCanceled")) =>
            {
                let out = self
                    .db
                    .get_item()
                    .table_name(&self.table)
                    .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
                    .consistent_read(true)
                    .send()
                    .await
                    .map_err(ddb_err)?;
                match out.item().and_then(Self::to_record) {
                    Some(existing) => Ok(existing),
                    None => Err(StoreError::Transient(
                        "federated identity creation fence changed".into(),
                    )),
                }
            }
            Err(e) => Err(ddb_err(e)),
        }
    }

    async fn get_by_id(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        // **强一致读(评审 codex High)**:此方法是 `require_active_user` gate 的数据源——GetItem 默认
        // 最终一致,disable/tombstone 刚写、gate 立即读可能读到 stale `Active` → fail-OPEN(被禁用户
        // 仍签出 token/建会话)。主表 pk=user_id 强一致读消除该窗(admin get 也受益于读到最新 status)。
        let out = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(out.item().and_then(Self::to_record))
    }

    async fn get_by_email(
        &self,
        tenant: &str,
        email: &str,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        // 只读:先 GSI email-index 查(归一 email);未注册 → None(绝不 create)。
        let key = email.trim().to_lowercase();
        self.lookup_local_by_email(tenant, &key).await
    }

    async fn create_scim(
        &self,
        tenant: &str,
        input: crate::ports::ScimUserInput,
    ) -> Result<crate::ports::ScimCreateOutcome, StoreError> {
        use crate::ports::{ScimCreateOutcome, UserStatus};
        use aws_sdk_dynamodb::types::{ConditionCheck, Put, TransactWriteItem, Update};

        let user_name = input.user_name.trim().to_lowercase();
        for _ in 0..3 {
            if let Some(claim) = self
                .lookup_scim_create_claim(tenant, &input.external_id, &user_name)
                .await?
            {
                let record = self
                    .get_by_id(tenant, &claim.user_id)
                    .await?
                    .ok_or_else(|| {
                        StoreError::Permanent(
                            "SCIM create claim references a missing canonical user".into(),
                        )
                    })?;
                return if record.status == UserStatus::Tombstoned {
                    Ok(ScimCreateOutcome::Tombstoned)
                } else {
                    Ok(ScimCreateOutcome::Existing {
                        record,
                        pending_initial_epoch: claim.pending_initial_epoch,
                    })
                };
            }
            let (external_match, user_name_match) = self
                .classify_scim_aliases(tenant, &input.external_id, &user_name)
                .await?;
            match (external_match, user_name_match) {
                (Some(left), Some(right)) if left == right => {
                    let Some(record) = self.get_by_id(tenant, &left).await? else {
                        return Err(StoreError::Permanent(
                            "SCIM aliases reference a missing canonical user".into(),
                        ));
                    };
                    if record.status == UserStatus::Tombstoned {
                        return Ok(ScimCreateOutcome::Tombstoned);
                    }
                    if record.scim_external_id.as_deref() == Some(input.external_id.as_str())
                        && record.scim_user_name.as_deref() == Some(user_name.as_str())
                    {
                        self.ensure_scim_create_claim(
                            tenant,
                            &input.external_id,
                            &user_name,
                            &record.user_id,
                        )
                        .await?;
                        return Ok(ScimCreateOutcome::Existing {
                            record,
                            pending_initial_epoch: None,
                        });
                    }
                    return Ok(ScimCreateOutcome::Conflict);
                }
                (Some(_), _) | (_, Some(_)) => return Ok(ScimCreateOutcome::Conflict),
                (None, None) => {}
            }

            let existing = self.lookup_local_by_email(tenant, &user_name).await?;
            if existing
                .as_ref()
                .is_some_and(|record| record.status == UserStatus::Tombstoned)
            {
                return Ok(ScimCreateOutcome::Tombstoned);
            }
            if existing.as_ref().is_some_and(|record| {
                record.scim_external_id.is_some() || record.scim_user_name.is_some()
            }) {
                return Ok(ScimCreateOutcome::Conflict);
            }
            let canonical_id = existing
                .as_ref()
                .map(|record| record.user_id.clone())
                .unwrap_or_else(|| input.user_id.clone());
            let initial_status = existing
                .as_ref()
                .map_or(UserStatus::Active, |record| record.status);
            let initial_epoch = existing
                .as_ref()
                .map_or(0, |record| record.credential_epoch);
            let disable_epoch = (!input.active)
                .then(|| crate::ports::next_disable_epoch(initial_status, initial_epoch))
                .transpose()?;

            let external_put = Put::builder()
                .table_name(&self.table)
                .set_item(Some(Self::scim_alias_item(
                    tenant,
                    SCIM_ALIAS_EXTERNAL,
                    &input.external_id,
                    &canonical_id,
                )))
                .condition_expression("attribute_not_exists(user_id)")
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!("build SCIM external alias put: {error}"))
                })?;
            let user_name_put = Put::builder()
                .table_name(&self.table)
                .set_item(Some(Self::scim_alias_item(
                    tenant,
                    SCIM_ALIAS_USERNAME,
                    &user_name,
                    &canonical_id,
                )))
                .condition_expression("attribute_not_exists(user_id)")
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!("build SCIM userName alias put: {error}"))
                })?;
            let create_claim_put = Put::builder()
                .table_name(&self.table)
                .set_item(Some(Self::scim_create_claim_item(
                    tenant,
                    &input.external_id,
                    &user_name,
                    &canonical_id,
                    (!input.active).then_some(initial_epoch),
                )))
                .condition_expression("attribute_not_exists(user_id)")
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!("build SCIM create claim put: {error}"))
                })?;

            let mut transact = self
                .db
                .transact_write_items()
                .transact_items(TransactWriteItem::builder().put(create_claim_put).build())
                .transact_items(TransactWriteItem::builder().put(external_put).build())
                .transact_items(TransactWriteItem::builder().put(user_name_put).build());
            for condition in [
                self.suppression_condition(
                    tenant,
                    crate::governance::GovernanceAliasKind::CanonicalId,
                    &canonical_id,
                )?,
                self.suppression_condition(
                    tenant,
                    crate::governance::GovernanceAliasKind::ScimExternalId,
                    &input.external_id,
                )?,
                self.suppression_condition(
                    tenant,
                    crate::governance::GovernanceAliasKind::ScimUserName,
                    &user_name,
                )?,
                self.suppression_condition(
                    tenant,
                    crate::governance::GovernanceAliasKind::Email,
                    &user_name,
                )?,
            ]
            .into_iter()
            .flatten()
            {
                transact = transact.transact_items(condition);
            }
            if let Some(current) = existing.as_ref() {
                let mut assignments = vec![
                    "email = :email",
                    "updated_at = :updated",
                    "scim_external_id = :external",
                    "scim_user_name = :username",
                    "scim_tenant = :scim_tenant",
                ];
                if input.display_name.is_some() {
                    assignments.push("scim_display_name = :display");
                }
                if disable_epoch.is_some() {
                    assignments.extend([
                        "#status = :disabled",
                        "credential_epoch = :next",
                        "revocation_pending = :true",
                    ]);
                }
                let mut update_expression = format!("SET {}", assignments.join(", "));
                if input.display_name.is_none() {
                    update_expression.push_str(" REMOVE scim_display_name");
                }
                let mut update = Update::builder()
                    .table_name(&self.table)
                    .key("user_id", AttributeValue::S(tpk(tenant, &canonical_id)))
                    .update_expression(update_expression)
                    .expression_attribute_names("#status", "status")
                    .expression_attribute_values(
                        ":email",
                        AttributeValue::S(tpk(tenant, &user_name)),
                    )
                    .expression_attribute_values(
                        ":updated",
                        AttributeValue::N(input.now.to_string()),
                    )
                    .expression_attribute_values(
                        ":external",
                        AttributeValue::S(input.external_id.clone()),
                    )
                    .expression_attribute_values(
                        ":scim_tenant",
                        AttributeValue::S(Self::scim_tenant_key(tenant)),
                    )
                    .expression_attribute_values(":username", AttributeValue::S(user_name.clone()));
                if let Some(display_name) = input.display_name.as_ref() {
                    update = update.expression_attribute_values(
                        ":display",
                        AttributeValue::S(display_name.clone()),
                    );
                }
                if let Some(disable_epoch) = disable_epoch {
                    let epoch_condition = if current.credential_epoch == 0 {
                        "(attribute_not_exists(credential_epoch) OR credential_epoch = :expected)"
                    } else {
                        "credential_epoch = :expected"
                    };
                    let (status_condition, needs_active_value) =
                        disable_status_condition(current.status);
                    update = update
                        .condition_expression(format!(
                            "attribute_exists(user_id) AND \
                             attribute_not_exists(scim_external_id) AND \
                             attribute_not_exists(scim_user_name) AND \
                             {status_condition} AND {epoch_condition}"
                        ))
                        .expression_attribute_values(
                            ":expected",
                            AttributeValue::N(current.credential_epoch.to_string()),
                        )
                        .expression_attribute_values(
                            ":disabled",
                            AttributeValue::S("disabled".to_string()),
                        )
                        .expression_attribute_values(
                            ":next",
                            AttributeValue::N(disable_epoch.to_string()),
                        )
                        .expression_attribute_values(":true", AttributeValue::Bool(true));
                    if needs_active_value {
                        update = update.expression_attribute_values(
                            ":active",
                            AttributeValue::S("active".to_string()),
                        );
                    }
                } else {
                    update = update
                        .condition_expression(
                            "attribute_exists(user_id) AND \
                             attribute_not_exists(scim_external_id) AND \
                             attribute_not_exists(scim_user_name) AND \
                             (attribute_not_exists(#status) OR #status <> :tombstoned)",
                        )
                        .expression_attribute_values(
                            ":tombstoned",
                            AttributeValue::S("tombstoned".to_string()),
                        );
                }
                let update = update.build().map_err(|error| {
                    StoreError::Permanent(format!("build SCIM canonical update: {error}"))
                })?;
                transact =
                    transact.transact_items(TransactWriteItem::builder().update(update).build());
            } else {
                let local_user_id = format!("user:{user_name}");
                if canonical_id != local_user_id {
                    let local_identity_check = ConditionCheck::builder()
                        .table_name(&self.table)
                        .key("user_id", AttributeValue::S(tpk(tenant, &local_user_id)))
                        .condition_expression("attribute_not_exists(user_id) OR email <> :email")
                        .expression_attribute_values(
                            ":email",
                            AttributeValue::S(tpk(tenant, &user_name)),
                        )
                        .build()
                        .map_err(|error| {
                            StoreError::Permanent(format!(
                                "build local canonical identity condition: {error}"
                            ))
                        })?;
                    transact = transact.transact_items(
                        TransactWriteItem::builder()
                            .condition_check(local_identity_check)
                            .build(),
                    );
                }
                let mut item = HashMap::from([
                    (
                        "user_id".to_string(),
                        AttributeValue::S(tpk(tenant, &canonical_id)),
                    ),
                    (
                        "email".to_string(),
                        AttributeValue::S(tpk(tenant, &user_name)),
                    ),
                    (
                        "created_at".to_string(),
                        AttributeValue::N(input.now.to_string()),
                    ),
                    (
                        "updated_at".to_string(),
                        AttributeValue::N(input.now.to_string()),
                    ),
                    (
                        "status".to_string(),
                        AttributeValue::S(
                            if input.active { "active" } else { "disabled" }.to_string(),
                        ),
                    ),
                    (
                        "credential_epoch".to_string(),
                        AttributeValue::N(disable_epoch.unwrap_or(0).to_string()),
                    ),
                    (
                        "revocation_pending".to_string(),
                        AttributeValue::Bool(!input.active),
                    ),
                    (
                        "scim_external_id".to_string(),
                        AttributeValue::S(input.external_id.clone()),
                    ),
                    (
                        "scim_user_name".to_string(),
                        AttributeValue::S(user_name.clone()),
                    ),
                    (
                        "scim_tenant".to_string(),
                        AttributeValue::S(Self::scim_tenant_key(tenant)),
                    ),
                ]);
                if let Some(display_name) = input.display_name.as_ref() {
                    item.insert(
                        "scim_display_name".to_string(),
                        AttributeValue::S(display_name.clone()),
                    );
                }
                let canonical_put = Put::builder()
                    .table_name(&self.table)
                    .set_item(Some(item))
                    .condition_expression("attribute_not_exists(user_id)")
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!("build SCIM canonical put: {error}"))
                    })?;
                transact = transact
                    .transact_items(TransactWriteItem::builder().put(canonical_put).build());
            }

            match transact.send().await {
                Ok(_) => {
                    let record = self
                        .get_by_id(tenant, &canonical_id)
                        .await?
                        .ok_or_else(|| {
                            StoreError::Transient(
                                "SCIM transaction committed but canonical user was not readable"
                                    .into(),
                            )
                        })?;
                    return Ok(ScimCreateOutcome::Created(record));
                }
                Err(error) => match classify_transact_write_error(&error) {
                    Some((TransactionCancelAction::RetryCondition, _)) => continue,
                    Some((_, classified)) => return Err(classified),
                    None => return Err(ddb_err(error)),
                },
            }
        }

        if let Some(claim) = self
            .lookup_scim_create_claim(tenant, &input.external_id, &user_name)
            .await?
        {
            let record = self
                .get_by_id(tenant, &claim.user_id)
                .await?
                .ok_or_else(|| {
                    StoreError::Permanent(
                        "SCIM create claim references a missing canonical user".into(),
                    )
                })?;
            return if record.status == UserStatus::Tombstoned {
                Ok(ScimCreateOutcome::Tombstoned)
            } else {
                Ok(ScimCreateOutcome::Existing {
                    record,
                    pending_initial_epoch: claim.pending_initial_epoch,
                })
            };
        }
        let (external_match, user_name_match) = self
            .classify_scim_aliases(tenant, &input.external_id, &user_name)
            .await?;
        match (external_match, user_name_match) {
            (Some(left), Some(right)) if left == right => {
                let record = self.get_by_id(tenant, &left).await?.ok_or_else(|| {
                    StoreError::Permanent("SCIM aliases reference a missing canonical user".into())
                })?;
                if record.status == UserStatus::Tombstoned {
                    Ok(ScimCreateOutcome::Tombstoned)
                } else if record.scim_external_id.as_deref() == Some(input.external_id.as_str())
                    && record.scim_user_name.as_deref() == Some(user_name.as_str())
                {
                    self.ensure_scim_create_claim(
                        tenant,
                        &input.external_id,
                        &user_name,
                        &record.user_id,
                    )
                    .await?;
                    Ok(ScimCreateOutcome::Existing {
                        record,
                        pending_initial_epoch: None,
                    })
                } else {
                    Ok(ScimCreateOutcome::Conflict)
                }
            }
            (Some(_), _) | (_, Some(_)) => Ok(ScimCreateOutcome::Conflict),
            (None, None) => Err(StoreError::Transient(
                "SCIM create transaction contention did not converge".into(),
            )),
        }
    }

    async fn begin_scim_create_lifecycle(
        &self,
        tenant: &str,
        external_id: &str,
        user_name: &str,
        user_id: &str,
        now: i64,
    ) -> Result<crate::ports::ScimCreateLifecycleStart, StoreError> {
        use crate::ports::{ScimCreateLifecycleStart, UserStatus};
        use aws_sdk_dynamodb::types::{ConditionCheck, TransactWriteItem, Update};

        let user_name = user_name.trim().to_lowercase();
        for _ in 0..3 {
            let Some(claim) = self
                .lookup_scim_create_claim(tenant, external_id, &user_name)
                .await?
            else {
                return Ok(ScimCreateLifecycleStart::Complete);
            };
            if claim.user_id != user_id {
                return Err(StoreError::Permanent(
                    "SCIM create claim is bound to another canonical user".into(),
                ));
            }
            let Some(initial_epoch) = claim.pending_initial_epoch else {
                return Ok(ScimCreateLifecycleStart::Complete);
            };
            let current = self.get_by_id(tenant, user_id).await?.ok_or_else(|| {
                StoreError::Permanent(
                    "SCIM create claim references a missing canonical user".into(),
                )
            })?;
            if current.status == UserStatus::Tombstoned {
                return Ok(ScimCreateLifecycleStart::Tombstoned);
            }
            if !current.revocation_pending
                && (current.credential_epoch != initial_epoch
                    || (current.status == UserStatus::Disabled && current.credential_epoch != 0))
            {
                return Ok(ScimCreateLifecycleStart::Complete);
            }

            let next_epoch =
                crate::ports::next_disable_epoch(current.status, current.credential_epoch)?;
            let claim_check = ConditionCheck::builder()
                .table_name(&self.table)
                .key(
                    "user_id",
                    AttributeValue::S(Self::scim_create_claim_key(tenant, external_id, &user_name)),
                )
                .condition_expression(
                    "record_type = :record_type AND canonical_user_id = :canonical AND \
                     initial_lifecycle_epoch = :initial",
                )
                .expression_attribute_values(
                    ":record_type",
                    AttributeValue::S(SCIM_CREATE_RECORD_TYPE.to_string()),
                )
                .expression_attribute_values(":canonical", AttributeValue::S(tpk(tenant, user_id)))
                .expression_attribute_values(
                    ":initial",
                    AttributeValue::N(initial_epoch.to_string()),
                )
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!("build SCIM create lifecycle condition: {error}"))
                })?;
            let epoch_condition = if current.credential_epoch == 0 {
                "(attribute_not_exists(credential_epoch) OR credential_epoch = :expected)"
            } else {
                "credential_epoch = :expected"
            };
            let (status_condition, needs_active_value) = disable_status_condition(current.status);
            let condition =
                format!("attribute_exists(user_id) AND {status_condition} AND {epoch_condition}");
            let mut update = Update::builder()
                .table_name(&self.table)
                .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
                .update_expression(
                    "SET #status = :disabled, credential_epoch = :next, \
                     revocation_pending = :true, updated_at = :now REMOVE credential_change_id",
                )
                .condition_expression(condition)
                .expression_attribute_names("#status", "status")
                .expression_attribute_values(":disabled", AttributeValue::S("disabled".into()))
                .expression_attribute_values(
                    ":expected",
                    AttributeValue::N(current.credential_epoch.to_string()),
                )
                .expression_attribute_values(":next", AttributeValue::N(next_epoch.to_string()))
                .expression_attribute_values(":true", AttributeValue::Bool(true))
                .expression_attribute_values(":now", AttributeValue::N(now.to_string()));
            if needs_active_value {
                update = update.expression_attribute_values(
                    ":active",
                    AttributeValue::S("active".to_string()),
                );
            }
            let update = update.build().map_err(|error| {
                StoreError::Permanent(format!("build SCIM create lifecycle update: {error}"))
            })?;
            let result = self
                .db
                .transact_write_items()
                .transact_items(
                    TransactWriteItem::builder()
                        .condition_check(claim_check)
                        .build(),
                )
                .transact_items(TransactWriteItem::builder().update(update).build())
                .send()
                .await;
            match result {
                Ok(_) => {
                    let record = self.get_by_id(tenant, user_id).await?.ok_or_else(|| {
                        StoreError::Permanent(
                            "SCIM create lifecycle lost its canonical user".into(),
                        )
                    })?;
                    return Ok(ScimCreateLifecycleStart::Ready {
                        record,
                        epoch: next_epoch,
                    });
                }
                Err(error) => match classify_transact_write_error(&error) {
                    Some((TransactionCancelAction::RetryCondition, _)) => continue,
                    Some((_, classified)) => return Err(classified),
                    None => return Err(ddb_err(error)),
                },
            }
        }
        Err(StoreError::Transient(
            "SCIM create lifecycle transaction did not converge".into(),
        ))
    }

    async fn complete_scim_create_lifecycle(
        &self,
        tenant: &str,
        external_id: &str,
        user_name: &str,
        user_id: &str,
    ) -> Result<(), StoreError> {
        let result = self
            .db
            .update_item()
            .table_name(&self.table)
            .key(
                "user_id",
                AttributeValue::S(Self::scim_create_claim_key(
                    tenant,
                    external_id,
                    &user_name.trim().to_lowercase(),
                )),
            )
            .update_expression("REMOVE initial_lifecycle_epoch")
            .condition_expression("record_type = :record_type AND canonical_user_id = :canonical")
            .expression_attribute_values(
                ":record_type",
                AttributeValue::S(SCIM_CREATE_RECORD_TYPE.to_string()),
            )
            .expression_attribute_values(":canonical", AttributeValue::S(tpk(tenant, user_id)))
            .send()
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                match self
                    .lookup_scim_create_claim(tenant, external_id, user_name)
                    .await?
                {
                    None => Ok(()),
                    Some(claim) if claim.user_id == user_id => Ok(()),
                    Some(_) => Err(StoreError::Permanent(
                        "SCIM create claim is bound to another canonical user".into(),
                    )),
                }
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn get_scim_by_external_id(
        &self,
        tenant: &str,
        external_id: &str,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        let Some(user_id) = self
            .lookup_scim_alias(tenant, SCIM_ALIAS_EXTERNAL, external_id)
            .await?
        else {
            return Ok(None);
        };
        Ok(self.get_by_id(tenant, &user_id).await?.filter(|record| {
            record.status != crate::ports::UserStatus::Tombstoned
                && record.scim_external_id.as_deref() == Some(external_id)
        }))
    }

    async fn get_scim_by_user_name(
        &self,
        tenant: &str,
        user_name: &str,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        let user_name = user_name.trim().to_lowercase();
        let Some(user_id) = self
            .lookup_scim_alias(tenant, SCIM_ALIAS_USERNAME, &user_name)
            .await?
        else {
            return Ok(None);
        };
        Ok(self.get_by_id(tenant, &user_id).await?.filter(|record| {
            record.status != crate::ports::UserStatus::Tombstoned
                && record.scim_user_name.as_deref() == Some(user_name.as_str())
        }))
    }

    async fn list_scim(
        &self,
        tenant: &str,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<crate::ports::UserRecord>, usize), StoreError> {
        let tenant_key = Self::scim_tenant_key(tenant);
        let tombstoned = AttributeValue::S("tombstoned".to_string());
        let mut records = Vec::with_capacity(limit);
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        let mut total_results = 0usize;
        loop {
            let output = self
                .db
                .query()
                .table_name(&self.table)
                .index_name(&self.scim_tenant_index)
                .key_condition_expression("scim_tenant = :tenant")
                .filter_expression("attribute_not_exists(#status) OR #status <> :tombstoned")
                .expression_attribute_names("#status", "status")
                .expression_attribute_values(":tenant", AttributeValue::S(tenant_key.clone()))
                .expression_attribute_values(":tombstoned", tombstoned.clone())
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in output.items() {
                if total_results >= offset && records.len() < limit {
                    records.push(Self::to_record(item).ok_or_else(|| {
                        StoreError::Permanent(
                            "scim_tenant-index returned malformed canonical user".into(),
                        )
                    })?);
                }
                total_results = total_results
                    .checked_add(1)
                    .ok_or_else(|| StoreError::Permanent("SCIM user count overflow".into()))?;
            }
            match output.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        Ok((records, total_results))
    }

    async fn replace_scim(
        &self,
        tenant: &str,
        user_id: &str,
        input: crate::ports::ScimReplaceInput,
    ) -> Result<crate::ports::ScimReplaceOutcome, StoreError> {
        use crate::ports::{ScimReplaceInput, ScimReplaceOutcome, UserStatus};
        use aws_sdk_dynamodb::types::{ConditionCheck, Delete, Put, TransactWriteItem, Update};

        let ScimReplaceInput {
            external_id,
            user_name,
            display_name,
            active,
            now,
        } = input;
        let user_name = user_name.trim().to_lowercase();
        for _ in 0..3 {
            let Some(current) = self.get_by_id(tenant, user_id).await? else {
                return Ok(ScimReplaceOutcome::NotFound);
            };
            if current.scim_external_id.is_none() || current.scim_user_name.is_none() {
                return Ok(ScimReplaceOutcome::NotFound);
            }
            if current.status == UserStatus::Tombstoned {
                return Ok(ScimReplaceOutcome::Tombstoned);
            }
            let disable_epoch = (!active
                && (current.status == UserStatus::Active || current.credential_epoch == 0))
                .then(|| crate::ports::next_disable_epoch(current.status, current.credential_epoch))
                .transpose()?;
            let old_external = current.scim_external_id.as_deref().unwrap();
            let old_user_name = current.scim_user_name.as_deref().unwrap();
            if old_user_name != user_name {
                if let Some(existing) = self.lookup_local_by_email(tenant, &user_name).await? {
                    if existing.user_id != user_id {
                        return Ok(ScimReplaceOutcome::Conflict);
                    }
                }
            }

            let (external_match, user_name_match) = self
                .classify_scim_aliases(tenant, &external_id, &user_name)
                .await?;
            if external_match
                .as_deref()
                .is_some_and(|matched| matched != user_id)
                || user_name_match
                    .as_deref()
                    .is_some_and(|matched| matched != user_id)
            {
                return Ok(ScimReplaceOutcome::Conflict);
            }

            let mut assignments = vec![
                "email = :email",
                "updated_at = :updated",
                "scim_external_id = :external",
                "scim_user_name = :username",
            ];
            if display_name.is_some() {
                assignments.push("scim_display_name = :display");
            }
            if disable_epoch.is_some() {
                assignments.extend([
                    "#status = :disabled",
                    "credential_epoch = :next",
                    "revocation_pending = :true",
                ]);
            }
            let mut update_expression = format!("SET {}", assignments.join(", "));
            if display_name.is_none() {
                update_expression.push_str(" REMOVE scim_display_name");
            }
            let mut update = Update::builder()
                .table_name(&self.table)
                .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
                .update_expression(update_expression)
                .expression_attribute_names("#status", "status")
                .expression_attribute_values(
                    ":old_external",
                    AttributeValue::S(old_external.to_string()),
                )
                .expression_attribute_values(
                    ":old_username",
                    AttributeValue::S(old_user_name.to_string()),
                )
                .expression_attribute_values(":email", AttributeValue::S(tpk(tenant, &user_name)))
                .expression_attribute_values(":updated", AttributeValue::N(now.to_string()))
                .expression_attribute_values(":external", AttributeValue::S(external_id.clone()))
                .expression_attribute_values(":username", AttributeValue::S(user_name.clone()));
            if let Some(display_name) = display_name.as_deref() {
                update = update.expression_attribute_values(
                    ":display",
                    AttributeValue::S(display_name.to_string()),
                );
            }
            if !active {
                let epoch_condition = if current.credential_epoch == 0 {
                    "(attribute_not_exists(credential_epoch) OR credential_epoch = :expected)"
                } else {
                    "credential_epoch = :expected"
                };
                let (status_condition, needs_active_value) =
                    disable_status_condition(current.status);
                update = update
                    .condition_expression(format!(
                        "attribute_exists(user_id) AND \
                         scim_external_id = :old_external AND \
                         scim_user_name = :old_username AND \
                         {status_condition} AND {epoch_condition}"
                    ))
                    .expression_attribute_values(
                        ":expected",
                        AttributeValue::N(current.credential_epoch.to_string()),
                    )
                    .expression_attribute_values(
                        ":disabled",
                        AttributeValue::S("disabled".to_string()),
                    );
                if needs_active_value {
                    update = update.expression_attribute_values(
                        ":active",
                        AttributeValue::S("active".to_string()),
                    );
                }
                if let Some(disable_epoch) = disable_epoch {
                    update = update
                        .expression_attribute_values(
                            ":next",
                            AttributeValue::N(disable_epoch.to_string()),
                        )
                        .expression_attribute_values(":true", AttributeValue::Bool(true));
                }
            } else {
                update = update
                    .condition_expression(
                        "attribute_exists(user_id) AND scim_external_id = :old_external AND \
                         scim_user_name = :old_username AND \
                         (attribute_not_exists(#status) OR #status <> :tombstoned)",
                    )
                    .expression_attribute_values(
                        ":tombstoned",
                        AttributeValue::S("tombstoned".to_string()),
                    );
            }
            let update = update.build().map_err(|error| {
                StoreError::Permanent(format!("build SCIM replacement update: {error}"))
            })?;
            let mut transaction = vec![TransactWriteItem::builder().update(update).build()];
            for condition in [
                self.suppression_condition(
                    tenant,
                    crate::governance::GovernanceAliasKind::ScimExternalId,
                    &external_id,
                )?,
                self.suppression_condition(
                    tenant,
                    crate::governance::GovernanceAliasKind::ScimUserName,
                    &user_name,
                )?,
                self.suppression_condition(
                    tenant,
                    crate::governance::GovernanceAliasKind::Email,
                    &user_name,
                )?,
            ]
            .into_iter()
            .flatten()
            {
                transaction.push(condition);
            }
            let local_user_id = format!("user:{user_name}");
            if old_user_name != user_name && local_user_id != user_id {
                let local_identity_check = ConditionCheck::builder()
                    .table_name(&self.table)
                    .key("user_id", AttributeValue::S(tpk(tenant, &local_user_id)))
                    .condition_expression("attribute_not_exists(user_id) OR email <> :email")
                    .expression_attribute_values(
                        ":email",
                        AttributeValue::S(tpk(tenant, &user_name)),
                    )
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!(
                            "build local SCIM replacement identity condition: {error}"
                        ))
                    })?;
                transaction.push(
                    TransactWriteItem::builder()
                        .condition_check(local_identity_check)
                        .build(),
                );
            }

            for (kind, old_value, new_value) in [
                (SCIM_ALIAS_EXTERNAL, old_external, external_id.as_str()),
                (SCIM_ALIAS_USERNAME, old_user_name, user_name.as_str()),
            ] {
                if old_value == new_value {
                    continue;
                }
                let delete = Delete::builder()
                    .table_name(&self.table)
                    .key(
                        "user_id",
                        AttributeValue::S(Self::scim_alias_key(tenant, kind, old_value)),
                    )
                    .condition_expression(
                        "canonical_user_id = :canonical AND alias_value = :old_value",
                    )
                    .expression_attribute_values(
                        ":canonical",
                        AttributeValue::S(tpk(tenant, user_id)),
                    )
                    .expression_attribute_values(
                        ":old_value",
                        AttributeValue::S(old_value.to_string()),
                    )
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!("build SCIM alias delete: {error}"))
                    })?;
                let put = Put::builder()
                    .table_name(&self.table)
                    .set_item(Some(Self::scim_alias_item(
                        tenant, kind, new_value, user_id,
                    )))
                    .condition_expression("attribute_not_exists(user_id)")
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!("build SCIM alias put: {error}"))
                    })?;
                transaction.push(TransactWriteItem::builder().delete(delete).build());
                transaction.push(TransactWriteItem::builder().put(put).build());
            }

            match self
                .db
                .transact_write_items()
                .set_transact_items(Some(transaction))
                .send()
                .await
            {
                Ok(_) => {
                    let record = self.get_by_id(tenant, user_id).await?.ok_or_else(|| {
                        StoreError::Transient(
                            "SCIM replacement committed but canonical user was not readable".into(),
                        )
                    })?;
                    return Ok(ScimReplaceOutcome::Updated(record));
                }
                Err(error) => match classify_transact_write_error(&error) {
                    Some((TransactionCancelAction::RetryCondition, _)) => continue,
                    Some((_, classified)) => return Err(classified),
                    None => return Err(ddb_err(error)),
                },
            }
        }

        let Some(current) = self.get_by_id(tenant, user_id).await? else {
            return Ok(ScimReplaceOutcome::NotFound);
        };
        if current.status == UserStatus::Tombstoned {
            return Ok(ScimReplaceOutcome::Tombstoned);
        }
        if current.scim_external_id.as_deref() == Some(external_id.as_str())
            && current.scim_user_name.as_deref() == Some(user_name.as_str())
            && current.scim_display_name.as_deref() == display_name.as_deref()
            && (active || (current.status == UserStatus::Disabled && current.credential_epoch != 0))
        {
            return Ok(ScimReplaceOutcome::Updated(current));
        }
        if let Some(existing) = self.lookup_local_by_email(tenant, &user_name).await? {
            if existing.user_id != user_id {
                return Ok(ScimReplaceOutcome::Conflict);
            }
        }
        let (external_match, user_name_match) = self
            .classify_scim_aliases(tenant, &external_id, &user_name)
            .await?;
        if external_match
            .as_deref()
            .is_some_and(|matched| matched != user_id)
            || user_name_match
                .as_deref()
                .is_some_and(|matched| matched != user_id)
        {
            Ok(ScimReplaceOutcome::Conflict)
        } else {
            Err(StoreError::Transient(
                "SCIM replacement transaction contention did not converge".into(),
            ))
        }
    }

    async fn list(
        &self,
        tenant: &str,
        limit: usize,
        cursor: Option<&str>,
        query: Option<&str>,
        status: crate::ports::UserListStatusFilter,
    ) -> Result<(Vec<crate::ports::UserRecord>, Option<String>), StoreError> {
        // 分页 Scan(admin 面,量小)。cursor = base64url(JSON of LastEvaluatedKey 的物理 {user_id}),
        // 篡改/非法 → Permanent(handler 映射 400)。**tenant 隔离**:Scan 结果按物理 pk 前缀过滤
        // (空 tenant = 现网单租户,只收无前缀行;非空 = 只收 `{tenant}\x1f` 前缀行)。
        use base64::Engine;
        let want = limit.clamp(1, 100);
        let want_prefix = if tenant.is_empty() {
            None
        } else {
            Some(format!("{tenant}\u{1f}"))
        };
        let matches_tenant = |phys: &str| match &want_prefix {
            Some(p) => phys.starts_with(p.as_str()),
            None => !phys.contains('\u{1f}'), // 空 tenant:排除他租户前缀行
        };
        let query = query
            .map(|q| q.trim().to_lowercase())
            .filter(|q| !q.is_empty());
        // 🔴 P0-D 修(审计 I):**分区后必须循环 Scan 直到攒够 `want` 条本租户记录或表耗尽**。
        // 原实现 `.limit(want)` 施加在**租户前缀过滤之前** → 一页 raw items 里本租户可能 < want(甚至 0),
        // 导致 admin "加载更多" 丢用户 / 提前停(多租户交错时尤甚)。now:累积过滤后满 want 即停,
        // next cursor = 最后消费的物理 key(下页从此续),保证不漏不重。
        let mut recs: Vec<crate::ports::UserRecord> = Vec::with_capacity(want);
        let mut start_key: Option<HashMap<String, AttributeValue>> = match cursor {
            None => None,
            Some(c) => {
                let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(c)
                    .map_err(|_| StoreError::Permanent("bad cursor".into()))?;
                let uid: String = serde_json::from_slice::<serde_json::Value>(&raw)
                    .ok()
                    .and_then(|v| v.get("user_id").and_then(|x| x.as_str()).map(String::from))
                    .ok_or_else(|| StoreError::Permanent("bad cursor".into()))?;
                Some(HashMap::from([(
                    "user_id".to_string(),
                    AttributeValue::S(uid),
                )]))
            }
        };
        // Once the visible page is full, retain its physical boundary but keep scanning until
        // another combined-filter match is found. This avoids advertising a cursor whose only
        // remaining physical rows are filtered out.
        let mut page_cursor: Option<String> = None;
        loop {
            let mut scan = self
                .db
                .scan()
                .table_name(&self.table)
                .consistent_read(USER_LIST_CONSISTENT_READ)
                .limit(want.clamp(1, 100) as i32);
            if let Some(sk) = &start_key {
                scan = scan.set_exclusive_start_key(Some(sk.clone()));
            }
            let out = scan.send().await.map_err(ddb_err)?;
            for item in out.items() {
                let phys = item
                    .get("user_id")
                    .and_then(|v| v.as_s().ok())
                    .map(String::as_str)
                    .unwrap_or("");
                if matches_tenant(phys) {
                    if let Some(r) = Self::to_record(item) {
                        let matches_query = match query.as_deref() {
                            Some(query) => {
                                r.email.to_lowercase().contains(query)
                                    || r.user_id.to_lowercase().contains(query)
                            }
                            None => true,
                        };
                        if matches_query && status.matches(r.status) {
                            if recs.len() < want {
                                recs.push(r);
                                if recs.len() == want {
                                    page_cursor = Some(
                                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                                            serde_json::json!({ "user_id": phys }).to_string(),
                                        ),
                                    );
                                }
                            } else {
                                return Ok((recs, page_cursor));
                            }
                        }
                    }
                }
            }
            match out.last_evaluated_key() {
                Some(k) if !k.is_empty() => start_key = Some(k.clone()),
                _ => break, // 表耗尽:next=None(末页)
            }
        }
        Ok((recs, None))
    }

    async fn touch_last_login(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        let res = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .update_expression(TOUCH_LAST_LOGIN_UPDATE_EXPRESSION)
            .condition_expression(TOUCH_LAST_LOGIN_CONDITION_EXPRESSION)
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":active", AttributeValue::S("active".to_string()))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .send()
            .await;
        match res {
            Ok(_) => Ok(()),
            Err(e) if e.code().unwrap_or("").contains("ConditionalCheckFailed") => Ok(()),
            Err(e) => Err(ddb_err(e)),
        }
    }

    async fn set_status(
        &self,
        tenant: &str,
        user_id: &str,
        status: crate::ports::UserStatus,
        now: i64,
    ) -> Result<bool, StoreError> {
        // UpdateItem 条件 attribute_exists(user_id):不存在 → Ok(false)(handler 幂等/404);存在 → 置 status + 时间戳。
        let ts_attr = match status {
            crate::ports::UserStatus::Disabled => "disabled_at",
            crate::ports::UserStatus::Tombstoned => "tombstoned_at",
            crate::ports::UserStatus::Active => "enabled_at",
        };
        // **tombstone 终态条件写(评审 codex Blocker)**:除非本次就是置 Tombstoned,否则要求当前 status
        // ≠ 'tombstoned'(含缺省 attr 视为非 tombstone)——**存储层**堵死 delete→disable→enable 的竞态复活
        // (即便 handler 前置检查因并发被绕过,DynamoDB 条件写仍拒)。ConditionalCheckFailed → Ok(false)。
        let setting_tombstone = status == crate::ports::UserStatus::Tombstoned;
        // GDPR 级联(spec 007 §6.1):tombstone(admin 删除)时同一 UpdateItem 内 REMOVE attributes,
        // 不留孤儿个人数据。非 tombstone(disable/enable)不动属性。
        let update_expr = if setting_tombstone {
            "SET #s = :s, #t = :now REMOVE attributes, scim_tenant"
        } else {
            "SET #s = :s, #t = :now"
        };
        let mut upd = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .update_expression(update_expr)
            .expression_attribute_names("#s", "status")
            .expression_attribute_names("#t", ts_attr)
            .expression_attribute_values(
                ":s",
                AttributeValue::S(Self::status_str(status).to_string()),
            )
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()));
        upd = if setting_tombstone {
            upd.condition_expression("attribute_exists(user_id)")
        } else {
            upd.condition_expression(
                "attribute_exists(user_id) AND (attribute_not_exists(#s) OR #s <> :tomb)",
            )
            .expression_attribute_values(":tomb", AttributeValue::S("tombstoned".to_string()))
        };
        let res = upd.send().await;
        match res {
            Ok(_) => Ok(true),
            Err(e) if e.code().unwrap_or("").contains("ConditionalCheckFailed") => Ok(false),
            Err(e) => Err(ddb_err(e)),
        }
    }

    async fn begin_credential_change(
        &self,
        tenant: &str,
        user_id: &str,
        expected_epoch: u64,
        operation_id: &str,
        now: i64,
    ) -> Result<crate::ports::CredentialChangeStart, StoreError> {
        use crate::ports::{CredentialChangeStart, UserStatus};

        let next_epoch = expected_epoch
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("user credential_epoch exhausted".to_string()))?;
        let epoch_condition = if expected_epoch == 0 {
            "(attribute_not_exists(credential_epoch) OR credential_epoch = :expected)"
        } else {
            "credential_epoch = :expected"
        };
        let condition = format!(
            "attribute_exists(user_id) AND \
             (attribute_not_exists(#status) OR #status = :active) AND \
             (attribute_not_exists(revocation_pending) OR revocation_pending = :false) AND \
             {epoch_condition}"
        );
        let result = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .update_expression(
                "SET credential_epoch = :next, revocation_pending = :true, \
                 credential_change_id = :operation, updated_at = :now",
            )
            .condition_expression(condition)
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":active", AttributeValue::S("active".to_string()))
            .expression_attribute_values(":false", AttributeValue::Bool(false))
            .expression_attribute_values(":true", AttributeValue::Bool(true))
            .expression_attribute_values(":expected", AttributeValue::N(expected_epoch.to_string()))
            .expression_attribute_values(":next", AttributeValue::N(next_epoch.to_string()))
            .expression_attribute_values(":operation", AttributeValue::S(operation_id.to_string()))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .send()
            .await;
        match result {
            Ok(_) => Ok(CredentialChangeStart::Started { epoch: next_epoch }),
            Err(error) => {
                let conditional = error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed"));
                let classified = if conditional {
                    None
                } else {
                    let classified = ddb_err(error);
                    if !matches!(classified, StoreError::Transient(_)) {
                        return Err(classified);
                    }
                    Some(classified)
                };
                let observed = self
                    .db
                    .get_item()
                    .table_name(&self.table)
                    .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
                    .consistent_read(true)
                    .send()
                    .await
                    .map_err(ddb_err)?;
                let committed = observed.item().is_some_and(|item| {
                    s(item.get("credential_change_id")).as_deref() == Some(operation_id)
                        && n_u64(item.get("credential_epoch")) == Some(next_epoch)
                        && item
                            .get("revocation_pending")
                            .and_then(|value| value.as_bool().ok())
                            .copied()
                            == Some(true)
                });
                if committed {
                    Ok(CredentialChangeStart::Started { epoch: next_epoch })
                } else if observed.item().is_some_and(|item| {
                    Self::to_record(item).is_some_and(|record| {
                        record.status == UserStatus::Active && record.revocation_pending
                    }) && s(item.get("credential_change_id")).as_deref() != Some(operation_id)
                }) {
                    Ok(CredentialChangeStart::ConcurrentChange)
                } else if conditional {
                    match observed.item().and_then(Self::to_record) {
                        None => Ok(CredentialChangeStart::NotFound),
                        Some(record) if record.status != UserStatus::Active => {
                            Ok(CredentialChangeStart::Ineligible)
                        }
                        Some(_) => Ok(CredentialChangeStart::ConcurrentChange),
                    }
                } else {
                    Err(classified.expect("non-conditional failures are classified"))
                }
            }
        }
    }

    async fn complete_credential_change(
        &self,
        tenant: &str,
        user_id: &str,
        owner: crate::ports::CredentialChangeOwner<'_>,
        now: i64,
    ) -> Result<bool, StoreError> {
        let result = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .update_expression(
                "SET revocation_pending = :false, updated_at = :now REMOVE credential_change_id",
            )
            .condition_expression(
                "attribute_exists(user_id) AND \
                 (attribute_not_exists(#status) OR #status = :active) AND \
                 credential_epoch = :epoch AND revocation_pending = :true AND \
                 credential_change_id = :operation",
            )
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":active", AttributeValue::S("active".to_string()))
            .expression_attribute_values(":false", AttributeValue::Bool(false))
            .expression_attribute_values(":true", AttributeValue::Bool(true))
            .expression_attribute_values(":epoch", AttributeValue::N(owner.epoch.to_string()))
            .expression_attribute_values(
                ":operation",
                AttributeValue::S(owner.operation_id.to_string()),
            )
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                Ok(false)
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn recover_expired_credential_change(
        &self,
        tenant: &str,
        user_id: &str,
        epoch: u64,
        started_before: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        let result = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .update_expression(
                "SET revocation_pending = :false, updated_at = :now REMOVE credential_change_id",
            )
            .condition_expression(
                "attribute_exists(user_id) AND \
                 (attribute_not_exists(#status) OR #status <> :tomb) AND \
                 credential_epoch = :epoch AND revocation_pending = :true AND \
                 attribute_exists(credential_change_id) AND updated_at <= :started_before",
            )
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":tomb", AttributeValue::S("tombstoned".to_string()))
            .expression_attribute_values(":false", AttributeValue::Bool(false))
            .expression_attribute_values(":true", AttributeValue::Bool(true))
            .expression_attribute_values(":epoch", AttributeValue::N(epoch.to_string()))
            .expression_attribute_values(
                ":started_before",
                AttributeValue::N(started_before.to_string()),
            )
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                Ok(false)
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn begin_disable(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<crate::ports::DisableStart, StoreError> {
        use crate::ports::{DisableStart, UserStatus};
        use aws_sdk_dynamodb::types::ReturnValue;

        for _ in 0..3 {
            let Some(current) = self.get_by_id(tenant, user_id).await? else {
                return Ok(DisableStart::NotFound);
            };
            if current.status == UserStatus::Tombstoned {
                return Ok(DisableStart::Tombstoned);
            }
            let next_epoch =
                crate::ports::next_disable_epoch(current.status, current.credential_epoch)?;
            let epoch_condition = if current.credential_epoch == 0 {
                "(attribute_not_exists(credential_epoch) OR credential_epoch = :expected)"
            } else {
                "credential_epoch = :expected"
            };
            let (status_condition, needs_active_value) = disable_status_condition(current.status);
            let condition =
                format!("attribute_exists(user_id) AND {status_condition} AND {epoch_condition}");
            let mut update = self
                .db
                .update_item()
                .table_name(&self.table)
                .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
                .update_expression(
                    "SET #status = :disabled, credential_epoch = :next, \
                     revocation_pending = :true, updated_at = :now \
                     REMOVE credential_change_id",
                )
                .condition_expression(condition)
                .expression_attribute_names("#status", "status")
                .expression_attribute_values(":disabled", AttributeValue::S("disabled".to_string()))
                .expression_attribute_values(
                    ":expected",
                    AttributeValue::N(current.credential_epoch.to_string()),
                )
                .expression_attribute_values(":next", AttributeValue::N(next_epoch.to_string()))
                .expression_attribute_values(":true", AttributeValue::Bool(true))
                .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
                .return_values(ReturnValue::AllNew);
            if needs_active_value {
                update = update.expression_attribute_values(
                    ":active",
                    AttributeValue::S("active".to_string()),
                );
            }
            let result = update.send().await;
            match result {
                Ok(output) => {
                    let record =
                        output
                            .attributes()
                            .and_then(Self::to_record)
                            .ok_or_else(|| {
                                StoreError::Permanent(
                                    "DynamoDB returned malformed user after begin_disable".into(),
                                )
                            })?;
                    return Ok(DisableStart::Ready {
                        record,
                        epoch: next_epoch,
                    });
                }
                Err(error)
                    if error
                        .code()
                        .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
                {
                    continue;
                }
                Err(error) => return Err(ddb_err(error)),
            }
        }
        let Some(current) = self.get_by_id(tenant, user_id).await? else {
            return Ok(DisableStart::NotFound);
        };
        if current.status == UserStatus::Tombstoned {
            Ok(DisableStart::Tombstoned)
        } else {
            Err(StoreError::Transient(
                "begin_disable conditional update did not converge".into(),
            ))
        }
    }

    async fn complete_disable(
        &self,
        tenant: &str,
        user_id: &str,
        epoch: u64,
        now: i64,
    ) -> Result<bool, StoreError> {
        let epoch_condition = if epoch == 0 {
            "(attribute_not_exists(credential_epoch) OR credential_epoch = :epoch)"
        } else {
            "credential_epoch = :epoch"
        };
        let result = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .update_expression(
                "SET revocation_pending = :false, updated_at = :now REMOVE credential_change_id",
            )
            .condition_expression(format!(
                "attribute_exists(user_id) AND #status = :disabled AND {epoch_condition}"
            ))
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":disabled", AttributeValue::S("disabled".to_string()))
            .expression_attribute_values(":epoch", AttributeValue::N(epoch.to_string()))
            .expression_attribute_values(":false", AttributeValue::Bool(false))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                Ok(false)
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn begin_legacy_disable_cleanup(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        use aws_sdk_dynamodb::types::ReturnValue;

        let result = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .update_expression(
                "SET credential_epoch = :one, revocation_pending = :true, updated_at = :now \
                 REMOVE credential_change_id",
            )
            .condition_expression(
                "attribute_exists(user_id) AND #status = :disabled AND \
                 (attribute_not_exists(credential_epoch) OR credential_epoch = :zero)",
            )
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":disabled", AttributeValue::S("disabled".to_string()))
            .expression_attribute_values(":zero", AttributeValue::N("0".to_string()))
            .expression_attribute_values(":one", AttributeValue::N("1".to_string()))
            .expression_attribute_values(":true", AttributeValue::Bool(true))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .return_values(ReturnValue::AllNew)
            .send()
            .await;
        match result {
            Ok(output) => output
                .attributes()
                .and_then(Self::to_record)
                .map(Some)
                .ok_or_else(|| {
                    StoreError::Permanent(
                        "DynamoDB returned malformed user after legacy cleanup start".into(),
                    )
                }),
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                Ok(None)
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn enable_completed(
        &self,
        tenant: &str,
        user_id: &str,
        expected_epoch: u64,
        now: i64,
    ) -> Result<crate::ports::EnableOutcome, StoreError> {
        use crate::ports::{EnableOutcome, UserStatus};
        use aws_sdk_dynamodb::types::ReturnValue;

        let result = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .update_expression(
                "SET #status = :active, revocation_pending = :false, updated_at = :now \
                 REMOVE credential_change_id",
            )
            .condition_expression(
                "attribute_exists(user_id) AND #status = :disabled AND \
                 credential_epoch = :expected_epoch AND \
                 (attribute_not_exists(revocation_pending) OR revocation_pending = :false)",
            )
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":active", AttributeValue::S("active".to_string()))
            .expression_attribute_values(":disabled", AttributeValue::S("disabled".to_string()))
            .expression_attribute_values(
                ":expected_epoch",
                AttributeValue::N(expected_epoch.to_string()),
            )
            .expression_attribute_values(":false", AttributeValue::Bool(false))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .return_values(ReturnValue::AllNew)
            .send()
            .await;
        match result {
            Ok(output) => output
                .attributes()
                .and_then(Self::to_record)
                .map(EnableOutcome::Enabled)
                .ok_or_else(|| {
                    StoreError::Permanent(
                        "DynamoDB returned malformed user after enable_completed".into(),
                    )
                }),
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                match self.get_by_id(tenant, user_id).await? {
                    None => Ok(EnableOutcome::NotFound),
                    Some(record) if record.status == UserStatus::Tombstoned => {
                        Ok(EnableOutcome::Tombstoned)
                    }
                    Some(record) if record.revocation_pending => {
                        Ok(EnableOutcome::RevocationPending)
                    }
                    Some(record)
                        if record.status == UserStatus::Active
                            && record.credential_epoch == expected_epoch =>
                    {
                        Ok(EnableOutcome::Enabled(record))
                    }
                    Some(_) => Ok(EnableOutcome::ConcurrentChange),
                }
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn put_attributes(
        &self,
        tenant: &str,
        user_id: &str,
        namespace: &str,
        kv: std::collections::BTreeMap<String, String>,
        expected_revision: u64,
    ) -> Result<crate::ports::PutAttrOutcome, StoreError> {
        self.put_attributes_conditioned(tenant, user_id, namespace, kv, expected_revision, None)
            .await?
            .ok_or_else(|| {
                StoreError::Permanent(
                    "unguarded attribute write reported an authority conflict".into(),
                )
            })
    }

    async fn migrate_attributes(
        &self,
        tenant: &str,
        user_id: &str,
        canonical_namespace: &str,
        source_namespaces: &std::collections::BTreeSet<String>,
    ) -> Result<crate::ports::AttributeMigrationOutcome, StoreError> {
        use crate::attribute_namespace::{plan_attribute_migration, MigrationDecision};
        use crate::ports::AttributeMigrationOutcome;

        let pk = tpk(tenant, user_id);
        for _ in 0..5 {
            let out = self
                .db
                .get_item()
                .table_name(&self.table)
                .key("user_id", AttributeValue::S(pk.clone()))
                .consistent_read(true)
                .send()
                .await
                .map_err(ddb_err)?;
            let Some(record) = out.item().and_then(Self::to_record) else {
                return Ok(AttributeMigrationOutcome::NotFound);
            };
            if record.status == crate::ports::UserStatus::Tombstoned {
                return Ok(AttributeMigrationOutcome::Tombstoned);
            }
            let attributes = match plan_attribute_migration(
                &record.attributes,
                canonical_namespace,
                source_namespaces,
            ) {
                MigrationDecision::Noop => return Ok(AttributeMigrationOutcome::Noop),
                MigrationDecision::Conflict { namespaces } => {
                    return Ok(AttributeMigrationOutcome::Conflict { namespaces });
                }
                MigrationDecision::RevisionExhausted => {
                    return Ok(AttributeMigrationOutcome::RevisionExhausted);
                }
                MigrationDecision::Replace { attributes } => attributes,
            };
            if crate::adapters::memory::attributes_serialized_len(&attributes)
                > crate::ports::ATTRIBUTES_MAX_BYTES
            {
                return Ok(AttributeMigrationOutcome::TooLarge);
            }
            let generation = record.attributes_generation.checked_add(1).ok_or_else(|| {
                StoreError::Permanent("user attributes generation exhausted".into())
            })?;
            let generation_condition = if record.attributes_generation == 0 {
                "(attribute_not_exists(#generation) OR #generation = :expected_generation)"
            } else {
                "#generation = :expected_generation"
            };
            let result = self
                .db
                .update_item()
                .table_name(&self.table)
                .key("user_id", AttributeValue::S(pk.clone()))
                .update_expression("SET #attrs = :attrs, #generation = :next_generation")
                .condition_expression(format!(
                    "{ATTRIBUTE_USER_EXISTS_CONDITION} AND \
                     (attribute_not_exists(#status) OR #status <> :tomb) AND \
                     {generation_condition}"
                ))
                .expression_attribute_names("#status", "status")
                .expression_attribute_names("#attrs", "attributes")
                .expression_attribute_names("#generation", "attributes_generation")
                .expression_attribute_values(":tomb", AttributeValue::S("tombstoned".to_string()))
                .expression_attribute_values(":attrs", Self::attributes_to_av(&attributes))
                .expression_attribute_values(
                    ":expected_generation",
                    AttributeValue::N(record.attributes_generation.to_string()),
                )
                .expression_attribute_values(
                    ":next_generation",
                    AttributeValue::N(generation.to_string()),
                )
                .send()
                .await;
            match result {
                Ok(_) => return Ok(AttributeMigrationOutcome::Migrated { generation }),
                Err(error)
                    if error
                        .code()
                        .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
                {
                    continue;
                }
                Err(error) => return Err(ddb_err(error)),
            }
        }
        Err(StoreError::Transient(
            "attribute migration did not converge after generation conflicts".into(),
        ))
    }

    async fn fence_for_erasure(
        &self,
        tenant: &str,
        user_id: &str,
        target_epoch: u64,
        now: i64,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        let expected_epoch = target_epoch.checked_sub(1).ok_or_else(|| {
            StoreError::Permanent("user erasure target epoch must be non-zero".into())
        })?;
        let epoch_condition = if expected_epoch == 0 {
            "(attribute_not_exists(credential_epoch) OR credential_epoch = :expected)"
        } else {
            "credential_epoch = :expected"
        };
        let result = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .update_expression(
                "SET #status = :tomb, credential_epoch = :target, \
                 revocation_pending = :true, updated_at = :now, tombstoned_at = :now \
                 REMOVE attributes, scim_tenant",
            )
            .condition_expression(format!(
                "attribute_exists(user_id) AND \
                 (attribute_not_exists(#status) OR #status <> :tomb) AND {epoch_condition}"
            ))
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":tomb", AttributeValue::S("tombstoned".into()))
            .expression_attribute_values(":expected", AttributeValue::N(expected_epoch.to_string()))
            .expression_attribute_values(":target", AttributeValue::N(target_epoch.to_string()))
            .expression_attribute_values(":true", AttributeValue::Bool(true))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllNew)
            .send()
            .await;
        match result {
            Ok(output) => output
                .attributes()
                .and_then(Self::to_record)
                .map(Some)
                .ok_or_else(|| {
                    StoreError::Permanent(
                        "fenced user did not decode as a canonical identity".into(),
                    )
                }),
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                match self.get_by_id(tenant, user_id).await? {
                    None => Ok(None),
                    Some(record)
                        if record.status == crate::ports::UserStatus::Tombstoned
                            && record.credential_epoch == target_epoch =>
                    {
                        Ok(Some(record))
                    }
                    Some(_) => Err(StoreError::Permanent(
                        "user erasure fence no longer matches the target epoch".into(),
                    )),
                }
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn delete_erased_identity(
        &self,
        tenant: &str,
        user_id: &str,
        target_epoch: u64,
    ) -> Result<bool, StoreError> {
        use aws_sdk_dynamodb::types::{Delete, TransactWriteItem};

        let Some(record) = self.get_by_id(tenant, user_id).await? else {
            return Ok(true);
        };
        if record.status != crate::ports::UserStatus::Tombstoned
            || record.credential_epoch != target_epoch
        {
            return Err(StoreError::Permanent(
                "user identity is not fenced for this erasure epoch".into(),
            ));
        }

        let canonical = Delete::builder()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .condition_expression("#status = :tomb AND credential_epoch = :epoch")
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":tomb", AttributeValue::S("tombstoned".into()))
            .expression_attribute_values(":epoch", AttributeValue::N(target_epoch.to_string()))
            .build()
            .map_err(|error| StoreError::Permanent(format!("build erased user delete: {error}")))?;
        let mut request = self
            .db
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().delete(canonical).build());
        for (kind, alias) in [
            (SCIM_ALIAS_EXTERNAL, record.scim_external_id.as_deref()),
            (SCIM_ALIAS_USERNAME, record.scim_user_name.as_deref()),
        ] {
            if let Some(alias) = alias {
                let delete = Delete::builder()
                    .table_name(&self.table)
                    .key(
                        "user_id",
                        AttributeValue::S(Self::scim_alias_key(tenant, kind, alias)),
                    )
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!("build erased SCIM alias delete: {error}"))
                    })?;
                request =
                    request.transact_items(TransactWriteItem::builder().delete(delete).build());
            }
        }
        if let (Some(external_id), Some(user_name)) = (
            record.scim_external_id.as_deref(),
            record.scim_user_name.as_deref(),
        ) {
            let delete = Delete::builder()
                .table_name(&self.table)
                .key(
                    "user_id",
                    AttributeValue::S(Self::scim_create_claim_key(tenant, external_id, user_name)),
                )
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!("build erased SCIM create claim delete: {error}"))
                })?;
            request = request.transact_items(TransactWriteItem::builder().delete(delete).build());
        }
        match request.send().await {
            Ok(_) => Ok(true),
            Err(error) => {
                let classified = ddb_err(error);
                if matches!(classified, StoreError::Transient(_))
                    && self.get_by_id(tenant, user_id).await?.is_none()
                {
                    Ok(true)
                } else {
                    Err(classified)
                }
            }
        }
    }
}

impl DynamoUsersStore {
    fn governance_fence_conflict(operation: &str) -> StoreError {
        StoreError::Transient(format!(
            "{operation}: governance destructive fence conflict"
        ))
    }

    fn erasure_update(
        &self,
        tenant: &str,
        user_id: &str,
        target_epoch: u64,
        now: i64,
        transition: crate::governance::UserErasureFenceTransition,
    ) -> Result<aws_sdk_dynamodb::types::TransactWriteItem, StoreError> {
        use aws_sdk_dynamodb::types::{TransactWriteItem, Update};

        let expected_epoch = target_epoch.checked_sub(1).ok_or_else(|| {
            StoreError::Permanent("user erasure target epoch must be non-zero".into())
        })?;
        let mut update = Update::builder()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":tomb", AttributeValue::S("tombstoned".into()))
            .expression_attribute_values(":target", AttributeValue::N(target_epoch.to_string()));
        if transition == crate::governance::UserErasureFenceTransition::AlreadyFenced {
            update = update
                .update_expression("SET #status = :tomb")
                .condition_expression(
                    "attribute_exists(user_id) AND #status = :tomb AND credential_epoch = :target",
                );
        } else {
            let epoch_condition = if expected_epoch == 0 {
                "(attribute_not_exists(credential_epoch) OR credential_epoch = :expected)"
            } else {
                "credential_epoch = :expected"
            };
            let status_condition = match transition {
                crate::governance::UserErasureFenceTransition::Advance => {
                    "(attribute_not_exists(#status) OR #status <> :tomb)"
                }
                crate::governance::UserErasureFenceTransition::LegacyZeroEpochTombstone => {
                    "#status = :tomb"
                }
                crate::governance::UserErasureFenceTransition::AlreadyFenced => unreachable!(),
            };
            update = update
                .update_expression(
                    "SET #status = :tomb, credential_epoch = :target, \
                     revocation_pending = :true, updated_at = :now, tombstoned_at = :now \
                     REMOVE attributes, scim_tenant",
                )
                .condition_expression(format!(
                    "attribute_exists(user_id) AND {status_condition} AND {epoch_condition}"
                ))
                .expression_attribute_values(
                    ":expected",
                    AttributeValue::N(expected_epoch.to_string()),
                )
                .expression_attribute_values(":true", AttributeValue::Bool(true))
                .expression_attribute_values(":now", AttributeValue::N(now.to_string()));
        }
        let update = update.build().map_err(|error| {
            StoreError::Permanent(format!("build governed user erasure fence: {error}"))
        })?;
        Ok(TransactWriteItem::builder().update(update).build())
    }

    pub(crate) async fn governance_fence_for_erasure_fenced(
        &self,
        governance: &super::governance::DynamoGovernanceStore,
        logical_tenant: &str,
        data_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        user_id: &str,
        target_epoch: u64,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        use super::governance::GovernanceDestructiveWriteOutcome;

        if fence.target_epoch != Some(target_epoch) {
            return Err(Self::governance_fence_conflict(
                "fence user identity for erasure",
            ));
        }
        let Some(current) =
            <Self as crate::ports::UsersStore>::get_by_id(self, data_tenant, user_id).await?
        else {
            return Ok(None);
        };
        let transition = crate::governance::classify_user_erasure_fence_transition(
            current.status,
            current.credential_epoch,
            target_epoch,
        )?;
        let write = self.erasure_update(data_tenant, user_id, target_epoch, now, transition)?;
        match governance
            .execute_destructive_transaction(logical_tenant, fence.clone(), now, vec![write])
            .await?
        {
            GovernanceDestructiveWriteOutcome::Applied => {}
            GovernanceDestructiveWriteOutcome::FenceConflict => {
                return Err(Self::governance_fence_conflict(
                    "fence user identity for erasure",
                ))
            }
        }

        let current =
            <Self as crate::ports::UsersStore>::get_by_id(self, data_tenant, user_id).await?;
        match current {
            Some(record)
                if record.status == crate::ports::UserStatus::Tombstoned
                    && record.credential_epoch == target_epoch =>
            {
                Ok(Some(record))
            }
            Some(_) => Err(StoreError::Transient(
                "governed user erasure fence changed after commit".into(),
            )),
            None => Err(StoreError::Transient(
                "governed user disappeared after erasure fence commit".into(),
            )),
        }
    }

    fn governed_identity_delete(
        &self,
        tenant: &str,
        user_id: &str,
        target_epoch: u64,
        external_id: Option<&str>,
        user_name: Option<&str>,
    ) -> Result<Vec<aws_sdk_dynamodb::types::TransactWriteItem>, StoreError> {
        use aws_sdk_dynamodb::types::{Delete, TransactWriteItem};

        let canonical_id = tpk(tenant, user_id);
        let canonical = Delete::builder()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(canonical_id.clone()))
            .condition_expression(
                "attribute_not_exists(user_id) OR \
                 (#status = :tomb AND credential_epoch = :epoch)",
            )
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":tomb", AttributeValue::S("tombstoned".into()))
            .expression_attribute_values(":epoch", AttributeValue::N(target_epoch.to_string()))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build governed erased user delete: {error}"))
            })?;
        let mut writes = vec![TransactWriteItem::builder().delete(canonical).build()];

        for (kind, alias) in [
            (SCIM_ALIAS_EXTERNAL, external_id),
            (SCIM_ALIAS_USERNAME, user_name),
        ] {
            if let Some(alias) = alias {
                let delete = Delete::builder()
                    .table_name(&self.table)
                    .key(
                        "user_id",
                        AttributeValue::S(Self::scim_alias_key(tenant, kind, alias)),
                    )
                    .condition_expression(
                        "attribute_not_exists(user_id) OR \
                         (record_type = :record_type AND alias_kind = :kind \
                         AND alias_value = :value AND canonical_user_id = :canonical)",
                    )
                    .expression_attribute_values(
                        ":record_type",
                        AttributeValue::S(SCIM_ALIAS_RECORD_TYPE.into()),
                    )
                    .expression_attribute_values(":kind", AttributeValue::S(kind.into()))
                    .expression_attribute_values(":value", AttributeValue::S(alias.into()))
                    .expression_attribute_values(
                        ":canonical",
                        AttributeValue::S(canonical_id.clone()),
                    )
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!(
                            "build governed erased SCIM alias delete: {error}"
                        ))
                    })?;
                writes.push(TransactWriteItem::builder().delete(delete).build());
            }
        }
        if let (Some(external_id), Some(user_name)) = (external_id, user_name) {
            let delete = Delete::builder()
                .table_name(&self.table)
                .key(
                    "user_id",
                    AttributeValue::S(Self::scim_create_claim_key(tenant, external_id, user_name)),
                )
                .condition_expression(
                    "attribute_not_exists(user_id) OR \
                     (record_type = :record_type AND canonical_user_id = :canonical)",
                )
                .expression_attribute_values(
                    ":record_type",
                    AttributeValue::S(SCIM_CREATE_RECORD_TYPE.into()),
                )
                .expression_attribute_values(":canonical", AttributeValue::S(canonical_id))
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!(
                        "build governed erased SCIM create claim delete: {error}"
                    ))
                })?;
            writes.push(TransactWriteItem::builder().delete(delete).build());
        }
        Ok(writes)
    }

    pub(crate) async fn governance_delete_erased_identity_fenced(
        &self,
        governance: &super::governance::DynamoGovernanceStore,
        logical_tenant: &str,
        data_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        user_id: &str,
        target_epoch: u64,
        scim_external_id: Option<&str>,
        scim_user_name: Option<&str>,
    ) -> Result<bool, StoreError> {
        use super::governance::GovernanceDestructiveWriteOutcome;

        if fence.target_epoch != Some(target_epoch) {
            return Err(Self::governance_fence_conflict(
                "delete erased user identity",
            ));
        }
        let current =
            <Self as crate::ports::UsersStore>::get_by_id(self, data_tenant, user_id).await?;
        if current.as_ref().is_some_and(|record| {
            record.status != crate::ports::UserStatus::Tombstoned
                || record.credential_epoch != target_epoch
        }) {
            return Err(StoreError::Permanent(
                "user identity is not fenced for this erasure epoch".into(),
            ));
        }
        let external_id = scim_external_id.or_else(|| {
            current
                .as_ref()
                .and_then(|record| record.scim_external_id.as_deref())
        });
        let user_name = scim_user_name.or_else(|| {
            current
                .as_ref()
                .and_then(|record| record.scim_user_name.as_deref())
        });
        let writes = self.governed_identity_delete(
            data_tenant,
            user_id,
            target_epoch,
            external_id,
            user_name,
        )?;
        match governance
            .execute_destructive_transaction(logical_tenant, fence.clone(), now, writes)
            .await?
        {
            GovernanceDestructiveWriteOutcome::Applied => Ok(true),
            GovernanceDestructiveWriteOutcome::FenceConflict => Err(
                Self::governance_fence_conflict("delete erased user identity"),
            ),
        }
    }

    async fn governed_identity_item(
        &self,
        key: String,
    ) -> Result<Option<HashMap<String, AttributeValue>>, StoreError> {
        let response = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(key))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(response.item)
    }

    pub(crate) async fn governance_user_identity_inventory(
        &self,
        data_tenant: &str,
        user_id: &str,
        scim_external_id: Option<&str>,
        scim_user_name: Option<&str>,
    ) -> Result<GovernanceUserIdentityInventory, StoreError> {
        let canonical_id = tpk(data_tenant, user_id);
        let canonical = self.governed_identity_item(canonical_id.clone()).await?;
        let record = canonical.as_ref().and_then(Self::to_record);
        if canonical.is_some() && record.is_none() {
            return Err(StoreError::Permanent(
                "user identity inventory found a malformed canonical row".into(),
            ));
        }
        let mut scim_aliases_remaining = 0usize;
        for (kind, value) in [
            (SCIM_ALIAS_EXTERNAL, scim_external_id),
            (SCIM_ALIAS_USERNAME, scim_user_name),
        ] {
            let Some(value) = value else {
                continue;
            };
            if let Some(item) = self
                .governed_identity_item(Self::scim_alias_key(data_tenant, kind, value))
                .await?
            {
                let exact = item
                    .get("record_type")
                    .and_then(|value| value.as_s().ok())
                    .is_some_and(|record_type| record_type == SCIM_ALIAS_RECORD_TYPE)
                    && item
                        .get("alias_kind")
                        .and_then(|value| value.as_s().ok())
                        .is_some_and(|stored| stored == kind)
                    && item
                        .get("alias_value")
                        .and_then(|value| value.as_s().ok())
                        .is_some_and(|stored| stored == value)
                    && item
                        .get("canonical_user_id")
                        .and_then(|value| value.as_s().ok())
                        == Some(&canonical_id);
                if !exact {
                    return Err(StoreError::Permanent(
                        "user identity inventory found a malformed SCIM alias".into(),
                    ));
                }
                scim_aliases_remaining = scim_aliases_remaining.saturating_add(1);
            }
        }
        let scim_create_claims_remaining = if let (Some(external_id), Some(user_name)) =
            (scim_external_id, scim_user_name)
        {
            match self
                .governed_identity_item(Self::scim_create_claim_key(
                    data_tenant,
                    external_id,
                    user_name,
                ))
                .await?
            {
                Some(item) => {
                    let exact = item
                        .get("record_type")
                        .and_then(|value| value.as_s().ok())
                        .is_some_and(|record_type| record_type == SCIM_CREATE_RECORD_TYPE)
                        && item
                            .get("canonical_user_id")
                            .and_then(|value| value.as_s().ok())
                            == Some(&canonical_id);
                    if !exact {
                        return Err(StoreError::Permanent(
                            "user identity inventory found a malformed SCIM create claim".into(),
                        ));
                    }
                    1
                }
                None => 0,
            }
        } else {
            0
        };
        Ok(GovernanceUserIdentityInventory {
            canonical_exists: canonical.is_some(),
            canonical_tombstoned: record
                .as_ref()
                .is_some_and(|record| record.status == crate::ports::UserStatus::Tombstoned),
            canonical_epoch: record.map(|record| record.credential_epoch),
            scim_aliases_remaining,
            scim_create_claims_remaining,
        })
    }

    fn governance_key_belongs_to_tenant(physical_key: &str, tenant: &str) -> bool {
        if tenant.is_empty() {
            !physical_key.contains('\u{1f}')
        } else {
            physical_key.starts_with(&format!("{tenant}\u{1f}"))
        }
    }

    fn validate_governance_canonical_row(
        tenant: &str,
        physical_key: &str,
        item: &HashMap<String, AttributeValue>,
    ) -> Result<(), StoreError> {
        let record = Self::to_record(item).ok_or_else(|| {
            StoreError::Permanent(
                "tenant identity inventory found malformed canonical user row".into(),
            )
        })?;
        if tpk(tenant, &record.user_id) != physical_key {
            return Err(StoreError::Permanent(
                "tenant identity inventory found cross-tenant canonical user row".into(),
            ));
        }
        if let Some(email) = item.get("email") {
            let email = email.as_s().map_err(|_| {
                StoreError::Permanent(
                    "tenant identity inventory found malformed canonical email".into(),
                )
            })?;
            if !Self::governance_key_belongs_to_tenant(email, tenant) {
                return Err(StoreError::Permanent(
                    "tenant identity inventory found cross-tenant canonical email".into(),
                ));
            }
        }
        if item.get("status").is_some_and(|status| {
            status.as_s().ok().is_none_or(|status| {
                !matches!(status.as_str(), "active" | "disabled" | "tombstoned")
            })
        }) || item
            .get("credential_epoch")
            .is_some_and(|value| n_u64(Some(value)).is_none())
            || item
                .get("revocation_pending")
                .is_some_and(|value| value.as_bool().is_err())
        {
            return Err(StoreError::Permanent(
                "tenant identity inventory found malformed canonical lifecycle fields".into(),
            ));
        }
        for name in ["scim_external_id", "scim_user_name", "scim_display_name"] {
            if item.get(name).is_some_and(|value| value.as_s().is_err()) {
                return Err(StoreError::Permanent(format!(
                    "tenant identity inventory found malformed canonical field {name}"
                )));
            }
        }
        if item.get("scim_tenant").is_some_and(|value| {
            value
                .as_s()
                .ok()
                .is_none_or(|value| value != &Self::scim_tenant_key(tenant))
        }) {
            return Err(StoreError::Permanent(
                "tenant identity inventory found cross-tenant SCIM canonical row".into(),
            ));
        }
        Ok(())
    }

    fn validate_governance_alias_row(
        tenant: &str,
        physical_key: &str,
        item: &HashMap<String, AttributeValue>,
    ) -> Result<(), StoreError> {
        let kind = item
            .get("alias_kind")
            .and_then(|value| value.as_s().ok())
            .filter(|kind| matches!(kind.as_str(), SCIM_ALIAS_EXTERNAL | SCIM_ALIAS_USERNAME))
            .ok_or_else(|| {
                StoreError::Permanent(
                    "tenant identity inventory found malformed SCIM alias kind".into(),
                )
            })?;
        let value = item
            .get("alias_value")
            .and_then(|value| value.as_s().ok())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                StoreError::Permanent(
                    "tenant identity inventory found malformed SCIM alias value".into(),
                )
            })?;
        let canonical = item
            .get("canonical_user_id")
            .and_then(|value| value.as_s().ok())
            .ok_or_else(|| {
                StoreError::Permanent(
                    "tenant identity inventory found malformed SCIM alias owner".into(),
                )
            })?;
        if Self::scim_alias_key(tenant, kind, value) != physical_key
            || !Self::governance_key_belongs_to_tenant(canonical, tenant)
        {
            return Err(StoreError::Permanent(
                "tenant identity inventory found cross-tenant SCIM alias row".into(),
            ));
        }
        Ok(())
    }

    fn validate_governance_create_claim_row(
        tenant: &str,
        physical_key: &str,
        item: &HashMap<String, AttributeValue>,
    ) -> Result<(), StoreError> {
        let logical_key = strip_tpk(physical_key);
        let digest = logical_key
            .strip_prefix("scim-create:")
            .filter(|digest| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(digest)
                    .is_ok_and(|decoded| decoded.len() == 32)
            })
            .ok_or_else(|| {
                StoreError::Permanent(
                    "tenant identity inventory found malformed SCIM create-claim key".into(),
                )
            })?;
        let canonical = item
            .get("canonical_user_id")
            .and_then(|value| value.as_s().ok())
            .ok_or_else(|| {
                StoreError::Permanent(
                    "tenant identity inventory found malformed SCIM create-claim owner".into(),
                )
            })?;
        if digest.len() != 43
            || !Self::governance_key_belongs_to_tenant(canonical, tenant)
            || item
                .get("initial_lifecycle_epoch")
                .is_some_and(|value| n_u64(Some(value)).is_none())
        {
            return Err(StoreError::Permanent(
                "tenant identity inventory found cross-tenant SCIM create-claim row".into(),
            ));
        }
        Ok(())
    }

    fn classify_governance_tenant_identity_row(
        tenant: &str,
        item: &HashMap<String, AttributeValue>,
        inventory: &mut GovernanceTenantIdentityInventory,
    ) -> Result<(), StoreError> {
        let physical_key = item
            .get("user_id")
            .and_then(|value| value.as_s().ok())
            .ok_or_else(|| {
                StoreError::Permanent("tenant identity inventory row is missing user_id".into())
            })?;
        if !Self::governance_key_belongs_to_tenant(physical_key, tenant) {
            return Ok(());
        }
        match item
            .get("record_type")
            .map(|value| value.as_s())
            .transpose()
            .map_err(|_| {
                StoreError::Permanent(
                    "tenant identity inventory found malformed record_type".into(),
                )
            })?
            .map(String::as_str)
        {
            None => {
                Self::validate_governance_canonical_row(tenant, physical_key, item)?;
                inventory.canonical_rows = inventory.canonical_rows.saturating_add(1);
            }
            Some(SCIM_ALIAS_RECORD_TYPE) => {
                Self::validate_governance_alias_row(tenant, physical_key, item)?;
                inventory.scim_alias_rows = inventory.scim_alias_rows.saturating_add(1);
            }
            Some(SCIM_CREATE_RECORD_TYPE) => {
                Self::validate_governance_create_claim_row(tenant, physical_key, item)?;
                inventory.scim_create_claim_rows =
                    inventory.scim_create_claim_rows.saturating_add(1);
            }
            Some(_) => {
                return Err(StoreError::Permanent(
                    "tenant identity inventory found unknown record_type".into(),
                ))
            }
        }
        Ok(())
    }

    pub(crate) async fn governance_tenant_identity_inventory(
        &self,
        data_tenant: &str,
    ) -> Result<GovernanceTenantIdentityInventory, StoreError> {
        let mut inventory = GovernanceTenantIdentityInventory::default();
        let mut last_key = None;
        loop {
            let response = self
                .db
                .scan()
                .table_name(&self.table)
                .consistent_read(true)
                .set_exclusive_start_key(last_key)
                .send()
                .await
                .map_err(ddb_err)?;
            for item in response.items() {
                Self::classify_governance_tenant_identity_row(data_tenant, item, &mut inventory)?;
            }
            match response.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        Ok(inventory)
    }

    fn governance_canonical_from_tenant_row(
        tenant: &str,
        item: &HashMap<String, AttributeValue>,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        let physical_key = item
            .get("user_id")
            .and_then(|value| value.as_s().ok())
            .ok_or_else(|| {
                StoreError::Permanent("governance user scan row is missing user_id".into())
            })?;
        if !Self::governance_key_belongs_to_tenant(physical_key, tenant) {
            return Ok(None);
        }
        match item
            .get("record_type")
            .map(|value| value.as_s())
            .transpose()
            .map_err(|_| {
                StoreError::Permanent("governance user scan found malformed record_type".into())
            })?
            .map(String::as_str)
        {
            None => {
                Self::validate_governance_canonical_row(tenant, physical_key, item)?;
                Self::to_record(item).map(Some).ok_or_else(|| {
                    StoreError::Permanent(
                        "governance user scan failed to decode canonical row".into(),
                    )
                })
            }
            Some(SCIM_ALIAS_RECORD_TYPE) => {
                Self::validate_governance_alias_row(tenant, physical_key, item)?;
                Ok(None)
            }
            Some(SCIM_CREATE_RECORD_TYPE) => {
                Self::validate_governance_create_claim_row(tenant, physical_key, item)?;
                Ok(None)
            }
            Some(_) => Err(StoreError::Permanent(
                "governance user scan found unknown record_type".into(),
            )),
        }
    }

    pub(crate) async fn governance_first_user(
        &self,
        data_tenant: &str,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        let mut last_key = None;
        loop {
            let response = self
                .db
                .scan()
                .table_name(&self.table)
                .consistent_read(true)
                .set_exclusive_start_key(last_key)
                .send()
                .await
                .map_err(ddb_err)?;
            for item in response.items() {
                if let Some(record) = Self::governance_canonical_from_tenant_row(data_tenant, item)?
                {
                    return Ok(Some(record));
                }
            }
            match response.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => return Ok(None),
            }
        }
    }
}

#[cfg(test)]
#[path = "credential_change_idempotency_tests.rs"]
mod credential_change_idempotency_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::UsersStore;
    use aws_smithy_http_client::test_util::{capture_request, ReplayEvent, StaticReplayClient};
    use aws_smithy_types::body::SdkBody;

    fn dynamo_response(body: serde_json::Value) -> axum::http::Response<SdkBody> {
        axum::http::Response::builder()
            .status(200)
            .header("content-type", "application/x-amz-json-1.0")
            .body(SdkBody::from(body.to_string()))
            .unwrap()
    }

    fn placeholder_request() -> axum::http::Request<SdkBody> {
        axum::http::Request::builder()
            .uri("https://dynamodb.us-east-1.amazonaws.com/")
            .body(SdkBody::empty())
            .unwrap()
    }

    fn dynamo_client(http: StaticReplayClient) -> aws_sdk_dynamodb::Client {
        aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                .endpoint_url("https://dynamodb.us-east-1.amazonaws.com")
                .http_client(http)
                .build(),
        )
    }

    #[tokio::test]
    async fn touch_last_login_dynamo_contract_is_monotonic_active_and_existing_only() {
        let (http, request) = capture_request(Some(dynamo_response(serde_json::json!({}))));
        let db = aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                .endpoint_url("https://dynamodb.us-east-1.amazonaws.com")
                .http_client(http)
                .build(),
        );
        DynamoUsersStore::new(db, "users-table")
            .touch_last_login("tenant-a", "user-a", 1_234)
            .await
            .expect("activity observation update");

        let request = request.expect_request();
        let body: serde_json::Value = serde_json::from_slice(
            request
                .body()
                .bytes()
                .expect("captured Dynamo request body is in memory"),
        )
        .expect("captured Dynamo request is JSON");
        assert_eq!(body["TableName"], "users-table");
        assert_eq!(body["Key"]["user_id"]["S"], "tenant-a\u{1f}user-a");
        assert_eq!(body["UpdateExpression"], "SET last_login_at = :now");
        assert_eq!(
            body["ConditionExpression"],
            "attribute_exists(user_id) AND \
             (attribute_not_exists(#status) OR #status = :active) AND \
             (attribute_not_exists(last_login_at) OR last_login_at < :now)"
        );
        assert_eq!(body["ExpressionAttributeNames"]["#status"], "status");
        assert_eq!(body["ExpressionAttributeValues"][":active"]["S"], "active");
        assert_eq!(body["ExpressionAttributeValues"][":now"]["N"], "1234");
    }

    #[test]
    fn attribute_mutations_require_the_canonical_user_to_still_exist() {
        assert_eq!(ATTRIBUTE_USER_EXISTS_CONDITION, "attribute_exists(user_id)");
    }

    #[test]
    fn user_list_scan_is_strongly_consistent_for_namespace_migrations() {
        const {
            assert!(USER_LIST_CONSISTENT_READ);
        }
    }

    #[tokio::test]
    async fn canonical_user_get_is_strongly_consistent_for_issuance_gates() {
        let (http, request) = capture_request(Some(dynamo_response(serde_json::json!({}))));
        let db = aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                .endpoint_url("https://dynamodb.us-east-1.amazonaws.com")
                .http_client(http)
                .build(),
        );
        let store = DynamoUsersStore::new(db, "users-table");

        assert!(store
            .get_by_id("tenant-a", "user-a")
            .await
            .unwrap()
            .is_none());

        let request = request.expect_request();
        let body: serde_json::Value = serde_json::from_slice(
            request
                .body()
                .bytes()
                .expect("captured Dynamo request body is in memory"),
        )
        .expect("captured Dynamo request is JSON");
        assert_eq!(body["TableName"], "users-table");
        assert_eq!(body["Key"]["user_id"]["S"], "tenant-a\u{1f}user-a");
        assert_eq!(body["ConsistentRead"], true);
    }

    #[tokio::test]
    async fn c10_23_dynamo_user_search_continues_across_scan_pages_by_email_and_user_id() {
        let http = StaticReplayClient::new(vec![
            ReplayEvent::new(
                placeholder_request(),
                dynamo_response(serde_json::json!({
                    "Items": [{
                        "user_id": {"S": "tenant-b\u{1f}foreign-email-owner"},
                        "email": {"S": "tenant-b\u{1f}zeta@example.net"},
                        "created_at": {"N": "1"}
                    }],
                    "LastEvaluatedKey": {
                        "user_id": {"S": "tenant-b\u{1f}foreign-email-owner"}
                    }
                })),
            ),
            ReplayEvent::new(
                placeholder_request(),
                dynamo_response(serde_json::json!({
                    "Items": [{
                        "user_id": {"S": "tenant-a\u{1f}opaque-email-owner"},
                        "email": {"S": "tenant-a\u{1f}zeta@example.net"},
                        "created_at": {"N": "2"}
                    }]
                })),
            ),
            ReplayEvent::new(
                placeholder_request(),
                dynamo_response(serde_json::json!({
                    "Items": [{
                        "user_id": {"S": "tenant-b\u{1f}zz-scim-random-7f3"},
                        "email": {"S": "tenant-b\u{1f}foreign@example.net"},
                        "created_at": {"N": "1"}
                    }],
                    "LastEvaluatedKey": {
                        "user_id": {"S": "tenant-b\u{1f}zz-scim-random-7f3"}
                    }
                })),
            ),
            ReplayEvent::new(
                placeholder_request(),
                dynamo_response(serde_json::json!({
                    "Items": [{
                        "user_id": {"S": "tenant-a\u{1f}zz-scim-random-7f3"},
                        "email": {"S": "tenant-a\u{1f}other@example.net"},
                        "created_at": {"N": "3"}
                    }]
                })),
            ),
        ]);
        let store = DynamoUsersStore::new(dynamo_client(http.clone()), "users");

        let (email_matches, email_cursor) = store
            .list(
                "tenant-a",
                1,
                None,
                Some("ZETA@EXAMPLE.NET"),
                crate::ports::UserListStatusFilter::All,
            )
            .await
            .unwrap();
        assert_eq!(email_matches.len(), 1);
        assert_eq!(email_matches[0].user_id, "opaque-email-owner");
        assert_eq!(email_matches[0].email, "zeta@example.net");
        assert!(
            email_cursor.is_none(),
            "a matching page that exhausts the table must not advertise an empty next page"
        );

        assert_eq!(
            store
                .list(
                    "tenant-a",
                    1,
                    Some("!!!not-base64!!!"),
                    None,
                    crate::ports::UserListStatusFilter::All,
                )
                .await,
            Err(StoreError::Permanent("bad cursor".into()))
        );
        let (user_id_matches, _) = store
            .list(
                "tenant-a",
                1,
                None,
                Some("ZZ-SCIM-RANDOM-7F3"),
                crate::ports::UserListStatusFilter::All,
            )
            .await
            .unwrap();
        assert_eq!(user_id_matches.len(), 1);
        assert_eq!(user_id_matches[0].user_id, "zz-scim-random-7f3");
        assert_eq!(user_id_matches[0].email, "other@example.net");

        let requests: Vec<_> = http.actual_requests().collect();
        assert_eq!(requests.len(), 4);
        let bodies: Vec<serde_json::Value> = requests
            .iter()
            .map(|request| {
                serde_json::from_slice(request.body().bytes().expect("Dynamo Scan request body"))
                    .expect("Dynamo Scan request JSON")
            })
            .collect();
        for body in &bodies {
            assert_eq!(body["TableName"], "users");
            assert_eq!(body["ConsistentRead"], true);
            assert_eq!(body["Limit"], 1);
        }
        assert!(bodies[0].get("ExclusiveStartKey").is_none());
        assert_eq!(
            bodies[1]["ExclusiveStartKey"]["user_id"]["S"],
            "tenant-b\u{1f}foreign-email-owner"
        );
        assert!(bodies[2].get("ExclusiveStartKey").is_none());
        assert_eq!(
            bodies[3]["ExclusiveStartKey"]["user_id"]["S"],
            "tenant-b\u{1f}zz-scim-random-7f3"
        );
    }

    #[tokio::test]
    async fn admin_user_status_filter_continues_past_tombstoned_scan_pages() {
        let http = StaticReplayClient::new(vec![
            ReplayEvent::new(
                placeholder_request(),
                dynamo_response(serde_json::json!({
                    "Items": [{
                        "user_id": {"S": "tenant-a\u{1f}a-deleted"},
                        "email": {"S": "tenant-a\u{1f}a-deleted@example.com"},
                        "status": {"S": "tombstoned"},
                        "created_at": {"N": "1"}
                    }],
                    "LastEvaluatedKey": {
                        "user_id": {"S": "tenant-a\u{1f}a-deleted"}
                    }
                })),
            ),
            ReplayEvent::new(
                placeholder_request(),
                dynamo_response(serde_json::json!({
                    "Items": [{
                        "user_id": {"S": "tenant-b\u{1f}foreign-active"},
                        "email": {"S": "tenant-b\u{1f}foreign@example.com"},
                        "status": {"S": "active"},
                        "created_at": {"N": "2"}
                    }],
                    "LastEvaluatedKey": {
                        "user_id": {"S": "tenant-b\u{1f}foreign-active"}
                    }
                })),
            ),
            ReplayEvent::new(
                placeholder_request(),
                dynamo_response(serde_json::json!({
                    "Items": [{
                        "user_id": {"S": "tenant-a\u{1f}b-active"},
                        "email": {"S": "tenant-a\u{1f}b-active@example.com"},
                        "status": {"S": "active"},
                        "created_at": {"N": "3"}
                    }]
                })),
            ),
        ]);
        let store = DynamoUsersStore::new(dynamo_client(http.clone()), "users");

        let (users, cursor) = store
            .list(
                "tenant-a",
                1,
                None,
                None,
                crate::ports::UserListStatusFilter::NonDeleted,
            )
            .await
            .unwrap();

        assert_eq!(users.len(), 1);
        assert_eq!(users[0].user_id, "b-active");
        assert!(
            cursor.is_none(),
            "a full matching page at table exhaustion must not advertise an empty page"
        );

        let requests: Vec<_> = http.actual_requests().collect();
        assert_eq!(
            requests.len(),
            3,
            "Dynamo scan must continue across tombstoned and foreign-tenant pages"
        );
    }

    #[tokio::test]
    async fn admin_user_status_filter_cursor_preserves_unconsumed_tail_items() {
        let active_item = |user_id: &str, created_at: &str| {
            serde_json::json!({
                "user_id": {"S": format!("tenant-a\u{1f}{user_id}")},
                "email": {"S": format!("tenant-a\u{1f}{user_id}@example.com")},
                "status": {"S": "active"},
                "created_at": {"N": created_at}
            })
        };
        let http = StaticReplayClient::new(vec![
            ReplayEvent::new(
                placeholder_request(),
                dynamo_response(serde_json::json!({
                    "Items": [active_item("a-active", "1")],
                    "LastEvaluatedKey": {
                        "user_id": {"S": "tenant-a\u{1f}a-active"}
                    }
                })),
            ),
            ReplayEvent::new(
                placeholder_request(),
                dynamo_response(serde_json::json!({
                    "Items": [
                        active_item("b-active", "2"),
                        active_item("c-active", "3")
                    ]
                })),
            ),
            ReplayEvent::new(
                placeholder_request(),
                dynamo_response(serde_json::json!({
                    "Items": [active_item("c-active", "3")]
                })),
            ),
        ]);
        let store = DynamoUsersStore::new(dynamo_client(http), "users");

        let (first, cursor) = store
            .list(
                "tenant-a",
                2,
                None,
                None,
                crate::ports::UserListStatusFilter::NonDeleted,
            )
            .await
            .unwrap();
        assert_eq!(
            first
                .iter()
                .map(|user| user.user_id.as_str())
                .collect::<Vec<_>>(),
            ["a-active", "b-active"]
        );
        let cursor = cursor.expect("unconsumed items in the final scan page require a cursor");

        let (second, next) = store
            .list(
                "tenant-a",
                2,
                Some(&cursor),
                None,
                crate::ports::UserListStatusFilter::NonDeleted,
            )
            .await
            .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].user_id, "c-active");
        assert!(next.is_none());
    }

    #[tokio::test]
    async fn admin_user_status_filter_omits_cursor_for_filtered_only_tail() {
        let http = StaticReplayClient::new(vec![
            ReplayEvent::new(
                placeholder_request(),
                dynamo_response(serde_json::json!({
                    "Items": [{
                        "user_id": {"S": "tenant-a\u{1f}a-active"},
                        "email": {"S": "tenant-a\u{1f}a-active@example.com"},
                        "status": {"S": "active"},
                        "created_at": {"N": "1"}
                    }],
                    "LastEvaluatedKey": {
                        "user_id": {"S": "tenant-a\u{1f}a-active"}
                    }
                })),
            ),
            ReplayEvent::new(
                placeholder_request(),
                dynamo_response(serde_json::json!({
                    "Items": [{
                        "user_id": {"S": "tenant-a\u{1f}b-deleted"},
                        "email": {"S": "tenant-a\u{1f}b-deleted@example.com"},
                        "status": {"S": "tombstoned"},
                        "created_at": {"N": "2"}
                    }],
                    "LastEvaluatedKey": {
                        "user_id": {"S": "tenant-a\u{1f}b-deleted"}
                    }
                })),
            ),
            ReplayEvent::new(
                placeholder_request(),
                dynamo_response(serde_json::json!({
                    "Items": [{
                        "user_id": {"S": "tenant-b\u{1f}foreign-active"},
                        "email": {"S": "tenant-b\u{1f}foreign@example.com"},
                        "status": {"S": "active"},
                        "created_at": {"N": "3"}
                    }]
                })),
            ),
        ]);
        let store = DynamoUsersStore::new(dynamo_client(http.clone()), "users");

        let (users, cursor) = store
            .list(
                "tenant-a",
                1,
                None,
                None,
                crate::ports::UserListStatusFilter::NonDeleted,
            )
            .await
            .unwrap();

        assert_eq!(users.len(), 1);
        assert_eq!(users[0].user_id, "a-active");
        assert!(
            cursor.is_none(),
            "a tail containing only filtered records must not create an empty next page"
        );
        assert_eq!(
            http.actual_requests().count(),
            3,
            "the adapter must inspect the filtered tail before declaring table exhaustion"
        );
    }

    #[test]
    fn attribute_replay_condition_fences_the_exact_user_snapshot() {
        let store = DynamoUsersStore::new(
            aws_sdk_dynamodb::Client::from_conf(
                aws_sdk_dynamodb::Config::builder()
                    .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
                    .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                    .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                    .build(),
            ),
            "users",
        );
        let attributes = crate::ports::NamespaceAttrs {
            revision: 4,
            kv: std::collections::BTreeMap::from([("role".into(), "admin".into())]),
            federation_owners: std::collections::BTreeMap::new(),
        };
        let item = store
            .attribute_replay_condition(
                "tenant\u{1f}user-1",
                "https://resource.example.com",
                7,
                &attributes,
            )
            .unwrap();
        let condition = item.condition_check().unwrap();
        assert_eq!(condition.table_name(), "users");
        assert_eq!(
            condition.key().get("user_id"),
            Some(&AttributeValue::S("tenant\u{1f}user-1".into()))
        );
        let expression = condition.condition_expression();
        assert!(expression.contains("attribute_exists(user_id)"));
        assert!(expression.contains("#generation = :expected_generation"));
        assert!(expression.contains("#attrs.#namespace = :namespace_value"));
        assert_eq!(
            condition
                .expression_attribute_names()
                .unwrap()
                .get("#namespace")
                .map(String::as_str),
            Some("https://resource.example.com")
        );
        assert_eq!(
            condition
                .expression_attribute_values()
                .unwrap()
                .get(":expected_generation"),
            Some(&AttributeValue::N("7".into()))
        );
        assert_eq!(
            condition
                .expression_attribute_values()
                .unwrap()
                .get(":namespace_value"),
            Some(&DynamoUsersStore::namespace_attrs_to_av(&attributes))
        );
    }

    #[test]
    fn repeated_disable_does_not_bind_unused_active_expression_value() {
        let (active_condition, active_value) =
            disable_status_condition(crate::ports::UserStatus::Active);
        assert!(active_condition.contains(":active"));
        assert!(active_value);

        let (disabled_condition, active_value) =
            disable_status_condition(crate::ports::UserStatus::Disabled);
        assert_eq!(disabled_condition, "#status = :disabled");
        assert!(!active_value);
    }

    #[test]
    fn internal_scim_items_never_decode_as_canonical_users() {
        for record_type in [
            AttributeValue::S(SCIM_ALIAS_RECORD_TYPE.to_string()),
            AttributeValue::S(SCIM_CREATE_RECORD_TYPE.to_string()),
            AttributeValue::Bool(true),
        ] {
            let item = HashMap::from([
                (
                    "user_id".to_string(),
                    AttributeValue::S("internal".to_string()),
                ),
                ("created_at".to_string(), AttributeValue::N("1".to_string())),
                ("record_type".to_string(), record_type),
            ]);
            assert!(DynamoUsersStore::to_record(&item).is_none());
        }
    }

    #[test]
    fn user_attributes_generation_defaults_to_zero_and_round_trips() {
        let mut item = HashMap::from([
            (
                "user_id".to_string(),
                AttributeValue::S("user-1".to_string()),
            ),
            ("created_at".to_string(), AttributeValue::N("1".to_string())),
        ]);
        assert_eq!(
            DynamoUsersStore::to_record(&item)
                .unwrap()
                .attributes_generation,
            0
        );

        item.insert(
            "attributes_generation".to_string(),
            AttributeValue::N("7".to_string()),
        );
        assert_eq!(
            DynamoUsersStore::to_record(&item)
                .unwrap()
                .attributes_generation,
            7
        );
    }

    #[test]
    fn federation_attribute_owners_default_empty_and_round_trip() {
        let legacy = AttributeValue::M(HashMap::from([
            ("rev".to_string(), AttributeValue::N("2".to_string())),
            (
                "kv".to_string(),
                AttributeValue::M(HashMap::from([(
                    "role".to_string(),
                    AttributeValue::S("admin".to_string()),
                )])),
            ),
        ]));
        let legacy_item = HashMap::from([(
            "attributes".to_string(),
            AttributeValue::M(HashMap::from([(
                "https://resource.example.com".to_string(),
                legacy,
            )])),
        )]);
        let decoded = DynamoUsersStore::attributes_from_item(&legacy_item).unwrap();
        assert!(decoded["https://resource.example.com"]
            .federation_owners
            .is_empty());

        let namespace = crate::ports::NamespaceAttrs {
            revision: 3,
            kv: std::collections::BTreeMap::from([("role".into(), "admin".into())]),
            federation_owners: std::collections::BTreeMap::from([(
                "role".into(),
                crate::ports::FederatedAttributeOwner {
                    upstream_idp_id: "corp".into(),
                    upstream_issuer: "https://idp.example.com".into(),
                    mapping_id: "fm_role".into(),
                    mapping_revision: 7,
                },
            )]),
        };
        let item = HashMap::from([(
            "attributes".to_string(),
            DynamoUsersStore::attributes_to_av(&std::collections::BTreeMap::from([(
                "https://resource.example.com".into(),
                namespace.clone(),
            )])),
        )]);
        let decoded = DynamoUsersStore::attributes_from_item(&item).unwrap();
        assert_eq!(decoded["https://resource.example.com"], namespace);
    }

    #[test]
    fn federation_reconciliation_update_fences_active_user_generation() {
        let store = DynamoUsersStore::new(
            aws_sdk_dynamodb::Client::from_conf(
                aws_sdk_dynamodb::Config::builder()
                    .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
                    .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                    .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                    .build(),
            ),
            "users",
        );
        let mut current = DynamoUsersStore::to_record(&HashMap::from([
            (
                "user_id".to_string(),
                AttributeValue::S("tenant\u{1f}user-1".to_string()),
            ),
            ("created_at".to_string(), AttributeValue::N("1".to_string())),
            (
                "attributes_generation".to_string(),
                AttributeValue::N("3".to_string()),
            ),
        ]))
        .unwrap();
        current.attributes.insert(
            "https://resource.example.com".into(),
            crate::ports::NamespaceAttrs {
                revision: 1,
                kv: std::collections::BTreeMap::from([("note".into(), "local".into())]),
                federation_owners: std::collections::BTreeMap::new(),
            },
        );
        let mut next = current.clone();
        next.attributes_generation = 4;
        next.attributes
            .get_mut("https://resource.example.com")
            .unwrap()
            .revision = 2;

        let item = store
            .federation_reconciliation_user_item(
                "tenant",
                &current,
                &next,
                true,
                "flow-1",
                "fingerprint-1",
            )
            .unwrap();
        let update = item.update().unwrap();
        assert_eq!(update.table_name(), "users");
        let condition = update.condition_expression().unwrap();
        assert!(condition.contains("attribute_exists(user_id)"));
        assert!(condition.contains("#status = :active"));
        assert!(condition.contains("#generation = :expected_generation"));
        assert!(condition.contains("#attrs = :expected_attributes"));
        assert_eq!(
            update
                .expression_attribute_values()
                .unwrap()
                .get(":next_generation"),
            Some(&AttributeValue::N("4".into()))
        );
    }

    #[test]
    fn federation_owner_purge_update_fences_exact_non_tombstoned_user_snapshot() {
        let store = DynamoUsersStore::new(
            aws_sdk_dynamodb::Client::from_conf(
                aws_sdk_dynamodb::Config::builder()
                    .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
                    .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                    .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                    .build(),
            ),
            "users",
        );
        let owner = crate::ports::FederatedAttributeOwner {
            upstream_idp_id: "okta".into(),
            upstream_issuer: "https://idp.example.com".into(),
            mapping_id: "fm_role".into(),
            mapping_revision: 2,
        };
        let mut current = DynamoUsersStore::to_record(&HashMap::from([
            (
                "user_id".to_string(),
                AttributeValue::S("tenant\u{1f}user-1".to_string()),
            ),
            ("created_at".to_string(), AttributeValue::N("1".to_string())),
            (
                "attributes_generation".to_string(),
                AttributeValue::N("3".to_string()),
            ),
        ]))
        .unwrap();
        current.attributes.insert(
            "https://resource.example.com".into(),
            crate::ports::NamespaceAttrs {
                revision: 4,
                kv: std::collections::BTreeMap::from([("role".into(), "admin".into())]),
                federation_owners: std::collections::BTreeMap::from([(
                    "role".into(),
                    owner.clone(),
                )]),
            },
        );
        let outcome = crate::federation_attributes::plan_federated_attribute_owner_purge(
            &current,
            "https://resource.example.com",
            "role",
            4,
            &owner,
        )
        .unwrap();
        let crate::federation_attributes::FederationAttributeOwnerPurgeOutcome::Purged {
            user: next,
            ..
        } = outcome
        else {
            panic!("stale owner must produce a purge plan");
        };

        let item = store
            .federation_owner_purge_user_item("tenant", &current, &next)
            .unwrap();
        let update = item.update().unwrap();
        assert_eq!(update.table_name(), "users");
        let condition = update.condition_expression().unwrap();
        assert!(condition.contains("attribute_exists(user_id)"));
        assert!(condition.contains("#status <> :tombstoned"));
        assert!(condition.contains("#generation = :expected_generation"));
        assert!(condition.contains("#attrs = :expected_attributes"));
        assert_eq!(
            update
                .expression_attribute_values()
                .unwrap()
                .get(":next_generation"),
            Some(&AttributeValue::N("4".into()))
        );
        assert_eq!(
            update
                .expression_attribute_values()
                .unwrap()
                .get(":next_attributes"),
            Some(&DynamoUsersStore::attributes_to_av(&next.attributes))
        );
    }

    #[test]
    fn scim_tenant_index_key_is_non_empty_and_tenant_scoped() {
        assert_eq!(DynamoUsersStore::scim_tenant_key(""), "scim-users");
        assert_eq!(
            DynamoUsersStore::scim_tenant_key("t1"),
            "t1\u{1f}scim-users"
        );
        assert_ne!(
            DynamoUsersStore::scim_tenant_key("t1"),
            DynamoUsersStore::scim_tenant_key("t2")
        );
    }

    #[test]
    fn governed_identity_delete_is_idempotent_and_exact() {
        let store = DynamoUsersStore::new(
            aws_sdk_dynamodb::Client::from_conf(
                aws_sdk_dynamodb::Config::builder()
                    .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
                    .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                    .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                    .build(),
            ),
            "users",
        );
        let writes = store
            .governed_identity_delete(
                "tenant-1",
                "user-1",
                7,
                Some("external-1"),
                Some("user@example.com"),
            )
            .unwrap();
        assert_eq!(writes.len(), 4);
        let canonical = writes[0].delete().unwrap();
        assert!(canonical
            .condition_expression()
            .unwrap()
            .contains("attribute_not_exists(user_id)"));
        assert!(canonical
            .condition_expression()
            .unwrap()
            .contains("credential_epoch = :epoch"));
        for write in &writes[1..] {
            let delete = write.delete().unwrap();
            assert!(delete
                .condition_expression()
                .unwrap()
                .contains("canonical_user_id = :canonical"));
        }
    }

    #[test]
    fn governed_erasure_update_fences_legacy_zero_epoch_tombstone_exactly() {
        let store = DynamoUsersStore::new(
            aws_sdk_dynamodb::Client::from_conf(
                aws_sdk_dynamodb::Config::builder()
                    .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
                    .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                    .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                    .build(),
            ),
            "users",
        );
        let update = store
            .erasure_update(
                "tenant-1",
                "user-1",
                1,
                100,
                crate::governance::UserErasureFenceTransition::LegacyZeroEpochTombstone,
            )
            .unwrap()
            .update()
            .unwrap()
            .clone();
        assert_eq!(
            update.condition_expression(),
            Some(
                "attribute_exists(user_id) AND #status = :tomb AND \
                 (attribute_not_exists(credential_epoch) OR credential_epoch = :expected)"
            )
        );
        let values = update.expression_attribute_values().unwrap();
        assert_eq!(values[":expected"].as_n().unwrap(), "0");
        assert_eq!(values[":target"].as_n().unwrap(), "1");
        assert_eq!(values[":tomb"].as_s().unwrap(), "tombstoned");
        assert_eq!(values[":true"].as_bool().unwrap(), &true);
    }

    #[test]
    fn tenant_identity_inventory_counts_internal_rows_and_rejects_cross_tenant_owners() {
        let mut inventory = GovernanceTenantIdentityInventory::default();
        let canonical = HashMap::from([
            (
                "user_id".into(),
                AttributeValue::S(tpk("tenant-1", "user-1")),
            ),
            ("created_at".into(), AttributeValue::N("1".into())),
            ("status".into(), AttributeValue::S("active".into())),
        ]);
        DynamoUsersStore::classify_governance_tenant_identity_row(
            "tenant-1",
            &canonical,
            &mut inventory,
        )
        .unwrap();
        let alias =
            DynamoUsersStore::scim_alias_item("tenant-1", SCIM_ALIAS_USERNAME, "alice", "user-1");
        DynamoUsersStore::classify_governance_tenant_identity_row(
            "tenant-1",
            &alias,
            &mut inventory,
        )
        .unwrap();
        let claim = DynamoUsersStore::scim_create_claim_item(
            "tenant-1",
            "external-1",
            "alice",
            "user-1",
            None,
        );
        DynamoUsersStore::classify_governance_tenant_identity_row(
            "tenant-1",
            &claim,
            &mut inventory,
        )
        .unwrap();
        let other_tenant =
            DynamoUsersStore::scim_alias_item("tenant-2", SCIM_ALIAS_USERNAME, "alice", "user-2");
        DynamoUsersStore::classify_governance_tenant_identity_row(
            "tenant-1",
            &other_tenant,
            &mut inventory,
        )
        .unwrap();
        assert_eq!(
            inventory,
            GovernanceTenantIdentityInventory {
                canonical_rows: 1,
                scim_alias_rows: 1,
                scim_create_claim_rows: 1,
            }
        );

        let mut cross_tenant = alias;
        cross_tenant.insert(
            "canonical_user_id".into(),
            AttributeValue::S(tpk("tenant-2", "user-2")),
        );
        assert!(DynamoUsersStore::classify_governance_tenant_identity_row(
            "tenant-1",
            &cross_tenant,
            &mut GovernanceTenantIdentityInventory::default(),
        )
        .is_err());
    }

    #[test]
    fn governance_first_user_skips_internal_and_other_tenant_rows() {
        let alias =
            DynamoUsersStore::scim_alias_item("tenant-1", SCIM_ALIAS_USERNAME, "alice", "user-1");
        assert!(
            DynamoUsersStore::governance_canonical_from_tenant_row("tenant-1", &alias)
                .unwrap()
                .is_none()
        );

        let other_tenant = HashMap::from([
            (
                "user_id".into(),
                AttributeValue::S(tpk("tenant-2", "user-2")),
            ),
            ("created_at".into(), AttributeValue::N("1".into())),
        ]);
        assert!(
            DynamoUsersStore::governance_canonical_from_tenant_row("tenant-1", &other_tenant)
                .unwrap()
                .is_none()
        );

        let canonical = HashMap::from([
            (
                "user_id".into(),
                AttributeValue::S(tpk("tenant-1", "user-1")),
            ),
            ("created_at".into(), AttributeValue::N("1".into())),
            ("status".into(), AttributeValue::S("active".into())),
        ]);
        let record = DynamoUsersStore::governance_canonical_from_tenant_row("tenant-1", &canonical)
            .unwrap()
            .unwrap();
        assert_eq!(record.user_id, "user-1");
    }
}
