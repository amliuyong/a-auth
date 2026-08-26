use super::*;

const SCIM_GROUP_RECORD_TYPE: &str = "scim_group";
const SCIM_GROUP_ALIAS_RECORD_TYPE: &str = "scim_group_alias";
const SCIM_GROUP_MEMBER_RECORD_TYPE: &str = "scim_group_member";
const SCIM_GROUP_SK: &str = "GROUP";
const SCIM_GROUP_ALIAS_SK: &str = "ALIAS";
const GOVERNANCE_TARGET_WRITE_BATCH: usize = 95;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GovernanceScimMembershipInventory {
    pub membership_rows: usize,
    pub confirmed_live_memberships: usize,
    pub role_index_rows: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GovernanceScimTenantInventory {
    pub group_rows: usize,
    pub alias_rows: usize,
    pub membership_rows: usize,
    pub live_groups: usize,
    pub role_index_rows: usize,
}

#[derive(Clone)]
struct DynamoScimGroupState {
    record: crate::ports::ScimGroupRecord,
    role: Option<crate::ports::TenantRole>,
    role_updated_at: Option<i64>,
    deleted: bool,
}

#[derive(Clone)]
pub struct DynamoScimGroupsStore {
    db: aws_sdk_dynamodb::Client,
    table: String,
    tenant_kind_index: String,
}

impl DynamoScimGroupsStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        Self {
            db,
            table: table.into(),
            tenant_kind_index: "tenant_kind-index".to_string(),
        }
    }

    fn digest(value: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
    }

    fn group_pk(tenant: &str, group_id: &str) -> String {
        tpk(tenant, &format!("scim-group:{group_id}"))
    }

    fn alias_pk(tenant: &str, external_id: &str) -> String {
        tpk(
            tenant,
            &format!("scim-group-external:{}", Self::digest(external_id)),
        )
    }

    fn member_pk(tenant: &str, user_id: &str) -> String {
        tpk(
            tenant,
            &format!("scim-group-member:{}", Self::digest(user_id)),
        )
    }

    fn member_sk(group_id: &str) -> String {
        format!("GROUP#{group_id}")
    }

    fn tenant_kind(tenant: &str) -> String {
        tpk(tenant, "scim-groups")
    }

    fn role_str(role: crate::ports::TenantRole) -> &'static str {
        match role {
            crate::ports::TenantRole::Member => "member",
            crate::ports::TenantRole::Auditor => "auditor",
            crate::ports::TenantRole::Admin => "admin",
            crate::ports::TenantRole::Owner => "owner",
        }
    }

    fn parse_role(value: Option<&AttributeValue>) -> Option<crate::ports::TenantRole> {
        match value
            .and_then(|value| value.as_s().ok())
            .map(String::as_str)
        {
            Some("member") => Some(crate::ports::TenantRole::Member),
            Some("auditor") => Some(crate::ports::TenantRole::Auditor),
            Some("admin") => Some(crate::ports::TenantRole::Admin),
            Some("owner") => Some(crate::ports::TenantRole::Owner),
            _ => None,
        }
    }

    fn members_attr(members: &[String]) -> AttributeValue {
        AttributeValue::L(
            members
                .iter()
                .map(|member| AttributeValue::S(member.clone()))
                .collect(),
        )
    }

    fn to_state(item: &HashMap<String, AttributeValue>) -> Option<DynamoScimGroupState> {
        if s(item.get("record_type")).as_deref() != Some(SCIM_GROUP_RECORD_TYPE) {
            return None;
        }
        Some(DynamoScimGroupState {
            record: crate::ports::ScimGroupRecord {
                group_id: s(item.get("group_id"))?,
                external_id: s(item.get("external_id"))?,
                display_name: s(item.get("display_name"))?,
                members: ss(item.get("members")),
                version: n_u64(item.get("version"))?,
                created_at: n_i64(item.get("created_at"))?,
                updated_at: n_i64(item.get("updated_at"))?,
            },
            role: Self::parse_role(item.get("tenant_role")),
            role_updated_at: n_i64(item.get("role_updated_at")),
            deleted: item
                .get("deleted")
                .and_then(|value| value.as_bool().ok())
                .copied()
                .unwrap_or(false),
        })
    }

    fn group_item(
        tenant: &str,
        record: &crate::ports::ScimGroupRecord,
    ) -> HashMap<String, AttributeValue> {
        HashMap::from([
            (
                "pk".to_string(),
                AttributeValue::S(Self::group_pk(tenant, &record.group_id)),
            ),
            (
                "sk".to_string(),
                AttributeValue::S(SCIM_GROUP_SK.to_string()),
            ),
            (
                "record_type".to_string(),
                AttributeValue::S(SCIM_GROUP_RECORD_TYPE.to_string()),
            ),
            (
                "group_id".to_string(),
                AttributeValue::S(record.group_id.clone()),
            ),
            (
                "external_id".to_string(),
                AttributeValue::S(record.external_id.clone()),
            ),
            (
                "display_name".to_string(),
                AttributeValue::S(record.display_name.clone()),
            ),
            ("members".to_string(), Self::members_attr(&record.members)),
            (
                "version".to_string(),
                AttributeValue::N(record.version.to_string()),
            ),
            (
                "created_at".to_string(),
                AttributeValue::N(record.created_at.to_string()),
            ),
            (
                "updated_at".to_string(),
                AttributeValue::N(record.updated_at.to_string()),
            ),
            ("deleted".to_string(), AttributeValue::Bool(false)),
            (
                "tenant_kind".to_string(),
                AttributeValue::S(Self::tenant_kind(tenant)),
            ),
        ])
    }

    fn alias_item(
        tenant: &str,
        external_id: &str,
        group_id: &str,
    ) -> HashMap<String, AttributeValue> {
        HashMap::from([
            (
                "pk".to_string(),
                AttributeValue::S(Self::alias_pk(tenant, external_id)),
            ),
            (
                "sk".to_string(),
                AttributeValue::S(SCIM_GROUP_ALIAS_SK.to_string()),
            ),
            (
                "record_type".to_string(),
                AttributeValue::S(SCIM_GROUP_ALIAS_RECORD_TYPE.to_string()),
            ),
            (
                "external_id".to_string(),
                AttributeValue::S(external_id.to_string()),
            ),
            (
                "group_id".to_string(),
                AttributeValue::S(group_id.to_string()),
            ),
        ])
    }

    fn member_item(
        tenant: &str,
        user_id: &str,
        group: &DynamoScimGroupState,
    ) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::from([
            (
                "pk".to_string(),
                AttributeValue::S(Self::member_pk(tenant, user_id)),
            ),
            (
                "sk".to_string(),
                AttributeValue::S(Self::member_sk(&group.record.group_id)),
            ),
            (
                "record_type".to_string(),
                AttributeValue::S(SCIM_GROUP_MEMBER_RECORD_TYPE.to_string()),
            ),
            (
                "user_id".to_string(),
                AttributeValue::S(user_id.to_string()),
            ),
            (
                "group_id".to_string(),
                AttributeValue::S(group.record.group_id.clone()),
            ),
            (
                "external_id".to_string(),
                AttributeValue::S(group.record.external_id.clone()),
            ),
        ]);
        if let Some(role) = group.role {
            item.insert(
                "tenant_role".to_string(),
                AttributeValue::S(Self::role_str(role).to_string()),
            );
        }
        if let Some(updated_at) = group.role_updated_at {
            item.insert(
                "role_updated_at".to_string(),
                AttributeValue::N(updated_at.to_string()),
            );
        }
        item
    }

    async fn get_state(
        &self,
        tenant: &str,
        group_id: &str,
    ) -> Result<Option<DynamoScimGroupState>, StoreError> {
        let response = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("pk", AttributeValue::S(Self::group_pk(tenant, group_id)))
            .key("sk", AttributeValue::S(SCIM_GROUP_SK.to_string()))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(response.item().and_then(Self::to_state))
    }

    async fn group_id_for_external(
        &self,
        tenant: &str,
        external_id: &str,
    ) -> Result<Option<String>, StoreError> {
        let response = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("pk", AttributeValue::S(Self::alias_pk(tenant, external_id)))
            .key("sk", AttributeValue::S(SCIM_GROUP_ALIAS_SK.to_string()))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        let Some(item) = response.item() else {
            return Ok(None);
        };
        if s(item.get("record_type")).as_deref() != Some(SCIM_GROUP_ALIAS_RECORD_TYPE)
            || s(item.get("external_id")).as_deref() != Some(external_id)
        {
            return Err(StoreError::Permanent(
                "SCIM Group externalId claim is malformed or collided".into(),
            ));
        }
        Ok(s(item.get("group_id")))
    }

    async fn send_transaction(
        &self,
        items: Vec<aws_sdk_dynamodb::types::TransactWriteItem>,
    ) -> Result<(), StoreError> {
        let mut request = self.db.transact_write_items();
        for item in items {
            request = request.transact_items(item);
        }
        request.send().await.map(|_| ()).map_err(|error| {
            classify_transact_write_error(&error)
                .map(|(_, classified)| classified)
                .unwrap_or_else(|| ddb_err(error))
        })
    }

    fn mapping(state: &DynamoScimGroupState) -> Option<crate::ports::ScimGroupRoleMapping> {
        Some(crate::ports::ScimGroupRoleMapping {
            group_id: state.record.group_id.clone(),
            external_id: state.record.external_id.clone(),
            role: state.role?,
            updated_at: state.role_updated_at?,
        })
    }
}

impl crate::ports::ScimGroupsStore for DynamoScimGroupsStore {
    async fn create(
        &self,
        tenant: &str,
        input: crate::ports::ScimGroupCreateInput,
    ) -> Result<crate::ports::ScimGroupCreateOutcome, StoreError> {
        use crate::ports::{ScimGroupCreateOutcome, ScimGroupRecord};
        use aws_sdk_dynamodb::types::{Put, TransactWriteItem};

        let members = crate::ports::canonical_scim_group_members(input.members);
        if members.len() > crate::ports::SCIM_GROUP_MAX_MEMBERS {
            return Err(StoreError::Permanent(
                "SCIM Group exceeds the supported member limit".into(),
            ));
        }
        let record = ScimGroupRecord {
            group_id: input.group_id,
            external_id: input.external_id,
            display_name: input.display_name,
            members,
            version: 1,
            created_at: input.now,
            updated_at: input.now,
        };
        let state = DynamoScimGroupState {
            record: record.clone(),
            role: None,
            role_updated_at: None,
            deleted: false,
        };
        let canonical = Put::builder()
            .table_name(&self.table)
            .set_item(Some(Self::group_item(tenant, &record)))
            .condition_expression("attribute_not_exists(pk)")
            .build()
            .map_err(|error| StoreError::Permanent(format!("build SCIM Group put: {error}")))?;
        let alias = Put::builder()
            .table_name(&self.table)
            .set_item(Some(Self::alias_item(
                tenant,
                &record.external_id,
                &record.group_id,
            )))
            .condition_expression("attribute_not_exists(pk)")
            .build()
            .map_err(|error| StoreError::Permanent(format!("build Group alias put: {error}")))?;
        let mut items = vec![
            TransactWriteItem::builder().put(canonical).build(),
            TransactWriteItem::builder().put(alias).build(),
        ];
        for member in &record.members {
            let put = Put::builder()
                .table_name(&self.table)
                .set_item(Some(Self::member_item(tenant, member, &state)))
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!("build Group member put: {error}"))
                })?;
            items.push(TransactWriteItem::builder().put(put).build());
        }
        match self.send_transaction(items).await {
            Ok(()) => Ok(ScimGroupCreateOutcome::Created(record)),
            Err(error) => {
                if let Some(group_id) = self
                    .group_id_for_external(tenant, &state.record.external_id)
                    .await?
                {
                    if let Some(existing) = self.get_state(tenant, &group_id).await? {
                        if !existing.deleted {
                            return Ok(ScimGroupCreateOutcome::Existing(existing.record));
                        }
                    }
                }
                Err(error)
            }
        }
    }

    async fn get(
        &self,
        tenant: &str,
        group_id: &str,
    ) -> Result<Option<crate::ports::ScimGroupRecord>, StoreError> {
        Ok(self
            .get_state(tenant, group_id)
            .await?
            .filter(|state| !state.deleted)
            .map(|state| state.record))
    }

    async fn get_by_external_id(
        &self,
        tenant: &str,
        external_id: &str,
    ) -> Result<Option<crate::ports::ScimGroupRecord>, StoreError> {
        let Some(group_id) = self.group_id_for_external(tenant, external_id).await? else {
            return Ok(None);
        };
        self.get(tenant, &group_id).await
    }

    async fn list(
        &self,
        tenant: &str,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<crate::ports::ScimGroupRecord>, usize), StoreError> {
        let mut records = Vec::new();
        let mut last_key = None;
        loop {
            let mut query = self
                .db
                .query()
                .table_name(&self.table)
                .index_name(&self.tenant_kind_index)
                .key_condition_expression("tenant_kind = :tenant")
                .expression_attribute_values(
                    ":tenant",
                    AttributeValue::S(Self::tenant_kind(tenant)),
                );
            if let Some(key) = last_key {
                query = query.set_exclusive_start_key(Some(key));
            }
            let response = query.send().await.map_err(ddb_err)?;
            records.extend(
                response
                    .items()
                    .iter()
                    .filter_map(Self::to_state)
                    .filter(|state| !state.deleted)
                    .map(|state| state.record),
            );
            match response.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        records.sort_by(|left, right| left.group_id.cmp(&right.group_id));
        let total = records.len();
        Ok((
            records.into_iter().skip(offset).take(limit).collect(),
            total,
        ))
    }

    async fn mutate(
        &self,
        tenant: &str,
        group_id: &str,
        mutation: crate::ports::ScimGroupMutation,
    ) -> Result<crate::ports::ScimGroupMutationOutcome, StoreError> {
        use crate::ports::ScimGroupMutationOutcome;
        use aws_sdk_dynamodb::types::{Delete, Put, TransactWriteItem, Update};

        for _ in 0..5 {
            let Some(current) = self.get_state(tenant, group_id).await? else {
                return Ok(ScimGroupMutationOutcome::NotFound);
            };
            if current.deleted {
                return Ok(ScimGroupMutationOutcome::NotFound);
            }
            let (mut next_record, now) =
                crate::ports::apply_scim_group_mutation(&current.record, mutation.clone());
            if next_record.members.len() > crate::ports::SCIM_GROUP_MAX_MEMBERS {
                return Ok(ScimGroupMutationOutcome::TooManyMembers);
            }
            if next_record.display_name == current.record.display_name
                && next_record.members == current.record.members
            {
                return Ok(ScimGroupMutationOutcome::Updated(current.record));
            }
            next_record.version = current
                .record
                .version
                .checked_add(1)
                .ok_or_else(|| StoreError::Permanent("SCIM Group version exhausted".into()))?;
            next_record.updated_at = now;
            let next = DynamoScimGroupState {
                record: next_record.clone(),
                role: current.role,
                role_updated_at: current.role_updated_at,
                deleted: false,
            };
            let update = Update::builder()
                .table_name(&self.table)
                .key(
                    "pk",
                    AttributeValue::S(Self::group_pk(tenant, group_id)),
                )
                .key("sk", AttributeValue::S(SCIM_GROUP_SK.to_string()))
                .update_expression(
                    "SET display_name = :display, #members = :members, #version = :next, updated_at = :now",
                )
                .condition_expression(
                    "#version = :expected AND (attribute_not_exists(deleted) OR deleted = :false)",
                )
                .expression_attribute_names("#members", "members")
                .expression_attribute_names("#version", "version")
                .expression_attribute_values(
                    ":display",
                    AttributeValue::S(next.record.display_name.clone()),
                )
                .expression_attribute_values(":members", Self::members_attr(&next.record.members))
                .expression_attribute_values(
                    ":next",
                    AttributeValue::N(next.record.version.to_string()),
                )
                .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
                .expression_attribute_values(
                    ":expected",
                    AttributeValue::N(current.record.version.to_string()),
                )
                .expression_attribute_values(":false", AttributeValue::Bool(false))
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!("build Group mutation update: {error}"))
                })?;
            let old: std::collections::HashSet<_> =
                current.record.members.iter().cloned().collect();
            let new: std::collections::HashSet<_> = next.record.members.iter().cloned().collect();
            let mut items = vec![TransactWriteItem::builder().update(update).build()];
            for member in old.difference(&new) {
                let delete = Delete::builder()
                    .table_name(&self.table)
                    .key("pk", AttributeValue::S(Self::member_pk(tenant, member)))
                    .key(
                        "sk",
                        AttributeValue::S(Self::member_sk(&next.record.group_id)),
                    )
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!("build Group member delete: {error}"))
                    })?;
                items.push(TransactWriteItem::builder().delete(delete).build());
            }
            for member in new.difference(&old) {
                let put = Put::builder()
                    .table_name(&self.table)
                    .set_item(Some(Self::member_item(tenant, member, &next)))
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!("build Group member put: {error}"))
                    })?;
                items.push(TransactWriteItem::builder().put(put).build());
            }
            match self.send_transaction(items).await {
                Ok(()) => return Ok(ScimGroupMutationOutcome::Updated(next.record)),
                Err(StoreError::Transient(_)) => continue,
                Err(error) => return Err(error),
            }
        }
        Err(StoreError::Transient(
            "SCIM Group mutation did not converge".into(),
        ))
    }

    async fn delete(
        &self,
        tenant: &str,
        group_id: &str,
        now: i64,
    ) -> Result<crate::ports::ScimGroupDeleteOutcome, StoreError> {
        use crate::ports::ScimGroupDeleteOutcome;
        use aws_sdk_dynamodb::types::{Delete, TransactWriteItem, Update};

        for _ in 0..5 {
            let Some(current) = self.get_state(tenant, group_id).await? else {
                return Ok(ScimGroupDeleteOutcome::NotFound);
            };
            if current.deleted {
                return Ok(ScimGroupDeleteOutcome::Deleted);
            }
            let next_version = current
                .record
                .version
                .checked_add(1)
                .ok_or_else(|| StoreError::Permanent("SCIM Group version exhausted".into()))?;
            let update = Update::builder()
                .table_name(&self.table)
                .key(
                    "pk",
                    AttributeValue::S(Self::group_pk(tenant, group_id)),
                )
                .key("sk", AttributeValue::S(SCIM_GROUP_SK.to_string()))
                .update_expression(
                    "SET deleted = :true, #version = :next, updated_at = :now, #members = :empty REMOVE tenant_kind, tenant_role, role_updated_at",
                )
                .condition_expression(
                    "#version = :expected AND (attribute_not_exists(deleted) OR deleted = :false)",
                )
                .expression_attribute_names("#members", "members")
                .expression_attribute_names("#version", "version")
                .expression_attribute_values(":true", AttributeValue::Bool(true))
                .expression_attribute_values(":false", AttributeValue::Bool(false))
                .expression_attribute_values(
                    ":next",
                    AttributeValue::N(next_version.to_string()),
                )
                .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
                .expression_attribute_values(":empty", AttributeValue::L(Vec::new()))
                .expression_attribute_values(
                    ":expected",
                    AttributeValue::N(current.record.version.to_string()),
                )
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!("build Group tombstone update: {error}"))
                })?;
            let alias = Delete::builder()
                .table_name(&self.table)
                .key(
                    "pk",
                    AttributeValue::S(Self::alias_pk(tenant, &current.record.external_id)),
                )
                .key("sk", AttributeValue::S(SCIM_GROUP_ALIAS_SK.to_string()))
                .condition_expression("group_id = :group_id")
                .expression_attribute_values(":group_id", AttributeValue::S(group_id.to_string()))
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!("build Group alias delete: {error}"))
                })?;
            let mut items = vec![
                TransactWriteItem::builder().update(update).build(),
                TransactWriteItem::builder().delete(alias).build(),
            ];
            for member in &current.record.members {
                let delete = Delete::builder()
                    .table_name(&self.table)
                    .key("pk", AttributeValue::S(Self::member_pk(tenant, member)))
                    .key("sk", AttributeValue::S(Self::member_sk(group_id)))
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!("build Group member delete: {error}"))
                    })?;
                items.push(TransactWriteItem::builder().delete(delete).build());
            }
            match self.send_transaction(items).await {
                Ok(()) => return Ok(ScimGroupDeleteOutcome::Deleted),
                Err(StoreError::Transient(_)) => continue,
                Err(error) => return Err(error),
            }
        }
        Err(StoreError::Transient(
            "SCIM Group delete did not converge".into(),
        ))
    }

    async fn set_role_mapping(
        &self,
        tenant: &str,
        external_id: &str,
        role: Option<crate::ports::TenantRole>,
        now: i64,
    ) -> Result<crate::ports::ScimRoleMappingOutcome, StoreError> {
        use crate::ports::ScimRoleMappingOutcome;
        use aws_sdk_dynamodb::types::{TransactWriteItem, Update};

        for _ in 0..5 {
            let Some(group_id) = self.group_id_for_external(tenant, external_id).await? else {
                return Ok(ScimRoleMappingOutcome::GroupNotFound);
            };
            let Some(current) = self.get_state(tenant, &group_id).await? else {
                return Err(StoreError::Permanent(
                    "SCIM Group externalId references a missing canonical Group".into(),
                ));
            };
            if current.deleted {
                return Ok(ScimRoleMappingOutcome::GroupNotFound);
            }
            if current.role == role {
                return match role {
                    Some(_) => Ok(ScimRoleMappingOutcome::Updated(
                        Self::mapping(&current).ok_or_else(|| {
                            StoreError::Permanent(
                                "SCIM Group mapping metadata is incomplete".into(),
                            )
                        })?,
                    )),
                    None => Ok(ScimRoleMappingOutcome::Removed),
                };
            }
            let next_version = current
                .record
                .version
                .checked_add(1)
                .ok_or_else(|| StoreError::Permanent("SCIM Group version exhausted".into()))?;
            let (group_update_expression, member_update_expression, role_updated_at) = match role {
                Some(_) => (
                    "SET tenant_role = :role, role_updated_at = :now, #version = :next, updated_at = :now",
                    "SET tenant_role = :role, role_updated_at = :now",
                    Some(now),
                ),
                None => (
                    "SET #version = :next, updated_at = :now REMOVE tenant_role, role_updated_at",
                    "REMOVE tenant_role, role_updated_at",
                    None,
                ),
            };
            let mut group_update = Update::builder()
                .table_name(&self.table)
                .key("pk", AttributeValue::S(Self::group_pk(tenant, &group_id)))
                .key("sk", AttributeValue::S(SCIM_GROUP_SK.to_string()))
                .update_expression(group_update_expression)
                .condition_expression(
                    "#version = :expected AND (attribute_not_exists(deleted) OR deleted = :false)",
                )
                .expression_attribute_names("#version", "version")
                .expression_attribute_values(
                    ":expected",
                    AttributeValue::N(current.record.version.to_string()),
                )
                .expression_attribute_values(":next", AttributeValue::N(next_version.to_string()))
                .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
                .expression_attribute_values(":false", AttributeValue::Bool(false));
            if let Some(role) = role {
                group_update = group_update.expression_attribute_values(
                    ":role",
                    AttributeValue::S(Self::role_str(role).to_string()),
                );
            }
            let group_update = group_update.build().map_err(|error| {
                StoreError::Permanent(format!("build Group role update: {error}"))
            })?;
            let mut items = vec![TransactWriteItem::builder().update(group_update).build()];
            for member in &current.record.members {
                let mut member_update = Update::builder()
                    .table_name(&self.table)
                    .key("pk", AttributeValue::S(Self::member_pk(tenant, member)))
                    .key("sk", AttributeValue::S(Self::member_sk(&group_id)))
                    .update_expression(member_update_expression)
                    .condition_expression("attribute_exists(pk)");
                if let Some(role) = role {
                    member_update = member_update
                        .expression_attribute_values(
                            ":role",
                            AttributeValue::S(Self::role_str(role).to_string()),
                        )
                        .expression_attribute_values(":now", AttributeValue::N(now.to_string()));
                }
                let member_update = member_update.build().map_err(|error| {
                    StoreError::Permanent(format!("build member role update: {error}"))
                })?;
                items.push(TransactWriteItem::builder().update(member_update).build());
            }
            match self.send_transaction(items).await {
                Ok(()) => {
                    return match role {
                        Some(role) => Ok(ScimRoleMappingOutcome::Updated(
                            crate::ports::ScimGroupRoleMapping {
                                group_id,
                                external_id: external_id.to_string(),
                                role,
                                updated_at: role_updated_at.expect("set for mapped role"),
                            },
                        )),
                        None => Ok(ScimRoleMappingOutcome::Removed),
                    }
                }
                Err(StoreError::Transient(_)) => continue,
                Err(error) => return Err(error),
            }
        }
        Err(StoreError::Transient(
            "SCIM Group role mapping did not converge".into(),
        ))
    }

    async fn list_role_mappings(
        &self,
        tenant: &str,
    ) -> Result<Vec<crate::ports::ScimGroupRoleMapping>, StoreError> {
        let (groups, _) = self.list(tenant, 0, usize::MAX).await?;
        let mut mappings = Vec::new();
        for group in groups {
            if let Some(state) = self.get_state(tenant, &group.group_id).await? {
                if let Some(mapping) = Self::mapping(&state) {
                    mappings.push(mapping);
                }
            }
        }
        mappings.sort_by(|left, right| left.external_id.cmp(&right.external_id));
        Ok(mappings)
    }

    async fn mapped_role_for_member(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<crate::ports::MappedTenantRole, StoreError> {
        let member_pk = Self::member_pk(tenant, user_id);
        let mut mappings = Vec::new();
        let mut last_key = None;
        loop {
            let mut query = self
                .db
                .query()
                .table_name(&self.table)
                .key_condition_expression("pk = :pk")
                .expression_attribute_values(":pk", AttributeValue::S(member_pk.clone()))
                .consistent_read(true);
            if let Some(key) = last_key {
                query = query.set_exclusive_start_key(Some(key));
            }
            let response = query.send().await.map_err(ddb_err)?;
            mappings.extend(
                response
                    .items()
                    .iter()
                    .filter(|item| {
                        s(item.get("record_type")).as_deref() == Some(SCIM_GROUP_MEMBER_RECORD_TYPE)
                            && s(item.get("user_id")).as_deref() == Some(user_id)
                    })
                    .filter_map(|item| {
                        Some(crate::ports::ScimGroupRoleMapping {
                            group_id: s(item.get("group_id"))?,
                            external_id: s(item.get("external_id"))?,
                            role: Self::parse_role(item.get("tenant_role"))?,
                            updated_at: n_i64(item.get("role_updated_at"))?,
                        })
                    }),
            );
            match response.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        mappings.sort_by(|left, right| left.external_id.cmp(&right.external_id));
        let role = mappings.iter().map(|mapping| mapping.role).max();
        Ok(crate::ports::MappedTenantRole { role, mappings })
    }

    async fn remove_member_from_all(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<usize, StoreError> {
        let mut offset = 0;
        let mut group_ids = Vec::new();
        loop {
            let (groups, total) = self.list(tenant, offset, 100).await?;
            let count = groups.len();
            group_ids.extend(
                groups
                    .into_iter()
                    .filter(|group| group.members.iter().any(|member| member == user_id))
                    .map(|group| group.group_id),
            );
            offset += count;
            if count == 0 || offset >= total {
                break;
            }
        }
        for group_id in &group_ids {
            match self
                .mutate(
                    tenant,
                    group_id,
                    crate::ports::ScimGroupMutation::Patch {
                        changes: vec![crate::ports::ScimGroupChange::RemoveMembers(vec![
                            user_id.to_string()
                        ])],
                        now,
                    },
                )
                .await?
            {
                crate::ports::ScimGroupMutationOutcome::Updated(_) => {}
                crate::ports::ScimGroupMutationOutcome::NotFound => continue,
                crate::ports::ScimGroupMutationOutcome::TooManyMembers => {
                    return Err(StoreError::Permanent(
                        "SCIM Group removal unexpectedly exceeded member limit".into(),
                    ))
                }
            }
        }
        Ok(group_ids.len())
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let prefix = (!tenant.is_empty()).then(|| format!("{tenant}\u{1f}"));
        let mut keys = Vec::new();
        let mut last_key = None;
        loop {
            let scan = self
                .db
                .scan()
                .table_name(&self.table)
                .projection_expression("pk, sk")
                .consistent_read(true)
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in scan.items() {
                let Some(pk) = s(item.get("pk")) else {
                    return Err(StoreError::Permanent(
                        "SCIM Group governance row is missing pk".into(),
                    ));
                };
                if prefix
                    .as_ref()
                    .is_some_and(|prefix| !pk.starts_with(prefix))
                {
                    continue;
                }
                let sk = item.get("sk").cloned().ok_or_else(|| {
                    StoreError::Permanent("SCIM Group governance row is missing sk".into())
                })?;
                keys.push((pk, sk));
            }
            match scan.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        for (pk, sk) in &keys {
            self.db
                .delete_item()
                .table_name(&self.table)
                .key("pk", AttributeValue::S(pk.clone()))
                .key("sk", sk.clone())
                .send()
                .await
                .map_err(ddb_err)?;
        }
        Ok(keys.len())
    }
}

impl DynamoScimGroupsStore {
    fn governance_fence_conflict(operation: &str) -> StoreError {
        StoreError::Transient(format!(
            "{operation}: governance destructive fence conflict"
        ))
    }

    fn membership_delete(
        &self,
        tenant: &str,
        user_id: &str,
        group_id: &str,
    ) -> Result<aws_sdk_dynamodb::types::TransactWriteItem, StoreError> {
        use aws_sdk_dynamodb::types::{Delete, TransactWriteItem};

        let delete = Delete::builder()
            .table_name(&self.table)
            .key("pk", AttributeValue::S(Self::member_pk(tenant, user_id)))
            .key("sk", AttributeValue::S(Self::member_sk(group_id)))
            .condition_expression(
                "attribute_exists(pk) AND record_type = :record_type \
                 AND user_id = :user_id AND group_id = :group_id",
            )
            .expression_attribute_values(
                ":record_type",
                AttributeValue::S(SCIM_GROUP_MEMBER_RECORD_TYPE.into()),
            )
            .expression_attribute_values(":user_id", AttributeValue::S(user_id.into()))
            .expression_attribute_values(":group_id", AttributeValue::S(group_id.into()))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build governed SCIM membership delete: {error}"))
            })?;
        Ok(TransactWriteItem::builder().delete(delete).build())
    }

    fn membership_group_update(
        &self,
        tenant: &str,
        user_id: &str,
        current: &DynamoScimGroupState,
        now: i64,
    ) -> Result<aws_sdk_dynamodb::types::TransactWriteItem, StoreError> {
        use aws_sdk_dynamodb::types::{TransactWriteItem, Update};

        let next_version = current
            .record
            .version
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("SCIM Group version exhausted".into()))?;
        let members: Vec<_> = current
            .record
            .members
            .iter()
            .filter(|member| member.as_str() != user_id)
            .cloned()
            .collect();
        let update = Update::builder()
            .table_name(&self.table)
            .key(
                "pk",
                AttributeValue::S(Self::group_pk(tenant, &current.record.group_id)),
            )
            .key("sk", AttributeValue::S(SCIM_GROUP_SK.into()))
            .update_expression("SET #members = :members, #version = :next, updated_at = :now")
            .condition_expression(
                "#version = :expected AND (attribute_not_exists(deleted) OR deleted = :false)",
            )
            .expression_attribute_names("#members", "members")
            .expression_attribute_names("#version", "version")
            .expression_attribute_values(":members", Self::members_attr(&members))
            .expression_attribute_values(":next", AttributeValue::N(next_version.to_string()))
            .expression_attribute_values(
                ":expected",
                AttributeValue::N(current.record.version.to_string()),
            )
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .expression_attribute_values(":false", AttributeValue::Bool(false))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "build governed SCIM membership group update: {error}"
                ))
            })?;
        Ok(TransactWriteItem::builder().update(update).build())
    }

    async fn membership_rows(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<Vec<HashMap<String, AttributeValue>>, StoreError> {
        let mut rows = Vec::new();
        let mut last_key = None;
        loop {
            let response = self
                .db
                .query()
                .table_name(&self.table)
                .key_condition_expression("pk = :pk")
                .expression_attribute_values(
                    ":pk",
                    AttributeValue::S(Self::member_pk(tenant, user_id)),
                )
                .consistent_read(true)
                .set_exclusive_start_key(last_key)
                .send()
                .await
                .map_err(ddb_err)?;
            rows.extend(response.items().iter().cloned());
            match response.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        Ok(rows)
    }

    pub(crate) async fn governance_remove_member_from_all_fenced(
        &self,
        governance: &super::governance::DynamoGovernanceStore,
        logical_tenant: &str,
        data_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        user_id: &str,
    ) -> Result<usize, StoreError> {
        use super::governance::GovernanceDestructiveWriteOutcome;

        let mut removed = 0usize;
        for row in self.membership_rows(data_tenant, user_id).await? {
            if s(row.get("record_type")).as_deref() != Some(SCIM_GROUP_MEMBER_RECORD_TYPE)
                || s(row.get("user_id")).as_deref() != Some(user_id)
            {
                return Err(StoreError::Permanent(
                    "SCIM membership row has invalid governance identity".into(),
                ));
            }
            let group_id = s(row.get("group_id")).ok_or_else(|| {
                StoreError::Permanent("SCIM membership row is missing group_id".into())
            })?;
            let current = self.get_state(data_tenant, &group_id).await?;
            let mut writes = Vec::with_capacity(2);
            if let Some(current) = current.as_ref().filter(|state| {
                !state.deleted && state.record.members.iter().any(|member| member == user_id)
            }) {
                writes.push(self.membership_group_update(data_tenant, user_id, current, now)?);
            }
            writes.push(self.membership_delete(data_tenant, user_id, &group_id)?);
            match governance
                .execute_destructive_transaction(logical_tenant, fence.clone(), now, writes)
                .await?
            {
                GovernanceDestructiveWriteOutcome::Applied => {
                    removed = removed.saturating_add(1);
                }
                GovernanceDestructiveWriteOutcome::FenceConflict => {
                    return Err(Self::governance_fence_conflict(
                        "remove governed SCIM membership",
                    ))
                }
            }
        }
        Ok(removed)
    }

    fn pk_belongs_to_tenant(pk: &str, tenant: &str) -> bool {
        if tenant.is_empty() {
            !pk.contains('\u{1f}')
        } else {
            pk.starts_with(&format!("{tenant}\u{1f}"))
        }
    }

    fn governed_tenant_delete(
        &self,
        item: &HashMap<String, AttributeValue>,
    ) -> Result<aws_sdk_dynamodb::types::TransactWriteItem, StoreError> {
        use aws_sdk_dynamodb::types::{Delete, TransactWriteItem};

        let pk = s(item.get("pk")).ok_or_else(|| {
            StoreError::Permanent("SCIM Group governance row is missing pk".into())
        })?;
        let sk = item.get("sk").cloned().ok_or_else(|| {
            StoreError::Permanent("SCIM Group governance row is missing sk".into())
        })?;
        let record_type = s(item.get("record_type")).ok_or_else(|| {
            StoreError::Permanent("SCIM Group governance row is missing record_type".into())
        })?;
        if !matches!(
            record_type.as_str(),
            SCIM_GROUP_RECORD_TYPE | SCIM_GROUP_ALIAS_RECORD_TYPE | SCIM_GROUP_MEMBER_RECORD_TYPE
        ) {
            return Err(StoreError::Permanent(
                "SCIM Group governance row has unknown record_type".into(),
            ));
        }
        let delete = Delete::builder()
            .table_name(&self.table)
            .key("pk", AttributeValue::S(pk))
            .key("sk", sk)
            .condition_expression("attribute_exists(pk) AND record_type = :record_type")
            .expression_attribute_values(":record_type", AttributeValue::S(record_type))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build governed SCIM tenant delete: {error}"))
            })?;
        Ok(TransactWriteItem::builder().delete(delete).build())
    }

    async fn governance_tenant_rows(
        &self,
        tenant: &str,
    ) -> Result<Vec<HashMap<String, AttributeValue>>, StoreError> {
        let mut rows = Vec::new();
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
            rows.extend(
                response
                    .items()
                    .iter()
                    .filter(|item| {
                        s(item.get("pk")).is_some_and(|pk| Self::pk_belongs_to_tenant(&pk, tenant))
                    })
                    .cloned(),
            );
            match response.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        Ok(rows)
    }

    pub(crate) async fn governance_delete_all_by_tenant_fenced(
        &self,
        governance: &super::governance::DynamoGovernanceStore,
        logical_tenant: &str,
        data_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
    ) -> Result<usize, StoreError> {
        use super::governance::GovernanceDestructiveWriteOutcome;

        let rows = self.governance_tenant_rows(data_tenant).await?;
        let mut removed = 0usize;
        for batch in rows.chunks(GOVERNANCE_TARGET_WRITE_BATCH) {
            let writes = batch
                .iter()
                .map(|item| self.governed_tenant_delete(item))
                .collect::<Result<Vec<_>, _>>()?;
            match governance
                .execute_destructive_transaction(logical_tenant, fence.clone(), now, writes)
                .await?
            {
                GovernanceDestructiveWriteOutcome::Applied => {
                    removed = removed.saturating_add(batch.len());
                }
                GovernanceDestructiveWriteOutcome::FenceConflict => {
                    return Err(Self::governance_fence_conflict(
                        "delete governed SCIM tenant rows",
                    ))
                }
            }
        }
        Ok(removed)
    }

    pub(crate) async fn governance_user_membership_inventory(
        &self,
        data_tenant: &str,
        user_id: &str,
    ) -> Result<GovernanceScimMembershipInventory, StoreError> {
        let rows = self.membership_rows(data_tenant, user_id).await?;
        let mut confirmed_live_memberships = 0usize;
        let mut role_index_rows = 0usize;
        for row in &rows {
            if s(row.get("record_type")).as_deref() != Some(SCIM_GROUP_MEMBER_RECORD_TYPE)
                || s(row.get("user_id")).as_deref() != Some(user_id)
            {
                return Err(StoreError::Permanent(
                    "SCIM membership inventory found malformed row".into(),
                ));
            }
            if row.contains_key("tenant_role") {
                if Self::parse_role(row.get("tenant_role")).is_none()
                    || n_i64(row.get("role_updated_at")).is_none()
                {
                    return Err(StoreError::Permanent(
                        "SCIM membership inventory found malformed role index".into(),
                    ));
                }
                role_index_rows = role_index_rows.saturating_add(1);
            }
            let group_id = s(row.get("group_id")).ok_or_else(|| {
                StoreError::Permanent("SCIM membership row is missing group_id".into())
            })?;
            if self
                .get_state(data_tenant, &group_id)
                .await?
                .is_some_and(|state| {
                    !state.deleted && state.record.members.iter().any(|member| member == user_id)
                })
            {
                confirmed_live_memberships = confirmed_live_memberships.saturating_add(1);
            }
        }
        Ok(GovernanceScimMembershipInventory {
            membership_rows: rows.len(),
            confirmed_live_memberships,
            role_index_rows,
        })
    }

    pub(crate) async fn governance_tenant_inventory(
        &self,
        data_tenant: &str,
    ) -> Result<GovernanceScimTenantInventory, StoreError> {
        let rows = self.governance_tenant_rows(data_tenant).await?;
        let mut inventory = GovernanceScimTenantInventory {
            group_rows: 0,
            alias_rows: 0,
            membership_rows: 0,
            live_groups: 0,
            role_index_rows: 0,
        };
        for row in rows {
            match s(row.get("record_type")).as_deref() {
                Some(SCIM_GROUP_RECORD_TYPE) => {
                    inventory.group_rows = inventory.group_rows.saturating_add(1);
                    let state = Self::to_state(&row).ok_or_else(|| {
                        StoreError::Permanent(
                            "SCIM tenant inventory found malformed group row".into(),
                        )
                    })?;
                    if !state.deleted {
                        inventory.live_groups = inventory.live_groups.saturating_add(1);
                    }
                    if row.contains_key("tenant_role") {
                        if state.role.is_none() || state.role_updated_at.is_none() {
                            return Err(StoreError::Permanent(
                                "SCIM tenant inventory found malformed group role index".into(),
                            ));
                        }
                        inventory.role_index_rows = inventory.role_index_rows.saturating_add(1);
                    }
                }
                Some(SCIM_GROUP_ALIAS_RECORD_TYPE) => {
                    inventory.alias_rows = inventory.alias_rows.saturating_add(1);
                }
                Some(SCIM_GROUP_MEMBER_RECORD_TYPE) => {
                    inventory.membership_rows = inventory.membership_rows.saturating_add(1);
                    if row.contains_key("tenant_role") {
                        if Self::parse_role(row.get("tenant_role")).is_none()
                            || n_i64(row.get("role_updated_at")).is_none()
                        {
                            return Err(StoreError::Permanent(
                                "SCIM tenant inventory found malformed member role index".into(),
                            ));
                        }
                        inventory.role_index_rows = inventory.role_index_rows.saturating_add(1);
                    }
                }
                _ => {
                    return Err(StoreError::Permanent(
                        "SCIM tenant inventory found malformed row".into(),
                    ))
                }
            }
        }
        Ok(inventory)
    }
}

#[cfg(test)]
mod governance_tests {
    use super::*;

    #[test]
    fn tenant_partition_filter_does_not_cross_default_or_named_tenants() {
        assert!(DynamoScimGroupsStore::pk_belongs_to_tenant(
            "scim-group:1",
            ""
        ));
        assert!(!DynamoScimGroupsStore::pk_belongs_to_tenant(
            "tenant-1\u{1f}scim-group:1",
            ""
        ));
        assert!(DynamoScimGroupsStore::pk_belongs_to_tenant(
            "tenant-1\u{1f}scim-group:1",
            "tenant-1"
        ));
        assert!(!DynamoScimGroupsStore::pk_belongs_to_tenant(
            "tenant-10\u{1f}scim-group:1",
            "tenant-1"
        ));
    }

    #[test]
    fn governed_membership_delete_checks_exact_base_row() {
        let store = DynamoScimGroupsStore::new(
            aws_sdk_dynamodb::Client::from_conf(
                aws_sdk_dynamodb::Config::builder()
                    .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
                    .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                    .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                    .build(),
            ),
            "groups",
        );
        let write = store
            .membership_delete("tenant-1", "user-1", "group-1")
            .unwrap();
        let delete = write.delete().unwrap();
        let condition = delete.condition_expression().unwrap();
        assert!(condition.contains("record_type = :record_type"));
        assert!(condition.contains("user_id = :user_id"));
        assert!(condition.contains("group_id = :group_id"));
    }

    #[test]
    fn governance_batches_leave_room_for_all_authority_checks() {
        const { assert!(GOVERNANCE_TARGET_WRITE_BATCH + 4 <= 100) };
    }
}
