//! AWS workload identity, federation, and outbound identity adapters.

use super::*;

/// DynamoDB workload 信任绑定存储(spec 012 C5.5)。表主键 = `binding_id`(S)。
/// 绑定体存 JSON 字符串(TrustBinding serde 序列化);`tenant_id` 另存一列供 Scan 过滤。
#[derive(Clone)]
pub struct DynamoWorkloadTrustStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
}

impl DynamoWorkloadTrustStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        DynamoWorkloadTrustStore {
            db,
            table: table.into(),
        }
    }
}

impl crate::ports::WorkloadTrustStore for DynamoWorkloadTrustStore {
    async fn put(
        &self,
        tenant: &str,
        binding_id: String,
        binding: agent_auth_workload::TrustBinding,
    ) -> Result<(), StoreError> {
        let json = serde_json::to_string(&binding)
            .map_err(|e| StoreError::Permanent(format!("serialize binding: {e}")))?;
        // binding_id 主键 tpk(tenant, ...):按 tenant 物理隔离(评审 codex Low:SPIFFE 派生 binding_id
        // 跨租户可碰撞,不隔离则 A 可覆盖 B)。tenant_id 属性仍存逻辑值(list_by_tenant filter 用)。
        let item = HashMap::from([
            (
                "binding_id".to_string(),
                AttributeValue::S(tpk(tenant, &binding_id)),
            ),
            (
                "tenant_id".to_string(),
                AttributeValue::S(binding.tenant_id.clone()),
            ),
            ("binding_json".to_string(), AttributeValue::S(json)),
        ]);
        self.db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(())
    }

    async fn list_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<crate::ports::WorkloadTrustEntry>, StoreError> {
        // 分页 Scan + filter tenant_id(量小;量大另建 GSI,见 spec 020)。
        let mut out = Vec::new();
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let scan = self
                .db
                .scan()
                .table_name(&self.table)
                .filter_expression("tenant_id = :t")
                .expression_attribute_values(":t", AttributeValue::S(tenant_id.to_string()))
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in scan.items() {
                if let Some(j) = s(item.get("binding_json")) {
                    if let Ok(b) = serde_json::from_str::<agent_auth_workload::TrustBinding>(&j) {
                        let physical_id = s(item.get("binding_id")).ok_or_else(|| {
                            StoreError::Permanent("workload trust row is missing binding_id".into())
                        })?;
                        out.push(crate::ports::WorkloadTrustEntry {
                            binding_id: strip_tpk(&physical_id),
                            binding: b,
                        });
                    }
                }
            }
            match scan.last_evaluated_key() {
                Some(k) if !k.is_empty() => last_key = Some(k.clone()),
                _ => break,
            }
        }
        Ok(out)
    }

    async fn delete(&self, tenant: &str, binding_id: &str) -> Result<(), StoreError> {
        // 按 tenant tpk 删 → 绝不删他租户同 binding_id 绑定(评审 codex Low)。
        self.db
            .delete_item()
            .table_name(&self.table)
            .key("binding_id", AttributeValue::S(tpk(tenant, binding_id)))
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(())
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut deleted = 0usize;
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let scan = self
                .db
                .scan()
                .table_name(&self.table)
                .filter_expression("tenant_id = :tenant")
                .expression_attribute_values(":tenant", AttributeValue::S(tenant.to_string()))
                .projection_expression("binding_id")
                .consistent_read(true)
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in scan.items() {
                let binding_id = item.get("binding_id").cloned().ok_or_else(|| {
                    StoreError::Permanent(
                        "workload trust governance row is missing binding_id".into(),
                    )
                })?;
                self.db
                    .delete_item()
                    .table_name(&self.table)
                    .key("binding_id", binding_id)
                    .send()
                    .await
                    .map_err(ddb_err)?;
                deleted = deleted.saturating_add(1);
            }
            match scan.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        Ok(deleted)
    }
}

/// DynamoDB 联邦配置存储(spec 003 §4 Task 4.7)。**复合键隔离**:pk=`tenant_id`、sk=`upstream_idp_id`
/// → `get`/`delete` 按精确复合键(跨租户物理取不到);`list_by_tenant` 按 pk Query(不 Scan 全表,天然只本租户)。
/// 值 = FederationConfig JSON(config 非 secret;secret 只存引用名,不落明文)。
#[derive(Clone)]
pub struct DynamoFederationConfigStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
}

impl DynamoFederationConfigStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        DynamoFederationConfigStore {
            db,
            table: table.into(),
        }
    }

    /// DynamoDB keys cannot be empty. The separator is forbidden in logical
    /// tenant IDs, so this self-hosted key cannot collide with a named tenant.
    /// Non-empty tenant keys and the logical tenant inside JSON stay unchanged.
    pub(super) fn physical_tenant_id(tenant_id: &str) -> &str {
        if tenant_id.is_empty() {
            "\u{1f}self-hosted"
        } else {
            tenant_id
        }
    }

    fn key(
        tenant_id: &str,
        upstream_idp_id: &str,
    ) -> HashMap<String, aws_sdk_dynamodb::types::AttributeValue> {
        HashMap::from([
            (
                "tenant_id".to_string(),
                AttributeValue::S(Self::physical_tenant_id(tenant_id).to_string()),
            ),
            (
                "upstream_idp_id".to_string(),
                AttributeValue::S(upstream_idp_id.to_string()),
            ),
        ])
    }

    fn config_json(
        config: &agent_auth_authn::federation::FederationConfig,
    ) -> Result<String, StoreError> {
        serde_json::to_string(config)
            .map_err(|error| StoreError::Permanent(format!("serialize federation config: {error}")))
    }

    fn item(
        config: &agent_auth_authn::federation::FederationConfig,
    ) -> Result<HashMap<String, AttributeValue>, StoreError> {
        let mut item = Self::key(&config.tenant_id, &config.upstream_idp_id);
        item.insert(
            "config_json".into(),
            AttributeValue::S(Self::config_json(config)?),
        );
        Ok(item)
    }

    pub(crate) fn snapshot_condition(
        &self,
        config: &agent_auth_authn::federation::FederationConfig,
    ) -> Result<aws_sdk_dynamodb::types::TransactWriteItem, StoreError> {
        let condition = aws_sdk_dynamodb::types::ConditionCheck::builder()
            .table_name(&self.table)
            .set_key(Some(Self::key(&config.tenant_id, &config.upstream_idp_id)))
            .condition_expression("config_json = :config")
            .expression_attribute_values(":config", AttributeValue::S(Self::config_json(config)?))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "build federation config snapshot condition: {error}"
                ))
            })?;
        Ok(aws_sdk_dynamodb::types::TransactWriteItem::builder()
            .condition_check(condition)
            .build())
    }

    fn put_item(
        &self,
        current: Option<&agent_auth_authn::federation::FederationConfig>,
        next: &agent_auth_authn::federation::FederationConfig,
    ) -> Result<aws_sdk_dynamodb::types::TransactWriteItem, StoreError> {
        let mut put = aws_sdk_dynamodb::types::Put::builder()
            .table_name(&self.table)
            .set_item(Some(Self::item(next)?));
        put = match current {
            Some(current) => put
                .condition_expression("config_json = :expected_config")
                .expression_attribute_values(
                    ":expected_config",
                    AttributeValue::S(Self::config_json(current)?),
                ),
            None => put.condition_expression(
                "attribute_not_exists(tenant_id) AND attribute_not_exists(upstream_idp_id)",
            ),
        };
        Ok(aws_sdk_dynamodb::types::TransactWriteItem::builder()
            .put(put.build().map_err(|error| {
                StoreError::Permanent(format!("build federation config transaction put: {error}"))
            })?)
            .build())
    }

    fn delete_item(
        &self,
        current: &agent_auth_authn::federation::FederationConfig,
    ) -> Result<aws_sdk_dynamodb::types::TransactWriteItem, StoreError> {
        let delete = aws_sdk_dynamodb::types::Delete::builder()
            .table_name(&self.table)
            .set_key(Some(Self::key(
                &current.tenant_id,
                &current.upstream_idp_id,
            )))
            .condition_expression("config_json = :expected_config")
            .expression_attribute_values(
                ":expected_config",
                AttributeValue::S(Self::config_json(current)?),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "build federation config transaction delete: {error}"
                ))
            })?;
        Ok(aws_sdk_dynamodb::types::TransactWriteItem::builder()
            .delete(delete)
            .build())
    }

    pub(crate) async fn put_authorized(
        &self,
        mapping_condition: aws_sdk_dynamodb::types::TransactWriteItem,
        current: Option<&agent_auth_authn::federation::FederationConfig>,
        next: agent_auth_authn::federation::FederationConfig,
    ) -> Result<bool, StoreError> {
        super::send_idempotent_transaction(
            self.db
                .transact_write_items()
                .transact_items(mapping_condition)
                .transact_items(self.put_item(current, &next)?),
        )
        .await
    }

    pub(crate) async fn delete_authorized(
        &self,
        mapping_condition: aws_sdk_dynamodb::types::TransactWriteItem,
        current: &agent_auth_authn::federation::FederationConfig,
    ) -> Result<bool, StoreError> {
        super::send_idempotent_transaction(
            self.db
                .transact_write_items()
                .transact_items(mapping_condition)
                .transact_items(self.delete_item(current)?),
        )
        .await
    }
}

impl crate::ports::FederationConfigStore for DynamoFederationConfigStore {
    async fn get(
        &self,
        tenant_id: &str,
        upstream_idp_id: &str,
    ) -> Result<Option<agent_auth_authn::federation::FederationConfig>, StoreError> {
        let out = self
            .db
            .get_item()
            .table_name(&self.table)
            .set_key(Some(Self::key(tenant_id, upstream_idp_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        let Some(item) = out.item() else {
            return Ok(None);
        };
        match s(item.get("config_json")) {
            Some(j) => serde_json::from_str(&j)
                .map(Some)
                .map_err(|e| StoreError::Permanent(format!("deserialize federation config: {e}"))),
            None => Ok(None),
        }
    }

    async fn list_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<agent_auth_authn::federation::FederationConfig>, StoreError> {
        // pk Query(只本租户分区,不 Scan 全表 → 天然不跨租户)。
        let mut out = Vec::new();
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let q = self
                .db
                .query()
                .table_name(&self.table)
                .key_condition_expression("tenant_id = :t")
                .expression_attribute_values(
                    ":t",
                    AttributeValue::S(Self::physical_tenant_id(tenant_id).to_string()),
                )
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in q.items() {
                if let Some(j) = s(item.get("config_json")) {
                    if let Ok(c) =
                        serde_json::from_str::<agent_auth_authn::federation::FederationConfig>(&j)
                    {
                        out.push(c);
                    }
                }
            }
            match q.last_evaluated_key() {
                Some(k) if !k.is_empty() => last_key = Some(k.clone()),
                _ => break,
            }
        }
        Ok(out)
    }

    async fn put(
        &self,
        config: agent_auth_authn::federation::FederationConfig,
    ) -> Result<(), StoreError> {
        self.db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(Self::item(&config)?))
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(())
    }

    async fn delete(&self, tenant_id: &str, upstream_idp_id: &str) -> Result<(), StoreError> {
        self.db
            .delete_item()
            .table_name(&self.table)
            .set_key(Some(Self::key(tenant_id, upstream_idp_id)))
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(())
    }

    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        let mut deleted = 0usize;
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let query = self
                .db
                .query()
                .table_name(&self.table)
                .key_condition_expression("tenant_id = :tenant")
                .expression_attribute_values(
                    ":tenant",
                    AttributeValue::S(Self::physical_tenant_id(tenant_id).to_string()),
                )
                .projection_expression("tenant_id, upstream_idp_id")
                .consistent_read(true)
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in query.items() {
                let upstream_idp_id = item.get("upstream_idp_id").cloned().ok_or_else(|| {
                    StoreError::Permanent(
                        "federation governance row is missing upstream_idp_id".into(),
                    )
                })?;
                self.db
                    .delete_item()
                    .table_name(&self.table)
                    .key(
                        "tenant_id",
                        AttributeValue::S(Self::physical_tenant_id(tenant_id).to_string()),
                    )
                    .key("upstream_idp_id", upstream_idp_id)
                    .send()
                    .await
                    .map_err(ddb_err)?;
                deleted = deleted.saturating_add(1);
            }
            match query.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        Ok(deleted)
    }
}

/// Admin OIDC configuration and Region-local runtime state. Configuration stays
/// in the original durable table; one-time flows and sessions use a separate
/// table so Global Tables never replicate replay-sensitive rows.
#[derive(Clone)]
pub struct DynamoAdminAuthStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) config_table: String,
    pub(super) runtime_table: String,
}

impl DynamoAdminAuthStore {
    pub fn new(
        db: aws_sdk_dynamodb::Client,
        config_table: impl Into<String>,
        runtime_table: impl Into<String>,
    ) -> Self {
        Self {
            db,
            config_table: config_table.into(),
            runtime_table: runtime_table.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdminAuthRecordKind {
    Config,
    Flow,
    Session,
}

fn admin_auth_table<'a>(
    config_table: &'a str,
    runtime_table: &'a str,
    kind: AdminAuthRecordKind,
) -> &'a str {
    match kind {
        AdminAuthRecordKind::Config => config_table,
        AdminAuthRecordKind::Flow | AdminAuthRecordKind::Session => runtime_table,
    }
}

pub(super) fn admin_config_key(tenant_id: &str) -> String {
    format!("config#{tenant_id}")
}

fn admin_flow_key(state_hash: &str) -> String {
    format!("flow#{state_hash}")
}

fn admin_session_key(session_hash: &str) -> String {
    format!("session#{session_hash}")
}

impl crate::ports::AdminAuthStore for DynamoAdminAuthStore {
    async fn get_config(
        &self,
        tenant_id: &str,
    ) -> Result<Option<crate::ports::AdminOidcConfig>, StoreError> {
        let out = self
            .db
            .get_item()
            .table_name(admin_auth_table(
                &self.config_table,
                &self.runtime_table,
                AdminAuthRecordKind::Config,
            ))
            .key("key", AttributeValue::S(admin_config_key(tenant_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        let Some(item) = out.item() else {
            return Ok(None);
        };
        let Some(json) = s(item.get("record_json")) else {
            return Err(StoreError::Permanent(
                "Admin OIDC config row missing record_json".into(),
            ));
        };
        if s(item.get("record_type")).as_deref() != Some("config") {
            return Err(StoreError::Permanent(
                "Admin OIDC config row has wrong record_type".into(),
            ));
        }
        let config: crate::ports::AdminOidcConfig =
            serde_json::from_str(&json).map_err(|error| {
                StoreError::Permanent(format!("deserialize Admin OIDC config: {error}"))
            })?;
        if config.tenant_id != tenant_id {
            return Err(StoreError::Permanent(
                "Admin OIDC config tenant mismatch".into(),
            ));
        }
        Ok(Some(config))
    }

    async fn put_config(
        &self,
        config: crate::ports::AdminOidcConfig,
        expected_revision: u64,
    ) -> Result<crate::ports::AdminOidcConfigPutOutcome, StoreError> {
        if config.revision != expected_revision.saturating_add(1) {
            return Ok(crate::ports::AdminOidcConfigPutOutcome::Conflict);
        }
        let json = serde_json::to_string(&config).map_err(|error| {
            StoreError::Permanent(format!("serialize Admin OIDC config: {error}"))
        })?;
        let item = HashMap::from([
            (
                "key".to_string(),
                AttributeValue::S(admin_config_key(&config.tenant_id)),
            ),
            (
                "record_type".to_string(),
                AttributeValue::S("config".into()),
            ),
            (
                "tenant_id".to_string(),
                AttributeValue::S(config.tenant_id.clone()),
            ),
            (
                "revision".to_string(),
                AttributeValue::N(config.revision.to_string()),
            ),
            ("record_json".to_string(), AttributeValue::S(json)),
        ]);
        let request = self
            .db
            .put_item()
            .table_name(admin_auth_table(
                &self.config_table,
                &self.runtime_table,
                AdminAuthRecordKind::Config,
            ))
            .set_item(Some(item));
        let request = if expected_revision == 0 {
            request
                .condition_expression("attribute_not_exists(#key)")
                .expression_attribute_names("#key", "key")
        } else {
            request
                .condition_expression("#revision = :expected")
                .expression_attribute_names("#revision", "revision")
                .expression_attribute_values(
                    ":expected",
                    AttributeValue::N(expected_revision.to_string()),
                )
        };
        match request.send().await {
            Ok(_) => Ok(crate::ports::AdminOidcConfigPutOutcome::Stored(config)),
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                Ok(crate::ports::AdminOidcConfigPutOutcome::Conflict)
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn delete_config(
        &self,
        tenant_id: &str,
        expected_revision: u64,
    ) -> Result<crate::ports::AdminOidcConfigDeleteOutcome, StoreError> {
        let request = self
            .db
            .delete_item()
            .table_name(admin_auth_table(
                &self.config_table,
                &self.runtime_table,
                AdminAuthRecordKind::Config,
            ))
            .key("key", AttributeValue::S(admin_config_key(tenant_id)))
            .condition_expression("#revision = :expected")
            .expression_attribute_names("#revision", "revision")
            .expression_attribute_values(
                ":expected",
                AttributeValue::N(expected_revision.to_string()),
            );
        match request.send().await {
            Ok(_) => Ok(crate::ports::AdminOidcConfigDeleteOutcome::Deleted),
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                Ok(crate::ports::AdminOidcConfigDeleteOutcome::Conflict)
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn put_flow(&self, flow: crate::ports::AdminOidcFlow) -> Result<(), StoreError> {
        let json = serde_json::to_string(&flow).map_err(|error| {
            StoreError::Permanent(format!("serialize Admin OIDC flow: {error}"))
        })?;
        let item = HashMap::from([
            (
                "key".to_string(),
                AttributeValue::S(admin_flow_key(&flow.state_hash)),
            ),
            ("record_type".to_string(), AttributeValue::S("flow".into())),
            (
                "expires_at".to_string(),
                AttributeValue::N(flow.expires_at.to_string()),
            ),
            ("record_json".to_string(), AttributeValue::S(json)),
        ]);
        self.db
            .put_item()
            .table_name(admin_auth_table(
                &self.config_table,
                &self.runtime_table,
                AdminAuthRecordKind::Flow,
            ))
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(#key)")
            .expression_attribute_names("#key", "key")
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(())
    }

    async fn consume_flow(
        &self,
        state_hash: &str,
        now: i64,
    ) -> Result<Option<crate::ports::AdminOidcFlow>, StoreError> {
        let out = self
            .db
            .delete_item()
            .table_name(admin_auth_table(
                &self.config_table,
                &self.runtime_table,
                AdminAuthRecordKind::Flow,
            ))
            .key("key", AttributeValue::S(admin_flow_key(state_hash)))
            .condition_expression("attribute_exists(#key)")
            .expression_attribute_names("#key", "key")
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllOld)
            .send()
            .await;
        let out = match out {
            Ok(output) => output,
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|service| service.is_conditional_check_failed_exception()) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(ddb_err(error)),
        };
        let Some(item) = out.attributes() else {
            return Ok(None);
        };
        let Some(json) = s(item.get("record_json")) else {
            return Ok(None);
        };
        match serde_json::from_str::<crate::ports::AdminOidcFlow>(&json) {
            Ok(flow)
                if flow.state_hash == state_hash
                    && flow.expires_at > now
                    && s(item.get("record_type")).as_deref() == Some("flow") =>
            {
                Ok(Some(flow))
            }
            _ => Ok(None),
        }
    }

    async fn create_session(
        &self,
        session: crate::ports::AdminSessionRecord,
    ) -> Result<(), StoreError> {
        let json = serde_json::to_string(&session)
            .map_err(|error| StoreError::Permanent(format!("serialize Admin session: {error}")))?;
        let item = HashMap::from([
            (
                "key".to_string(),
                AttributeValue::S(admin_session_key(&session.session_hash)),
            ),
            (
                "record_type".to_string(),
                AttributeValue::S("session".into()),
            ),
            (
                "tenant_id".to_string(),
                AttributeValue::S(session.tenant_id.clone()),
            ),
            (
                "expires_at".to_string(),
                AttributeValue::N(session.expires_at.to_string()),
            ),
            ("record_json".to_string(), AttributeValue::S(json)),
        ]);
        self.db
            .put_item()
            .table_name(admin_auth_table(
                &self.config_table,
                &self.runtime_table,
                AdminAuthRecordKind::Session,
            ))
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(#key)")
            .expression_attribute_names("#key", "key")
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(())
    }

    async fn get_session(
        &self,
        session_hash: &str,
        now: i64,
    ) -> Result<Option<crate::ports::AdminSessionRecord>, StoreError> {
        let out = self
            .db
            .get_item()
            .table_name(admin_auth_table(
                &self.config_table,
                &self.runtime_table,
                AdminAuthRecordKind::Session,
            ))
            .key("key", AttributeValue::S(admin_session_key(session_hash)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        let Some(item) = out.item() else {
            return Ok(None);
        };
        if s(item.get("record_type")).as_deref() != Some("session") {
            return Ok(None);
        }
        let Some(json) = s(item.get("record_json")) else {
            return Ok(None);
        };
        match serde_json::from_str::<crate::ports::AdminSessionRecord>(&json) {
            Ok(session) if session.session_hash == session_hash && session.expires_at > now => {
                Ok(Some(session))
            }
            _ => Ok(None),
        }
    }

    async fn delete_session(&self, tenant_id: &str, session_hash: &str) -> Result<(), StoreError> {
        let result = self
            .db
            .delete_item()
            .table_name(admin_auth_table(
                &self.config_table,
                &self.runtime_table,
                AdminAuthRecordKind::Session,
            ))
            .key("key", AttributeValue::S(admin_session_key(session_hash)))
            .condition_expression("attribute_not_exists(#key) OR #tenant = :tenant")
            .expression_attribute_names("#key", "key")
            .expression_attribute_names("#tenant", "tenant_id")
            .expression_attribute_values(":tenant", AttributeValue::S(tenant_id.to_string()))
            .send()
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                Ok(())
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        let mut deleted = 0usize;
        if self.get_config(tenant_id).await?.is_some() {
            self.db
                .delete_item()
                .table_name(admin_auth_table(
                    &self.config_table,
                    &self.runtime_table,
                    AdminAuthRecordKind::Config,
                ))
                .key("key", AttributeValue::S(admin_config_key(tenant_id)))
                .send()
                .await
                .map_err(ddb_err)?;
            deleted = deleted.saturating_add(1);
        }

        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let scan = self
                .db
                .scan()
                .table_name(admin_auth_table(
                    &self.config_table,
                    &self.runtime_table,
                    AdminAuthRecordKind::Session,
                ))
                .consistent_read(true)
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in scan.items() {
                let belongs = match s(item.get("record_type")).as_deref() {
                    Some("session") => s(item.get("tenant_id")).as_deref() == Some(tenant_id),
                    Some("flow") => s(item.get("record_json"))
                        .and_then(|json| {
                            serde_json::from_str::<crate::ports::AdminOidcFlow>(&json).ok()
                        })
                        .is_some_and(|flow| flow.tenant_id == tenant_id),
                    _ => false,
                };
                if !belongs {
                    continue;
                }
                let key = item.get("key").cloned().ok_or_else(|| {
                    StoreError::Permanent("Admin runtime governance row is missing key".into())
                })?;
                self.db
                    .delete_item()
                    .table_name(admin_auth_table(
                        &self.config_table,
                        &self.runtime_table,
                        AdminAuthRecordKind::Session,
                    ))
                    .key("key", key)
                    .send()
                    .await
                    .map_err(ddb_err)?;
                deleted = deleted.saturating_add(1);
            }
            match scan.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        Ok(deleted)
    }
}

/// STS `GetCallerIdentity` 真转发适配器(spec 012 C5.2/C5.3)。reqwest(rustls)POST 到**已校验的
/// STS host**(调用方前校 `validate_sigv4_pre_sts` 已确认 assertion.url host ∈ STS allowlist),
/// 只转发 allowlist 头(`authorization`/`x-amz-date`/audience 头;**绝不**转发客户端自带
/// `x-amz-security-token`,C5.3),硬超时 2s(热路径外呼)。
///
/// 语义(与 `StsCaller` 端口一致):STS 200 + 可解析 → `Ok(Some(id))`;STS 4xx / 响应不可解析 →
/// `Ok(None)`(签名无效,拒认证、非重试);网络/超时/5xx → `Err(Transient)`(上层熔断 + 503)。
#[derive(Clone)]
pub struct HttpStsCaller {
    client: reqwest::Client,
}

impl Default for HttpStsCaller {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpStsCaller {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2)) // C5.4:STS 调用超时 2s。
            .build()
            .expect("reqwest client");
        HttpStsCaller { client }
    }
}

impl crate::ports::StsCaller for HttpStsCaller {
    async fn get_caller_identity(
        &self,
        assertion: &agent_auth_workload::SigV4Assertion,
    ) -> Result<Option<agent_auth_workload::StsCallerIdentity>, StoreError> {
        // 转发头 allowlist(C5.3):只保 authorization / x-amz-date / audience 头。键已在 handler 归一小写。
        // **拒转发** x-amz-security-token(防客户端自带临时凭证转用)及其它任意头。
        const FORWARD_HEADERS: &[&str] = &["authorization", "x-amz-date", "x-agent-auth-audience"];
        let mut builder = self
            .client
            .post(&assertion.url) // host 已由前校确认 ∈ STS allowlist
            .header("content-type", "application/x-www-form-urlencoded");
        for name in FORWARD_HEADERS {
            if let Some(v) = assertion.headers.get(*name) {
                builder = builder.header(*name, v);
            }
        }
        let resp = builder
            .body(assertion.body.clone())
            .send()
            .await
            .map_err(|e| StoreError::Transient(format!("STS POST: {e}")))?;
        let status = resp.status();
        // 5xx → 瞬时(熔断);4xx → 签名无效/拒 → Ok(None)(非重试)。
        if status.is_server_error() {
            return Err(StoreError::Transient(format!("STS 5xx {status}")));
        }
        if !status.is_success() {
            return Ok(None); // 4xx:STS 拒(签名无效)→ 认证失败
        }
        let body = resp
            .text()
            .await
            .map_err(|e| StoreError::Transient(format!("STS body: {e}")))?;
        // 解析 XML(纯逻辑);解析失败 = 响应异常 → Ok(None)(fail-closed,不臆测身份)。
        Ok(agent_auth_workload::parse_get_caller_identity(&body))
    }
}

/// 真机 secret 解析器(spec 003 §4,评审 Kiro F4)。引用名 → 明文,走 Secrets Manager `GetSecretValue`。
/// 引用名 = secret 的 name 或 ARN。**明文只在调用栈返回、不缓存/不日志**(用完即弃,守 secret 红线)。
/// 找不到(ResourceNotFound)→ Ok(None)(误配拒);其它错误(网络/权限/限流)→ Transient(上层 503)。
#[derive(Clone)]
pub struct SecretsManagerResolver {
    client: aws_sdk_secretsmanager::Client,
}

impl SecretsManagerResolver {
    pub fn new(conf: &aws_config::SdkConfig) -> Self {
        SecretsManagerResolver {
            client: aws_sdk_secretsmanager::Client::new(conf),
        }
    }
}

impl crate::ports::SecretResolver for SecretsManagerResolver {
    async fn resolve(&self, secret_ref: &str) -> Result<Option<String>, StoreError> {
        let out = self
            .client
            .get_secret_value()
            .secret_id(secret_ref)
            .send()
            .await;
        match out {
            Ok(v) => Ok(v.secret_string().map(String::from)),
            Err(e) => {
                // ResourceNotFound → None(误配,非重试);其它 → Transient。
                let svc = e.into_service_error();
                if svc.is_resource_not_found_exception() {
                    Ok(None)
                } else {
                    Err(StoreError::Transient(format!("secretsmanager: {svc}")))
                }
            }
        }
    }
}

/// DynamoDB 联邦 flow 状态存储(spec 003 §4 Task 4.7)。表主键 = `state`(S);TTL=expires_at 短命 GC。
/// consume = **条件删**(DeleteItem + ReturnValues=ALL_OLD:取出旧值同时删,一次性防 state 重放)。
#[derive(Clone)]
pub struct DynamoFederationFlowStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
}

impl DynamoFederationFlowStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        DynamoFederationFlowStore {
            db,
            table: table.into(),
        }
    }
}

impl crate::ports::FederationFlowStore for DynamoFederationFlowStore {
    async fn put(&self, st: crate::ports::FederationFlowState) -> Result<(), StoreError> {
        let json = serde_json::to_string(&FlowStateSer::from(&st))
            .map_err(|e| StoreError::Permanent(format!("serialize flow: {e}")))?;
        let item = HashMap::from([
            ("state".to_string(), AttributeValue::S(st.state.clone())),
            ("flow_json".to_string(), AttributeValue::S(json)),
            (
                "expires_at".to_string(),
                AttributeValue::N(st.expires_at.to_string()),
            ),
        ]);
        self.db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(())
    }

    async fn consume(
        &self,
        state: &str,
    ) -> Result<Option<crate::ports::FederationFlowState>, StoreError> {
        // 条件删:DeleteItem 返回旧值(一次性——取出即删,防 state 重放)。
        let out = self
            .db
            .delete_item()
            .table_name(&self.table)
            .key("state", AttributeValue::S(state.to_string()))
            .condition_expression("attribute_exists(#state)")
            .expression_attribute_names("#state", "state")
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllOld)
            .send()
            .await;
        let out = match out {
            Ok(output) => output,
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|service| service.is_conditional_check_failed_exception()) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(ddb_err(error)),
        };
        let Some(item) = out.attributes() else {
            return Ok(None); // 不存在/已消费
        };
        let Some(j) = s(item.get("flow_json")) else {
            return Ok(None);
        };
        let now = crate::token::current_unix_secs_pub();
        match serde_json::from_str::<FlowStateSer>(&j) {
            Ok(fs) if fs.expires_at > now => Ok(Some(fs.into())),
            _ => Ok(None), // 过期(fail-closed)或解析失败
        }
    }

    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        let mut candidates = Vec::new();
        let mut start_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let output = self
                .db
                .scan()
                .table_name(&self.table)
                .projection_expression("#state, flow_json")
                .expression_attribute_names("#state", "state")
                .consistent_read(true)
                .set_exclusive_start_key(start_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in output.items() {
                let Some(json) = s(item.get("flow_json")) else {
                    continue;
                };
                if serde_json::from_str::<FlowStateSer>(&json)
                    .is_ok_and(|flow| flow.tenant_id == tenant_id)
                {
                    let state = item.get("state").cloned().ok_or_else(|| {
                        StoreError::Permanent(
                            "federation flow governance row is missing state".into(),
                        )
                    })?;
                    candidates.push((state, json));
                }
            }
            match output.last_evaluated_key() {
                Some(key) if !key.is_empty() => start_key = Some(key.clone()),
                _ => break,
            }
        }

        let mut deleted = 0usize;
        for (state, json) in candidates {
            let result = self
                .db
                .delete_item()
                .table_name(&self.table)
                .key("state", state)
                .condition_expression("flow_json = :flow_json")
                .expression_attribute_values(":flow_json", AttributeValue::S(json))
                .send()
                .await;
            match result {
                Ok(_) => deleted = deleted.saturating_add(1),
                Err(error)
                    if error
                        .as_service_error()
                        .is_some_and(|service| service.is_conditional_check_failed_exception()) => {
                }
                Err(error) => return Err(ddb_err(error)),
            }
        }
        Ok(deleted)
    }
}

/// FederationFlowState 的可序列化镜像(ports 里的 struct 不 derive serde;此处本地映射,不污染 ports)。
#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct FlowStateSer {
    state: String,
    nonce: String,
    code_verifier: String,
    pub(super) tenant_id: String,
    upstream_idp_id: String,
    original_authz_request: String,
    #[serde(default)]
    required_max_age_secs: Option<i64>,
    expires_at: i64,
}

impl FlowStateSer {
    fn from(s: &crate::ports::FederationFlowState) -> Self {
        FlowStateSer {
            state: s.state.clone(),
            nonce: s.nonce.clone(),
            code_verifier: s.code_verifier.clone(),
            tenant_id: s.tenant_id.clone(),
            upstream_idp_id: s.upstream_idp_id.clone(),
            original_authz_request: s.original_authz_request.clone(),
            required_max_age_secs: s.required_max_age_secs,
            expires_at: s.expires_at,
        }
    }
}

impl From<FlowStateSer> for crate::ports::FederationFlowState {
    fn from(s: FlowStateSer) -> Self {
        crate::ports::FederationFlowState {
            state: s.state,
            nonce: s.nonce,
            code_verifier: s.code_verifier,
            tenant_id: s.tenant_id,
            upstream_idp_id: s.upstream_idp_id,
            original_authz_request: s.original_authz_request,
            required_max_age_secs: s.required_max_age_secs,
            expires_at: s.expires_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DynamoAdminAuthStore;
    use crate::ports::{AdminAuthStore, AdminOidcFlow, AdminSessionRecord, StoreError, TenantRole};
    use aws_smithy_http_client::test_util::capture_request;
    use aws_smithy_types::body::SdkBody;

    fn dynamo_response(body: serde_json::Value) -> axum::http::Response<SdkBody> {
        axum::http::Response::builder()
            .status(200)
            .header("content-type", "application/x-amz-json-1.0")
            .body(SdkBody::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn admin_auth_records_route_config_to_durable_and_flows_sessions_to_runtime_tables() {
        let (config_http, config_request) =
            capture_request(Some(dynamo_response(serde_json::json!({}))));
        let config_db = aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                .endpoint_url("https://dynamodb.us-east-1.amazonaws.com")
                .http_client(config_http)
                .build(),
        );
        let config_store =
            DynamoAdminAuthStore::new(config_db, "AdminAuthDurable", "AdminAuthRuntime");
        assert!(config_store
            .get_config("tenant-a")
            .await
            .expect("Admin config read")
            .is_none());
        let config_request = config_request.expect_request();
        let config_body: serde_json::Value = serde_json::from_slice(
            config_request
                .body()
                .bytes()
                .expect("captured config request body"),
        )
        .expect("captured config request is JSON");
        assert_eq!(
            config_body["TableName"], "AdminAuthDurable",
            "configuration must use the durable table"
        );
        assert_eq!(config_body["Key"]["key"]["S"], "config#tenant-a");

        let (flow_http, flow_request) =
            capture_request(Some(dynamo_response(serde_json::json!({}))));
        let flow_db = aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                .endpoint_url("https://dynamodb.us-east-1.amazonaws.com")
                .http_client(flow_http)
                .build(),
        );
        DynamoAdminAuthStore::new(flow_db, "AdminAuthDurable", "AdminAuthRuntime")
            .put_flow(AdminOidcFlow {
                state_hash: "state-hash".into(),
                nonce: "nonce".into(),
                code_verifier: "verifier".into(),
                tenant_id: "tenant-a".into(),
                config_revision: 7,
                config_binding_id: "binding-a".into(),
                required_acr: None,
                required_max_age_secs: None,
                expires_at: 1_000,
            })
            .await
            .expect("Admin flow write");
        let flow_request = flow_request.expect_request();
        let flow_body: serde_json::Value = serde_json::from_slice(
            flow_request
                .body()
                .bytes()
                .expect("captured flow request body"),
        )
        .expect("captured flow request is JSON");
        assert_eq!(
            flow_body["TableName"], "AdminAuthRuntime",
            "one-time flows must use the Region-local runtime table"
        );
        assert_eq!(flow_body["Item"]["key"]["S"], "flow#state-hash");
        assert_eq!(flow_body["Item"]["record_type"]["S"], "flow");

        let (session_http, session_request) =
            capture_request(Some(dynamo_response(serde_json::json!({}))));
        let session_db = aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                .endpoint_url("https://dynamodb.us-east-1.amazonaws.com")
                .http_client(session_http)
                .build(),
        );
        DynamoAdminAuthStore::new(session_db, "AdminAuthDurable", "AdminAuthRuntime")
            .create_session(AdminSessionRecord {
                session_hash: "session-hash".into(),
                tenant_id: "tenant-a".into(),
                user_id: "user-a".into(),
                upstream_subject: "subject-a".into(),
                role: TenantRole::Admin,
                credential_epoch: 3,
                config_revision: 7,
                config_binding_id: "binding-a".into(),
                acr: None,
                auth_time: 900,
                created_at: 900,
                expires_at: 1_000,
            })
            .await
            .expect("Admin session write");
        let session_request = session_request.expect_request();
        let session_body: serde_json::Value = serde_json::from_slice(
            session_request
                .body()
                .bytes()
                .expect("captured session request body"),
        )
        .expect("captured session request is JSON");
        assert_eq!(
            session_body["TableName"], "AdminAuthRuntime",
            "short-lived sessions must use the Region-local runtime table"
        );
        assert_eq!(session_body["Item"]["key"]["S"], "session#session-hash");
        assert_eq!(session_body["Item"]["record_type"]["S"], "session");
    }

    use super::HttpStsCaller;
    use crate::ports::StsCaller;
    use agent_auth_workload::SigV4Assertion;
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn sts_http_caller_times_out_slow_dependency() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let caller = HttpStsCaller::new();
        let assertion = SigV4Assertion {
            method: "POST".to_string(),
            url: format!("http://{address}/"),
            headers: BTreeMap::from([
                (
                    "authorization".to_string(),
                    "AWS4-HMAC-SHA256 Credential=test,SignedHeaders=host;x-amz-date;x-agent-auth-audience,Signature=slow"
                        .to_string(),
                ),
                ("x-amz-date".to_string(), "20260812T000000Z".to_string()),
                (
                    "x-agent-auth-audience".to_string(),
                    "https://auth.example.com".to_string(),
                ),
            ]),
            body: "Action=GetCallerIdentity&Version=2011-06-15".to_string(),
        };

        let started = Instant::now();
        let result = caller.get_caller_identity(&assertion).await;
        assert!(
            matches!(result, Err(StoreError::Transient(_))),
            "slow STS dependency must surface as a retryable timeout: {result:?}"
        );
        assert!(
            started.elapsed() >= Duration::from_millis(1_500)
                && started.elapsed() < Duration::from_millis(3_500),
            "production caller must enforce its two-second deadline: {:?}",
            started.elapsed()
        );
        server.abort();
    }
}
