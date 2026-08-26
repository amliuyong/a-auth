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

    fn key(
        tenant_id: &str,
        upstream_idp_id: &str,
    ) -> HashMap<String, aws_sdk_dynamodb::types::AttributeValue> {
        HashMap::from([
            (
                "tenant_id".to_string(),
                AttributeValue::S(tenant_id.to_string()),
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
        Ok(HashMap::from([
            (
                "tenant_id".to_string(),
                AttributeValue::S(config.tenant_id.clone()),
            ),
            (
                "upstream_idp_id".to_string(),
                AttributeValue::S(config.upstream_idp_id.clone()),
            ),
            (
                "config_json".to_string(),
                AttributeValue::S(Self::config_json(config)?),
            ),
        ]))
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
            .key("tenant_id", AttributeValue::S(tenant_id.to_string()))
            .key(
                "upstream_idp_id",
                AttributeValue::S(upstream_idp_id.to_string()),
            )
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
                .expression_attribute_values(":t", AttributeValue::S(tenant_id.to_string()))
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
            .key("tenant_id", AttributeValue::S(tenant_id.to_string()))
            .key(
                "upstream_idp_id",
                AttributeValue::S(upstream_idp_id.to_string()),
            )
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
                .expression_attribute_values(":tenant", AttributeValue::S(tenant_id.to_string()))
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
                    .key("tenant_id", AttributeValue::S(tenant_id.to_string()))
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
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllOld)
            .send()
            .await
            .map_err(ddb_err)?;
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

/// 平台 JWKS HTTP 取用(spec 012 workload_oidc_jwt),带 **TTL 缓存 + 负缓存 + 限速**(评审 M3:
/// 防 unknown-kid 触发的重取放大成 DoS)。rustls;只 GET 管理面登记的 `jwks_uri`(调用方保证,绝不取
/// JWT header 的 jku/x5u)。缓存键 = jwks_uri。
/// 正/负缓存共用:空 vec 即成功获取的空集。每个 URI 自带异步锁,并发冷取/强刷等待同一结果。
struct JwksCacheEntry {
    keys: Vec<crate::ports::PlatformJwk>,
    fetched_at: Option<i64>,
    last_forced_at: Option<i64>,
    last_failure: Option<(StoreError, i64)>,
    last_used_at: i64,
    refresh_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
}

type JwksCache = std::sync::Arc<tokio::sync::Mutex<HashMap<String, JwksCacheEntry>>>;

#[derive(Clone)]
pub struct HttpJwksFetcher {
    cache: JwksCache,
    #[cfg(test)]
    network_requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Default for HttpJwksFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpJwksFetcher {
    pub fn new() -> Self {
        HttpJwksFetcher {
            cache: std::sync::Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            #[cfg(test)]
            network_requests: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}

/// JWKS 缓存 TTL(秒):正缓存 5min(平台 key 轮换慢);负缓存/限速窗同用,防重取风暴。
const JWKS_CACHE_TTL: i64 = 300;
const JWKS_FORCE_REFRESH_MIN_INTERVAL: i64 = 5;
const JWKS_MAX_CACHE_ENTRIES: usize = 256;
const JWKS_MAX_RESPONSE_BYTES: usize = 64 * 1024;
const JWKS_MAX_KEYS: usize = 10;
const JWKS_DNS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

impl HttpJwksFetcher {
    fn evict_oldest_if_full(
        cache: &mut HashMap<String, JwksCacheEntry>,
        incoming_uri: &str,
    ) -> Result<(), StoreError> {
        if cache.contains_key(incoming_uri) || cache.len() < JWKS_MAX_CACHE_ENTRIES {
            return Ok(());
        }
        if let Some(oldest) = cache
            .iter()
            .filter(|(_, entry)| std::sync::Arc::strong_count(&entry.refresh_lock) == 1)
            .min_by_key(|(_, entry)| entry.last_used_at)
            .map(|(uri, _)| uri.clone())
        {
            cache.remove(&oldest);
            return Ok(());
        }
        Err(StoreError::Transient(
            "JWKS cache capacity is busy".to_string(),
        ))
    }

    async fn cached_result(
        &self,
        jwks_uri: &str,
        honor_cache_ttl: bool,
    ) -> Option<Result<Vec<crate::ports::PlatformJwk>, StoreError>> {
        let now = crate::token::current_unix_secs_pub();
        let mut cache = self.cache.lock().await;
        if let Some(entry) = cache.get_mut(jwks_uri) {
            entry.last_used_at = now;
            let recently_fetched = if honor_cache_ttl {
                entry
                    .fetched_at
                    .is_some_and(|at| now.saturating_sub(at) < JWKS_CACHE_TTL)
            } else {
                entry
                    .last_forced_at
                    .is_some_and(|at| now.saturating_sub(at) < JWKS_FORCE_REFRESH_MIN_INTERVAL)
            };
            if recently_fetched {
                if !honor_cache_ttl {
                    if let Some((error, failed_at)) = &entry.last_failure {
                        if entry
                            .last_forced_at
                            .is_some_and(|forced_at| *failed_at >= forced_at)
                        {
                            return Some(Err(error.clone()));
                        }
                    }
                }
                return Some(Ok(entry.keys.clone()));
            }
            if let Some((error, failed_at)) = &entry.last_failure {
                if now.saturating_sub(*failed_at) < JWKS_FORCE_REFRESH_MIN_INTERVAL {
                    return Some(Err(error.clone()));
                }
            }
        }
        None
    }

    async fn refresh_lock_for_uri(
        &self,
        jwks_uri: &str,
    ) -> Result<std::sync::Arc<tokio::sync::Mutex<()>>, StoreError> {
        let now = crate::token::current_unix_secs_pub();
        let mut cache = self.cache.lock().await;
        if let Some(entry) = cache.get_mut(jwks_uri) {
            entry.last_used_at = now;
            return Ok(entry.refresh_lock.clone());
        }
        Self::evict_oldest_if_full(&mut cache, jwks_uri)?;
        let refresh_lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
        cache.insert(
            jwks_uri.to_string(),
            JwksCacheEntry {
                keys: Vec::new(),
                fetched_at: None,
                last_forced_at: None,
                last_failure: None,
                last_used_at: now,
                refresh_lock: refresh_lock.clone(),
            },
        );
        Ok(refresh_lock)
    }

    async fn store_network_result(
        &self,
        jwks_uri: &str,
        forced: bool,
        result: &Result<Vec<crate::ports::PlatformJwk>, StoreError>,
    ) {
        let now = crate::token::current_unix_secs_pub();
        let mut cache = self.cache.lock().await;
        let Some(entry) = cache.get_mut(jwks_uri) else {
            return;
        };
        entry.last_used_at = now;
        if forced {
            entry.last_forced_at = Some(now);
        }
        match result {
            Ok(keys) => {
                entry.keys = keys.clone();
                entry.fetched_at = Some(now);
                entry.last_failure = None;
            }
            Err(error) => {
                entry.last_failure = Some((error.clone(), now));
            }
        }
    }

    async fn fetch_cached(
        &self,
        jwks_uri: &str,
        honor_cache_ttl: bool,
    ) -> Result<Vec<crate::ports::PlatformJwk>, StoreError> {
        if let Some(result) = self.cached_result(jwks_uri, honor_cache_ttl).await {
            return result;
        }
        let refresh_lock = self.refresh_lock_for_uri(jwks_uri).await?;
        let _refresh_guard = refresh_lock.lock().await;
        // 跟随者拿锁后复查 owner 已写入的成功/失败结果,不重复外呼。
        if let Some(result) = self.cached_result(jwks_uri, honor_cache_ttl).await {
            return result;
        }
        let result = self.fetch_network(jwks_uri).await;
        self.store_network_result(jwks_uri, !honor_cache_ttl, &result)
            .await;
        result
    }

    /// 外呼取一次；调用方持有该 URI 的 refresh lock 并负责写缓存结果。
    async fn fetch_network(
        &self,
        jwks_uri: &str,
    ) -> Result<Vec<crate::ports::PlatformJwk>, StoreError> {
        #[cfg(test)]
        self.network_requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        agent_auth_ciba::validate_endpoint_url(jwks_uri, None)
            .map_err(|_| StoreError::Permanent("JWKS URI blocked by SSRF policy".to_string()))?;
        let url = reqwest::Url::parse(jwks_uri)
            .map_err(|_| StoreError::Permanent("invalid JWKS URI".to_string()))?;
        let host = url
            .host_str()
            .ok_or_else(|| StoreError::Permanent("invalid JWKS host".to_string()))?
            .to_string();
        let port = url.port_or_known_default().unwrap_or(443);
        let addrs: Vec<std::net::SocketAddr> = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            vec![std::net::SocketAddr::new(ip, port)]
        } else {
            tokio::time::timeout(
                JWKS_DNS_TIMEOUT,
                tokio::net::lookup_host((host.as_str(), port)),
            )
            .await
            .map_err(|_| StoreError::Transient("JWKS DNS timeout".to_string()))?
            .map_err(|e| StoreError::Transient(format!("JWKS DNS: {e}")))?
            .collect()
        };
        let ips: Vec<std::net::IpAddr> = addrs.iter().map(|address| address.ip()).collect();
        if !agent_auth_ciba::resolved_ips_allowed(&ips) {
            return Err(StoreError::Permanent(
                "JWKS host blocked by SSRF policy".to_string(),
            ));
        }
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(&host, &[addrs[0]])
            .no_proxy()
            .build()
            .map_err(|e| StoreError::Permanent(format!("JWKS client: {e}")))?;
        let mut resp = client
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| StoreError::Transient(format!("JWKS GET: {e}")))?;
        if !resp.status().is_success() {
            return Err(StoreError::Transient(format!(
                "JWKS GET status {}",
                resp.status()
            )));
        }
        if resp
            .content_length()
            .is_some_and(|length| length > JWKS_MAX_RESPONSE_BYTES as u64)
        {
            return Err(StoreError::Permanent(
                "JWKS response exceeds size limit".to_string(),
            ));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| StoreError::Transient(format!("JWKS body: {e}")))?
        {
            if body.len() + chunk.len() > JWKS_MAX_RESPONSE_BYTES {
                return Err(StoreError::Permanent(
                    "JWKS response exceeds size limit".to_string(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        parse_jwks_document(&body)
    }
}

impl crate::ports::JwksFetcher for HttpJwksFetcher {
    async fn fetch(&self, jwks_uri: &str) -> Result<Vec<crate::ports::PlatformJwk>, StoreError> {
        self.fetch_cached(jwks_uri, true).await
    }

    async fn fetch_fresh(
        &self,
        jwks_uri: &str,
    ) -> Result<Vec<crate::ports::PlatformJwk>, StoreError> {
        self.fetch_cached(jwks_uri, false).await
    }
}

fn parse_jwks_document(body: &[u8]) -> Result<Vec<crate::ports::PlatformJwk>, StoreError> {
    if body.len() > JWKS_MAX_RESPONSE_BYTES {
        return Err(StoreError::Permanent(
            "JWKS response exceeds size limit".to_string(),
        ));
    }
    let doc: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| StoreError::Permanent(format!("JWKS json: {e}")))?;
    let source = doc
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| StoreError::Permanent("JWKS keys must be an array".to_string()))?;
    if source.len() > JWKS_MAX_KEYS {
        return Err(StoreError::Permanent(
            "JWKS key count exceeds limit".to_string(),
        ));
    }
    Ok(source
        .iter()
        .filter_map(|key| {
            let allows_verification = key
                .get("use")
                .is_none_or(|value| value.as_str() == Some("sig"))
                && match key.get("key_ops") {
                    None => true,
                    Some(serde_json::Value::Array(operations)) => operations
                        .iter()
                        .any(|operation| operation.as_str() == Some("verify")),
                    Some(_) => false,
                };
            if !allows_verification {
                return None;
            }
            let kty = key.get("kty").and_then(serde_json::Value::as_str);
            let kid = key
                .get("kid")
                .and_then(serde_json::Value::as_str)
                .map(String::from);
            let alg = key
                .get("alg")
                .and_then(serde_json::Value::as_str)
                .map(String::from);
            match kty {
                Some("RSA") => Some(crate::ports::PlatformJwk {
                    kid,
                    kty: Some("RSA".into()),
                    n: key
                        .get("n")
                        .and_then(serde_json::Value::as_str)?
                        .to_string(),
                    e: key
                        .get("e")
                        .and_then(serde_json::Value::as_str)?
                        .to_string(),
                    crv: None,
                    x: None,
                    y: None,
                    alg,
                }),
                Some("EC")
                    if key.get("crv").and_then(serde_json::Value::as_str) == Some("P-256") =>
                {
                    Some(crate::ports::PlatformJwk {
                        kid,
                        kty: Some("EC".into()),
                        n: String::new(),
                        e: String::new(),
                        crv: Some("P-256".into()),
                        x: Some(
                            key.get("x")
                                .and_then(serde_json::Value::as_str)?
                                .to_string(),
                        ),
                        y: Some(
                            key.get("y")
                                .and_then(serde_json::Value::as_str)?
                                .to_string(),
                        ),
                        alg,
                    })
                }
                _ => None,
            }
        })
        .collect())
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

/// 真机上游 token 交换器(spec 003 §4,联邦/Admin OIDC RP code→token)。每次请求重新解析已登记的
/// HTTPS endpoint，拒绝私网/保留地址，禁止代理和重定向，并把连接钉到校验过的 IP，避免配置型 SSRF
/// 与 DNS rebinding。硬超时 3s；响应体有界。client_secret_basic 的明文只在调用栈内存活。
#[derive(Clone)]
pub struct HttpUpstreamTokenExchanger;

impl Default for HttpUpstreamTokenExchanger {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpUpstreamTokenExchanger {
    pub fn new() -> Self {
        Self
    }

    async fn pinned_client(token_endpoint: &str) -> Result<reqwest::Client, StoreError> {
        agent_auth_ciba::validate_endpoint_url(token_endpoint, None).map_err(|_| {
            StoreError::Permanent("upstream token endpoint blocked by SSRF policy".to_string())
        })?;
        let url = reqwest::Url::parse(token_endpoint)
            .map_err(|_| StoreError::Permanent("invalid upstream token endpoint".to_string()))?;
        let host = url
            .host_str()
            .ok_or_else(|| StoreError::Permanent("invalid upstream token host".to_string()))?
            .to_string();
        let port = url.port_or_known_default().unwrap_or(443);
        let addrs: Vec<std::net::SocketAddr> = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            vec![std::net::SocketAddr::new(ip, port)]
        } else {
            tokio::time::timeout(
                JWKS_DNS_TIMEOUT,
                tokio::net::lookup_host((host.as_str(), port)),
            )
            .await
            .map_err(|_| StoreError::Transient("upstream token DNS timeout".to_string()))?
            .map_err(|error| {
                StoreError::Transient(format!("upstream token DNS resolution: {error}"))
            })?
            .collect()
        };
        let Some(pinned) = addrs.first().copied() else {
            return Err(StoreError::Transient(
                "upstream token DNS returned no addresses".to_string(),
            ));
        };
        let ips: Vec<std::net::IpAddr> = addrs.iter().map(|address| address.ip()).collect();
        if !agent_auth_ciba::resolved_ips_allowed(&ips) {
            return Err(StoreError::Permanent(
                "upstream token host blocked by SSRF policy".to_string(),
            ));
        }
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(&host, &[pinned])
            .no_proxy()
            .build()
            .map_err(|error| StoreError::Permanent(format!("upstream token HTTP client: {error}")))
    }
}

const UPSTREAM_TOKEN_MAX_RESPONSE_BYTES: usize = 128 * 1024;

impl crate::ports::UpstreamTokenExchanger for HttpUpstreamTokenExchanger {
    async fn exchange_code(
        &self,
        req: &crate::ports::UpstreamTokenExchangeRequest<'_>,
    ) -> Result<Option<crate::ports::UpstreamTokenSet>, StoreError> {
        // RFC 6749 §4.1.3 授权码交换 form + PKCE code_verifier;client 认证走 basic(§2.3.1)。
        // client_id 也放 body(部分上游 basic + body 双要;冗余无害)。
        let form = [
            ("grant_type", "authorization_code"),
            ("code", req.code),
            ("redirect_uri", req.redirect_uri),
            ("code_verifier", req.code_verifier),
            ("client_id", req.client_id),
        ];
        let client = Self::pinned_client(req.token_endpoint).await?;
        let mut resp = client
            .post(req.token_endpoint) // URL 来自登记 config(SSRF 防线,已 validate https)
            .basic_auth(req.client_id, Some(req.client_secret))
            .form(&form)
            .send()
            .await
            .map_err(|e| StoreError::Transient(format!("upstream token POST: {e}")))?;
        let status = resp.status();
        if status.is_server_error() {
            return Err(StoreError::Transient(format!(
                "upstream token 5xx {status}"
            )));
        }
        if !status.is_success() {
            return Ok(None); // 4xx:上游拒(code 无效/client 认证失败)→ 登录失败,非重试
        }
        if resp
            .content_length()
            .is_some_and(|length| length > UPSTREAM_TOKEN_MAX_RESPONSE_BYTES as u64)
        {
            return Err(StoreError::Permanent(
                "upstream token response exceeds size limit".to_string(),
            ));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|error| StoreError::Transient(format!("upstream token body: {error}")))?
        {
            if body.len() + chunk.len() > UPSTREAM_TOKEN_MAX_RESPONSE_BYTES {
                return Err(StoreError::Permanent(
                    "upstream token response exceeds size limit".to_string(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        // 解析 JSON;缺 id_token 或解析失败 = 响应异常 → Ok(None)(fail-closed,不臆测)。
        let v: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let Some(id_token) = v.get("id_token").and_then(|x| x.as_str()) else {
            return Ok(None); // OIDC 换 token 必带 id_token;缺 = 异常
        };
        Ok(Some(crate::ports::UpstreamTokenSet {
            id_token: id_token.to_string(),
            access_token: v
                .get("access_token")
                .and_then(|x| x.as_str())
                .map(String::from),
        }))
    }
}

#[cfg(test)]
mod upstream_token_exchanger_tests {
    use super::HttpUpstreamTokenExchanger;
    use crate::ports::{StoreError, UpstreamTokenExchangeRequest, UpstreamTokenExchanger};

    #[tokio::test]
    async fn private_and_metadata_token_endpoints_are_blocked_before_network_io() {
        let exchanger = HttpUpstreamTokenExchanger::new();
        for endpoint in [
            "https://127.0.0.1/token",
            "https://169.254.169.254/latest/token",
        ] {
            let result = exchanger
                .exchange_code(&UpstreamTokenExchangeRequest {
                    token_endpoint: endpoint,
                    client_id: "client",
                    client_secret: "secret",
                    code: "code",
                    code_verifier: "verifier",
                    redirect_uri: "https://rp.example.com/callback",
                })
                .await;
            assert!(
                matches!(result, Err(StoreError::Permanent(_))),
                "{endpoint} must fail the SSRF policy before a request is sent"
            );
        }
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
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllOld)
            .send()
            .await
            .map_err(ddb_err)?;
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
    use super::{
        parse_jwks_document, DynamoAdminAuthStore, HttpJwksFetcher, JwksCacheEntry,
        JWKS_MAX_CACHE_ENTRIES, JWKS_MAX_KEYS, JWKS_MAX_RESPONSE_BYTES,
    };
    use crate::ports::{
        AdminAuthStore, AdminOidcFlow, AdminSessionRecord, JwksFetcher, PlatformJwk, StoreError,
        TenantRole,
    };
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

    #[test]
    fn parser_enforces_response_and_key_count_limits() {
        assert!(matches!(
            parse_jwks_document(&vec![b' '; JWKS_MAX_RESPONSE_BYTES + 1]),
            Err(StoreError::Permanent(_))
        ));
        let keys: Vec<serde_json::Value> = (0..=JWKS_MAX_KEYS)
            .map(|index| {
                serde_json::json!({
                    "kid": format!("key-{index}"),
                    "kty": "RSA",
                    "alg": "RS256",
                    "n": "modulus",
                    "e": "AQAB"
                })
            })
            .collect();
        assert!(matches!(
            parse_jwks_document(&serde_json::to_vec(&serde_json::json!({ "keys": keys })).unwrap()),
            Err(StoreError::Permanent(_))
        ));
    }

    #[test]
    fn parser_excludes_keys_not_allowed_for_signature_verification() {
        let rsa_key = |kid: &str| {
            serde_json::json!({
                "kid": kid,
                "kty": "RSA",
                "alg": "RS256",
                "n": "modulus",
                "e": "AQAB"
            })
        };
        let mut encryption_use = rsa_key("encryption-use");
        encryption_use["use"] = serde_json::json!("enc");
        let mut encryption_ops = rsa_key("encryption-ops");
        encryption_ops["key_ops"] = serde_json::json!(["encrypt"]);
        let mut malformed_ops = rsa_key("malformed-ops");
        malformed_ops["key_ops"] = serde_json::json!("verify");
        let mut verification_ops = rsa_key("verification-ops");
        verification_ops["key_ops"] = serde_json::json!(["verify"]);
        let parsed = parse_jwks_document(
            &serde_json::to_vec(&serde_json::json!({
                "keys": [
                    rsa_key("unspecified"),
                    encryption_use,
                    encryption_ops,
                    malformed_ops,
                    verification_ops
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            parsed
                .iter()
                .filter_map(|key| key.kid.as_deref())
                .collect::<Vec<_>>(),
            vec!["unspecified", "verification-ops"]
        );
    }

    #[tokio::test]
    async fn fetcher_blocks_literal_private_targets_before_network_io() {
        let fetcher = HttpJwksFetcher::new();
        assert!(matches!(
            fetcher.fetch("https://127.0.0.1/jwks").await,
            Err(StoreError::Permanent(_))
        ));
        assert!(matches!(
            fetcher.fetch("https://169.254.169.254/latest").await,
            Err(StoreError::Permanent(_))
        ));
    }

    #[tokio::test]
    async fn concurrent_force_refreshes_share_one_network_failure() {
        let fetcher = HttpJwksFetcher::new();
        let uri = "https://127.0.0.1/jwks";
        let mut attempts = Vec::new();
        for _ in 0..16 {
            let fetcher = fetcher.clone();
            attempts.push(tokio::spawn(async move { fetcher.fetch_fresh(uri).await }));
        }
        for attempt in attempts {
            assert!(attempt.await.unwrap().is_err());
        }
        assert_eq!(
            fetcher
                .network_requests
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "并发 unknown-kid 强刷应等待并共享一次外呼结果"
        );
    }

    #[tokio::test]
    async fn failed_force_refresh_preserves_cached_key_ttl_and_starts_cooldown_on_completion() {
        let fetcher = HttpJwksFetcher::new();
        let uri = "https://127.0.0.1/jwks";
        let fetched_at = crate::token::current_unix_secs_pub() - 60;
        fetcher.cache.lock().await.insert(
            uri.to_string(),
            JwksCacheEntry {
                keys: vec![PlatformJwk {
                    kid: Some("known-key".to_string()),
                    ..Default::default()
                }],
                fetched_at: Some(fetched_at),
                last_forced_at: None,
                last_failure: None,
                last_used_at: fetched_at,
                refresh_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            },
        );

        let before = crate::token::current_unix_secs_pub();
        assert!(fetcher.fetch_fresh(uri).await.is_err());
        {
            let cache = fetcher.cache.lock().await;
            let entry = cache.get(uri).unwrap();
            assert_eq!(entry.fetched_at, Some(fetched_at));
            assert!(
                entry
                    .last_failure
                    .as_ref()
                    .is_some_and(|(_, failed_at)| *failed_at >= before),
                "失败冷却应从外呼完成时开始且不得延长旧 key TTL"
            );
        }
        assert_eq!(
            fetcher.fetch(uri).await.unwrap()[0].kid.as_deref(),
            Some("known-key"),
            "failed unknown-kid refresh must not hide a still-valid cached key"
        );
        assert!(fetcher.fetch_fresh(uri).await.is_err());
        assert_eq!(
            fetcher
                .network_requests
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "forced refresh failures must be rate-limited during the cooldown"
        );
    }

    #[tokio::test]
    async fn ordinary_fetch_timestamp_does_not_suppress_forced_refresh() {
        let fetcher = HttpJwksFetcher::new();
        let uri = "https://127.0.0.1/jwks";
        let fetched_at = crate::token::current_unix_secs_pub();
        fetcher.cache.lock().await.insert(
            uri.to_string(),
            JwksCacheEntry {
                keys: Vec::new(),
                fetched_at: Some(fetched_at),
                last_forced_at: None,
                last_failure: None,
                last_used_at: fetched_at,
                refresh_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            },
        );

        assert!(fetcher.fetch_fresh(uri).await.is_err());
        assert_eq!(
            fetcher
                .network_requests
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "a recent ordinary fetch must not count as the unknown-kid forced attempt"
        );
    }

    #[tokio::test]
    async fn concurrent_cold_fetches_make_one_network_attempt_and_cache_the_failure() {
        let fetcher = HttpJwksFetcher::new();
        let uri = "https://127.0.0.1/jwks";
        let mut attempts = Vec::new();
        for _ in 0..16 {
            let fetcher = fetcher.clone();
            attempts.push(tokio::spawn(async move { fetcher.fetch(uri).await }));
        }
        for attempt in attempts {
            assert!(attempt.await.unwrap().is_err());
        }
        assert_eq!(
            fetcher
                .network_requests
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert!(fetcher.fetch(uri).await.is_err());
        assert_eq!(
            fetcher
                .network_requests
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "失败结果应在限速窗内负缓存"
        );
    }

    #[tokio::test]
    async fn cache_entry_count_is_bounded() {
        let fetcher = HttpJwksFetcher::new();
        for index in 0..=JWKS_MAX_CACHE_ENTRIES {
            assert!(fetcher
                .refresh_lock_for_uri(&format!("https://keys-{index}.example.com/jwks"))
                .await
                .is_ok());
        }
        assert_eq!(fetcher.cache.lock().await.len(), JWKS_MAX_CACHE_ENTRIES);
    }

    #[tokio::test]
    async fn cache_does_not_evict_entries_with_active_refresh_callers() {
        let fetcher = HttpJwksFetcher::new();
        let mut active_locks = Vec::new();
        for index in 0..JWKS_MAX_CACHE_ENTRIES {
            active_locks.push(
                fetcher
                    .refresh_lock_for_uri(&format!("https://keys-{index}.example.com/jwks"))
                    .await
                    .unwrap(),
            );
        }
        assert!(matches!(
            fetcher
                .refresh_lock_for_uri("https://overflow.example.com/jwks")
                .await,
            Err(StoreError::Transient(_))
        ));
        assert_eq!(fetcher.cache.lock().await.len(), JWKS_MAX_CACHE_ENTRIES);
        drop(active_locks);
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
