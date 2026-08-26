//! AWS authorization, grants, replay, and anti-abuse adapters.

use super::*;

/// DynamoDB 授权会话存储(spec 004)。表主键 = `session_id`(S);GSI `client_id-index`(PK=client_id)
/// 支撑 `list_by_client`。transition 用带 `sequence` 的乐观并发条件写(读→改→条件写),并在应用层
/// 用纯逻辑判终态/合法迁移;并发只一个成功(防重复迁移)。
#[derive(Clone)]
pub struct DynamoAuthzSessionStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
    pub(super) client_index: String,
}

impl DynamoAuthzSessionStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        DynamoAuthzSessionStore {
            db,
            table: table.into(),
            client_index: "client_id-index".to_string(),
        }
    }

    fn to_item(tenant: &str, r: &AuthzSessionRecord) -> HashMap<String, AttributeValue> {
        // pk session_id + GSI client_id 值 tenant 化(codex Blocker:list_by_client 跨租户隔离)。
        let mut m = HashMap::from([
            (
                "session_id".to_string(),
                AttributeValue::S(tpk(tenant, &r.session_id)),
            ),
            (
                "client_id".to_string(),
                AttributeValue::S(tpk(tenant, &r.client_id)),
            ),
            ("state".to_string(), AttributeValue::S(r.state.clone())),
            (
                "session_token_hash".to_string(),
                AttributeValue::S(r.session_token_hash.clone()),
            ),
            (
                "sequence".to_string(),
                AttributeValue::N(r.sequence.to_string()),
            ),
            (
                "expires_at".to_string(),
                AttributeValue::N(r.expires_at.to_string()),
            ),
        ]);
        if let Some(user_id) = &r.user_id {
            m.insert(
                "user_id".to_string(),
                AttributeValue::S(tpk(tenant, user_id)),
            );
        }
        if let Some(le) = &r.last_error {
            m.insert("last_error".to_string(), AttributeValue::S(le.clone()));
        }
        m
    }

    fn from_item(item: &HashMap<String, AttributeValue>) -> AuthzSessionRecord {
        AuthzSessionRecord {
            session_id: strip_tpk(&s(item.get("session_id")).unwrap_or_default()),
            client_id: strip_tpk(&s(item.get("client_id")).unwrap_or_default()),
            user_id: s(item.get("user_id")).map(|user_id| strip_tpk(&user_id)),
            state: s(item.get("state")).unwrap_or_default(),
            session_token_hash: s(item.get("session_token_hash")).unwrap_or_default(),
            sequence: n_u64(item.get("sequence")).unwrap_or(0),
            last_error: s(item.get("last_error")),
            expires_at: n_i64(item.get("expires_at")).unwrap_or(0),
        }
    }

    async fn transition_with_clock<N>(
        &self,
        tenant: &str,
        session_id: &str,
        new_state: &str,
        last_error: Option<String>,
        now: i64,
        clock: N,
    ) -> Result<Option<AuthzSessionRecord>, StoreError>
    where
        N: Fn() -> i64,
    {
        use agent_auth_authn::authz_session::AuthzState;

        const MAX_RETRY: u32 = 5;
        for _ in 0..MAX_RETRY {
            let Some(rec) = self.get(tenant, session_id).await? else {
                return Ok(None);
            };
            let commit_now = now.max(clock());
            if agent_auth_infra_core::lifecycle::shortlived_is_expired(commit_now, rec.expires_at) {
                return Ok(None);
            }
            let (Some(from), Some(to)) =
                (AuthzState::parse(&rec.state), AuthzState::parse(new_state))
            else {
                return Ok(None);
            };
            if !from.can_transition_to(to) {
                return Ok(None);
            }
            let next_seq = rec.sequence + 1;
            let mut next = rec.clone();
            next.state = new_state.to_string();
            next.sequence = next_seq;
            if last_error.is_some() {
                next.last_error = last_error.clone();
            }
            let res = self
                .db
                .put_item()
                .table_name(&self.table)
                .set_item(Some(Self::to_item(tenant, &next)))
                .condition_expression("#seq = :cur AND expires_at > :now")
                .expression_attribute_names("#seq", "sequence")
                .expression_attribute_values(":cur", AttributeValue::N(rec.sequence.to_string()))
                .expression_attribute_values(":now", AttributeValue::N(commit_now.to_string()))
                .send()
                .await;
            match res {
                Ok(_) => return Ok(Some(next)),
                Err(e) => {
                    if e.code().unwrap_or("").contains("ConditionalCheckFailed") {
                        continue;
                    }
                    return Err(ddb_err(e));
                }
            }
        }
        Err(StoreError::Transient(
            "authz transition: too many CAS conflicts".into(),
        ))
    }
}

impl AuthzSessionStore for DynamoAuthzSessionStore {
    async fn create(&self, tenant: &str, record: AuthzSessionRecord) -> Result<(), StoreError> {
        self.db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(Self::to_item(tenant, &record)))
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(())
    }

    async fn get(
        &self,
        tenant: &str,
        session_id: &str,
    ) -> Result<Option<AuthzSessionRecord>, StoreError> {
        let out = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("session_id", AttributeValue::S(tpk(tenant, session_id)))
            // create_session writes `created` and immediately transitions it. An eventual
            // read here can miss that PutItem and strand the session in `created`.
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(out.item().map(Self::from_item))
    }

    async fn transition(
        &self,
        tenant: &str,
        session_id: &str,
        new_state: &str,
        last_error: Option<String>,
        now: i64,
    ) -> Result<Option<AuthzSessionRecord>, StoreError> {
        self.transition_with_clock(
            tenant,
            session_id,
            new_state,
            last_error,
            now,
            crate::token::current_unix_secs_pub,
        )
        .await
    }

    async fn bind_user(
        &self,
        tenant: &str,
        session_id: &str,
        user_id: &str,
        now: i64,
    ) -> Result<Option<AuthzSessionRecord>, StoreError> {
        let physical_user_id = tpk(tenant, user_id);
        let result = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("session_id", AttributeValue::S(tpk(tenant, session_id)))
            .update_expression("SET user_id = :user")
            .condition_expression(
                "attribute_exists(session_id) AND \
                 expires_at > :now AND \
                 (attribute_not_exists(user_id) OR user_id = :user)",
            )
            .expression_attribute_values(":user", AttributeValue::S(physical_user_id))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllNew)
            .send()
            .await;
        match result {
            Ok(output) => Ok(output.attributes().map(Self::from_item)),
            Err(error)
                if error
                    .code()
                    .unwrap_or("")
                    .contains("ConditionalCheckFailed") =>
            {
                Ok(self.get(tenant, session_id).await?.filter(|record| {
                    record.user_id.as_deref() == Some(user_id)
                        && agent_auth_infra_core::lifecycle::shortlived_is_valid(
                            now,
                            record.expires_at,
                        )
                }))
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn delete(&self, tenant: &str, session_id: &str) -> Result<(), StoreError> {
        self.db
            .delete_item()
            .table_name(&self.table)
            .key("session_id", AttributeValue::S(tpk(tenant, session_id)))
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(())
    }

    async fn list_by_client(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> Result<Vec<String>, StoreError> {
        let mut ids = Vec::new();
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let q = self
                .db
                .query()
                .table_name(&self.table)
                .index_name(&self.client_index)
                .key_condition_expression("client_id = :c")
                // GSI client_id 值 tenant 化 → 只列本租户会话(codex Blocker:跨租户 client_id 碰撞隔离)。
                .expression_attribute_values(":c", AttributeValue::S(tpk(tenant, client_id)))
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in q.items() {
                // session_id 是物理 pk;strip 回逻辑 id 给调用方(与 get/from_item 一致)。
                if let Some(id) = s(item.get("session_id")) {
                    ids.push(strip_tpk(&id));
                }
            }
            match q.last_evaluated_key() {
                Some(k) if !k.is_empty() => last_key = Some(k.clone()),
                _ => break,
            }
        }
        Ok(ids)
    }

    async fn count_active(&self, tenant: &str, now: i64) -> Result<usize, StoreError> {
        use agent_auth_authn::authz_session::AuthzState;
        // 分页 Scan;DDB 侧先按 expires_at > now 过滤未过期,终态判定用 authn 权威集在 Rust 侧做
        // (终态集是纯逻辑真相,不复制进 DDB 表达式)。量大改投影/计数器,见 spec 020。
        // **tenant 过滤**:空 tenant = 全局(现网单租户 / 控制面 overview);非空 = 仅该租户前缀。
        let want_prefix = if tenant.is_empty() {
            None
        } else {
            Some(format!("{tenant}\u{1f}"))
        };
        let mut count = 0usize;
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let scan = self
                .db
                .scan()
                .table_name(&self.table)
                .filter_expression("expires_at > :now")
                .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in scan.items() {
                let phys_sid = s(item.get("session_id")).unwrap_or_default();
                match &want_prefix {
                    Some(p) if !phys_sid.starts_with(p.as_str()) => continue,
                    None if phys_sid.contains('\u{1f}') => continue, // 空 tenant 排除他租户前缀行
                    _ => {}
                }
                let state = s(item.get("state")).unwrap_or_default();
                if AuthzState::parse(&state)
                    .map(|s| !s.is_terminal())
                    .unwrap_or(false)
                {
                    count += 1;
                }
            }
            match scan.last_evaluated_key() {
                Some(k) if !k.is_empty() => last_key = Some(k.clone()),
                _ => break,
            }
        }
        Ok(count)
    }

    async fn delete_by_client(&self, tenant: &str, client_id: &str) -> Result<usize, StoreError> {
        let session_ids = self.list_by_client(tenant, client_id).await?;
        for session_id in &session_ids {
            self.db
                .delete_item()
                .table_name(&self.table)
                .key("session_id", AttributeValue::S(tpk(tenant, session_id)))
                .send()
                .await
                .map_err(ddb_err)?;
        }
        Ok(session_ids.len())
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        governance_delete_by_tenant_key(&self.db, &self.table, "session_id", tenant).await
    }
}

/// DynamoDB PAR 存储(spec 006 §7.3,RFC 9126)。pk=request_uri;TTL=expires_at 只做 GC。
/// consume = 条件删(DeleteItem ReturnValues=ALL_OLD 一次性)+ **fail-closed 校 expires_at**(不靠 TTL,H4/C10.4)。
#[derive(Clone)]
pub struct DynamoParStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
}

impl DynamoParStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        DynamoParStore {
            db,
            table: table.into(),
        }
    }
}

impl crate::ports::ParStore for DynamoParStore {
    async fn put(&self, tenant: &str, record: crate::ports::ParRecord) -> Result<(), StoreError> {
        let item = HashMap::from([
            (
                "request_uri".to_string(),
                AttributeValue::S(tpk(tenant, &record.request_uri)),
            ),
            ("client_id".to_string(), AttributeValue::S(record.client_id)),
            (
                "raw_params".to_string(),
                AttributeValue::S(record.raw_params),
            ),
            (
                "expires_at".to_string(),
                AttributeValue::N(record.expires_at.to_string()),
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
        tenant: &str,
        request_uri: &str,
        now: i64,
    ) -> Result<Option<crate::ports::ParRecord>, StoreError> {
        // 一次性:条件删取旧值。fail-closed:expires_at <= now 视作无效(不靠 TTL 惰性删,H4/C10.4)。
        let out = self
            .db
            .delete_item()
            .table_name(&self.table)
            .key("request_uri", AttributeValue::S(tpk(tenant, request_uri)))
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllOld)
            .send()
            .await
            .map_err(ddb_err)?;
        let Some(item) = out.attributes() else {
            return Ok(None); // 不存在/已消费
        };
        let exp = n_i64(item.get("expires_at")).unwrap_or(0);
        if exp <= now {
            return Ok(None); // 过期(已删,fail-closed)
        }
        Ok(Some(crate::ports::ParRecord {
            request_uri: s(item.get("request_uri"))
                .map(|value| strip_tpk(&value))
                .unwrap_or_default(),
            client_id: s(item.get("client_id")).unwrap_or_default(),
            raw_params: s(item.get("raw_params")).unwrap_or_default(),
            expires_at: exp,
        }))
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        governance_delete_by_tenant_key(&self.db, &self.table, "request_uri", tenant).await
    }
}

/// DynamoDB BYOD 域名映射(spec 010 §5.4 / C8.1b)。**主键 = `domain`(归一小写,全局键,非 tenant 分区)**——
/// BYOD host 查前解不出 tenant,且全局键 + conditional put 保 fleet 全局域名唯一(防跨租户抢注)。
#[derive(Clone)]
pub struct DynamoDomainMapStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
}

impl DynamoDomainMapStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        DynamoDomainMapStore {
            db,
            table: table.into(),
        }
    }
}

impl crate::ports::DomainMapStore for DynamoDomainMapStore {
    async fn get(&self, domain: &str) -> Result<Option<crate::ports::DomainBinding>, StoreError> {
        let out = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("domain", AttributeValue::S(domain.to_ascii_lowercase()))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        let Some(item) = out.item() else {
            return Ok(None);
        };
        Ok(Some(crate::ports::DomainBinding {
            domain: s(item.get("domain")).unwrap_or_default(),
            resource_id: s(item.get("resource_id")).unwrap_or_default(),
            tenant_id: s(item.get("tenant_id")).unwrap_or_default(),
            client_id: s(item.get("client_id")).unwrap_or_default(),
        }))
    }
    async fn put_if_absent(
        &self,
        binding: crate::ports::DomainBinding,
    ) -> Result<bool, StoreError> {
        // conditional put:仅当 domain 未被任何租户登记(全局唯一;attribute_not_exists 保先到先得防抢注)。
        let key = binding.domain.to_ascii_lowercase();
        let item = HashMap::from([
            ("domain".to_string(), AttributeValue::S(key)),
            (
                "resource_id".to_string(),
                AttributeValue::S(binding.resource_id),
            ),
            (
                "tenant_id".to_string(),
                AttributeValue::S(binding.tenant_id),
            ),
            (
                "client_id".to_string(),
                AttributeValue::S(binding.client_id),
            ),
        ]);
        let res = self
            .db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(#d)")
            .expression_attribute_names("#d", "domain")
            .send()
            .await;
        match res {
            Ok(_) => Ok(true),
            Err(e) if e.code().unwrap_or("").contains("ConditionalCheckFailed") => Ok(false),
            Err(e) => Err(ddb_err(e)),
        }
    }
    async fn delete_if_owner(&self, domain: &str, client_id: &str) -> Result<bool, StoreError> {
        // CAS on owner:仅当记录存在且 client_id 匹配才删(防删他人 / 换租户悬空返错 issuer)。
        let res = self
            .db
            .delete_item()
            .table_name(&self.table)
            .key("domain", AttributeValue::S(domain.to_ascii_lowercase()))
            .condition_expression("attribute_exists(#d) AND client_id = :c")
            .expression_attribute_names("#d", "domain")
            .expression_attribute_values(":c", AttributeValue::S(client_id.to_string()))
            .send()
            .await;
        match res {
            Ok(_) => Ok(true),
            Err(e) if e.code().unwrap_or("").contains("ConditionalCheckFailed") => Ok(false),
            Err(e) => Err(ddb_err(e)),
        }
    }
    async fn list_by_client(
        &self,
        client_id: &str,
    ) -> Result<Vec<crate::ports::DomainBinding>, StoreError> {
        // 反查 owner 的全部绑定(删 client 级联权威源,评审 M1/L3):走 client_id-index GSI(标量键可索引)。
        // ProjectionType ALL → 直接从 GSI item 组装 DomainBinding(不回主表)。分页收全(域名数极少,通常 1 页)。
        let mut out = Vec::new();
        let mut last_key = None;
        loop {
            let mut q = self
                .db
                .query()
                .table_name(&self.table)
                .index_name("client_id-index")
                .key_condition_expression("client_id = :c")
                .expression_attribute_values(":c", AttributeValue::S(client_id.to_string()));
            if let Some(k) = last_key {
                q = q.set_exclusive_start_key(Some(k));
            }
            let resp = q.send().await.map_err(ddb_err)?;
            for item in resp.items() {
                out.push(crate::ports::DomainBinding {
                    domain: s(item.get("domain")).unwrap_or_default(),
                    resource_id: s(item.get("resource_id")).unwrap_or_default(),
                    tenant_id: s(item.get("tenant_id")).unwrap_or_default(),
                    client_id: s(item.get("client_id")).unwrap_or_default(),
                });
            }
            match resp.last_evaluated_key() {
                Some(k) if !k.is_empty() => last_key = Some(k.clone()),
                _ => break,
            }
        }
        Ok(out)
    }

    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        let mut domains = Vec::new();
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let output = self
                .db
                .scan()
                .table_name(&self.table)
                .projection_expression("#domain")
                .filter_expression("tenant_id = :tenant")
                .expression_attribute_names("#domain", "domain")
                .expression_attribute_values(":tenant", AttributeValue::S(tenant_id.to_string()))
                .consistent_read(true)
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in output.items() {
                let domain = item.get("domain").cloned().ok_or_else(|| {
                    StoreError::Permanent("domain governance row is missing domain".into())
                })?;
                domains.push(domain);
            }
            match output.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }

        let mut deleted = 0usize;
        for domain in domains {
            let result = self
                .db
                .delete_item()
                .table_name(&self.table)
                .key("domain", domain)
                .condition_expression("tenant_id = :tenant")
                .expression_attribute_values(":tenant", AttributeValue::S(tenant_id.to_string()))
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

/// DynamoDB 一次性 replay 缓存(spec 012 C5.3②)。表主键 = `pk`(= replay key);TTL=expires_at 短命 GC。
/// check_and_set = 条件 PutItem(pk 不存在或已过期才写)。与 JtiTable 共表(不同 pk 前缀,复用短命表)。
#[derive(Clone)]
pub struct DynamoReplayStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
}

impl DynamoReplayStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        DynamoReplayStore {
            db,
            table: table.into(),
        }
    }
}

impl crate::ports::ReplayStore for DynamoReplayStore {
    async fn check_and_set(
        &self,
        tenant: &str,
        key: &str,
        expires_at: i64,
    ) -> Result<bool, StoreError> {
        // 条件写:pk 不存在 OR 现存项已过 TTL(懒过期,防 GC 延迟误拒)才写。写成功=首次(接受);
        // ConditionalCheckFailed=窗内已见(重放拒)。pk 加前缀避免与 JtiStore 的 pk 撞。
        let now = crate::token::current_unix_secs_pub();
        let pk = tpk(tenant, &format!("replay\u{1f}{key}"));
        let res = self
            .db
            .put_item()
            .table_name(&self.table)
            .item("pk", AttributeValue::S(pk))
            .item("expires_at", AttributeValue::N(expires_at.to_string()))
            .condition_expression("attribute_not_exists(pk) OR expires_at < :now")
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .send()
            .await;
        match res {
            Ok(_) => Ok(true),
            Err(e) if e.code().unwrap_or("").contains("ConditionalCheckFailed") => Ok(false),
            Err(e) => Err(ddb_err(e)),
        }
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let prefix = tpk(tenant, &format!("replay{}", crate::tenant::SEP));
        let mut keys = Vec::new();
        let mut last_key = None;
        loop {
            let scan = self
                .db
                .scan()
                .table_name(&self.table)
                .projection_expression("pk")
                .filter_expression("begins_with(pk, :prefix)")
                .expression_attribute_values(":prefix", AttributeValue::S(prefix.clone()))
                .consistent_read(true)
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            keys.extend(
                scan.items()
                    .iter()
                    .filter_map(|item| item.get("pk").cloned()),
            );
            match scan.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        for key in &keys {
            self.db
                .delete_item()
                .table_name(&self.table)
                .key("pk", key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
        }
        Ok(keys.len())
    }
}

/// DynamoDB Grant 存储(spec 011 §5.1)。表主键 = `grant_id`(S);GSI `user_id-index` 供用户自助列。
/// Grant 存为 serde JSON(`grant_json`),user_id 单独作 GSI 分区键。
#[derive(Clone)]
pub struct DynamoGrantStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
    clients_table: String,
    pub(super) user_index: String,
    pub(super) pv_index: String,
}

impl DynamoGrantStore {
    pub fn new(
        db: aws_sdk_dynamodb::Client,
        table: impl Into<String>,
        clients_table: impl Into<String>,
    ) -> Self {
        DynamoGrantStore {
            db,
            table: table.into(),
            clients_table: clients_table.into(),
            user_index: "user_id-index".to_string(),
            pv_index: "policy_version-index".to_string(),
        }
    }
    fn to_item(
        tenant: &str,
        g: &agent_auth_grant::Grant,
    ) -> Result<HashMap<String, AttributeValue>, StoreError> {
        // grant_json 存**逻辑** Grant(id 不带 tenant);仅 pk grant_id + GSI user_id 属性 tenant 化
        // (物理隔离 + by-user GSI 隔离,codex B1)。
        let json = serde_json::to_string(g)
            .map_err(|e| StoreError::Permanent(format!("serialize grant: {e}")))?;
        Ok(HashMap::from([
            (
                "grant_id".to_string(),
                AttributeValue::S(tpk(tenant, &g.grant_id)),
            ),
            (
                "user_id".to_string(),
                AttributeValue::S(tpk(tenant, &g.user_id)),
            ),
            // effective_pv 提升为**顶层属性**(spec 005 §7 补强 ⑩):blob 内字段无法建 GSI;重算 GSI
            // (pk=gv_tenant, sk=effective_pv)按此 Query stale。**GSI 分区键 MUST 非空**(DynamoDB 拒空串
            // key)——self-host tenant="" 若直接落空串会 ValidationException 整条写失败(评审 Blocker)。
            // 故用 `tpk(tenant,"gv")`:空 tenant→"gv"、真租户→"<t>\u{1f}gv",既非空又保持租户隔离,list_stale 同源。
            // 注:所有 Grant(含 flag 关、effective_pv=0)都进本 GSI(**非稀疏**)——重算按 effective_pv<current
            // Query 全表 stale 需要每条都可被索引;flag 关时 current_pv 恒 0 → 重算提前返回不扫,故无处置成本。
            (
                "gv_tenant".to_string(),
                AttributeValue::S(tpk(tenant, "gv")),
            ),
            (
                "effective_pv".to_string(),
                AttributeValue::N(g.effective_pv.to_string()),
            ),
            (
                "revision".to_string(),
                AttributeValue::N(g.revision.to_string()),
            ),
            (
                "credential_epoch".to_string(),
                AttributeValue::N(g.credential_epoch.to_string()),
            ),
            ("grant_json".to_string(), AttributeValue::S(json)),
        ]))
    }
    fn from_item(item: &HashMap<String, AttributeValue>) -> Option<agent_auth_grant::Grant> {
        let j = s(item.get("grant_json"))?;
        serde_json::from_str(&j).ok()
    }

    pub(crate) async fn put_for_active_client(
        &self,
        tenant: &str,
        grant: agent_auth_grant::Grant,
    ) -> Result<bool, StoreError> {
        use aws_sdk_dynamodb::types::{Put, TransactWriteItem, Update};

        let today = crate::current_unix_secs().div_euclid(86_400);
        let client_update = Update::builder()
            .table_name(&self.clients_table)
            .key(
                "client_id",
                AttributeValue::S(tpk(tenant, &grant.client_id)),
            )
            .update_expression("SET last_used_day = :today ADD authority_revision :one")
            .condition_expression(
                "attribute_exists(client_id) AND attribute_not_exists(tombstoned_at) AND \
                 (attribute_not_exists(last_used_day) OR last_used_day <= :today)",
            )
            .expression_attribute_values(":today", AttributeValue::N(today.to_string()))
            .expression_attribute_values(":one", AttributeValue::N("1".to_string()))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build Grant client authority update: {error}"))
            })?;
        let grant_put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(Self::to_item(tenant, &grant)?))
            .build()
            .map_err(|error| StoreError::Permanent(format!("build Grant put: {error}")))?;
        let request = self
            .db
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().update(client_update).build())
            .transact_items(TransactWriteItem::builder().put(grant_put).build());
        send_idempotent_transaction(request).await
    }
}

impl crate::ports::GrantStore for DynamoGrantStore {
    async fn put(&self, tenant: &str, grant: agent_auth_grant::Grant) -> Result<(), StoreError> {
        let item = Self::to_item(tenant, &grant)?;
        self.db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(())
    }
    async fn get(
        &self,
        tenant: &str,
        grant_id: &str,
    ) -> Result<Option<agent_auth_grant::Grant>, StoreError> {
        let out = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("grant_id", AttributeValue::S(tpk(tenant, grant_id)))
            // Grant is an authorization authority and revoke may immediately
            // follow put during password-reset race cleanup. A stale miss here
            // could leave a newly created Grant active.
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(out.item().and_then(Self::from_item))
    }
    async fn list_by_user(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<Vec<agent_auth_grant::Grant>, StoreError> {
        let mut out = Vec::new();
        let mut last: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let q = self
                .db
                .query()
                .table_name(&self.table)
                .index_name(&self.user_index)
                .key_condition_expression("user_id = :u")
                // GSI user_id 值 tenant 化 → 只命中本租户 Grant(codex B1:跨租户 user_id 碰撞隔离)。
                .expression_attribute_values(":u", AttributeValue::S(tpk(tenant, user_id)))
                .set_exclusive_start_key(last.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in q.items() {
                if let Some(g) = Self::from_item(item) {
                    out.push(g);
                }
            }
            match q.last_evaluated_key() {
                Some(k) if !k.is_empty() => last = Some(k.clone()),
                _ => break,
            }
        }
        Ok(out)
    }
    async fn revoke(&self, tenant: &str, grant_id: &str) -> Result<bool, StoreError> {
        // 读-改-写:取 Grant、置 Revoked、条件写回(pk 存在)。不存在返 false。
        let Some(mut g) = self.get(tenant, grant_id).await? else {
            return Ok(false);
        };
        g.status = agent_auth_grant::GrantStatus::Revoked;
        g.revision += 1; // bump revision:使并发/后续 put_conditional 的 expected 必不符 → 重算不复活已吊销(⑫)。
        let item = Self::to_item(tenant, &g)?;
        self.db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression("attribute_exists(grant_id)")
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(true)
    }
    async fn revoke_if_epoch_before(
        &self,
        tenant: &str,
        grant_id: &str,
        epoch: u64,
    ) -> Result<bool, StoreError> {
        for _ in 0..3 {
            let Some(mut grant) = self.get(tenant, grant_id).await? else {
                return Ok(false);
            };
            if grant.credential_epoch >= epoch {
                return Ok(false);
            }
            let expected_revision = grant.revision;
            let expected_epoch = grant.credential_epoch;
            grant.status = agent_auth_grant::GrantStatus::Revoked;
            grant.revision += 1;
            let item = Self::to_item(tenant, &grant)?;
            let epoch_condition = if expected_epoch == 0 {
                "(attribute_not_exists(credential_epoch) OR credential_epoch = :expected_epoch)"
            } else {
                "credential_epoch = :expected_epoch"
            };
            let result = self
                .db
                .put_item()
                .table_name(&self.table)
                .set_item(Some(item))
                .condition_expression(format!(
                    "attribute_exists(grant_id) AND revision = :expected_revision AND \
                     {epoch_condition}"
                ))
                .expression_attribute_values(
                    ":expected_revision",
                    AttributeValue::N(expected_revision.to_string()),
                )
                .expression_attribute_values(
                    ":expected_epoch",
                    AttributeValue::N(expected_epoch.to_string()),
                )
                .send()
                .await;
            match result {
                Ok(_) => return Ok(true),
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
            "Grant epoch-fenced revocation did not converge".into(),
        ))
    }
    async fn revoke_if_revision(
        &self,
        tenant: &str,
        grant_id: &str,
        expected_revision: u64,
    ) -> Result<bool, StoreError> {
        let Some(mut grant) = self.get(tenant, grant_id).await? else {
            return Ok(false);
        };
        if grant.revision != expected_revision
            || grant.status != agent_auth_grant::GrantStatus::Active
        {
            return Ok(false);
        }
        grant.status = agent_auth_grant::GrantStatus::Revoked;
        grant.revision = expected_revision.saturating_add(1);
        let item = Self::to_item(tenant, &grant)?;
        let result = self
            .db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression("attribute_exists(grant_id) AND revision = :expected_revision")
            .expression_attribute_values(
                ":expected_revision",
                AttributeValue::N(expected_revision.to_string()),
            )
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
    async fn put_conditional(
        &self,
        tenant: &str,
        mut grant: agent_auth_grant::Grant,
        expected_revision: u64,
    ) -> Result<bool, StoreError> {
        // CAS(spec 005 §7 补强 ⑫):仅当 revision==expected 且未 Revoked 才写,revision→expected+1。
        // status 存于 grant_json blob 内、非顶层属性,无法直接在 condition 里比对——但吊销走 `revoke()`
        // 会置 blob 内 status=Revoked **并不改 revision**,故"已吊销"场景 revision 仍等于 expected 会误过。
        // 解决:revoke 时也 bump revision(下方 revoke 已改),使吊销后 expected 必不符 → CAS 落败;
        // 双保险:重算读到 Revoked 的 Grant 时调用方本就跳过(recompute 只处理非终态)。此处以 revision 为准。
        grant.revision = expected_revision + 1;
        let item = Self::to_item(tenant, &grant)?;
        let res = self
            .db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            // 条件:记录存在 且 顶层 revision == expected(并发吊销/更新会 bump revision → 不符 → 落败)。
            .condition_expression("attribute_exists(grant_id) AND revision = :exp")
            .expression_attribute_values(":exp", AttributeValue::N(expected_revision.to_string()))
            .send()
            .await;
        match res {
            Ok(_) => Ok(true),
            Err(e) if e.code().unwrap_or("").contains("ConditionalCheckFailed") => Ok(false),
            Err(e) => Err(ddb_err(e)),
        }
    }
    async fn list_stale(
        &self,
        tenant: &str,
        current_pv: u64,
    ) -> Result<Vec<(String, agent_auth_grant::Grant)>, StoreError> {
        // GSI policy_version-index(pk=gv_tenant, sk=effective_pv,**KEYS_ONLY**):Query gv_tenant=X AND
        // effective_pv < current(分页,非全表 Scan;spec 005 §7 补强 ⑩)。KEYS_ONLY 只投影主键(grant_id +
        // gv_tenant + effective_pv),**不含 grant_json** → 必须回主表逐条 GetItem 取全 Grant(评审 Blocker:
        // 早期直接 from_item 空 grant_json 静默返 0)。先收命中的物理 grant_id(pk),再回表反序列化 + 过滤 Active。
        let mut pks: Vec<String> = Vec::new();
        let mut last: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let q = self
                .db
                .query()
                .table_name(&self.table)
                .index_name(&self.pv_index)
                .key_condition_expression("gv_tenant = :t AND effective_pv < :cur")
                // 与 to_item 同源:GSI 分区键 = tpk(tenant,"gv")(非空、租户隔离)。
                .expression_attribute_values(":t", AttributeValue::S(tpk(tenant, "gv")))
                .expression_attribute_values(":cur", AttributeValue::N(current_pv.to_string()))
                .set_exclusive_start_key(last.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in q.items() {
                // GSI item 的 grant_id 是**物理键**(tpk 前缀);回主表按此 GetItem。
                if let Some(pk) = s(item.get("grant_id")) {
                    pks.push(pk);
                }
            }
            match q.last_evaluated_key() {
                Some(k) if !k.is_empty() => last = Some(k.clone()),
                _ => break,
            }
        }
        // 回主表取全 Grant(强一致读:重算据此写 CAS,须看到最新 revision/status);过滤已终态(只重算 Active)。
        let mut out = Vec::new();
        for pk in pks {
            let got = self
                .db
                .get_item()
                .table_name(&self.table)
                .key("grant_id", AttributeValue::S(pk))
                .consistent_read(true)
                .send()
                .await
                .map_err(ddb_err)?;
            if let Some(item) = got.item() {
                if let Some(g) = Self::from_item(item) {
                    if g.status == agent_auth_grant::GrantStatus::Active {
                        out.push((tenant.to_string(), g));
                    }
                }
            }
        }
        Ok(out)
    }

    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        governance_delete_by_subject(
            &self.db,
            &self.table,
            "grant_id",
            tenant,
            "user_id",
            &tpk(tenant, user_id),
        )
        .await
    }

    async fn delete_by_client(&self, tenant: &str, client_id: &str) -> Result<usize, StoreError> {
        let mut observed = Vec::new();
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let output = self
                .db
                .scan()
                .table_name(&self.table)
                .consistent_read(true)
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in output.items() {
                let Some(grant) = Self::from_item(item) else {
                    continue;
                };
                let Some(grant_id) = item.get("grant_id").cloned() else {
                    continue;
                };
                let Some(grant_json) = item.get("grant_json").cloned() else {
                    continue;
                };
                let Some(user_id) = item.get("user_id").cloned() else {
                    continue;
                };
                if grant.client_id == client_id
                    && grant_id
                        .as_s()
                        .is_ok_and(|id| id == &tpk(tenant, &grant.grant_id))
                {
                    observed.push((grant_id, grant_json, user_id));
                }
            }
            match output.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }

        let mut deleted = 0usize;
        for (grant_id, grant_json, user_id) in observed {
            let result = self
                .db
                .delete_item()
                .table_name(&self.table)
                .key("grant_id", grant_id)
                .condition_expression(
                    "attribute_exists(grant_id) AND grant_json = :grant_json AND user_id = :user_id",
                )
                .expression_attribute_values(":grant_json", grant_json)
                .expression_attribute_values(":user_id", user_id)
                .send()
                .await;
            match result {
                Ok(_) => deleted = deleted.saturating_add(1),
                Err(error)
                    if error
                        .as_service_error()
                        .is_some_and(|service| service.is_conditional_check_failed_exception()) =>
                {
                    return Err(StoreError::Transient(
                        "Grant changed during client cascade".into(),
                    ));
                }
                Err(error) => return Err(ddb_err(error)),
            }
        }
        Ok(deleted)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut grant_ids = Vec::new();
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        let tenant_prefix = (!tenant.is_empty()).then(|| tpk(tenant, ""));
        loop {
            let output = self
                .db
                .scan()
                .table_name(&self.table)
                .projection_expression("grant_id")
                .filter_expression("attribute_exists(grant_json)")
                .consistent_read(true)
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in output.items() {
                let grant_id = item.get("grant_id").cloned().ok_or_else(|| {
                    StoreError::Permanent("Grant governance row is missing grant_id".into())
                })?;
                let physical = grant_id.as_s().map_err(|_| {
                    StoreError::Permanent("Grant governance key is not a string".into())
                })?;
                let belongs = match &tenant_prefix {
                    Some(prefix) => physical.starts_with(prefix),
                    None => !physical.contains(crate::tenant::SEP),
                };
                if belongs {
                    grant_ids.push(grant_id);
                }
            }
            match output.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }

        let mut deleted = 0usize;
        for grant_id in grant_ids {
            let result = self
                .db
                .delete_item()
                .table_name(&self.table)
                .key("grant_id", grant_id)
                .condition_expression("attribute_exists(grant_json)")
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

/// DynamoDB 逐租户 policy_version(spec 005 §7 补强 ②/③)。pk=`tpk(tenant,"policy-version")`;
/// `bump` = 原子 ADD 1 返回新值(单调);`get` 无记录 → 0。复用 Grants 表(单表少行)。
#[derive(Clone)]
pub struct DynamoPolicyVersionStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
}

impl DynamoPolicyVersionStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        DynamoPolicyVersionStore {
            db,
            table: table.into(),
        }
    }
    pub(super) fn pk(tenant: &str) -> String {
        tpk(tenant, "policy-version")
    }
}

impl crate::ports::PolicyVersionStore for DynamoPolicyVersionStore {
    async fn get(&self, tenant: &str) -> Result<u64, StoreError> {
        let out = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("grant_id", AttributeValue::S(Self::pk(tenant)))
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(out
            .item()
            .and_then(|i| n_i64(i.get("policy_version")))
            .map(|v| v.max(0) as u64)
            .unwrap_or(0))
    }
    async fn bump(&self, tenant: &str) -> Result<u64, StoreError> {
        // 原子 ADD 1(单调);ReturnValues=UPDATED_NEW 取新值。
        let out = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("grant_id", AttributeValue::S(Self::pk(tenant)))
            .update_expression("ADD policy_version :one")
            .expression_attribute_values(":one", AttributeValue::N("1".to_string()))
            .return_values(aws_sdk_dynamodb::types::ReturnValue::UpdatedNew)
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(out
            .attributes()
            .and_then(|a| n_i64(a.get("policy_version")))
            .map(|v| v.max(0) as u64)
            .unwrap_or(1))
    }

    async fn delete(&self, tenant: &str) -> Result<usize, StoreError> {
        let result = self
            .db
            .delete_item()
            .table_name(&self.table)
            .key("grant_id", AttributeValue::S(Self::pk(tenant)))
            .condition_expression("attribute_exists(policy_version)")
            .send()
            .await;
        match result {
            Ok(_) => Ok(1),
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|service| service.is_conditional_check_failed_exception()) =>
            {
                Ok(0)
            }
            Err(error) => Err(ddb_err(error)),
        }
    }
}

/// DynamoDB 不可变策略工件(spec 005 §7 补强 ⑨)。pk=`tpk(tenant,"policy-artifact#<version>")`;
/// 存 text + digest;工件不可变(同 version 不改写)。复用 Grants 表。
#[derive(Clone)]
pub struct DynamoPolicyArtifactStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
}

impl DynamoPolicyArtifactStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        DynamoPolicyArtifactStore {
            db,
            table: table.into(),
        }
    }
    fn pk(tenant: &str, version: u64) -> String {
        tpk(tenant, &format!("policy-artifact#{version}"))
    }
}

impl crate::ports::PolicyArtifactStore for DynamoPolicyArtifactStore {
    async fn put(
        &self,
        tenant: &str,
        version: u64,
        text: String,
        digest: String,
    ) -> Result<(), StoreError> {
        let item = HashMap::from([
            (
                "grant_id".to_string(),
                AttributeValue::S(Self::pk(tenant, version)),
            ),
            ("policy_text".to_string(), AttributeValue::S(text)),
            ("policy_digest".to_string(), AttributeValue::S(digest)),
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
    async fn get(
        &self,
        tenant: &str,
        version: u64,
    ) -> Result<Option<(String, String)>, StoreError> {
        let out = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("grant_id", AttributeValue::S(Self::pk(tenant, version)))
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(out.item().and_then(|i| {
            let text = s(i.get("policy_text"))?;
            let digest = s(i.get("policy_digest"))?;
            Some((text, digest))
        }))
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let prefix = tpk(tenant, "policy-artifact#");
        let mut grant_ids = Vec::new();
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let output = self
                .db
                .scan()
                .table_name(&self.table)
                .projection_expression("grant_id")
                .filter_expression(
                    "begins_with(grant_id, :prefix) AND attribute_exists(policy_text)",
                )
                .expression_attribute_values(":prefix", AttributeValue::S(prefix.clone()))
                .consistent_read(true)
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in output.items() {
                let grant_id = item.get("grant_id").cloned().ok_or_else(|| {
                    StoreError::Permanent("policy artifact row is missing grant_id".into())
                })?;
                grant_ids.push(grant_id);
            }
            match output.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }

        let mut deleted = 0usize;
        for grant_id in grant_ids {
            let result = self
                .db
                .delete_item()
                .table_name(&self.table)
                .key("grant_id", grant_id)
                .condition_expression("attribute_exists(policy_text)")
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

/// DynamoDB jti→主体映射(spec 011 C7.8)。表主键 = `pk`(= `tenant_id\x1fjti`,按 tenant 分区);
/// TTL=expires_at(短命 GC)。存 user_id/family_id(family_id 可空)。
#[derive(Clone)]
pub struct DynamoJtiStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
}

impl DynamoJtiStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        DynamoJtiStore {
            db,
            table: table.into(),
        }
    }
}

pub(super) fn jti_pk(tenant_id: &str, jti: &str) -> String {
    format!("{tenant_id}\u{1f}{jti}")
}

impl crate::ports::JtiStore for DynamoJtiStore {
    async fn put(&self, r: crate::ports::JtiRecord) -> Result<(), StoreError> {
        let mut item = HashMap::from([
            (
                "pk".to_string(),
                AttributeValue::S(jti_pk(&r.tenant_id, &r.jti)),
            ),
            ("jti".to_string(), AttributeValue::S(r.jti)),
            ("tenant_id".to_string(), AttributeValue::S(r.tenant_id)),
            ("user_id".to_string(), AttributeValue::S(r.user_id)),
            (
                "expires_at".to_string(),
                AttributeValue::N(r.expires_at.to_string()),
            ),
        ]);
        if let Some(fid) = r.family_id {
            item.insert("family_id".to_string(), AttributeValue::S(fid));
        }
        if let Some(gid) = r.grant_id {
            item.insert("grant_id".to_string(), AttributeValue::S(gid));
        }
        self.db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(())
    }

    async fn get(
        &self,
        tenant_id: &str,
        jti: &str,
    ) -> Result<Option<crate::ports::JtiRecord>, StoreError> {
        let out = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("pk", AttributeValue::S(jti_pk(tenant_id, jti)))
            .send()
            .await
            .map_err(ddb_err)?;
        let Some(item) = out.item() else {
            return Ok(None);
        };
        Ok(Some(crate::ports::JtiRecord {
            jti: s(item.get("jti")).unwrap_or_default(),
            tenant_id: s(item.get("tenant_id")).unwrap_or_default(),
            user_id: s(item.get("user_id")).unwrap_or_default(),
            family_id: s(item.get("family_id")),
            grant_id: s(item.get("grant_id")),
            expires_at: n_i64(item.get("expires_at")).unwrap_or(0),
        }))
    }

    async fn delete_by_user(&self, tenant_id: &str, user_id: &str) -> Result<usize, StoreError> {
        governance_delete_by_subject(&self.db, &self.table, "pk", tenant_id, "user_id", user_id)
            .await
    }

    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        let mut keys = Vec::new();
        let mut start_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let output = self
                .db
                .scan()
                .table_name(&self.table)
                .projection_expression("pk")
                .filter_expression("tenant_id = :tenant")
                .expression_attribute_values(":tenant", AttributeValue::S(tenant_id.to_string()))
                .consistent_read(true)
                .set_exclusive_start_key(start_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in output.items() {
                keys.push(item.get("pk").cloned().ok_or_else(|| {
                    StoreError::Permanent("JTI governance row is missing pk".into())
                })?);
            }
            match output.last_evaluated_key() {
                Some(key) if !key.is_empty() => start_key = Some(key.clone()),
                _ => break,
            }
        }
        for key in &keys {
            self.db
                .delete_item()
                .table_name(&self.table)
                .key("pk", key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
        }
        Ok(keys.len())
    }
}

/// AWS 事件 sink:P1 先 no-op(权威源是 DynamoDB 会话记录;真发 EventBridge 留 P2,spec 005 补栈)。
#[derive(Clone, Default)]
pub struct NoopAuthzEventSink;

impl AuthzEventSink for NoopAuthzEventSink {
    async fn emit(
        &self,
        _session_id: &str,
        _sequence: u64,
        _state: &str,
    ) -> Result<(), StoreError> {
        Ok(())
    }
}

/// EventBridge 事件 sink(spec 004 §3.3 / C6.5,P2):把授权会话状态迁移**投影**到 EventBridge bus。
/// bus → rule → CloudWatch Logs target(审计湖,CDK 补)= 持久可查的消费方。
///
/// **投影语义(C6.5,不是权威源)**:at-least-once、无序;detail 带每会话单调 `sequence`,消费方按
/// `(session_id, sequence)` 去重排序回放——权威源永远是 DynamoDB 会话记录,回放不依赖到达顺序。
/// **emit 失败静默**(调用方已 `let _ =`;投影是可观测旁路,绝不阻断主流程/会话迁移)。
#[derive(Clone)]
pub struct EventBridgeAuthzEventSink {
    eb: aws_sdk_eventbridge::Client,
    bus_name: String,
}

impl EventBridgeAuthzEventSink {
    pub fn new(eb: aws_sdk_eventbridge::Client, bus_name: impl Into<String>) -> Self {
        EventBridgeAuthzEventSink {
            eb,
            bus_name: bus_name.into(),
        }
    }
}

impl AuthzEventSink for EventBridgeAuthzEventSink {
    async fn emit(&self, session_id: &str, sequence: u64, state: &str) -> Result<(), StoreError> {
        // detail = 结构化 JSON(session_id/sequence/state);消费方按 (session_id,sequence) 去重排序回放。
        let detail = serde_json::json!({
            "session_id": session_id,
            "sequence": sequence,
            "state": state,
        })
        .to_string();
        let entry = aws_sdk_eventbridge::types::PutEventsRequestEntry::builder()
            .event_bus_name(&self.bus_name)
            .source("agent-auth.authz-session")
            .detail_type("AuthzSessionTransition")
            .detail(detail)
            .build();
        // PutEvents 失败/被 EventBridge 逐条拒(failed_entry_count>0)→ Transient(调用方静默旁路,不阻断)。
        let out = self
            .eb
            .put_events()
            .entries(entry)
            .send()
            .await
            .map_err(ddb_err)?;
        if out.failed_entry_count() > 0 {
            return Err(StoreError::Transient(format!(
                "EventBridge PutEvents 有 {} 条被拒",
                out.failed_entry_count()
            )));
        }
        Ok(())
    }
}

/// DynamoDB 宽限窗缓存,**item-level 应用层信封加密**(spec 001 C3.4)。
/// 表主键:partition `family_id`(S)+ sort `version`(N)——`delete_family`(C3.5)按 partition Query 删全部版本。
/// 信封加密:每 item 一把 KMS GenerateDataKey 生成的数据密钥 → AES-256-GCM 加密 token 明文 JSON → **只存密文**
/// (`enc_dk` = KMS 加密的数据密钥、`nonce`、`ciphertext`);读时 KMS Decrypt 数据密钥再 AES-GCM 解密。
/// KMS Decrypt 权限 MUST 只授 token 端点这一条代码路径(CDK 侧;表级 SSE-KMS 不满足 C3.4)。
#[derive(Clone)]
pub struct DynamoGraceStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) kms: aws_sdk_kms::Client,
    pub(super) table: String,
    /// 信封加密用的 KMS CMK(SYMMETRIC_DEFAULT;GenerateDataKey/Decrypt)。
    /// `None` 表示 delete-only runtime:可做撤销级联,但 put/get 必须 fail closed。
    pub(super) key_id: Option<String>,
}

impl DynamoGraceStore {
    pub fn new(
        db: aws_sdk_dynamodb::Client,
        kms: aws_sdk_kms::Client,
        table: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Self {
        DynamoGraceStore {
            db,
            kms,
            table: table.into(),
            key_id: Some(key_id.into()),
        }
    }

    pub fn new_delete_only(
        db: aws_sdk_dynamodb::Client,
        kms: aws_sdk_kms::Client,
        table: impl Into<String>,
    ) -> Self {
        DynamoGraceStore {
            db,
            kms,
            table: table.into(),
            key_id: None,
        }
    }

    pub(super) async fn encrypted_item(
        &self,
        entry: GraceCacheEntry,
    ) -> Result<HashMap<String, AttributeValue>, StoreError> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes256Gcm, Nonce};

        let aad = grace_aad(&entry.family_id, entry.version);
        let key_id = require_grace_key(self.key_id.as_deref(), "write")?;
        let dk = self
            .kms
            .generate_data_key()
            .key_id(key_id)
            .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
            .encryption_context("family_id", &entry.family_id)
            .encryption_context("version", entry.version.to_string())
            .send()
            .await
            .map_err(|e| StoreError::Transient(format!("KMS GenerateDataKey: {e:?}")))?;
        let plaintext_dk = dk
            .plaintext()
            .ok_or_else(|| StoreError::Permanent("KMS 未返回明文数据密钥".into()))?
            .as_ref()
            .to_vec();
        let enc_dk = dk
            .ciphertext_blob()
            .ok_or_else(|| StoreError::Permanent("KMS 未返回密文数据密钥".into()))?
            .as_ref()
            .to_vec();
        let payload = GracePlaintext {
            access_token: entry.response.access_token,
            refresh_token: entry.response.refresh_token,
            id_token: entry.response.id_token,
            scope: entry.response.scope,
            expires_in: entry.response.expires_in,
        };
        let plaintext = serde_json::to_vec(&payload)
            .map_err(|e| StoreError::Permanent(format!("序列化 grace payload: {e}")))?;
        let cipher = Aes256Gcm::new_from_slice(&plaintext_dk)
            .map_err(|e| StoreError::Permanent(format!("AES key: {e}")))?;
        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext.as_ref(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|e| StoreError::Permanent(format!("AES-GCM 加密: {e}")))?;

        use aws_sdk_dynamodb::primitives::Blob;
        let mut item = HashMap::from([
            ("family_id".to_string(), AttributeValue::S(entry.family_id)),
            (
                "version".to_string(),
                AttributeValue::N(entry.version.to_string()),
            ),
            (
                "fingerprint".to_string(),
                AttributeValue::B(Blob::new(entry.fingerprint.to_vec())),
            ),
            ("client_id".to_string(), AttributeValue::S(entry.client_id)),
            ("enc_dk".to_string(), AttributeValue::B(Blob::new(enc_dk))),
            (
                "nonce".to_string(),
                AttributeValue::B(Blob::new(nonce_bytes.to_vec())),
            ),
            (
                "ciphertext".to_string(),
                AttributeValue::B(Blob::new(ciphertext)),
            ),
            (
                "expires_at".to_string(),
                AttributeValue::N(entry.expires_at.to_string()),
            ),
        ]);
        if let Some(jkt) = entry.dpop_jkt {
            item.insert("dpop_jkt".to_string(), AttributeValue::S(jkt));
        }
        Ok(item)
    }
}

/// 序列化到密文前的明文载荷(只在内存;落库前 AES-GCM 加密)。
#[derive(serde::Serialize, serde::Deserialize)]
struct GracePlaintext {
    access_token: String,
    refresh_token: String,
    id_token: Option<String>,
    scope: Option<String>,
    expires_in: i64,
}

/// 绑定行位置的 AAD(评审 F4):既作 GCM AAD 又作 KMS EncryptionContext 的稳定串表示。
/// 与 KMS EncryptionContext {family_id,version} 语义一致——把密文钉死在其 (family_id,version) 行。
fn grace_aad(family_id: &str, version: u64) -> String {
    format!("grace:{family_id}:{version}")
}

fn require_grace_key<'a>(
    key_id: Option<&'a str>,
    operation: &'static str,
) -> Result<&'a str, StoreError> {
    key_id.ok_or_else(|| {
        StoreError::Permanent(format!(
            "grace delete-only runtime cannot {operation} envelope data"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::{
        DynamoAuthzSessionStore, DynamoGraceStore, DynamoGrantStore, DynamoRateLimitStore,
        DynamoReplayStore, EventBridgeAuthzEventSink,
    };
    use crate::ports::{
        AuthzEventSink, AuthzSessionRecord, AuthzSessionStore, GraceCacheEntry,
        GraceCachedResponse, GraceStore, GrantStore, RateLimitStore, ReplayStore, StoreError,
    };
    use aws_smithy_http_client::test_util::{capture_request, ReplayEvent, StaticReplayClient};
    use aws_smithy_types::body::SdkBody;
    use base64::Engine as _;
    use serde_json::Value;

    fn response(body: Value) -> axum::http::Response<SdkBody> {
        axum::http::Response::builder()
            .status(200)
            .header("content-type", "application/x-amz-json-1.1")
            .body(SdkBody::from(body.to_string()))
            .expect("response")
    }

    fn conditional_failure_response() -> axum::http::Response<SdkBody> {
        axum::http::Response::builder()
            .status(400)
            .header("content-type", "application/x-amz-json-1.0")
            .header("x-amzn-errortype", "ConditionalCheckFailedException")
            .body(SdkBody::from(
                r#"{"__type":"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException","message":"rate-limit version changed"}"#,
            ))
            .expect("conditional failure response")
    }

    fn request_json(body: &[u8]) -> Value {
        serde_json::from_slice(body).expect("captured AWS request is JSON")
    }

    fn grace_entry() -> GraceCacheEntry {
        GraceCacheEntry {
            family_id: "family-sensitive".to_string(),
            version: 7,
            fingerprint: [3u8; 32],
            client_id: "client-1".to_string(),
            dpop_jkt: Some("jkt-1".to_string()),
            response: GraceCachedResponse {
                access_token: "access-token-sensitive".to_string(),
                refresh_token: "refresh-token-sensitive".to_string(),
                id_token: Some("id-token-sensitive".to_string()),
                scope: Some("read write".to_string()),
                expires_in: 300,
            },
            expires_at: 1_700_000_300,
        }
    }

    #[tokio::test]
    async fn dynamo_grant_authority_read_is_strongly_consistent_and_tenant_scoped() {
        let grant = agent_auth_grant::Grant {
            grant_id: "grant-1".to_string(),
            user_id: "user-1".to_string(),
            client_id: "client-1".to_string(),
            per_resource: Vec::new(),
            effective_per_resource: Vec::new(),
            effective_pv: 0,
            allowed_ip_cidrs: Vec::new(),
            allowed_vpce: Vec::new(),
            credential_epoch: 0,
            revision: 1,
            constraints: agent_auth_grant::GrantConstraints {
                max_act_chain: 1,
                actor_allowlist: Vec::new(),
                expires_at: 1_800_000_000,
            },
            status: agent_auth_grant::GrantStatus::Revoked,
        };
        let placeholder_request = || {
            axum::http::Request::builder()
                .uri("https://dynamodb.us-east-1.amazonaws.com/")
                .body(SdkBody::empty())
                .expect("placeholder request")
        };
        let http = StaticReplayClient::new(vec![
            ReplayEvent::new(
                placeholder_request(),
                response(serde_json::json!({
                    "Item": {
                        "grant_json": {"S": serde_json::to_string(&grant).expect("grant JSON")}
                    }
                })),
            ),
            ReplayEvent::new(placeholder_request(), response(serde_json::json!({}))),
        ]);
        let db = aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                .endpoint_url("https://dynamodb.us-east-1.amazonaws.com")
                .http_client(http.clone())
                .build(),
        );

        let store = DynamoGrantStore::new(db, "grants-table", "clients-table");
        let loaded = store
            .get("tenant-a", "grant-1")
            .await
            .expect("read Grant authority")
            .expect("Grant is present");
        assert_eq!(loaded.status, agent_auth_grant::GrantStatus::Revoked);
        assert!(store
            .get("tenant-b", "grant-1")
            .await
            .expect("read sibling Grant authority")
            .is_none());

        let requests: Vec<_> = http.actual_requests().collect();
        assert_eq!(requests.len(), 2);
        let reads: Vec<_> = requests
            .iter()
            .map(|request| {
                request_json(
                    request
                        .body()
                        .bytes()
                        .expect("captured Dynamo GetItem body is in memory"),
                )
            })
            .collect();
        for read in &reads {
            assert_eq!(read["TableName"], "grants-table");
            assert_eq!(read["ConsistentRead"], true);
        }
        assert_eq!(reads[0]["Key"]["grant_id"]["S"], "tenant-a\u{1f}grant-1");
        assert_eq!(reads[1]["Key"]["grant_id"]["S"], "tenant-b\u{1f}grant-1");
        assert_ne!(
            reads[0]["Key"]["grant_id"]["S"],
            reads[1]["Key"]["grant_id"]["S"]
        );
    }

    #[tokio::test]
    async fn dynamo_authz_session_transition_increments_and_cas_fences_sequence() {
        let record = AuthzSessionRecord {
            session_id: "session-1".to_string(),
            client_id: "client-1".to_string(),
            user_id: Some("user-1".to_string()),
            state: "created".to_string(),
            session_token_hash: "session-token-hash".to_string(),
            sequence: 7,
            last_error: None,
            expires_at: 1_700_001_800,
        };
        let item = DynamoAuthzSessionStore::to_item("tenant-1", &record)
            .into_iter()
            .map(|(name, value)| {
                let value = match value {
                    aws_sdk_dynamodb::types::AttributeValue::S(value) => {
                        serde_json::json!({"S": value})
                    }
                    aws_sdk_dynamodb::types::AttributeValue::N(value) => {
                        serde_json::json!({"N": value})
                    }
                    other => panic!("unexpected authorization-session attribute: {other:?}"),
                };
                (name, value)
            })
            .collect::<serde_json::Map<_, _>>();
        let placeholder_request = || {
            axum::http::Request::builder()
                .uri("https://dynamodb.us-east-1.amazonaws.com/")
                .body(SdkBody::empty())
                .expect("placeholder request")
        };
        let http = StaticReplayClient::new(vec![
            ReplayEvent::new(
                placeholder_request(),
                response(serde_json::json!({"Item": item.clone()})),
            ),
            ReplayEvent::new(placeholder_request(), response(serde_json::json!({}))),
            ReplayEvent::new(
                placeholder_request(),
                response(serde_json::json!({"Attributes": item})),
            ),
        ]);
        let db = aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                .endpoint_url("https://dynamodb.us-east-1.amazonaws.com")
                .http_client(http.clone())
                .build(),
        );
        let transitioned = DynamoAuthzSessionStore::new(db, "sessions-table")
            .transition_with_clock(
                "tenant-1",
                "session-1",
                "pending_consent",
                Some("prior-error".to_string()),
                1_700_000_000,
                || 1_700_000_000,
            )
            .await
            .expect("transition authoritative authorization session")
            .expect("existing authorization session");
        assert_eq!(transitioned.state, "pending_consent");
        assert_eq!(transitioned.sequence, 8);
        assert_eq!(transitioned.last_error.as_deref(), Some("prior-error"));

        let requests: Vec<_> = http.actual_requests().collect();
        assert_eq!(requests.len(), 2);
        let read_json = request_json(
            requests[0]
                .body()
                .bytes()
                .expect("captured Dynamo GetItem body is in memory"),
        );
        assert_eq!(read_json["TableName"], "sessions-table");
        assert_eq!(read_json["ConsistentRead"], true);
        assert_eq!(
            read_json["Key"]["session_id"]["S"],
            "tenant-1\u{1f}session-1"
        );
        let write_json = request_json(
            requests[1]
                .body()
                .bytes()
                .expect("captured Dynamo PutItem body is in memory"),
        );
        assert_eq!(write_json["TableName"], "sessions-table");
        assert_eq!(write_json["Item"]["state"]["S"], "pending_consent");
        assert_eq!(write_json["Item"]["sequence"]["N"], "8");
        assert_eq!(write_json["Item"]["last_error"]["S"], "prior-error");
        assert_eq!(
            write_json["ConditionExpression"],
            "#seq = :cur AND expires_at > :now"
        );
        assert_eq!(write_json["ExpressionAttributeNames"]["#seq"], "sequence");
        assert_eq!(write_json["ExpressionAttributeValues"][":cur"]["N"], "7");
        assert_eq!(
            write_json["ExpressionAttributeValues"][":now"]["N"],
            "1700000000"
        );

        let rebound = DynamoAuthzSessionStore::new(
            aws_sdk_dynamodb::Client::from_conf(
                aws_sdk_dynamodb::Config::builder()
                    .behavior_version_latest()
                    .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                    .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                    .endpoint_url("https://dynamodb.us-east-1.amazonaws.com")
                    .http_client(http.clone())
                    .build(),
            ),
            "sessions-table",
        )
        .bind_user("tenant-1", "session-1", "user-1", 1_700_000_000)
        .await
        .expect("bind authoritative authorization session")
        .expect("existing authorization session");
        assert_eq!(rebound.user_id.as_deref(), Some("user-1"));
        let requests: Vec<_> = http.actual_requests().collect();
        let bind_json = request_json(
            requests[2]
                .body()
                .bytes()
                .expect("captured Dynamo UpdateItem body is in memory"),
        );
        assert_eq!(
            bind_json["ConditionExpression"],
            "attribute_exists(session_id) AND expires_at > :now AND (attribute_not_exists(user_id) OR user_id = :user)"
        );
        assert_eq!(
            bind_json["ExpressionAttributeValues"][":now"]["N"],
            "1700000000"
        );
    }

    #[tokio::test]
    async fn dynamo_authz_session_transition_resamples_expiry_after_authority_read() {
        let record = AuthzSessionRecord {
            session_id: "session-expiry-race".to_string(),
            client_id: "client-1".to_string(),
            user_id: Some("user-1".to_string()),
            state: "created".to_string(),
            session_token_hash: "session-token-hash".to_string(),
            sequence: 7,
            last_error: None,
            expires_at: 1_000,
        };
        let item = DynamoAuthzSessionStore::to_item("tenant-1", &record)
            .into_iter()
            .map(|(name, value)| {
                let value = match value {
                    aws_sdk_dynamodb::types::AttributeValue::S(value) => {
                        serde_json::json!({"S": value})
                    }
                    aws_sdk_dynamodb::types::AttributeValue::N(value) => {
                        serde_json::json!({"N": value})
                    }
                    other => panic!("unexpected authorization-session attribute: {other:?}"),
                };
                (name, value)
            })
            .collect::<serde_json::Map<_, _>>();
        let placeholder_request = || {
            axum::http::Request::builder()
                .uri("https://dynamodb.us-east-1.amazonaws.com/")
                .body(SdkBody::empty())
                .expect("placeholder request")
        };
        let http = StaticReplayClient::new(vec![
            ReplayEvent::new(
                placeholder_request(),
                response(serde_json::json!({"Item": item})),
            ),
            ReplayEvent::new(placeholder_request(), response(serde_json::json!({}))),
        ]);
        let db = aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                .endpoint_url("https://dynamodb.us-east-1.amazonaws.com")
                .http_client(http.clone())
                .build(),
        );
        let store = DynamoAuthzSessionStore::new(db, "sessions-table");
        let clock = || {
            if http.actual_requests().count() >= 1 {
                1_000
            } else {
                999
            }
        };

        let transitioned = store
            .transition_with_clock(
                "tenant-1",
                "session-expiry-race",
                "pending_consent",
                None,
                999,
                clock,
            )
            .await
            .expect("transition authority read");

        assert_eq!(
            transitioned, None,
            "a session expiring during the authority read must not be committed"
        );
        assert_eq!(
            http.actual_requests().count(),
            1,
            "an expired session must stop after the authoritative read"
        );
    }

    fn kms_client(
        response_body: Option<Value>,
    ) -> (
        aws_sdk_kms::Client,
        aws_smithy_http_client::test_util::CaptureRequestReceiver,
    ) {
        let (http, request) = capture_request(response_body.map(response));
        let client = aws_sdk_kms::Client::from_conf(
            aws_sdk_kms::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_kms::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_kms::config::Credentials::for_tests())
                .endpoint_url("https://kms.us-east-1.amazonaws.com")
                .http_client(http)
                .build(),
        );
        (client, request)
    }

    fn dynamo_client(
        response_body: Option<Value>,
    ) -> (
        aws_sdk_dynamodb::Client,
        aws_smithy_http_client::test_util::CaptureRequestReceiver,
    ) {
        let (http, request) = capture_request(response_body.map(response));
        let client = aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                .endpoint_url("https://dynamodb.us-east-1.amazonaws.com")
                .http_client(http)
                .build(),
        );
        (client, request)
    }

    fn eventbridge_client(
        response_body: Option<Value>,
    ) -> (
        aws_sdk_eventbridge::Client,
        aws_smithy_http_client::test_util::CaptureRequestReceiver,
    ) {
        let (http, request) = capture_request(response_body.map(response));
        let client = aws_sdk_eventbridge::Client::from_conf(
            aws_sdk_eventbridge::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_eventbridge::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_eventbridge::config::Credentials::for_tests())
                .endpoint_url("https://events.us-east-1.amazonaws.com")
                .http_client(http)
                .build(),
        );
        (client, request)
    }

    #[tokio::test]
    async fn dynamo_replay_check_and_set_is_atomic_and_ttl_bound() {
        let (client, request) = dynamo_client(Some(serde_json::json!({})));
        let store = DynamoReplayStore::new(client, "jti-table");
        let expires_at = 1_900_000_000;

        assert!(store
            .check_and_set("tenant-a", "ema-partitioned-key", expires_at)
            .await
            .unwrap());

        let request = request.expect_request();
        let body = request_json(
            request
                .body()
                .bytes()
                .expect("captured Dynamo request body"),
        );
        assert_eq!(body["TableName"], "jti-table");
        assert_eq!(
            body["Item"]["pk"]["S"],
            "tenant-a\u{1f}replay\u{1f}ema-partitioned-key"
        );
        assert_eq!(body["Item"]["expires_at"]["N"], expires_at.to_string());
        assert_eq!(
            body["ConditionExpression"],
            "attribute_not_exists(pk) OR expires_at < :now"
        );
        assert!(
            body["ExpressionAttributeValues"][":now"]["N"]
                .as_str()
                .unwrap()
                .parse::<i64>()
                .unwrap()
                > 0
        );
    }

    #[tokio::test]
    async fn eventbridge_authz_event_sink_emits_replayable_projection() {
        let (client, request) = eventbridge_client(Some(serde_json::json!({
            "FailedEntryCount": 0,
            "Entries": [{"EventId": "event-1"}]
        })));
        EventBridgeAuthzEventSink::new(client, "authz-events")
            .emit("session-1", 7, "pending_consent")
            .await
            .expect("emit authorization-session projection");
        let body = request_json(
            request
                .expect_request()
                .body()
                .bytes()
                .expect("captured EventBridge PutEvents body is in memory"),
        );
        let entry = &body["Entries"][0];
        assert_eq!(entry["EventBusName"], "authz-events");
        assert_eq!(entry["Source"], "agent-auth.authz-session");
        assert_eq!(entry["DetailType"], "AuthzSessionTransition");
        assert_eq!(
            serde_json::from_str::<Value>(
                entry["Detail"]
                    .as_str()
                    .expect("EventBridge detail is a JSON string")
            )
            .expect("EventBridge detail JSON"),
            serde_json::json!({
                "session_id": "session-1",
                "sequence": 7,
                "state": "pending_consent",
            })
        );
    }

    async fn assert_relocated_ciphertext_rejected(
        item: Value,
        family_id: &str,
        version: u64,
        plaintext_key: [u8; 32],
    ) {
        let (kms, kms_request) = kms_client(Some(serde_json::json!({
            "KeyId": "test-grace-key",
            "Plaintext": base64::engine::general_purpose::STANDARD.encode(plaintext_key)
        })));
        let (db, _) = dynamo_client(Some(serde_json::json!({"Item": item})));
        let store = DynamoGraceStore::new(db, kms, "grace-table", "test-grace-key");
        let error = store
            .get(family_id, version)
            .await
            .expect_err("ciphertext moved to another row must fail");
        let StoreError::Permanent(message) = error else {
            panic!("AAD mismatch must fail permanently");
        };
        assert!(message.contains("AES-GCM"));
        let kms_json = request_json(
            kms_request
                .expect_request()
                .body()
                .bytes()
                .expect("captured tampered KMS decrypt body is in memory"),
        );
        assert_eq!(
            kms_json["EncryptionContext"],
            serde_json::json!({"family_id":family_id,"version":version.to_string()})
        );
    }

    #[tokio::test]
    async fn delete_only_runtime_rejects_grace_reads_and_writes() {
        let (kms, kms_request) = kms_client(None);
        let (db, db_request) = dynamo_client(None);
        let store = DynamoGraceStore::new_delete_only(db, kms, "grace-table");

        for error in [
            store.put(grace_entry()).await.unwrap_err(),
            store.get("family-sensitive", 7).await.unwrap_err(),
        ] {
            let StoreError::Permanent(message) = error else {
                panic!("delete-only grace access must fail permanently");
            };
            assert!(message.contains("delete-only"));
        }
        kms_request.expect_no_request();
        db_request.expect_no_request();

        let (delete_kms, delete_kms_request) = kms_client(None);
        let (delete_db, delete_request) = dynamo_client(Some(serde_json::json!({"Items": []})));
        let delete_store = DynamoGraceStore::new_delete_only(delete_db, delete_kms, "grace-table");
        delete_store
            .delete_family("family-sensitive")
            .await
            .expect("delete-only runtime retains family cleanup");
        delete_kms_request.expect_no_request();
        let delete_json = request_json(
            delete_request
                .expect_request()
                .body()
                .bytes()
                .expect("captured Dynamo query body is in memory"),
        );
        assert_eq!(delete_json["TableName"], "grace-table");
        assert_eq!(
            delete_json["ExpressionAttributeValues"][":f"]["S"],
            "family-sensitive"
        );
        assert_eq!(delete_json["ConsistentRead"], true);
    }

    #[tokio::test]
    async fn dynamo_grace_store_encrypts_item_and_binds_ciphertext_to_row() {
        let plaintext_key = [7u8; 32];
        let encrypted_key = [9u8; 48];
        let (kms_http, kms_request) = capture_request(Some(response(serde_json::json!({
            "CiphertextBlob": base64::engine::general_purpose::STANDARD.encode(encrypted_key),
            "Plaintext": base64::engine::general_purpose::STANDARD.encode(plaintext_key),
            "KeyId": "test-grace-key"
        }))));
        let kms = aws_sdk_kms::Client::from_conf(
            aws_sdk_kms::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_kms::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_kms::config::Credentials::for_tests())
                .endpoint_url("https://kms.us-east-1.amazonaws.com")
                .http_client(kms_http)
                .build(),
        );

        let (ddb_http, ddb_request) = capture_request(Some(response(serde_json::json!({}))));
        let db = aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                .endpoint_url("https://dynamodb.us-east-1.amazonaws.com")
                .http_client(ddb_http)
                .build(),
        );
        let store = DynamoGraceStore::new(db, kms, "grace-table", "test-grace-key");
        let entry = grace_entry();
        store
            .put(entry.clone())
            .await
            .expect("encrypted grace write");

        let kms_request = kms_request.expect_request();
        let kms_json = request_json(
            kms_request
                .body()
                .bytes()
                .expect("captured KMS request body is in memory"),
        );
        assert_eq!(kms_json["KeyId"], "test-grace-key");
        assert_eq!(kms_json["KeySpec"], "AES_256");
        assert_eq!(
            kms_json["EncryptionContext"],
            serde_json::json!({"family_id":"family-sensitive","version":"7"})
        );

        let ddb_request = ddb_request.expect_request();
        let ddb_json = request_json(
            ddb_request
                .body()
                .bytes()
                .expect("captured Dynamo request body is in memory"),
        );
        let item = ddb_json["Item"].as_object().expect("Dynamo item");
        let mut keys = item.keys().map(String::as_str).collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "ciphertext",
                "client_id",
                "dpop_jkt",
                "enc_dk",
                "expires_at",
                "family_id",
                "fingerprint",
                "nonce",
                "version",
            ]
        );
        let serialized = ddb_json.to_string();
        for plaintext in [
            "access-token-sensitive",
            "refresh-token-sensitive",
            "id-token-sensitive",
            "read write",
        ] {
            assert!(
                !serialized.contains(plaintext),
                "Dynamo request leaked grace plaintext: {plaintext}"
            );
        }
        assert_eq!(
            item["enc_dk"]["B"],
            base64::engine::general_purpose::STANDARD.encode(encrypted_key)
        );
        assert!(item["ciphertext"]["B"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        assert_eq!(
            item["nonce"]["B"]
                .as_str()
                .and_then(|value| base64::engine::general_purpose::STANDARD.decode(value).ok())
                .map(|value| value.len()),
            Some(12)
        );

        let (decrypt_http, decrypt_request) = capture_request(Some(response(serde_json::json!({
            "KeyId": "test-grace-key",
            "Plaintext": base64::engine::general_purpose::STANDARD.encode(plaintext_key)
        }))));
        let decrypt_kms = aws_sdk_kms::Client::from_conf(
            aws_sdk_kms::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_kms::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_kms::config::Credentials::for_tests())
                .endpoint_url("https://kms.us-east-1.amazonaws.com")
                .http_client(decrypt_http)
                .build(),
        );
        let (get_http, get_request) = capture_request(Some(response(serde_json::json!({
            "Item": ddb_json["Item"].clone()
        }))));
        let get_db = aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                .endpoint_url("https://dynamodb.us-east-1.amazonaws.com")
                .http_client(get_http)
                .build(),
        );
        let read_store =
            DynamoGraceStore::new(get_db, decrypt_kms, "grace-table", "test-grace-key");
        assert_eq!(
            read_store
                .get("family-sensitive", 7)
                .await
                .expect("encrypted grace read"),
            Some(entry)
        );
        let get_request = get_request.expect_request();
        let get_json = request_json(
            get_request
                .body()
                .bytes()
                .expect("captured Dynamo get body is in memory"),
        );
        assert_eq!(get_json["ConsistentRead"], true);
        assert_eq!(get_json["Key"]["family_id"]["S"], "family-sensitive");
        assert_eq!(get_json["Key"]["version"]["N"], "7");
        let decrypt_request = decrypt_request.expect_request();
        let decrypt_json = request_json(
            decrypt_request
                .body()
                .bytes()
                .expect("captured KMS decrypt body is in memory"),
        );
        assert_eq!(
            decrypt_json["EncryptionContext"],
            serde_json::json!({"family_id":"family-sensitive","version":"7"})
        );
        assert_eq!(
            decrypt_json["CiphertextBlob"],
            base64::engine::general_purpose::STANDARD.encode(encrypted_key)
        );

        assert_relocated_ciphertext_rejected(
            ddb_json["Item"].clone(),
            "family-sensitive",
            8,
            plaintext_key,
        )
        .await;
        assert_relocated_ciphertext_rejected(
            ddb_json["Item"].clone(),
            "other-family",
            7,
            plaintext_key,
        )
        .await;
    }

    #[tokio::test]
    async fn dynamo_rate_limit_retry_exhaustion_is_transient() {
        let placeholder_request = || {
            axum::http::Request::builder()
                .uri("https://dynamodb.us-east-1.amazonaws.com/")
                .body(SdkBody::empty())
                .expect("placeholder request")
        };
        let mut events = Vec::new();
        for _ in 0..5 {
            events.push(ReplayEvent::new(
                placeholder_request(),
                response(serde_json::json!({})),
            ));
            events.push(ReplayEvent::new(
                placeholder_request(),
                conditional_failure_response(),
            ));
        }
        let http = StaticReplayClient::new(events);
        let db = aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                .endpoint_url("https://dynamodb.us-east-1.amazonaws.com")
                .http_client(http.clone())
                .build(),
        );

        let error = DynamoRateLimitStore::new(db, "rate-limit-table")
            .try_consume("pwd:account:tenant:digest", 1_700_000_000, 5.0, 0.1, 1.0)
            .await
            .expect_err("five consecutive CAS conflicts must not be treated as success");

        assert!(matches!(error, StoreError::Transient(_)));
        assert_eq!(
            http.actual_requests().count(),
            10,
            "retry exhaustion must perform five strong reads and five conditional writes"
        );
    }
}

impl GraceStore for DynamoGraceStore {
    async fn put(&self, entry: GraceCacheEntry) -> Result<(), StoreError> {
        let item = self.encrypted_item(entry).await?;
        self.db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(())
    }

    async fn get(
        &self,
        family_id: &str,
        version: u64,
    ) -> Result<Option<GraceCacheEntry>, StoreError> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes256Gcm, Nonce};

        require_grace_key(self.key_id.as_deref(), "read")?;
        let aad = grace_aad(family_id, version);

        let out = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("family_id", AttributeValue::S(family_id.to_string()))
            .key("version", AttributeValue::N(version.to_string()))
            .consistent_read(true) // 评审 F5:读刚写的 grace 项(避免最终一致漏读放大误吊销)
            .send()
            .await
            .map_err(ddb_err)?;
        let Some(item) = out.item() else {
            return Ok(None);
        };

        let b = |k: &str| -> Option<Vec<u8>> {
            item.get(k)
                .and_then(|a| a.as_b().ok())
                .map(|x| x.as_ref().to_vec())
        };
        let enc_dk = b("enc_dk").ok_or_else(|| StoreError::Permanent("grace 缺 enc_dk".into()))?;
        let nonce = b("nonce").ok_or_else(|| StoreError::Permanent("grace 缺 nonce".into()))?;
        let ciphertext =
            b("ciphertext").ok_or_else(|| StoreError::Permanent("grace 缺 ciphertext".into()))?;
        let fp_vec =
            b("fingerprint").ok_or_else(|| StoreError::Permanent("grace 缺 fingerprint".into()))?;
        let fingerprint: [u8; 32] = fp_vec
            .try_into()
            .map_err(|_| StoreError::Permanent("grace fingerprint 长度非 32".into()))?;

        // KMS Decrypt 数据密钥(同 EncryptionContext,否则 KMS 拒解)→ AES-GCM 解密 token 明文(同 AAD)。
        use aws_sdk_dynamodb::primitives::Blob;
        let dec = self
            .kms
            .decrypt()
            .ciphertext_blob(Blob::new(enc_dk))
            .encryption_context("family_id", family_id)
            .encryption_context("version", version.to_string())
            .send()
            .await
            .map_err(|e| StoreError::Transient(format!("KMS Decrypt: {e:?}")))?;
        let plaintext_dk = dec
            .plaintext()
            .ok_or_else(|| StoreError::Permanent("KMS Decrypt 未返回明文密钥".into()))?
            .as_ref()
            .to_vec();
        let cipher = Aes256Gcm::new_from_slice(&plaintext_dk)
            .map_err(|e| StoreError::Permanent(format!("AES key: {e}")))?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext.as_ref(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|e| StoreError::Permanent(format!("AES-GCM 解密: {e}")))?;
        let payload: GracePlaintext = serde_json::from_slice(&plaintext)
            .map_err(|e| StoreError::Permanent(format!("反序列化 grace payload: {e}")))?;

        Ok(Some(GraceCacheEntry {
            family_id: family_id.to_string(),
            version,
            fingerprint,
            client_id: s(item.get("client_id")).unwrap_or_default(),
            dpop_jkt: s(item.get("dpop_jkt")),
            response: GraceCachedResponse {
                access_token: payload.access_token,
                refresh_token: payload.refresh_token,
                id_token: payload.id_token,
                scope: payload.scope,
                expires_in: payload.expires_in,
            },
            expires_at: n_i64(item.get("expires_at")).unwrap_or(0),
        }))
    }

    async fn delete_family(&self, family_id: &str) -> Result<(), StoreError> {
        // C3.5:删该 family 所有版本。按 partition key Query 出全部 sort key,逐条删。
        // 评审 F5:consistent_read(读到刚写的项,避免最终一致漏删)+ 分页(>1MB 一页装不下时不漏删)。
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let q = self
                .db
                .query()
                .table_name(&self.table)
                .key_condition_expression("family_id = :f")
                .expression_attribute_values(":f", AttributeValue::S(family_id.to_string()))
                .consistent_read(true)
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in q.items() {
                if let Some(ver) = item.get("version").cloned() {
                    self.db
                        .delete_item()
                        .table_name(&self.table)
                        .key("family_id", AttributeValue::S(family_id.to_string()))
                        .key("version", ver)
                        .send()
                        .await
                        .map_err(ddb_err)?;
                }
            }
            match q.last_evaluated_key() {
                Some(k) if !k.is_empty() => last_key = Some(k.clone()),
                _ => break,
            }
        }
        Ok(())
    }
}

/// DynamoDB per-key 令牌桶限流(spec 005 C10.7)。表主键 = `key`(S,如 `client_id`)。
/// **乐观并发**:读当前桶(tokens/last_refill)→ `ratelimit::try_acquire` 算新桶 → **条件写回**
/// (条件 = 读到的 last_refill 未变;并发改动 → ConditionalCheckFailed → 保守放行,不阻断合法请求)。
/// expires_at = TTL GC(空闲桶自动清)。fail-open:存储错误由调用方按放行处理(anti-abuse 优先可用性)。
#[derive(Clone)]
pub struct DynamoRateLimitStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
}

impl DynamoRateLimitStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        DynamoRateLimitStore {
            db,
            table: table.into(),
        }
    }
}

/// 限流 CAS 冲突时的最大重试次数(评审 codex/Kiro HIGH:冲突不能直接放行——否则高并发全撞冲突→全
/// 放行→绕过限流。仿恢复码 CAS 重试:每次重读最新桶重算,耗尽仍冲突才 Transient(调用方 fail-open,
/// 绕过口窄化为"打满 N 次重试的极端并发",远严于"冲突即放行"))。
const RL_MAX_RETRY: u32 = 5;

impl crate::ports::RateLimitStore for DynamoRateLimitStore {
    async fn check_available(
        &self,
        key: &str,
        now: i64,
        capacity: f64,
        refill_per_sec: f64,
        cost: f64,
    ) -> Result<crate::ports::RateLimitDecision, StoreError> {
        use agent_auth_infra_core::{retry_after_secs, try_acquire, BucketConfig, BucketState};
        let cfg = BucketConfig::new(capacity, refill_per_sec);
        let now_f = now as f64;
        let out = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("key", AttributeValue::S(key.to_string()))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        let state = match out.item() {
            Some(item) => BucketState {
                tokens: n_f64(item.get("tokens")).unwrap_or(capacity),
                last_refill: n_f64(item.get("last_refill")).unwrap_or(now_f),
            },
            None => BucketState::full(&cfg, now_f),
        };
        let decision = try_acquire(&cfg, state, now_f, cost);
        Ok(crate::ports::RateLimitDecision {
            allowed: decision.allowed,
            retry_after_secs: if decision.allowed {
                None
            } else {
                retry_after_secs(&cfg, decision.state, cost).map(|s| s.ceil() as i64)
            },
        })
    }

    async fn try_consume(
        &self,
        key: &str,
        now: i64,
        capacity: f64,
        refill_per_sec: f64,
        cost: f64,
    ) -> Result<crate::ports::RateLimitDecision, StoreError> {
        use agent_auth_infra_core::{retry_after_secs, try_acquire, BucketConfig, BucketState};
        let cfg = BucketConfig::new(capacity, refill_per_sec);
        let now_f = now as f64;

        // 乐观 CAS 重试循环(评审 HIGH):读桶 → try_acquire → 条件写(version 递增)。冲突则重读重试;
        // 耗尽 → Transient(调用方 fail-open,不"冲突即放行")。version 单调递增作 CAS 版本。
        for _ in 0..RL_MAX_RETRY {
            let out = self
                .db
                .get_item()
                .table_name(&self.table)
                .key("key", AttributeValue::S(key.to_string()))
                .consistent_read(true) // 强一致读:避免读到陈旧副本反复撞 CAS
                .send()
                .await
                .map_err(ddb_err)?;
            let (state, prev_version) = match out.item() {
                Some(it) => {
                    let tokens = n_f64(it.get("tokens")).unwrap_or(capacity);
                    let last_refill = n_f64(it.get("last_refill")).unwrap_or(now_f);
                    let version = n_i64(it.get("version")).unwrap_or(0);
                    (
                        BucketState {
                            tokens,
                            last_refill,
                        },
                        Some(version),
                    )
                }
                None => (BucketState::full(&cfg, now_f), None),
            };

            let decision = try_acquire(&cfg, state, now_f, cost);
            let retry = if decision.allowed {
                None
            } else {
                retry_after_secs(&cfg, decision.state, cost).map(|s| s.ceil() as i64)
            };
            let next_version = prev_version.unwrap_or(0) + 1;

            // 条件写:version 未被并发改动(首次要求 version 属性不存在)。
            let mut put = self
                .db
                .put_item()
                .table_name(&self.table)
                .item("key", AttributeValue::S(key.to_string()))
                .item(
                    "tokens",
                    AttributeValue::N(decision.state.tokens.to_string()),
                )
                .item(
                    "last_refill",
                    AttributeValue::N(decision.state.last_refill.to_string()),
                )
                .item("version", AttributeValue::N(next_version.to_string()))
                .item("expires_at", AttributeValue::N((now + 3600).to_string()));
            put = match prev_version {
                Some(v) => put
                    .condition_expression("version = :v")
                    .expression_attribute_values(":v", AttributeValue::N(v.to_string())),
                None => put.condition_expression("attribute_not_exists(version)"),
            };
            match put.send().await {
                Ok(_) => {
                    return Ok(crate::ports::RateLimitDecision {
                        allowed: decision.allowed,
                        retry_after_secs: retry,
                    })
                }
                // 并发改动 → 重读重试(不放行)。
                Err(e) if e.code().unwrap_or("").contains("ConditionalCheckFailed") => continue,
                Err(e) => return Err(ddb_err(e)),
            }
        }
        // 重试耗尽(极端并发):Transient → 调用方 fail-open(anti-abuse 优先可用性;绕过口已窄化)。
        Err(StoreError::Transient("rate limit CAS 冲突,重试耗尽".into()))
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.db
            .delete_item()
            .table_name(&self.table)
            .key("key", AttributeValue::S(key.to_string()))
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(())
    }
}
