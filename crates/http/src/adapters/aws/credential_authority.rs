//! AWS credential authority adapters.

use super::*;

/// DynamoDB 授权码存储。表主键 = `code`(S)。
#[derive(Clone)]
pub struct DynamoCodeStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
    clients_table: String,
    refs: DynamoAuthorityReferenceStore,
}

impl DynamoCodeStore {
    pub fn new(
        db: aws_sdk_dynamodb::Client,
        table: impl Into<String>,
        clients_table: impl Into<String>,
        refs_table: impl Into<String>,
        authority_reference_coverage_version: impl Into<String>,
    ) -> Self {
        DynamoCodeStore {
            refs: DynamoAuthorityReferenceStore::new(
                db.clone(),
                refs_table,
                authority_reference_coverage_version,
            ),
            db,
            table: table.into(),
            clients_table: clients_table.into(),
        }
    }

    fn active_client_touch(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> Result<aws_sdk_dynamodb::types::Update, StoreError> {
        let today = crate::current_unix_secs().div_euclid(86_400);
        aws_sdk_dynamodb::types::Update::builder()
            .table_name(&self.clients_table)
            .key("client_id", AttributeValue::S(tpk(tenant, client_id)))
            .update_expression("SET last_used_day = :today ADD authority_revision :one")
            .condition_expression(
                "attribute_exists(client_id) AND attribute_not_exists(tombstoned_at) AND \
                 (attribute_not_exists(last_used_day) OR last_used_day <= :today)",
            )
            .expression_attribute_values(":today", AttributeValue::N(today.to_string()))
            .expression_attribute_values(":one", AttributeValue::N("1".to_string()))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build authorization code client touch: {error}"))
            })
    }

    fn item(tenant: &str, r: CodeRecord) -> Result<HashMap<String, AttributeValue>, StoreError> {
        // 物理 pk = tpk(tenant, code);GSI client_id 值也 tenant 化(has_unexpired_by_client 隔离,codex B1)。
        let mut item = HashMap::from([
            ("code".to_string(), AttributeValue::S(tpk(tenant, &r.code))),
            (
                "client_id".to_string(),
                AttributeValue::S(tpk(tenant, &r.client_id)),
            ),
            (
                "redirect_uri".to_string(),
                AttributeValue::S(r.redirect_uri),
            ),
            (
                "code_challenge".to_string(),
                AttributeValue::S(r.code_challenge),
            ),
            ("user_id".to_string(), AttributeValue::S(r.user_id)),
            (
                "expires_at".to_string(),
                AttributeValue::N(r.expires_at.to_string()),
            ),
            (
                "resources".to_string(),
                AttributeValue::L(r.resources.into_iter().map(AttributeValue::S).collect()),
            ),
            (
                "scope".to_string(),
                AttributeValue::L(r.scope.into_iter().map(AttributeValue::S).collect()),
            ),
        ]);
        insert_cimd_snapshot(&mut item, r.cimd_snapshot, "authorization code")?;
        if let Some(sid) = r.authz_session_id {
            item.insert("authz_session_id".to_string(), AttributeValue::S(sid));
        }
        if let Some(n) = r.nonce {
            item.insert("nonce".to_string(), AttributeValue::S(n));
        }
        item.insert(
            "auth_time".to_string(),
            AttributeValue::N(r.auth_time.to_string()),
        );
        // RAR(spec 010 §4):每条 authorization_details 序列化为 JSON 串,存字符串列表(非空才存)。
        if !r.authorization_details.is_empty() {
            let ad: Vec<AttributeValue> = r
                .authorization_details
                .iter()
                .filter_map(|v| serde_json::to_string(v).ok())
                .map(AttributeValue::S)
                .collect();
            item.insert("authorization_details".to_string(), AttributeValue::L(ad));
        }
        // acr/amr(C9.5b 联邦透传;非空才存)。amr 存 **List**(与 ss() 的 as_l() 读法一致,
        // 对齐 resources/scope;**不用 Ss** 字符串集——ss() 读的是 L,类型不符会静默读空)。
        if let Some(acr) = r.acr {
            item.insert("acr".to_string(), AttributeValue::S(acr));
        }
        if !r.amr.is_empty() {
            item.insert(
                "amr".to_string(),
                AttributeValue::L(r.amr.into_iter().map(AttributeValue::S).collect()),
            );
        }
        if let Some(epoch) = r.credential_epoch {
            item.insert(
                "credential_epoch".to_string(),
                AttributeValue::N(epoch.to_string()),
            );
        }
        if let Some(version) = r.password_credential_version {
            item.insert(
                "password_credential_version".to_string(),
                AttributeValue::N(version.to_string()),
            );
        }
        Ok(item)
    }

    pub(super) fn record(item: &HashMap<String, AttributeValue>) -> Result<CodeRecord, StoreError> {
        let cimd_snapshot = read_cimd_snapshot(item, "authorization code")?;
        Ok(CodeRecord {
            code: strip_tpk(&s(item.get("code")).unwrap_or_default()),
            client_id: strip_tpk(&s(item.get("client_id")).unwrap_or_default()),
            cimd_snapshot,
            redirect_uri: s(item.get("redirect_uri")).unwrap_or_default(),
            code_challenge: s(item.get("code_challenge")).unwrap_or_default(),
            resources: ss(item.get("resources")),
            user_id: s(item.get("user_id")).unwrap_or_default(),
            scope: ss(item.get("scope")),
            expires_at: n_i64(item.get("expires_at")).unwrap_or(0),
            authz_session_id: s(item.get("authz_session_id")),
            nonce: s(item.get("nonce")),
            auth_time: n_i64(item.get("auth_time")).unwrap_or(0),
            authorization_details: item
                .get("authorization_details")
                .and_then(|value| value.as_l().ok())
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_s().ok())
                        .filter_map(|value| serde_json::from_str(value).ok())
                        .collect()
                })
                .unwrap_or_default(),
            acr: s(item.get("acr")),
            amr: ss(item.get("amr")),
            credential_epoch: n_u64(item.get("credential_epoch")),
            password_credential_version: n_u64(item.get("password_credential_version")),
        })
    }

    fn reference_identity(
        item: &HashMap<String, AttributeValue>,
    ) -> Result<(String, String, String, i64), StoreError> {
        let physical_code = s(item.get("code")).ok_or_else(|| {
            StoreError::Permanent("authorization code row is missing code".to_string())
        })?;
        let physical_client = s(item.get("client_id")).ok_or_else(|| {
            StoreError::Permanent("authorization code row is missing client_id".to_string())
        })?;
        let expires_at = n_i64(item.get("expires_at")).ok_or_else(|| {
            StoreError::Permanent("authorization code row is missing expires_at".to_string())
        })?;
        Ok((
            tenant_from_tpk(&physical_code),
            strip_tpk(&physical_code),
            strip_tpk(&physical_client),
            expires_at,
        ))
    }

    async fn delete_with_reference(
        &self,
        item: &HashMap<String, AttributeValue>,
    ) -> Result<(), StoreError> {
        use aws_sdk_dynamodb::types::{Delete, TransactWriteItem};

        let (tenant, code, client_id, expires_at) = Self::reference_identity(item)?;
        let source_delete = Delete::builder()
            .table_name(&self.table)
            .key("code", AttributeValue::S(tpk(&tenant, &code)))
            .condition_expression(
                "attribute_exists(code) AND client_id = :client_id AND expires_at = :expires_at",
            )
            .expression_attribute_values(":client_id", AttributeValue::S(tpk(&tenant, &client_id)))
            .expression_attribute_values(":expires_at", AttributeValue::N(expires_at.to_string()))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "build authorization code governance delete: {error}"
                ))
            })?;
        let request = self
            .db
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().delete(source_delete).build())
            .transact_items(
                TransactWriteItem::builder()
                    .delete(
                        self.refs
                            .code_delete(&tenant, &client_id, expires_at, &code)?,
                    )
                    .build(),
            );
        match send_idempotent_transaction(request).await? {
            true => Ok(()),
            false => Err(StoreError::Transient(
                "authorization code governance delete conflicted".to_string(),
            )),
        }
    }

    async fn governance_delete_matching(
        &self,
        tenant: &str,
        user_id: Option<&str>,
    ) -> Result<usize, StoreError> {
        let mut deleted = 0usize;
        let mut start_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let output = self
                .db
                .scan()
                .table_name(&self.table)
                .projection_expression("code, client_id, expires_at, user_id")
                .consistent_read(true)
                .set_exclusive_start_key(start_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in output.items() {
                let Some(physical_code) = s(item.get("code")) else {
                    return Err(StoreError::Permanent(
                        "authorization code governance row is missing code".to_string(),
                    ));
                };
                if tenant_from_tpk(&physical_code) != tenant {
                    continue;
                }
                if user_id
                    .is_some_and(|expected| s(item.get("user_id")).as_deref() != Some(expected))
                {
                    continue;
                }
                self.delete_with_reference(item).await?;
                deleted += 1;
            }
            match output.last_evaluated_key() {
                Some(key) if !key.is_empty() => start_key = Some(key.clone()),
                _ => break,
            }
        }
        Ok(deleted)
    }

    pub(crate) async fn finalize_exchange_failure(
        &self,
        authz_sessions: &DynamoAuthzSessionStore,
        tenant: &str,
        code: &str,
        client_id: &str,
        expires_at: i64,
        now: i64,
        lease_owner: &str,
        authz_session_id: Option<&str>,
        last_error: String,
    ) -> Result<Option<AuthzSessionRecord>, StoreError> {
        self.finalize_exchange_failure_with_clock(
            authz_sessions,
            tenant,
            code,
            client_id,
            expires_at,
            now,
            lease_owner,
            authz_session_id,
            last_error,
            crate::token::current_unix_secs_pub,
        )
        .await
    }

    pub(super) async fn finalize_exchange_failure_with_clock<N>(
        &self,
        authz_sessions: &DynamoAuthzSessionStore,
        tenant: &str,
        code: &str,
        client_id: &str,
        expires_at: i64,
        now: i64,
        lease_owner: &str,
        authz_session_id: Option<&str>,
        last_error: String,
        clock: N,
    ) -> Result<Option<AuthzSessionRecord>, StoreError>
    where
        N: Fn() -> i64,
    {
        use agent_auth_authn::authz_session::AuthzState;
        use aws_sdk_dynamodb::types::{TransactWriteItem, Update};

        let Some(session_id) = authz_session_id else {
            let commit_now = now.max(clock());
            self.finalize(
                tenant,
                code,
                client_id,
                expires_at,
                commit_now,
                lease_owner,
                None,
            )
            .await?;
            return Ok(None);
        };
        let Some(current) = authz_sessions.get(tenant, session_id).await? else {
            return Err(StoreError::Transient(
                "authorization session is unavailable for exchange failure".into(),
            ));
        };
        let commit_now = now.max(clock());
        if agent_auth_infra_core::lifecycle::shortlived_is_expired(commit_now, expires_at)
            || agent_auth_infra_core::lifecycle::shortlived_is_expired(
                commit_now,
                current.expires_at,
            )
        {
            return Err(StoreError::Transient(
                "authorization code or session changed during exchange failure".into(),
            ));
        }
        let expected_sequence = current.sequence;
        let next =
            crate::authz_session::prepare_exchange_failure_transition(current, last_error.clone())?;
        let next_sequence = next.sequence;

        let code_update = Update::builder()
            .table_name(&self.table)
            .key("code", AttributeValue::S(tpk(tenant, code)))
            .update_expression("SET #consumed = :true REMOVE #lease, #owner")
            .condition_expression(
                "attribute_exists(code) AND attribute_not_exists(#consumed) \
                 AND #owner = :owner AND authz_session_id = :session_id \
                 AND client_id = :client_id AND expires_at = :expires_at \
                 AND expires_at > :now",
            )
            .expression_attribute_names("#consumed", "consumed")
            .expression_attribute_names("#lease", "lease_until")
            .expression_attribute_names("#owner", "lease_owner")
            .expression_attribute_values(":true", AttributeValue::Bool(true))
            .expression_attribute_values(":owner", AttributeValue::S(lease_owner.to_string()))
            .expression_attribute_values(":session_id", AttributeValue::S(session_id.to_string()))
            .expression_attribute_values(":client_id", AttributeValue::S(tpk(tenant, client_id)))
            .expression_attribute_values(":expires_at", AttributeValue::N(expires_at.to_string()))
            .expression_attribute_values(":now", AttributeValue::N(commit_now.to_string()))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "build authorization code exchange failure update: {error}"
                ))
            })?;
        let session_update = Update::builder()
            .table_name(&authz_sessions.table)
            .key("session_id", AttributeValue::S(tpk(tenant, session_id)))
            .update_expression(
                "SET #state = :failed, #last_error = :last_error, #sequence = :next_sequence",
            )
            .condition_expression(
                "attribute_exists(session_id) AND #state = :expected_state \
                 AND #sequence = :expected_sequence AND expires_at > :now",
            )
            .expression_attribute_names("#state", "state")
            .expression_attribute_names("#last_error", "last_error")
            .expression_attribute_names("#sequence", "sequence")
            .expression_attribute_values(
                ":failed",
                AttributeValue::S(AuthzState::ExchangeFailed.as_str().to_string()),
            )
            .expression_attribute_values(
                ":expected_state",
                AttributeValue::S(AuthzState::CodeIssuedAwaitingExchange.as_str().to_string()),
            )
            .expression_attribute_values(
                ":expected_sequence",
                AttributeValue::N(expected_sequence.to_string()),
            )
            .expression_attribute_values(
                ":next_sequence",
                AttributeValue::N(next_sequence.to_string()),
            )
            .expression_attribute_values(":now", AttributeValue::N(commit_now.to_string()))
            .expression_attribute_values(":last_error", AttributeValue::S(last_error))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "build authorization session exchange failure update: {error}"
                ))
            })?;
        let request = self
            .db
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().update(code_update).build())
            .transact_items(TransactWriteItem::builder().update(session_update).build())
            .transact_items(
                TransactWriteItem::builder()
                    .delete(self.refs.code_delete(tenant, client_id, expires_at, code)?)
                    .build(),
            );
        match send_idempotent_transaction(request).await {
            Ok(true) => Ok(Some(next)),
            Ok(false) => Err(StoreError::Transient(
                "authorization code or session changed during exchange failure".into(),
            )),
            Err(error) => Err(error),
        }
    }

    pub(crate) async fn put_authorized(
        &self,
        users: &DynamoUsersStore,
        tenant: &str,
        record: CodeRecord,
        expected_epoch: u64,
    ) -> Result<CodeIssueOutcome, StoreError> {
        use aws_sdk_dynamodb::types::{ConditionCheck, Put, TransactWriteItem};

        let user_id = record.user_id.clone();
        let requires_user_authority = crate::user_gate::is_human_user(&user_id);
        let registered_client = record.cimd_snapshot.is_none();
        let client_id = record.client_id.clone();
        let reference_put = self.refs.code_put(tenant, &record)?;
        let item = Self::item(tenant, record)?;
        let epoch_condition = if expected_epoch == 0 {
            "(attribute_not_exists(credential_epoch) OR credential_epoch = :epoch)"
        } else {
            "credential_epoch = :epoch"
        };
        let user_check = ConditionCheck::builder()
            .table_name(&users.table)
            .key("user_id", AttributeValue::S(tpk(tenant, &user_id)))
            .condition_expression(format!(
                "attribute_exists(user_id) AND \
                 (attribute_not_exists(#status) OR #status = :active) AND \
                 (attribute_not_exists(revocation_pending) OR revocation_pending = :false) AND \
                 {epoch_condition}"
            ))
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":active", AttributeValue::S("active".to_string()))
            .expression_attribute_values(":false", AttributeValue::Bool(false))
            .expression_attribute_values(":epoch", AttributeValue::N(expected_epoch.to_string()))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build authorization code user condition: {error}"))
            })?;
        let code_put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(code)")
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build authorized code put: {error}"))
            })?;
        let mut request = self.db.transact_write_items();
        if requires_user_authority {
            request = request.transact_items(
                TransactWriteItem::builder()
                    .condition_check(user_check)
                    .build(),
            );
        }
        request = request
            .transact_items(TransactWriteItem::builder().put(code_put).build())
            .transact_items(TransactWriteItem::builder().put(reference_put).build());
        if registered_client {
            request = request.transact_items(
                TransactWriteItem::builder()
                    .update(self.active_client_touch(tenant, &client_id)?)
                    .build(),
            );
        }
        match send_idempotent_transaction(request).await {
            Ok(true) => Ok(CodeIssueOutcome::Stored),
            Ok(false) => {
                let authority_remains = !requires_user_authority
                    || users
                        .get_by_id(tenant, &user_id)
                        .await?
                        .is_some_and(|user| {
                            user.status == crate::ports::UserStatus::Active
                                && !user.revocation_pending
                                && user.credential_epoch == expected_epoch
                        });
                if authority_remains {
                    Ok(CodeIssueOutcome::CodeExists)
                } else {
                    Ok(CodeIssueOutcome::AuthorityChanged)
                }
            }
            Err(error) => Err(error),
        }
    }
}

impl CodeStore for DynamoCodeStore {
    async fn put(&self, tenant: &str, r: CodeRecord) -> Result<(), StoreError> {
        use aws_sdk_dynamodb::types::{Put, TransactWriteItem};

        let registered_client = r.cimd_snapshot.is_none();
        let client_id = r.client_id.clone();
        let reference_put = self.refs.code_put(tenant, &r)?;
        let item = Self::item(tenant, r)?;
        let code_put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(code)")
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build authorization code put: {error}"))
            })?;
        let mut request = self
            .db
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().put(code_put).build())
            .transact_items(TransactWriteItem::builder().put(reference_put).build());
        if registered_client {
            request = request.transact_items(
                TransactWriteItem::builder()
                    .update(self.active_client_touch(tenant, &client_id)?)
                    .build(),
            );
        }
        match send_idempotent_transaction(request).await? {
            true => Ok(()),
            false => Err(StoreError::Transient(
                "authorization code reference write conflicted".to_string(),
            )),
        }
    }

    async fn acquire_lease(
        &self,
        tenant: &str,
        code: &str,
        lease_owner: &str,
        now: i64,
        lease_expires_at: i64,
    ) -> Result<LeaseAcquire, StoreError> {
        // 两阶段 lease 第①步(C10.1):条件 UpdateItem 原子占 signing lease。
        // 条件:item 存在(attribute_exists(code))且未 consumed 且(无 lease 或 lease 已过期)。
        // 并发只有一个满足条件成功,其余 ConditionalCheckFailed → 需区分 Locked/AlreadyConsumed/NotFound。
        // ⚠️ `consumed`/`lease_until` 用 ExpressionAttributeNames 别名——避免 DynamoDB 保留字冲突
        // (`consumed` 是保留关键字)。
        let res = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("code", AttributeValue::S(tpk(tenant, code)))
            .update_expression("SET #lease = :exp, #owner = :owner")
            .condition_expression(
                "attribute_exists(code) AND attribute_not_exists(#consumed) \
                 AND expires_at > :now \
                 AND (attribute_not_exists(#lease) OR #lease <= :now)",
            )
            .expression_attribute_names("#lease", "lease_until")
            .expression_attribute_names("#owner", "lease_owner")
            .expression_attribute_names("#consumed", "consumed")
            .expression_attribute_values(":exp", AttributeValue::N(lease_expires_at.to_string()))
            .expression_attribute_values(":owner", AttributeValue::S(lease_owner.to_string()))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllNew)
            .send()
            .await;

        match res {
            Ok(out) => {
                let item = out.attributes().ok_or_else(|| {
                    StoreError::Permanent("UpdateItem ALL_NEW 无 attributes".into())
                })?;
                Ok(LeaseAcquire::Acquired(Self::record(item)?))
            }
            Err(e) => {
                // 条件失败:读一次判 NotFound / AlreadyConsumed / Locked。
                let code_str = e.code().unwrap_or("");
                if code_str.contains("ConditionalCheckFailed") {
                    let got = self
                        .db
                        .get_item()
                        .table_name(&self.table)
                        .key("code", AttributeValue::S(tpk(tenant, code)))
                        .consistent_read(true)
                        .send()
                        .await
                        .map_err(ddb_err)?;
                    match got.item() {
                        None => Ok(LeaseAcquire::NotFound),
                        Some(item) => {
                            let record = Self::record(item)?;
                            if agent_auth_infra_core::lifecycle::shortlived_is_expired(
                                now,
                                record.expires_at,
                            ) {
                                Ok(LeaseAcquire::NotFound)
                            } else if item.contains_key("consumed") {
                                Ok(LeaseAcquire::AlreadyConsumed {
                                    record,
                                    issued_grant_id: s(item.get("issued_grant_id")),
                                })
                            } else {
                                Ok(LeaseAcquire::Locked)
                            }
                        }
                    }
                } else {
                    Err(ddb_err(e))
                }
            }
        }
    }

    async fn finalize(
        &self,
        tenant: &str,
        code: &str,
        client_id: &str,
        expires_at: i64,
        now: i64,
        lease_owner: &str,
        issued_grant_id: Option<&str>,
    ) -> Result<(), StoreError> {
        use aws_sdk_dynamodb::types::{TransactWriteItem, Update};

        // 仅当前 lease owner 可标记 consumed，防到期重占后旧请求覆盖新 owner 的签发结果。
        let mut code_update = Update::builder()
            .table_name(&self.table)
            .key("code", AttributeValue::S(tpk(tenant, code)))
            .update_expression("SET #consumed = :t REMOVE #lease, #owner")
            .condition_expression(
                "attribute_exists(code) AND attribute_not_exists(#consumed) AND #owner = :owner \
                 AND client_id = :client_id AND expires_at = :expires_at \
                 AND expires_at > :now",
            )
            .expression_attribute_names("#consumed", "consumed")
            .expression_attribute_names("#lease", "lease_until")
            .expression_attribute_names("#owner", "lease_owner")
            .expression_attribute_values(":t", AttributeValue::Bool(true))
            .expression_attribute_values(":owner", AttributeValue::S(lease_owner.to_string()))
            .expression_attribute_values(":client_id", AttributeValue::S(tpk(tenant, client_id)))
            .expression_attribute_values(":expires_at", AttributeValue::N(expires_at.to_string()))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()));
        if let Some(grant_id) = issued_grant_id {
            code_update = code_update
                .update_expression(
                    "SET #consumed = :t, issued_grant_id = :grant REMOVE #lease, #owner",
                )
                .expression_attribute_values(":grant", AttributeValue::S(grant_id.to_string()));
        }
        let code_update = code_update.build().map_err(|error| {
            StoreError::Permanent(format!("build authorization code finalize update: {error}"))
        })?;
        let request = self
            .db
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().update(code_update).build())
            .transact_items(
                TransactWriteItem::builder()
                    .delete(self.refs.code_delete(tenant, client_id, expires_at, code)?)
                    .build(),
            );
        match send_idempotent_transaction(request).await? {
            true => Ok(()),
            false => Err(StoreError::Transient(
                "authorization code lease ownership was lost".to_string(),
            )),
        }
    }

    async fn release_lease(
        &self,
        tenant: &str,
        code: &str,
        lease_owner: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        // 仅 owner 可清自己的 lease；旧请求不得清除到期后由新请求取得的 lease。
        let result = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("code", AttributeValue::S(tpk(tenant, code)))
            .update_expression("REMOVE #lease, #owner")
            .condition_expression(
                "attribute_exists(code) AND attribute_not_exists(#consumed) AND #owner = :owner \
                 AND expires_at > :now",
            )
            .expression_attribute_names("#lease", "lease_until")
            .expression_attribute_names("#owner", "lease_owner")
            .expression_attribute_names("#consumed", "consumed")
            .expression_attribute_values(":owner", AttributeValue::S(lease_owner.to_string()))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .send()
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(error)
                if error
                    .code()
                    .unwrap_or("")
                    .contains("ConditionalCheckFailed") =>
            {
                Err(StoreError::Transient(
                    "authorization code lease ownership was lost".into(),
                ))
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn record_replay(&self, tenant: &str, code: &str, now: i64) -> Result<bool, StoreError> {
        let result = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("code", AttributeValue::S(tpk(tenant, code)))
            .update_expression("SET replay_detected = :t")
            .condition_expression("attribute_exists(#consumed) AND expires_at > :now")
            .expression_attribute_names("#consumed", "consumed")
            .expression_attribute_values(":t", AttributeValue::Bool(true))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .code()
                    .unwrap_or("")
                    .contains("ConditionalCheckFailed") =>
            {
                Ok(false)
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn replay_detected(&self, tenant: &str, code: &str) -> Result<bool, StoreError> {
        let item = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("code", AttributeValue::S(tpk(tenant, code)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(item
            .item()
            .and_then(|values| values.get("replay_detected"))
            .and_then(|value| value.as_bool().ok())
            .copied()
            .unwrap_or(false))
    }

    async fn has_unexpired_by_client(
        &self,
        tenant: &str,
        client_id: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.refs.has_unexpired_code(tenant, client_id, now).await
    }

    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        self.governance_delete_matching(tenant, Some(user_id)).await
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        self.governance_delete_matching(tenant, None).await
    }
}

/// DynamoDB refresh family 存储。表主键 = `family_id`(S)。原子 rotation 用条件 UpdateItem。
#[derive(Clone)]
pub struct DynamoRefreshStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
    clients_table: String,
    refs: DynamoAuthorityReferenceStore,
}

const REFRESH_LEASE_UPDATE_EXPRESSION: &str =
    "SET signing_lease_owner = :owner, signing_lease_expires_at = :lease_expires_at";
const REFRESH_LEASE_CONDITION_EXPRESSION: &str =
    "attribute_exists(family_id) AND #ver = :expected \
     AND (attribute_not_exists(#revoked) OR #revoked = :f) \
     AND (attribute_not_exists(signing_lease_owner) \
     OR attribute_not_exists(signing_lease_expires_at) \
     OR signing_lease_expires_at <= :now)";
const REFRESH_FINALIZE_UPDATE_EXPRESSION: &str =
    "SET #ver = :next REMOVE signing_lease_owner, signing_lease_expires_at";
const REFRESH_FINALIZE_CONDITION_EXPRESSION: &str =
    "attribute_exists(family_id) AND #ver = :expected \
     AND (attribute_not_exists(#revoked) OR #revoked = :f) \
     AND signing_lease_owner = :owner AND signing_lease_expires_at > :now";
const REFRESH_RELEASE_UPDATE_EXPRESSION: &str =
    "REMOVE signing_lease_owner, signing_lease_expires_at";
const REFRESH_RELEASE_CONDITION_EXPRESSION: &str =
    "attribute_exists(family_id) AND #ver = :expected AND signing_lease_owner = :owner";

impl DynamoRefreshStore {
    pub fn new(
        db: aws_sdk_dynamodb::Client,
        table: impl Into<String>,
        clients_table: impl Into<String>,
        refs_table: impl Into<String>,
        authority_reference_coverage_version: impl Into<String>,
    ) -> Self {
        DynamoRefreshStore {
            refs: DynamoAuthorityReferenceStore::new(
                db.clone(),
                refs_table,
                authority_reference_coverage_version,
            ),
            db,
            table: table.into(),
            clients_table: clients_table.into(),
        }
    }

    fn active_client_touch(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> Result<aws_sdk_dynamodb::types::Update, StoreError> {
        let today = crate::current_unix_secs().div_euclid(86_400);
        aws_sdk_dynamodb::types::Update::builder()
            .table_name(&self.clients_table)
            .key("client_id", AttributeValue::S(tpk(tenant, client_id)))
            .update_expression("SET last_used_day = :today ADD authority_revision :one")
            .condition_expression(
                "attribute_exists(client_id) AND attribute_not_exists(tombstoned_at) AND \
                 (attribute_not_exists(last_used_day) OR last_used_day <= :today)",
            )
            .expression_attribute_values(":today", AttributeValue::N(today.to_string()))
            .expression_attribute_values(":one", AttributeValue::N("1".to_string()))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build refresh family client touch: {error}"))
            })
    }

    async fn classify_lease_conflict(
        &self,
        tenant: &str,
        family_id: &str,
        expected_version: u64,
        now: i64,
    ) -> Result<RefreshLeaseAcquire, StoreError> {
        let output = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("family_id", AttributeValue::S(tpk(tenant, family_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        let Some(item) = output.item() else {
            return Ok(RefreshLeaseAcquire::NotFound);
        };
        if item
            .get("revoked")
            .and_then(|value| value.as_bool().ok())
            .copied()
            .unwrap_or(false)
        {
            return Ok(RefreshLeaseAcquire::Revoked);
        }
        if n_u64(item.get("current_version")).unwrap_or(0) != expected_version {
            return Ok(RefreshLeaseAcquire::VersionMismatch);
        }
        if let Some(expires_at) = n_i64(item.get("signing_lease_expires_at")) {
            if expires_at > now {
                return Ok(RefreshLeaseAcquire::Locked {
                    retry_after_secs: expires_at.saturating_sub(now).max(1) as u64,
                });
            }
        }
        Err(StoreError::Transient(
            "refresh lease condition changed during conflict classification".into(),
        ))
    }

    pub async fn finalize_rotation_with_grace(
        &self,
        grace: Option<&DynamoGraceStore>,
        tenant: &str,
        family_id: &str,
        expected_version: u64,
        lease_owner: &str,
        now: i64,
        grace_entry: Option<GraceCacheEntry>,
    ) -> Result<bool, StoreError> {
        if grace.is_some() != grace_entry.is_some() {
            return Err(StoreError::Permanent(
                "refresh finalize grace store and entry must be configured together".into(),
            ));
        }
        if grace_entry
            .as_ref()
            .is_some_and(|entry| entry.family_id != family_id || entry.version != expected_version)
        {
            return Err(StoreError::Permanent(
                "refresh finalize grace entry does not match the leased version".into(),
            ));
        }
        let prepared_grace = match (grace, grace_entry) {
            (Some(grace), Some(entry)) => {
                Some((grace.table.as_str(), grace.encrypted_item(entry).await?))
            }
            (None, None) => None,
            _ => unreachable!("grace configuration equality checked above"),
        };
        self.finalize_rotation_transaction(
            tenant,
            family_id,
            expected_version,
            lease_owner,
            now,
            prepared_grace,
        )
        .await
    }

    async fn finalize_rotation_transaction(
        &self,
        tenant: &str,
        family_id: &str,
        expected_version: u64,
        lease_owner: &str,
        now: i64,
        prepared_grace: Option<(&str, HashMap<String, AttributeValue>)>,
    ) -> Result<bool, StoreError> {
        use aws_sdk_dynamodb::types::{Put, TransactWriteItem, Update};

        let update = Update::builder()
            .table_name(&self.table)
            .key("family_id", AttributeValue::S(tpk(tenant, family_id)))
            .update_expression(REFRESH_FINALIZE_UPDATE_EXPRESSION)
            .condition_expression(REFRESH_FINALIZE_CONDITION_EXPRESSION)
            .expression_attribute_names("#ver", "current_version")
            .expression_attribute_names("#revoked", "revoked")
            .expression_attribute_values(
                ":next",
                AttributeValue::N((expected_version + 1).to_string()),
            )
            .expression_attribute_values(
                ":expected",
                AttributeValue::N(expected_version.to_string()),
            )
            .expression_attribute_values(":f", AttributeValue::Bool(false))
            .expression_attribute_values(":owner", AttributeValue::S(lease_owner.to_string()))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .build()
            .map_err(|error| StoreError::Permanent(format!("build refresh finalize: {error}")))?;
        let mut request = self
            .db
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().update(update).build());
        if let Some((grace_table, item)) = prepared_grace {
            let put = Put::builder()
                .table_name(grace_table)
                .set_item(Some(item))
                .condition_expression(
                    "attribute_not_exists(family_id) AND attribute_not_exists(#version)",
                )
                .expression_attribute_names("#version", "version")
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!("build refresh grace finalize: {error}"))
                })?;
            request = request.transact_items(TransactWriteItem::builder().put(put).build());
        }
        send_idempotent_transaction(request).await
    }

    async fn revoke_with_epoch(
        &self,
        tenant: &str,
        family_id: &str,
        before_epoch: Option<u64>,
    ) -> Result<bool, StoreError> {
        use aws_sdk_dynamodb::types::{TransactWriteItem, Update};

        let output = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("family_id", AttributeValue::S(tpk(tenant, family_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        let Some(item) = output.item() else {
            return Ok(false);
        };
        let client_id = strip_tpk(&s(item.get("client_id")).ok_or_else(|| {
            StoreError::Permanent("refresh family is missing client_id".to_string())
        })?);
        let already_revoked = item
            .get("revoked")
            .and_then(|value| value.as_bool().ok())
            .copied()
            .unwrap_or(false);
        let epoch_matches = before_epoch.is_none_or(|epoch| {
            let stored = n_u64(item.get("credential_epoch"));
            if epoch == 0 {
                stored.is_some_and(|value| value < epoch)
            } else {
                stored.is_none_or(|value| value < epoch)
            }
        });
        if !epoch_matches {
            return Ok(false);
        }
        if already_revoked {
            self.db
                .delete_item()
                .table_name(self.refs.table())
                .key(
                    "client_key",
                    AttributeValue::S(DynamoAuthorityReferenceStore::client_key(
                        tenant, &client_id,
                    )),
                )
                .key(
                    "reference_key",
                    AttributeValue::S(DynamoAuthorityReferenceStore::refresh_reference_key(
                        family_id,
                    )),
                )
                .send()
                .await
                .map_err(ddb_err)?;
            return Ok(true);
        }

        let mut update = Update::builder()
            .table_name(&self.table)
            .key("family_id", AttributeValue::S(tpk(tenant, family_id)))
            .update_expression("SET #revoked = :true")
            .condition_expression(
                "attribute_exists(family_id) AND client_id = :client_id AND \
                 (attribute_not_exists(#revoked) OR #revoked = :false)",
            )
            .expression_attribute_names("#revoked", "revoked")
            .expression_attribute_values(":true", AttributeValue::Bool(true))
            .expression_attribute_values(":false", AttributeValue::Bool(false))
            .expression_attribute_values(":client_id", AttributeValue::S(tpk(tenant, &client_id)));
        if let Some(epoch) = before_epoch {
            let epoch_condition = if epoch == 0 {
                "attribute_exists(family_id) AND \
                 client_id = :client_id AND \
                 (attribute_not_exists(#revoked) OR #revoked = :false) AND \
                 attribute_exists(credential_epoch) AND credential_epoch < :epoch"
            } else {
                "attribute_exists(family_id) AND \
                 client_id = :client_id AND \
                 (attribute_not_exists(#revoked) OR #revoked = :false) AND \
                 (attribute_not_exists(credential_epoch) OR credential_epoch < :epoch)"
            };
            update = update
                .condition_expression(epoch_condition)
                .expression_attribute_values(":epoch", AttributeValue::N(epoch.to_string()));
        }
        let update = update.build().map_err(|error| {
            StoreError::Permanent(format!("build refresh family revoke update: {error}"))
        })?;
        let request = self
            .db
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().update(update).build())
            .transact_items(
                TransactWriteItem::builder()
                    .delete(self.refs.refresh_delete(tenant, &client_id, family_id)?)
                    .build(),
            );
        match send_idempotent_transaction(request).await? {
            true => Ok(true),
            false => {
                let current = self.get(tenant, family_id).await?;
                if current.is_none_or(|record| record.revoked) {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }

    fn reference_identity(
        item: &HashMap<String, AttributeValue>,
    ) -> Result<(String, String, String), StoreError> {
        let physical_family = s(item.get("family_id")).ok_or_else(|| {
            StoreError::Permanent("refresh family row is missing family_id".to_string())
        })?;
        let physical_client = s(item.get("client_id")).ok_or_else(|| {
            StoreError::Permanent("refresh family row is missing client_id".to_string())
        })?;
        Ok((
            tenant_from_tpk(&physical_family),
            strip_tpk(&physical_family),
            strip_tpk(&physical_client),
        ))
    }

    async fn delete_with_reference(
        &self,
        item: &HashMap<String, AttributeValue>,
    ) -> Result<String, StoreError> {
        use aws_sdk_dynamodb::types::{Delete, TransactWriteItem};

        let (tenant, family_id, client_id) = Self::reference_identity(item)?;
        let source_delete = Delete::builder()
            .table_name(&self.table)
            .key("family_id", AttributeValue::S(tpk(&tenant, &family_id)))
            .condition_expression("attribute_exists(family_id) AND client_id = :client_id")
            .expression_attribute_values(":client_id", AttributeValue::S(tpk(&tenant, &client_id)))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build refresh governance delete: {error}"))
            })?;
        let request = self
            .db
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().delete(source_delete).build())
            .transact_items(
                TransactWriteItem::builder()
                    .delete(self.refs.refresh_delete(&tenant, &client_id, &family_id)?)
                    .build(),
            );
        match send_idempotent_transaction(request).await? {
            true => Ok(family_id),
            false => Err(StoreError::Transient(
                "refresh governance delete conflicted".to_string(),
            )),
        }
    }

    async fn governance_delete_matching(
        &self,
        tenant: &str,
        user_id: Option<&str>,
    ) -> Result<Vec<String>, StoreError> {
        let mut removed = Vec::new();
        let mut start_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let output = self
                .db
                .scan()
                .table_name(&self.table)
                .projection_expression("family_id, client_id, user_id")
                .consistent_read(true)
                .set_exclusive_start_key(start_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in output.items() {
                let Some(physical_family) = s(item.get("family_id")) else {
                    return Err(StoreError::Permanent(
                        "refresh governance row is missing family_id".to_string(),
                    ));
                };
                if tenant_from_tpk(&physical_family) != tenant {
                    continue;
                }
                let logical_user = s(item.get("user_id"))
                    .map(|value| strip_tpk(&value))
                    .unwrap_or_default();
                if user_id.is_some_and(|expected| logical_user != expected) {
                    continue;
                }
                removed.push(self.delete_with_reference(item).await?);
            }
            match output.last_evaluated_key() {
                Some(key) if !key.is_empty() => start_key = Some(key.clone()),
                _ => break,
            }
        }
        Ok(removed)
    }
}

pub(super) fn n_u64(v: Option<&AttributeValue>) -> Option<u64> {
    v.and_then(|a| a.as_n().ok()).and_then(|s| s.parse().ok())
}

impl RefreshStore for DynamoRefreshStore {
    async fn create(&self, tenant: &str, r: RefreshFamilyRecord) -> Result<(), StoreError> {
        use aws_sdk_dynamodb::types::{Put, TransactWriteItem};

        let active = !r.revoked;
        let registered_client = r.cimd_snapshot.is_none();
        let client_id = r.client_id.clone();
        let reference_put = active
            .then(|| self.refs.refresh_put(tenant, &r))
            .transpose()?;
        // 物理 pk = tpk(tenant, family_id);GSI client_id/user_id 值 tenant 化(by-client/by-user 隔离,codex B1)。
        let mut item = HashMap::from([
            (
                "family_id".to_string(),
                AttributeValue::S(tpk(tenant, &r.family_id)),
            ),
            (
                "current_version".to_string(),
                AttributeValue::N(r.current_version.to_string()),
            ),
            ("revoked".to_string(), AttributeValue::Bool(r.revoked)),
            (
                "client_id".to_string(),
                AttributeValue::S(tpk(tenant, &r.client_id)),
            ),
            (
                "user_id".to_string(),
                AttributeValue::S(tpk(tenant, &r.user_id)),
            ),
            (
                "credential_epoch".to_string(),
                AttributeValue::N(r.credential_epoch.to_string()),
            ),
            (
                "resources".to_string(),
                AttributeValue::L(r.resources.into_iter().map(AttributeValue::S).collect()),
            ),
            (
                "scope".to_string(),
                AttributeValue::L(r.scope.into_iter().map(AttributeValue::S).collect()),
            ),
            (
                "max_act_chain".to_string(),
                AttributeValue::N(r.max_act_chain.to_string()),
            ),
        ]);
        insert_cimd_snapshot(&mut item, r.cimd_snapshot, "refresh family")?;
        if !r.actor_allowlist.is_empty() {
            item.insert(
                "actor_allowlist".to_string(),
                AttributeValue::L(
                    r.actor_allowlist
                        .into_iter()
                        .map(AttributeValue::S)
                        .collect(),
                ),
            );
        }
        // DPoP 绑定(spec 010 §5.2/B1):稀疏属性,仅 DPoP-bound family 有值。
        if let Some(jkt) = r.dpop_jkt {
            item.insert("dpop_jkt".to_string(), AttributeValue::S(jkt));
        }
        if let Some(challenge) = r.pkce_code_challenge {
            item.insert(
                "pkce_code_challenge".to_string(),
                AttributeValue::S(challenge),
            );
        }
        if let Some(auth_time) = r.auth_time {
            item.insert(
                "auth_time".to_string(),
                AttributeValue::N(auth_time.to_string()),
            );
        }
        if let Some(acr) = r.acr {
            item.insert("acr".to_string(), AttributeValue::S(acr));
        }
        if let Some(version) = r.password_credential_version {
            item.insert(
                "password_credential_version".to_string(),
                AttributeValue::N(version.to_string()),
            );
        }
        let family_put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(family_id)")
            .build()
            .map_err(|error| StoreError::Permanent(format!("build refresh family put: {error}")))?;
        let mut request = self
            .db
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().put(family_put).build());
        if let Some(reference_put) = reference_put {
            request =
                request.transact_items(TransactWriteItem::builder().put(reference_put).build());
        }
        if active && registered_client {
            request = request.transact_items(
                TransactWriteItem::builder()
                    .update(self.active_client_touch(tenant, &client_id)?)
                    .build(),
            );
        }
        match send_idempotent_transaction(request).await? {
            true => Ok(()),
            false => Err(StoreError::Transient(
                "refresh family reference write conflicted".to_string(),
            )),
        }
    }

    async fn get(
        &self,
        tenant: &str,
        family_id: &str,
    ) -> Result<Option<RefreshFamilyRecord>, StoreError> {
        let out = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("family_id", AttributeValue::S(tpk(tenant, family_id)))
            // Family revocation is an online authorization authority; stale reads could
            // temporarily re-enable tokens after code-replay or lifecycle cleanup.
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        let Some(item) = out.item() else {
            return Ok(None);
        };
        let cimd_snapshot = read_cimd_snapshot(item, "refresh family")?;
        Ok(Some(RefreshFamilyRecord {
            family_id: strip_tpk(&s(item.get("family_id")).unwrap_or_default()),
            current_version: n_u64(item.get("current_version")).unwrap_or(0),
            revoked: item
                .get("revoked")
                .and_then(|a| a.as_bool().ok())
                .copied()
                .unwrap_or(false),
            client_id: strip_tpk(&s(item.get("client_id")).unwrap_or_default()),
            cimd_snapshot,
            user_id: strip_tpk(&s(item.get("user_id")).unwrap_or_default()),
            credential_epoch: n_u64(item.get("credential_epoch")).unwrap_or(0),
            resources: ss(item.get("resources")),
            scope: ss(item.get("scope")),
            actor_allowlist: ss(item.get("actor_allowlist")),
            max_act_chain: n_u64(item.get("max_act_chain")).unwrap_or(1) as u32,
            // DPoP 绑定(spec 010 §5.2/B1;稀疏属性,旧 family 缺 → None=bearer,后向兼容)。
            dpop_jkt: s(item.get("dpop_jkt")),
            pkce_code_challenge: s(item.get("pkce_code_challenge")),
            auth_time: n_i64(item.get("auth_time")),
            acr: s(item.get("acr")),
            password_credential_version: n_u64(item.get("password_credential_version")),
        }))
    }

    async fn acquire_lease(
        &self,
        tenant: &str,
        family_id: &str,
        expected_version: u64,
        lease_owner: &str,
        now: i64,
        lease_expires_at: i64,
    ) -> Result<RefreshLeaseAcquire, StoreError> {
        if lease_owner.is_empty() || lease_expires_at <= now {
            return Err(StoreError::Permanent(
                "invalid refresh signing lease request".into(),
            ));
        }
        let result = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("family_id", AttributeValue::S(tpk(tenant, family_id)))
            .update_expression(REFRESH_LEASE_UPDATE_EXPRESSION)
            .condition_expression(REFRESH_LEASE_CONDITION_EXPRESSION)
            .expression_attribute_names("#ver", "current_version")
            .expression_attribute_names("#revoked", "revoked")
            .expression_attribute_values(
                ":expected",
                AttributeValue::N(expected_version.to_string()),
            )
            .expression_attribute_values(":f", AttributeValue::Bool(false))
            .expression_attribute_values(":owner", AttributeValue::S(lease_owner.to_string()))
            .expression_attribute_values(
                ":lease_expires_at",
                AttributeValue::N(lease_expires_at.to_string()),
            )
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .send()
            .await;
        match result {
            Ok(_) => Ok(RefreshLeaseAcquire::Acquired),
            Err(error)
                if error
                    .code()
                    .unwrap_or("")
                    .contains("ConditionalCheckFailed") =>
            {
                self.classify_lease_conflict(tenant, family_id, expected_version, now)
                    .await
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn finalize_rotation(
        &self,
        tenant: &str,
        family_id: &str,
        expected_version: u64,
        lease_owner: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.finalize_rotation_with_grace(
            None,
            tenant,
            family_id,
            expected_version,
            lease_owner,
            now,
            None,
        )
        .await
    }

    async fn release_lease(
        &self,
        tenant: &str,
        family_id: &str,
        expected_version: u64,
        lease_owner: &str,
    ) -> Result<bool, StoreError> {
        let result = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("family_id", AttributeValue::S(tpk(tenant, family_id)))
            .update_expression(REFRESH_RELEASE_UPDATE_EXPRESSION)
            .condition_expression(REFRESH_RELEASE_CONDITION_EXPRESSION)
            .expression_attribute_names("#ver", "current_version")
            .expression_attribute_values(
                ":expected",
                AttributeValue::N(expected_version.to_string()),
            )
            .expression_attribute_values(":owner", AttributeValue::S(lease_owner.to_string()))
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .code()
                    .unwrap_or("")
                    .contains("ConditionalCheckFailed") =>
            {
                Ok(false)
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn revoke(&self, tenant: &str, family_id: &str) -> Result<(), StoreError> {
        self.revoke_with_epoch(tenant, family_id, None).await?;
        Ok(())
    }

    async fn revoke_by_user(&self, tenant: &str, user_id: &str) -> Result<Vec<String>, StoreError> {
        // 账户恢复/SCIM disable:按 tenant-qualified user_id GSI 查询并吊销全部 family。
        // GSI 短暂未收敛的 family 仍被强一致 User credential_epoch gate 永久隔离,
        // re-enable 不会复活;返回已可见的全部 family_id 供上层清理宽限缓存 C3.5。
        let mut revoked = Vec::new();
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let query = self
                .db
                .query()
                .table_name(&self.table)
                .index_name("user_id-index")
                .key_condition_expression("user_id = :u")
                .expression_attribute_values(":u", AttributeValue::S(tpk(tenant, user_id)))
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in query.items() {
                let fid_phys = s(item.get("family_id")).ok_or_else(|| {
                    StoreError::Permanent("refresh user_id-index item missing family_id".into())
                })?;
                let fid = strip_tpk(&fid_phys);
                self.revoke(tenant, &fid).await?;
                revoked.push(fid);
            }
            match query.last_evaluated_key() {
                Some(k) if !k.is_empty() => last_key = Some(k.clone()),
                _ => break,
            }
        }
        Ok(revoked)
    }

    async fn revoke_by_user_before_epoch(
        &self,
        tenant: &str,
        user_id: &str,
        epoch: u64,
    ) -> Result<Vec<String>, StoreError> {
        let mut revoked = Vec::new();
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let query = self
                .db
                .query()
                .table_name(&self.table)
                .index_name("user_id-index")
                .key_condition_expression("user_id = :u")
                .expression_attribute_values(":u", AttributeValue::S(tpk(tenant, user_id)))
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in query.items() {
                let family_id = s(item.get("family_id")).ok_or_else(|| {
                    StoreError::Permanent("refresh user_id-index item missing family_id".into())
                })?;
                let logical_id = strip_tpk(&family_id);
                if self
                    .revoke_with_epoch(tenant, &logical_id, Some(epoch))
                    .await?
                {
                    revoked.push(logical_id);
                }
            }
            match query.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        Ok(revoked)
    }

    async fn revoke_by_client(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> Result<Vec<String>, StoreError> {
        // spec 025 DELETE client 级联:强一致扫描该 client 名下全部 family。tombstone 已阻止
        // 新 family 出现；返回已吊销和本次吊销的全部 family_id，使部分失败后的重试仍可清理宽限缓存。
        let mut family_ids = Vec::new();
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let scan = self
                .db
                .scan()
                .table_name(&self.table)
                .consistent_read(true)
                .filter_expression("client_id = :c")
                .expression_attribute_values(":c", AttributeValue::S(tpk(tenant, client_id)))
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in scan.items() {
                if let Some(fid_phys) = s(item.get("family_id")) {
                    let fid = strip_tpk(&fid_phys);
                    if !item
                        .get("revoked")
                        .and_then(|value| value.as_bool().ok())
                        .copied()
                        .unwrap_or(false)
                    {
                        self.revoke(tenant, &fid).await?;
                    }
                    family_ids.push(fid);
                }
            }
            match scan.last_evaluated_key() {
                Some(k) if !k.is_empty() => last_key = Some(k.clone()),
                _ => break,
            }
        }
        Ok(family_ids)
    }

    async fn has_active_family_by_client(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> Result<bool, StoreError> {
        self.refs.has_active_refresh(tenant, client_id).await
    }

    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<Vec<String>, StoreError> {
        self.governance_delete_matching(tenant, Some(user_id)).await
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<Vec<String>, StoreError> {
        self.governance_delete_matching(tenant, None).await
    }
}

/// DynamoDB 会话存储。表主键 = `session_id`(S);expires_at 可挂 TTL 做 GC(判定仍走应用层)。
struct DynamoStoredSession {
    record: SessionRecord,
    generation: u64,
}

#[derive(Clone)]
pub struct DynamoSessionStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
}

impl DynamoSessionStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        DynamoSessionStore {
            db,
            table: table.into(),
        }
    }

    fn from_item(item: &HashMap<String, AttributeValue>) -> DynamoStoredSession {
        let auth_time = n_i64(item.get("auth_time")).unwrap_or(0);
        let created_at = n_i64(item.get("created_at")).unwrap_or(auth_time);
        DynamoStoredSession {
            record: SessionRecord {
                session_id: strip_tpk(&s(item.get("session_id")).unwrap_or_default()),
                user_id: strip_tpk(&s(item.get("user_id")).unwrap_or_default()),
                credential_epoch: n_u64(item.get("credential_epoch")).unwrap_or(0),
                auth_time,
                created_at,
                last_used_at: n_i64(item.get("last_used_at")).unwrap_or(created_at),
                device: s(item.get("device")).unwrap_or_else(|| "Unknown device".to_string()),
                expires_at: n_i64(item.get("expires_at")).unwrap_or(0),
                acr: s(item.get("acr")),
                amr: ss(item.get("amr")),
            },
            generation: n_u64(item.get("session_generation")).unwrap_or(0),
        }
    }

    pub(super) fn generation_key(tenant: &str, user_id: &str) -> String {
        tpk(tenant, &format!("__login_session_generation__:{user_id}"))
    }

    fn credential_session_fence_id(
        tenant: &str,
        user_id: &str,
        actor_session_id: &str,
        generation: u64,
    ) -> String {
        let mut digest = Sha256::new();
        digest.update(b"credential-session-fence:v1");
        for value in [tenant, user_id, actor_session_id] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        digest.update(generation.to_be_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest.finalize()[..27])
    }

    fn generation_marker_condition(generation: u64) -> &'static str {
        if generation == 0 {
            "attribute_not_exists(session_id) OR #generation = :expected"
        } else {
            "#generation = :expected"
        }
    }

    fn authoritative_session_condition(generation: u64) -> &'static str {
        if generation == 0 {
            "user_id = :u AND \
             (attribute_not_exists(session_generation) OR session_generation = :expected)"
        } else {
            "user_id = :u AND session_generation = :expected"
        }
    }

    fn session_item(
        tenant: &str,
        session: &SessionRecord,
        generation: u64,
    ) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::from([
            (
                "session_id".to_string(),
                AttributeValue::S(tpk(tenant, &session.session_id)),
            ),
            (
                "user_id".to_string(),
                AttributeValue::S(tpk(tenant, &session.user_id)),
            ),
            (
                "credential_epoch".to_string(),
                AttributeValue::N(session.credential_epoch.to_string()),
            ),
            (
                "session_generation".to_string(),
                AttributeValue::N(generation.to_string()),
            ),
            (
                "auth_time".to_string(),
                AttributeValue::N(session.auth_time.to_string()),
            ),
            (
                "created_at".to_string(),
                AttributeValue::N(session.created_at.to_string()),
            ),
            (
                "last_used_at".to_string(),
                AttributeValue::N(session.last_used_at.to_string()),
            ),
            (
                "device".to_string(),
                AttributeValue::S(session.device.clone()),
            ),
            (
                "expires_at".to_string(),
                AttributeValue::N(session.expires_at.to_string()),
            ),
        ]);
        if let Some(acr) = session.acr.clone() {
            item.insert("acr".to_string(), AttributeValue::S(acr));
        }
        if !session.amr.is_empty() {
            item.insert(
                "amr".to_string(),
                AttributeValue::L(session.amr.iter().cloned().map(AttributeValue::S).collect()),
            );
        }
        item
    }

    async fn recovery_commit_items(
        &self,
        tenant: &str,
        session: &SessionRecord,
    ) -> Result<
        (
            aws_sdk_dynamodb::types::TransactWriteItem,
            aws_sdk_dynamodb::types::TransactWriteItem,
        ),
        StoreError,
    > {
        use aws_sdk_dynamodb::types::{Put, TransactWriteItem, Update};

        let generation = self.current_generation(tenant, &session.user_id).await?;
        let next_generation = generation.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("login session generation exhausted".to_string())
        })?;
        let generation_update = Update::builder()
            .table_name(&self.table)
            .key(
                "session_id",
                AttributeValue::S(Self::generation_key(tenant, &session.user_id)),
            )
            .update_expression("SET #generation = :next, #kind = :kind")
            .condition_expression(Self::generation_marker_condition(generation))
            .expression_attribute_names("#generation", "generation")
            .expression_attribute_names("#kind", "kind")
            .expression_attribute_values(":expected", AttributeValue::N(generation.to_string()))
            .expression_attribute_values(":next", AttributeValue::N(next_generation.to_string()))
            .expression_attribute_values(
                ":kind",
                AttributeValue::S("login_session_generation".to_string()),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "build recovery login session generation update: {error}"
                ))
            })?;
        let session_put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(Self::session_item(tenant, session, next_generation)))
            .condition_expression("attribute_not_exists(session_id)")
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build recovered login session put: {error}"))
            })?;
        Ok((
            TransactWriteItem::builder()
                .update(generation_update)
                .build(),
            TransactWriteItem::builder().put(session_put).build(),
        ))
    }

    async fn current_generation_with_fence(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<(u64, Option<String>), StoreError> {
        let output = self
            .db
            .get_item()
            .table_name(&self.table)
            .key(
                "session_id",
                AttributeValue::S(Self::generation_key(tenant, user_id)),
            )
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        let item = output.item();
        Ok((
            item.and_then(|item| n_u64(item.get("generation")))
                .unwrap_or(0),
            item.and_then(|item| s(item.get("credential_session_fence_id"))),
        ))
    }

    async fn current_generation(&self, tenant: &str, user_id: &str) -> Result<u64, StoreError> {
        self.current_generation_with_fence(tenant, user_id)
            .await
            .map(|(generation, _)| generation)
    }

    async fn get_stored(
        &self,
        tenant: &str,
        session_id: &str,
    ) -> Result<Option<DynamoStoredSession>, StoreError> {
        let output = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("session_id", AttributeValue::S(tpk(tenant, session_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(output.item().map(Self::from_item))
    }

    async fn is_authoritative_session(
        &self,
        tenant: &str,
        user_id: &str,
        session_id: &str,
        generation: u64,
    ) -> Result<bool, StoreError> {
        Ok(self
            .get_stored(tenant, session_id)
            .await?
            .is_some_and(|stored| {
                stored.record.user_id == user_id && stored.generation == generation
            }))
    }

    async fn retained_fence_conflict_action(
        &self,
        tenant: &str,
        user_id: &str,
        retained_session_id: &str,
        attempted_generation: u64,
        attempt: usize,
    ) -> Result<AuthorityConflictAction, StoreError> {
        let observed_generation = self.current_generation(tenant, user_id).await?;
        let retained_is_authoritative = self
            .is_authoritative_session(tenant, user_id, retained_session_id, observed_generation)
            .await?;
        Ok(retained_fence_conflict_action(
            attempt,
            attempted_generation,
            observed_generation,
            retained_is_authoritative,
        ))
    }
}

impl SessionStore for DynamoSessionStore {
    async fn create(&self, tenant: &str, s: SessionRecord) -> Result<(), StoreError> {
        use aws_sdk_dynamodb::types::{ConditionCheck, Put, TransactWriteItem};

        let generation_key = Self::generation_key(tenant, &s.user_id);
        for _ in 0..5 {
            let generation = self.current_generation(tenant, &s.user_id).await?;
            let item = Self::session_item(tenant, &s, generation);
            let generation_check = ConditionCheck::builder()
                .table_name(&self.table)
                .key("session_id", AttributeValue::S(generation_key.clone()))
                .condition_expression(Self::generation_marker_condition(generation))
                .expression_attribute_names("#generation", "generation")
                .expression_attribute_values(":expected", AttributeValue::N(generation.to_string()))
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!(
                        "build login session generation condition: {error}"
                    ))
                })?;
            let session_put = Put::builder()
                .table_name(&self.table)
                .set_item(Some(item))
                .condition_expression("attribute_not_exists(session_id)")
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!("build login session put: {error}"))
                })?;
            let result = self
                .db
                .transact_write_items()
                .transact_items(
                    TransactWriteItem::builder()
                        .condition_check(generation_check)
                        .build(),
                )
                .transact_items(TransactWriteItem::builder().put(session_put).build())
                .send()
                .await;
            match result {
                Ok(_) => return Ok(()),
                Err(error) => match classify_transact_write_error(&error) {
                    Some((TransactionCancelAction::RetryCondition, _)) => continue,
                    Some((_, classified)) => return Err(classified),
                    None => return Err(ddb_err(error)),
                },
            }
        }
        Err(StoreError::Transient(
            "login session generation changed during create".to_string(),
        ))
    }
    async fn get(
        &self,
        tenant: &str,
        session_id: &str,
    ) -> Result<Option<SessionRecord>, StoreError> {
        let Some(stored) = self.get_stored(tenant, session_id).await? else {
            return Ok(None);
        };
        let generation = self
            .current_generation(tenant, &stored.record.user_id)
            .await?;
        Ok((stored.generation == generation).then_some(stored.record))
    }
    async fn delete(&self, tenant: &str, session_id: &str) -> Result<(), StoreError> {
        let result = self
            .db
            .delete_item()
            .table_name(&self.table)
            .key("session_id", AttributeValue::S(tpk(tenant, session_id)))
            .condition_expression("attribute_exists(user_id)")
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
    async fn list_by_user(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<Vec<SessionRecord>, StoreError> {
        let generation = self.current_generation(tenant, user_id).await?;
        let mut sessions = Vec::new();
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let query = self
                .db
                .query()
                .table_name(&self.table)
                .index_name("user_id-index")
                .key_condition_expression("user_id = :u")
                .expression_attribute_values(":u", AttributeValue::S(tpk(tenant, user_id)))
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            sessions.extend(
                query
                    .items()
                    .iter()
                    .map(Self::from_item)
                    .filter(|stored| {
                        stored.generation == generation && stored.record.expires_at > now
                    })
                    .map(|stored| stored.record),
            );
            match query.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        Ok(sessions)
    }
    async fn delete_owned(
        &self,
        tenant: &str,
        user_id: &str,
        actor_session_id: &str,
        target_session_id: &str,
    ) -> Result<bool, StoreError> {
        use aws_sdk_dynamodb::types::{ConditionCheck, Delete, TransactWriteItem};

        let physical_user_id = tpk(tenant, user_id);
        let actor_physical_id = tpk(tenant, actor_session_id);
        let target_physical_id = tpk(tenant, target_session_id);
        for attempt in 0..TRANSACTION_RETRY_ATTEMPTS {
            let generation = self.current_generation(tenant, user_id).await?;
            let generation_condition = ConditionCheck::builder()
                .table_name(&self.table)
                .key(
                    "session_id",
                    AttributeValue::S(Self::generation_key(tenant, user_id)),
                )
                .condition_expression(Self::generation_marker_condition(generation))
                .expression_attribute_names("#generation", "generation")
                .expression_attribute_values(":expected", AttributeValue::N(generation.to_string()))
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!(
                        "build login session generation condition: {error}"
                    ))
                })?;
            let authoritative_condition = Self::authoritative_session_condition(generation);
            let target_delete = Delete::builder()
                .table_name(&self.table)
                .key("session_id", AttributeValue::S(target_physical_id.clone()))
                .condition_expression(authoritative_condition)
                .expression_attribute_values(":u", AttributeValue::S(physical_user_id.clone()))
                .expression_attribute_values(":expected", AttributeValue::N(generation.to_string()))
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!("build owned login session delete: {error}"))
                })?;
            let mut transaction = self.db.transact_write_items().transact_items(
                TransactWriteItem::builder()
                    .condition_check(generation_condition)
                    .build(),
            );
            if actor_session_id != target_session_id {
                let actor_check = ConditionCheck::builder()
                    .table_name(&self.table)
                    .key("session_id", AttributeValue::S(actor_physical_id.clone()))
                    .condition_expression(authoritative_condition)
                    .expression_attribute_values(":u", AttributeValue::S(physical_user_id.clone()))
                    .expression_attribute_values(
                        ":expected",
                        AttributeValue::N(generation.to_string()),
                    )
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!(
                            "build actor login session condition: {error}"
                        ))
                    })?;
                transaction = transaction.transact_items(
                    TransactWriteItem::builder()
                        .condition_check(actor_check)
                        .build(),
                );
            }
            let result = transaction
                .transact_items(TransactWriteItem::builder().delete(target_delete).build())
                .send()
                .await;
            match result {
                Ok(_) => return Ok(true),
                Err(error) => match classify_transact_write_error(&error) {
                    Some((TransactionCancelAction::RetryCondition, _)) => {
                        let current_generation = self.current_generation(tenant, user_id).await?;
                        let actor_is_current = self
                            .is_authoritative_session(
                                tenant,
                                user_id,
                                actor_session_id,
                                current_generation,
                            )
                            .await?;
                        let target_is_current = if actor_session_id == target_session_id {
                            actor_is_current
                        } else {
                            self.is_authoritative_session(
                                tenant,
                                user_id,
                                target_session_id,
                                current_generation,
                            )
                            .await?
                        };
                        match owned_delete_conflict_action(
                            attempt,
                            actor_is_current,
                            target_is_current,
                        ) {
                            AuthorityConflictAction::Noop => return Ok(false),
                            AuthorityConflictAction::Retry(delay) => {
                                tokio::time::sleep(delay).await;
                            }
                            AuthorityConflictAction::Exhausted => {
                                return Err(StoreError::Transient(
                                    "owned login session delete kept conflicting".to_string(),
                                ));
                            }
                        }
                    }
                    Some((TransactionCancelAction::Transient, classified)) => {
                        if let Some(delay) = transaction_retry_delay(attempt) {
                            tokio::time::sleep(delay).await;
                        } else {
                            return Err(classified);
                        }
                    }
                    Some((_, classified)) => return Err(classified),
                    None => {
                        let classified = ddb_err(error);
                        if matches!(classified, StoreError::Transient(_)) {
                            if let Some(delay) = transaction_retry_delay(attempt) {
                                tokio::time::sleep(delay).await;
                            } else {
                                return Err(classified);
                            }
                        } else {
                            return Err(classified);
                        }
                    }
                },
            }
        }
        Err(StoreError::Transient(
            "owned login session delete retries exhausted".to_string(),
        ))
    }
    async fn delete_others_by_user(
        &self,
        tenant: &str,
        user_id: &str,
        retained_session_id: &str,
    ) -> Result<Option<usize>, StoreError> {
        use aws_sdk_dynamodb::types::{TransactWriteItem, Update};

        let retained_physical_id = tpk(tenant, retained_session_id);
        let physical_user_id = tpk(tenant, user_id);
        let generation_key = Self::generation_key(tenant, user_id);

        // Fence first, clean up second. The two updates are atomic: the retained
        // current session moves to the next generation at the exact point all
        // other generations become invalid.
        let next_generation = {
            let mut committed = None;
            for attempt in 0..TRANSACTION_RETRY_ATTEMPTS {
                let current_generation = self.current_generation(tenant, user_id).await?;
                let Some(retained) = self.get_stored(tenant, retained_session_id).await? else {
                    return Ok(None);
                };
                if retained.record.user_id != user_id || retained.generation != current_generation {
                    return Ok(None);
                }
                let next = current_generation.checked_add(1).ok_or_else(|| {
                    StoreError::Permanent("login session generation exhausted".to_string())
                })?;

                let generation_update = Update::builder()
                    .table_name(&self.table)
                    .key("session_id", AttributeValue::S(generation_key.clone()))
                    .update_expression("SET #generation = :next, #kind = :kind")
                    .condition_expression(Self::generation_marker_condition(current_generation))
                    .expression_attribute_names("#generation", "generation")
                    .expression_attribute_names("#kind", "kind")
                    .expression_attribute_values(
                        ":expected",
                        AttributeValue::N(current_generation.to_string()),
                    )
                    .expression_attribute_values(":next", AttributeValue::N(next.to_string()))
                    .expression_attribute_values(
                        ":kind",
                        AttributeValue::S("login_session_generation".to_string()),
                    )
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!(
                            "build login session generation update: {error}"
                        ))
                    })?;

                let retained_update = Update::builder()
                    .table_name(&self.table)
                    .key(
                        "session_id",
                        AttributeValue::S(retained_physical_id.clone()),
                    )
                    .update_expression("SET session_generation = :next")
                    .condition_expression(Self::authoritative_session_condition(current_generation))
                    .expression_attribute_values(":u", AttributeValue::S(physical_user_id.clone()))
                    .expression_attribute_values(
                        ":expected",
                        AttributeValue::N(current_generation.to_string()),
                    )
                    .expression_attribute_values(":next", AttributeValue::N(next.to_string()))
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!(
                            "build retained login session update: {error}"
                        ))
                    })?;

                let result = self
                    .db
                    .transact_write_items()
                    .transact_items(
                        TransactWriteItem::builder()
                            .update(generation_update)
                            .build(),
                    )
                    .transact_items(TransactWriteItem::builder().update(retained_update).build())
                    .send()
                    .await;
                match result {
                    Ok(_) => {
                        committed = Some(next);
                        break;
                    }
                    Err(error) => match classify_transact_write_error(&error) {
                        Some((
                            TransactionCancelAction::RetryCondition
                            | TransactionCancelAction::Transient,
                            store_error,
                        )) => {
                            match self
                                .retained_fence_conflict_action(
                                    tenant,
                                    user_id,
                                    retained_session_id,
                                    current_generation,
                                    attempt,
                                )
                                .await?
                            {
                                AuthorityConflictAction::Noop => return Ok(None),
                                AuthorityConflictAction::Retry(delay) => {
                                    tokio::time::sleep(delay).await;
                                }
                                AuthorityConflictAction::Exhausted => return Err(store_error),
                            }
                        }
                        Some((_, store_error)) => return Err(store_error),
                        None => {
                            let store_error = ddb_err(error);
                            if matches!(store_error, StoreError::Transient(_)) {
                                match self
                                    .retained_fence_conflict_action(
                                        tenant,
                                        user_id,
                                        retained_session_id,
                                        current_generation,
                                        attempt,
                                    )
                                    .await?
                                {
                                    AuthorityConflictAction::Noop => return Ok(None),
                                    AuthorityConflictAction::Retry(delay) => {
                                        tokio::time::sleep(delay).await;
                                    }
                                    AuthorityConflictAction::Exhausted => return Err(store_error),
                                }
                            } else {
                                return Err(store_error);
                            }
                        }
                    },
                }
            }
            committed.ok_or_else(|| {
                StoreError::Transient("login session generation update conflicted".to_string())
            })?
        };

        // Physical cleanup is best-effort but tenant/user conditional. A record
        // omitted by the eventually-consistent GSI is still rejected by `get`
        // because its stored generation is now stale.
        let mut session_ids = Vec::new();
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let query = match self
                .db
                .query()
                .table_name(&self.table)
                .index_name("user_id-index")
                .key_condition_expression("user_id = :u")
                .expression_attribute_values(":u", AttributeValue::S(physical_user_id.clone()))
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
            {
                Ok(query) => query,
                Err(error) => {
                    eprintln!(
                        "LOGIN_SESSION_CLEANUP_DEFERRED tenant={tenant} user_id={user_id} \
                         stage=query err={error:?}"
                    );
                    return Ok(None);
                }
            };
            for item in query.items() {
                let stored = Self::from_item(item);
                if stored.generation < next_generation
                    && stored.record.session_id != retained_session_id
                {
                    session_ids.push(tpk(tenant, &stored.record.session_id));
                }
            }
            match query.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }

        for session_id in session_ids {
            let result = self
                .db
                .delete_item()
                .table_name(&self.table)
                .key("session_id", AttributeValue::S(session_id))
                .condition_expression(
                    "attribute_exists(session_id) AND user_id = :u AND \
                     (attribute_not_exists(session_generation) OR session_generation < :next)",
                )
                .expression_attribute_values(":u", AttributeValue::S(physical_user_id.clone()))
                .expression_attribute_values(
                    ":next",
                    AttributeValue::N(next_generation.to_string()),
                )
                .send()
                .await;
            match result {
                Ok(_) => {}
                Err(error)
                    if error
                        .code()
                        .is_some_and(|code| code.contains("ConditionalCheckFailed")) => {}
                Err(error) => {
                    eprintln!(
                        "LOGIN_SESSION_CLEANUP_DEFERRED tenant={tenant} user_id={user_id} \
                         stage=delete err={error:?}"
                    );
                }
            }
        }
        Ok(None)
    }
    async fn revoke_all_by_actor(
        &self,
        tenant: &str,
        user_id: &str,
        actor_session_id: &str,
    ) -> Result<bool, StoreError> {
        use aws_sdk_dynamodb::types::{Delete, TransactWriteItem, Update};

        let actor_key = tpk(tenant, actor_session_id);
        let physical_user_id = tpk(tenant, user_id);
        let generation_key = Self::generation_key(tenant, user_id);
        for attempt in 0..TRANSACTION_RETRY_ATTEMPTS {
            let generation = self.current_generation(tenant, user_id).await?;
            let fence_id =
                Self::credential_session_fence_id(tenant, user_id, actor_session_id, generation);
            if !self
                .is_authoritative_session(tenant, user_id, actor_session_id, generation)
                .await?
            {
                return Ok(false);
            }
            let next = generation.checked_add(1).ok_or_else(|| {
                StoreError::Permanent("login session generation exhausted".to_string())
            })?;
            let generation_update = Update::builder()
                .table_name(&self.table)
                .key("session_id", AttributeValue::S(generation_key.clone()))
                .update_expression(
                    "SET #generation = :next, #kind = :kind, \
                     credential_session_fence_id = :fence",
                )
                .condition_expression(Self::generation_marker_condition(generation))
                .expression_attribute_names("#generation", "generation")
                .expression_attribute_names("#kind", "kind")
                .expression_attribute_values(":expected", AttributeValue::N(generation.to_string()))
                .expression_attribute_values(":next", AttributeValue::N(next.to_string()))
                .expression_attribute_values(
                    ":kind",
                    AttributeValue::S("login_session_generation".to_string()),
                )
                .expression_attribute_values(":fence", AttributeValue::S(fence_id.clone()))
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!(
                        "build credential mutation generation update: {error}"
                    ))
                })?;
            let actor_delete = Delete::builder()
                .table_name(&self.table)
                .key("session_id", AttributeValue::S(actor_key.clone()))
                .condition_expression(Self::authoritative_session_condition(generation))
                .expression_attribute_values(":u", AttributeValue::S(physical_user_id.clone()))
                .expression_attribute_values(":expected", AttributeValue::N(generation.to_string()))
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!(
                        "build credential mutation actor delete: {error}"
                    ))
                })?;
            let request = self
                .db
                .transact_write_items()
                .transact_items(
                    TransactWriteItem::builder()
                        .update(generation_update)
                        .build(),
                )
                .transact_items(TransactWriteItem::builder().delete(actor_delete).build());
            let classified =
                match send_idempotent_transaction_with_token(request, fence_id.clone()).await {
                    Ok(true) => return Ok(true),
                    Ok(false) => StoreError::Transient(
                        "credential mutation session fence condition changed".to_string(),
                    ),
                    Err(error @ StoreError::Transient(_)) => error,
                    Err(error) => return Err(error),
                };
            let (observed, observed_fence_id) =
                self.current_generation_with_fence(tenant, user_id).await?;
            if observed == next && observed_fence_id.as_deref() == Some(fence_id.as_str()) {
                return Ok(true);
            }
            if !self
                .is_authoritative_session(tenant, user_id, actor_session_id, observed)
                .await?
            {
                return Ok(false);
            }
            if let Some(delay) = transaction_retry_delay(attempt) {
                tokio::time::sleep(delay).await;
            } else {
                return Err(classified);
            }
        }
        Err(StoreError::Transient(
            "credential mutation session fence retries exhausted".to_string(),
        ))
    }
    async fn touch_last_used(
        &self,
        tenant: &str,
        session_id: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        let result = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("session_id", AttributeValue::S(tpk(tenant, session_id)))
            .update_expression("SET last_used_at = :now")
            .condition_expression(
                "attribute_exists(session_id) AND \
                 (attribute_not_exists(last_used_at) OR last_used_at <= :now)",
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
    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        // Query tenant-qualified user_id GSI first, then delete after pagination so
        // index mutation cannot perturb the cursor while it is being consumed.
        // Any item not yet visible in the GSI remains unusable because session
        // authority compares its captured credential_epoch to the strongly read user.
        let mut session_ids = Vec::new();
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let query = self
                .db
                .query()
                .table_name(&self.table)
                .index_name("user_id-index")
                .key_condition_expression("user_id = :u")
                .expression_attribute_values(":u", AttributeValue::S(tpk(tenant, user_id)))
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in query.items() {
                session_ids.push(s(item.get("session_id")).ok_or_else(|| {
                    StoreError::Permanent("session user_id-index item missing session_id".into())
                })?);
            }
            match query.last_evaluated_key() {
                Some(k) if !k.is_empty() => last_key = Some(k.clone()),
                _ => break,
            }
        }
        for session_id in &session_ids {
            self.db
                .delete_item()
                .table_name(&self.table)
                .key("session_id", AttributeValue::S(session_id.clone()))
                .send()
                .await
                .map_err(ddb_err)?;
        }
        Ok(session_ids.len())
    }
    async fn delete_by_user_before_epoch(
        &self,
        tenant: &str,
        user_id: &str,
        epoch: u64,
    ) -> Result<usize, StoreError> {
        let epoch_condition = if epoch == 0 {
            "attribute_exists(session_id) AND credential_epoch < :epoch"
        } else {
            "attribute_exists(session_id) AND \
             (attribute_not_exists(credential_epoch) OR credential_epoch < :epoch)"
        };
        let mut session_ids = Vec::new();
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let query = self
                .db
                .query()
                .table_name(&self.table)
                .index_name("user_id-index")
                .key_condition_expression("user_id = :u")
                .expression_attribute_values(":u", AttributeValue::S(tpk(tenant, user_id)))
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in query.items() {
                session_ids.push(s(item.get("session_id")).ok_or_else(|| {
                    StoreError::Permanent("session user_id-index item missing session_id".into())
                })?);
            }
            match query.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        let mut deleted = 0;
        for session_id in session_ids {
            let result = self
                .db
                .delete_item()
                .table_name(&self.table)
                .key("session_id", AttributeValue::S(session_id))
                .condition_expression(epoch_condition)
                .expression_attribute_values(":epoch", AttributeValue::N(epoch.to_string()))
                .send()
                .await;
            match result {
                Ok(_) => deleted += 1,
                Err(error)
                    if error
                        .code()
                        .is_some_and(|code| code.contains("ConditionalCheckFailed")) => {}
                Err(error) => return Err(ddb_err(error)),
            }
        }
        Ok(deleted)
    }
    async fn count_by_user(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<usize, StoreError> {
        // 只读(admin get 全貌,§1.4):按 tenant-qualified user_id GSI 计未过期数。
        let generation = self.current_generation(tenant, user_id).await?;
        let mut n = 0usize;
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let query = self
                .db
                .query()
                .table_name(&self.table)
                .index_name("user_id-index")
                .key_condition_expression("user_id = :u")
                .expression_attribute_values(":u", AttributeValue::S(tpk(tenant, user_id)))
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in query.items() {
                // 未过期才计(expires_at 缺省视为未过期,与 get 读法一致)。
                let exp = n_i64(item.get("expires_at")).unwrap_or(i64::MAX);
                let session_generation = n_u64(item.get("session_generation")).unwrap_or(0);
                if exp > now && session_generation == generation {
                    n += 1;
                }
            }
            match query.last_evaluated_key() {
                Some(k) if !k.is_empty() => last_key = Some(k.clone()),
                _ => break,
            }
        }
        Ok(n)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        governance_delete_by_tenant_key(&self.db, &self.table, "session_id", tenant).await
    }
}

/// DynamoDB magic-link 存储 + per-email 冷却。link 表主键 = `pk`(S);
/// magic-link 记录 pk=`link#<id>`,冷却记录 pk=`cool#<email>`,同表区分前缀。
#[derive(Clone)]
pub struct DynamoMagicLinkStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
}

impl DynamoMagicLinkStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        DynamoMagicLinkStore {
            db,
            table: table.into(),
        }
    }
}

fn magic_link_record(item: &HashMap<String, AttributeValue>) -> MagicLinkRecord {
    MagicLinkRecord {
        link_id: s(item.get("link_id")).unwrap_or_default(),
        // Links issued before canonical binding fail closed because this value
        // remains empty when the callback validates the identity binding.
        user_id: s(item.get("user_id")).unwrap_or_default(),
        email: s(item.get("email")).unwrap_or_default(),
        session_nonce: s(item.get("session_nonce")).unwrap_or_default(),
        authorize_query: s(item.get("authorize_query")).unwrap_or_default(),
        next: s(item.get("next")).unwrap_or_default(),
        expires_at: n_i64(item.get("expires_at")).unwrap_or(0),
    }
}

impl MagicLinkStore for DynamoMagicLinkStore {
    async fn put(&self, tenant: &str, link: MagicLinkRecord) -> Result<(), StoreError> {
        // pk = tpk(tenant, "link#{id}"):按 tenant 物理隔离(评审 codex High;空 tenant→透传单租户)。
        let mut item = HashMap::from([
            (
                "pk".to_string(),
                AttributeValue::S(tpk(tenant, &format!("link#{}", link.link_id))),
            ),
            ("link_id".to_string(), AttributeValue::S(link.link_id)),
            ("user_id".to_string(), AttributeValue::S(link.user_id)),
            ("email".to_string(), AttributeValue::S(link.email)),
            (
                "session_nonce".to_string(),
                AttributeValue::S(link.session_nonce),
            ),
            (
                "authorize_query".to_string(),
                AttributeValue::S(link.authorize_query),
            ),
            (
                "expires_at".to_string(),
                AttributeValue::N(link.expires_at.to_string()),
            ),
        ]);
        // next 仅非空时存(避免空串属性;读侧 unwrap_or_default 回落空)。
        if !link.next.is_empty() {
            item.insert("next".to_string(), AttributeValue::S(link.next));
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
        tenant: &str,
        link_id: &str,
    ) -> Result<Option<MagicLinkRecord>, StoreError> {
        let out = self
            .db
            .get_item()
            .table_name(&self.table)
            .key(
                "pk",
                AttributeValue::S(tpk(tenant, &format!("link#{link_id}"))),
            )
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(out.item().map(magic_link_record))
    }
    async fn consume_bound(
        &self,
        tenant: &str,
        link_id: &str,
        expected_session_nonce: &str,
    ) -> Result<Option<MagicLinkRecord>, StoreError> {
        // 条件 DeleteItem + ALL_OLD:nonce 匹配才原子取出并删(C9.1/C9.2)。
        // pk 按 tenant tpk → 绝不跨租户消费。
        let out = match self
            .db
            .delete_item()
            .table_name(&self.table)
            .key(
                "pk",
                AttributeValue::S(tpk(tenant, &format!("link#{link_id}"))),
            )
            .condition_expression("session_nonce = :expected_session_nonce")
            .expression_attribute_values(
                ":expected_session_nonce",
                AttributeValue::S(expected_session_nonce.to_string()),
            )
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllOld)
            .send()
            .await
        {
            Ok(out) => out,
            Err(error)
                if error
                    .code()
                    .is_some_and(|code| code.contains("ConditionalCheckFailed")) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(ddb_err(error)),
        };
        let Some(item) = out.attributes() else {
            return Ok(None);
        };
        Ok(Some(magic_link_record(item)))
    }
    async fn last_sent_at(&self, tenant: &str, email: &str) -> Result<Option<i64>, StoreError> {
        // 冷却键 tpk(tenant, "cool#{email}"):每租户独立冷却窗(评审 codex High:全局键会跨租户
        // 耦合可用性 + 成存在性枚举 oracle)。
        let out = self
            .db
            .get_item()
            .table_name(&self.table)
            .key(
                "pk",
                AttributeValue::S(tpk(tenant, &format!("cool#{email}"))),
            )
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(out.item().and_then(|i| n_i64(i.get("last_sent_at"))))
    }
    async fn mark_sent(&self, tenant: &str, email: &str, now: i64) -> Result<(), StoreError> {
        let item = HashMap::from([
            (
                "pk".to_string(),
                AttributeValue::S(tpk(tenant, &format!("cool#{email}"))),
            ),
            (
                "last_sent_at".to_string(),
                AttributeValue::N(now.to_string()),
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

    async fn delete_by_user(
        &self,
        tenant: &str,
        user_id: &str,
        aliases: &[String],
    ) -> Result<usize, StoreError> {
        let deleted =
            governance_delete_by_subject(&self.db, &self.table, "pk", tenant, "user_id", user_id)
                .await?;
        for alias in aliases {
            self.db
                .delete_item()
                .table_name(&self.table)
                .key(
                    "pk",
                    AttributeValue::S(tpk(tenant, &format!("cool#{alias}"))),
                )
                .send()
                .await
                .map_err(ddb_err)?;
        }
        Ok(deleted)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        governance_delete_by_tenant_key(&self.db, &self.table, "pk", tenant).await
    }
}

/// DynamoDB "outbox" notifier(SES 未接前的模拟,spec 003 §1.5):把每封 magic-link / recovery 通知
/// 落 messages 表(**不真发邮件**),便于观测"发了什么"。表挂 TTL 属性 `ttl`(= created_at + 1 天),
/// DynamoDB 自动 GC。既实现 `Notifier`(写)又实现 `MessageOutbox`(读)。真机接 SES 后换真发适配器。
#[derive(Clone)]
pub struct DynamoNotifier {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
}

impl DynamoNotifier {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        DynamoNotifier {
            db,
            table: table.into(),
        }
    }

    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    fn rand_id() -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use rand::RngCore;
        let mut b = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut b);
        URL_SAFE_NO_PAD.encode(b)
    }

    async fn record(
        &self,
        tenant: &str,
        kind: &str,
        recipient: &str,
        body: &str,
        notification_id: Option<&str>,
    ) -> Result<(), StoreError> {
        let created_at = Self::now_secs();
        let message_id = notification_id
            .map(|id| format!("recovery#{id}"))
            .unwrap_or_else(Self::rand_id);
        // 物理主键 message_id 前缀 tenant(tpk):list_recent Scan 后按前缀过滤 → 跨租户隔离(C10.19)。
        let item = HashMap::from([
            (
                "message_id".to_string(),
                AttributeValue::S(tpk(tenant, &message_id)),
            ),
            ("tenant".to_string(), AttributeValue::S(tenant.to_string())),
            ("kind".to_string(), AttributeValue::S(kind.to_string())),
            (
                "recipient".to_string(),
                AttributeValue::S(recipient.to_string()),
            ),
            ("body".to_string(), AttributeValue::S(body.to_string())),
            (
                "created_at".to_string(),
                AttributeValue::N(created_at.to_string()),
            ),
            // TTL=1 天(DynamoDB 按 `ttl` 数字属性自动过期删除)。
            (
                "ttl".to_string(),
                AttributeValue::N((created_at + 86_400).to_string()),
            ),
        ]);
        let mut request = self
            .db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item));
        if notification_id.is_some() {
            request = request.condition_expression("attribute_not_exists(message_id)");
        }
        match request.send().await {
            Ok(_) => Ok(()),
            Err(error)
                if notification_id.is_some()
                    && error
                        .code()
                        .unwrap_or("")
                        .contains("ConditionalCheckFailed") =>
            {
                Ok(())
            }
            Err(error) => Err(ddb_err(error)),
        }
    }
}

impl Notifier for DynamoNotifier {
    async fn send_magic_link(
        &self,
        tenant: &str,
        email: &str,
        link_url: &str,
    ) -> Result<(), StoreError> {
        self.record(tenant, "magic_link", email, link_url, None)
            .await
    }
    async fn notify_recovery(
        &self,
        tenant: &str,
        notification_id: &str,
        recipient_email: &str,
        recovered_at: i64,
        client_ip: Option<&str>,
    ) -> Result<(), StoreError> {
        let body = format!(
            "account recovered at={recovered_at} ip={}",
            client_ip.unwrap_or("-")
        );
        self.record(
            tenant,
            "recovery",
            recipient_email,
            &body,
            Some(notification_id),
        )
        .await
    }
}

impl MessageOutbox for DynamoNotifier {
    async fn list_recent(
        &self,
        tenant: &str,
        limit: usize,
    ) -> Result<Vec<SentMessage>, StoreError> {
        // 全表 Scan(量小;messages TTL 1 天,规模有限)→ **按 tenant 过滤**(C10.19:绝不跨租户
        // 泄露他人 magic-link URL/PII)→ 内存按 created_at 倒序取 limit。量大另建时间序 GSI,见 spec 020。
        // 兼容旧记录:无 `tenant` attr 的历史行归属空 tenant(现网单租户,flag 关时命中)。
        let mut all: Vec<SentMessage> = Vec::new();
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let scan = self
                .db
                .scan()
                .table_name(&self.table)
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in scan.items() {
                let msg_tenant = s(item.get("tenant")).unwrap_or_default();
                if msg_tenant != tenant {
                    continue; // tenant-scope:跳过他租户消息
                }
                all.push(SentMessage {
                    // message_id 物理值带 tenant 前缀 → strip 回逻辑值(空 tenant 无前缀,零变化)。
                    message_id: strip_tpk(&s(item.get("message_id")).unwrap_or_default()),
                    tenant: msg_tenant,
                    kind: s(item.get("kind")).unwrap_or_default(),
                    recipient: s(item.get("recipient")).unwrap_or_default(),
                    body: s(item.get("body")).unwrap_or_default(),
                    created_at: n_i64(item.get("created_at")).unwrap_or(0),
                    ttl: n_i64(item.get("ttl")).unwrap_or(0),
                });
            }
            match scan.last_evaluated_key() {
                Some(k) if !k.is_empty() => last_key = Some(k.clone()),
                _ => break,
            }
        }
        all.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then(b.message_id.cmp(&a.message_id))
        });
        all.truncate(limit);
        Ok(all)
    }

    async fn delete_by_recipients(
        &self,
        tenant: &str,
        recipients: &[String],
    ) -> Result<usize, StoreError> {
        if recipients.is_empty() {
            return Ok(0);
        }

        let mut message_ids = Vec::new();
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let scan = self
                .db
                .scan()
                .table_name(&self.table)
                .projection_expression("message_id, #tenant, recipient")
                .expression_attribute_names("#tenant", "tenant")
                .consistent_read(true)
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in scan.items() {
                let item_tenant = s(item.get("tenant")).unwrap_or_default();
                let recipient = s(item.get("recipient")).unwrap_or_default();
                if item_tenant == tenant && recipients.iter().any(|alias| alias == &recipient) {
                    message_ids.push(item.get("message_id").cloned().ok_or_else(|| {
                        StoreError::Permanent("message governance row is missing message_id".into())
                    })?);
                }
            }
            match scan.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        for message_id in &message_ids {
            self.db
                .delete_item()
                .table_name(&self.table)
                .key("message_id", message_id.clone())
                .send()
                .await
                .map_err(ddb_err)?;
        }
        Ok(message_ids.len())
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        governance_delete_by_tenant_key(&self.db, &self.table, "message_id", tenant).await
    }
}

fn credential_change_completion_update(
    users: &DynamoUsersStore,
    tenant: &str,
    user_id: &str,
    epoch: u64,
    operation_id: &str,
    updated_at: i64,
    expected_email: Option<&str>,
) -> Result<aws_sdk_dynamodb::types::Update, StoreError> {
    let mut condition = "attribute_exists(user_id) AND \
                         (attribute_not_exists(#status) OR #status = :active) AND \
                         credential_epoch = :epoch AND revocation_pending = :true AND \
                         credential_change_id = :operation"
        .to_string();
    let mut update = aws_sdk_dynamodb::types::Update::builder()
        .table_name(&users.table)
        .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
        .update_expression(
            "SET revocation_pending = :false, updated_at = :now REMOVE credential_change_id",
        )
        .expression_attribute_names("#status", "status")
        .expression_attribute_values(":active", AttributeValue::S("active".to_string()))
        .expression_attribute_values(":false", AttributeValue::Bool(false))
        .expression_attribute_values(":true", AttributeValue::Bool(true))
        .expression_attribute_values(":epoch", AttributeValue::N(epoch.to_string()))
        .expression_attribute_values(":operation", AttributeValue::S(operation_id.to_string()))
        .expression_attribute_values(":now", AttributeValue::N(updated_at.to_string()));
    if let Some(expected_email) = expected_email {
        condition.push_str(" AND email = :expected_email");
        update = update.expression_attribute_values(
            ":expected_email",
            AttributeValue::S(tpk(tenant, expected_email)),
        );
    }
    update
        .condition_expression(condition)
        .build()
        .map_err(|error| {
            StoreError::Permanent(format!("build credential mutation completion: {error}"))
        })
}

async fn credential_change_completed(
    users: &DynamoUsersStore,
    tenant: &str,
    user_id: &str,
    epoch: u64,
) -> Result<bool, StoreError> {
    Ok(users.get_by_id(tenant, user_id).await?.is_some_and(|user| {
        user.status == crate::ports::UserStatus::Active
            && user.credential_epoch == epoch
            && !user.revocation_pending
    }))
}

/// DynamoDB 恢复码存储。表主键 = `user_lookup`(S,码非秘密前缀的短哈希;无效码也能按 user 定位限流)。
/// 记录内另存 `user_id`(真实登录 id,消费成功后取回建会话)。码哈希集 + 失败计数/锁定。
/// 原子性:verify_and_consume 用带 `version` 的乐观并发条件写(读→改→条件写,version 不符则败,
/// 上层可重试;并发验同码只有一个 version 匹配成功,避免双消费)。
#[derive(Clone)]
pub struct DynamoRecoveryStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
}

impl DynamoRecoveryStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        DynamoRecoveryStore {
            db,
            table: table.into(),
        }
    }

    fn record_to_item(
        &self,
        tenant: &str,
        r: &RecoveryRecord,
        version: u64,
    ) -> HashMap<String, AttributeValue> {
        // code_hashes 编码为并行两列表(hash + consumed),简单可读。主键 = tpk(tenant, user_lookup)。
        let hashes: Vec<AttributeValue> = r
            .code_hashes
            .iter()
            .map(|e| AttributeValue::S(e.hash_b64.clone()))
            .collect();
        let consumed: Vec<AttributeValue> = r
            .code_hashes
            .iter()
            .map(|e| AttributeValue::Bool(e.consumed))
            .collect();
        HashMap::from([
            (
                "user_lookup".to_string(),
                AttributeValue::S(tpk(tenant, &r.user_lookup)),
            ),
            ("user_id".to_string(), AttributeValue::S(r.user_id.clone())),
            (
                "activation_id".to_string(),
                AttributeValue::S(r.activation_id.clone()),
            ),
            ("code_hashes".to_string(), AttributeValue::L(hashes)),
            ("consumed".to_string(), AttributeValue::L(consumed)),
            (
                "attempt_count".to_string(),
                AttributeValue::N(r.attempt_count.to_string()),
            ),
            (
                "locked_until".to_string(),
                AttributeValue::N(r.locked_until.to_string()),
            ),
            (
                "version".to_string(),
                AttributeValue::N(version.to_string()),
            ),
        ])
    }

    fn success_result_key(tenant: &str, operation_key: &str) -> String {
        tpk(tenant, &format!("__recovery_success__:{operation_key}"))
    }

    fn success_result_to_item(
        &self,
        tenant: &str,
        result: &RecoverySuccessResult,
    ) -> HashMap<String, AttributeValue> {
        HashMap::from([
            (
                "user_lookup".to_string(),
                AttributeValue::S(Self::success_result_key(tenant, &result.operation_key)),
            ),
            (
                "kind".to_string(),
                AttributeValue::S("recovery_success_result".to_string()),
            ),
            (
                "recovery_user_lookup".to_string(),
                AttributeValue::S(result.user_lookup.clone()),
            ),
            (
                "user_id".to_string(),
                AttributeValue::S(result.user_id.clone()),
            ),
            (
                "presented_hash".to_string(),
                AttributeValue::S(result.presented_hash.clone()),
            ),
            (
                "credential_epoch".to_string(),
                AttributeValue::N(result.credential_epoch.to_string()),
            ),
            (
                "session_id".to_string(),
                AttributeValue::S(result.session_id.clone()),
            ),
            (
                "created_at".to_string(),
                AttributeValue::N(result.created_at.to_string()),
            ),
            (
                "expires_at".to_string(),
                AttributeValue::N(result.expires_at.to_string()),
            ),
        ])
    }

    async fn load_success_result(
        &self,
        tenant: &str,
        operation_key: &str,
    ) -> Result<Option<RecoverySuccessResult>, StoreError> {
        let output = self
            .db
            .get_item()
            .table_name(&self.table)
            .key(
                "user_lookup",
                AttributeValue::S(Self::success_result_key(tenant, operation_key)),
            )
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        let Some(item) = output.item() else {
            return Ok(None);
        };
        if s(item.get("kind")).as_deref() != Some("recovery_success_result") {
            return Err(StoreError::Permanent(
                "recovery success result has invalid kind".to_string(),
            ));
        }
        let required_string = |name| {
            s(item.get(name)).ok_or_else(|| {
                StoreError::Permanent(format!("recovery success result missing {name}"))
            })
        };
        let required_i64 = |name| {
            n_i64(item.get(name)).ok_or_else(|| {
                StoreError::Permanent(format!("recovery success result missing {name}"))
            })
        };
        let credential_epoch = n_u64(item.get("credential_epoch")).ok_or_else(|| {
            StoreError::Permanent("recovery success result missing credential_epoch".to_string())
        })?;
        Ok(Some(RecoverySuccessResult {
            operation_key: operation_key.to_string(),
            user_lookup: required_string("recovery_user_lookup")?,
            user_id: required_string("user_id")?,
            presented_hash: required_string("presented_hash")?,
            credential_epoch,
            session_id: required_string("session_id")?,
            created_at: required_i64("created_at")?,
            expires_at: required_i64("expires_at")?,
        }))
    }

    async fn reconcile_success_result(
        &self,
        users: &DynamoUsersStore,
        passwords: &DynamoPasswordStore,
        sessions: &DynamoSessionStore,
        request: RecoveryConsumeRequest<'_>,
        operation_key: &str,
    ) -> Result<Option<RecoveryAuthorityConsume>, StoreError> {
        let Some(result) = self
            .load_success_result(request.tenant, operation_key)
            .await?
        else {
            return Ok(None);
        };
        let binding_matches = result.operation_key == operation_key
            && result.user_lookup == request.user_lookup
            && result.user_id == request.user_id
            && agent_auth_authn::recovery::hash_eq_b64(
                &result.presented_hash,
                request.presented_hash,
            )
            && result.created_at < result.expires_at
            && result.expires_at > request.now;
        if !binding_matches {
            return Ok(Some(RecoveryAuthorityConsume::Invalid));
        }
        let authority = users.get_by_id(request.tenant, request.user_id).await?;
        if !authority.is_some_and(|user| {
            user.status == crate::ports::UserStatus::Active
                && !user.revocation_pending
                && user.credential_epoch == result.credential_epoch
                && user.email == request.expected_email
        }) {
            return Ok(Some(RecoveryAuthorityConsume::AuthorityChanged));
        }
        if !passwords
            .permits_recovered_session(request.tenant, request.user_id)
            .await?
        {
            return Ok(Some(RecoveryAuthorityConsume::PasswordChangeRequired));
        }
        let authoritative_session = sessions
            .get(request.tenant, &result.session_id)
            .await?
            .is_some_and(|stored| {
                stored.user_id == result.user_id
                    && stored.credential_epoch == result.credential_epoch
                    && stored.created_at == result.created_at
                    && stored.expires_at > request.now
                    && result.expires_at <= stored.expires_at
            });
        Ok(Some(if authoritative_session {
            RecoveryAuthorityConsume::Replayed { result }
        } else {
            RecoveryAuthorityConsume::AuthorityChanged
        }))
    }

    async fn load(
        &self,
        tenant: &str,
        user_lookup: &str,
    ) -> Result<Option<(RecoveryRecord, u64)>, StoreError> {
        let out = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("user_lookup", AttributeValue::S(tpk(tenant, user_lookup)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        let Some(item) = out.item() else {
            return Ok(None);
        };
        let hashes = ss(item.get("code_hashes"));
        let consumed: Vec<bool> = item
            .get("consumed")
            .and_then(|a| a.as_l().ok())
            .map(|l| {
                l.iter()
                    .map(|x| x.as_bool().copied().unwrap_or(false))
                    .collect()
            })
            .unwrap_or_default();
        let entries = hashes
            .into_iter()
            .enumerate()
            .map(|(i, h)| RecoveryCodeEntry {
                hash_b64: h,
                consumed: consumed.get(i).copied().unwrap_or(false),
            })
            .collect();
        let rec = RecoveryRecord {
            user_lookup: strip_tpk(&s(item.get("user_lookup")).unwrap_or_default()),
            user_id: s(item.get("user_id")).unwrap_or_default(),
            activation_id: s(item.get("activation_id")).unwrap_or_default(),
            code_hashes: entries,
            attempt_count: item
                .get("attempt_count")
                .and_then(|a| a.as_n().ok())
                .and_then(|n| n.parse().ok())
                .unwrap_or(0),
            locked_until: n_i64(item.get("locked_until")).unwrap_or(0),
        };
        let version = item
            .get("version")
            .and_then(|a| a.as_n().ok())
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        Ok(Some((rec, version)))
    }

    pub(crate) async fn commit_rotation(
        &self,
        users: &DynamoUsersStore,
        tenant: &str,
        record: RecoveryRecord,
        expected_email: &str,
        owner: crate::ports::CredentialChangeOwner<'_>,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        use aws_sdk_dynamodb::types::{Put, TransactWriteItem};

        let user_update = credential_change_completion_update(
            users,
            tenant,
            &record.user_id,
            owner.epoch,
            owner.operation_id,
            updated_at,
            Some(expected_email),
        )?;
        let recovery_put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(self.record_to_item(tenant, &record, 0)))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build recovery rotation put: {error}"))
            })?;
        let request = self
            .db
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().update(user_update).build())
            .transact_items(TransactWriteItem::builder().put(recovery_put).build());
        match send_idempotent_transaction(request).await {
            Ok(committed) => Ok(committed),
            Err(error @ StoreError::Transient(_)) => {
                let stored = self.load(tenant, &record.user_lookup).await?;
                if credential_change_completed(users, tenant, &record.user_id, owner.epoch).await?
                    && users
                        .get_by_id(tenant, &record.user_id)
                        .await?
                        .is_some_and(|user| user.email == expected_email)
                    && stored.is_some_and(|(stored, version)| stored == record && version == 0)
                {
                    Ok(true)
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) async fn verify_and_consume_at_epoch(
        &self,
        users: &DynamoUsersStore,
        passwords: &DynamoPasswordStore,
        sessions: &DynamoSessionStore,
        request: RecoveryConsumeRequest<'_>,
        session: SessionRecord,
        success_result: RecoverySuccessResult,
    ) -> Result<RecoveryAuthorityConsume, StoreError> {
        use agent_auth_authn::recovery::{hash_eq_b64, is_locked, on_failed_attempt};
        use aws_sdk_dynamodb::types::{ConditionCheck, Put, TransactWriteItem, Update};

        let next_epoch = request
            .expected_epoch
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("user credential_epoch exhausted".to_string()))?;
        if session.user_id != request.user_id
            || session.credential_epoch != next_epoch
            || success_result.operation_key.is_empty()
            || success_result.user_lookup != request.user_lookup
            || success_result.user_id != request.user_id
            || !hash_eq_b64(&success_result.presented_hash, request.presented_hash)
            || success_result.credential_epoch != next_epoch
            || success_result.session_id != session.session_id
            || success_result.created_at != session.created_at
            || success_result.created_at > request.now
            || success_result.expires_at <= request.now
            || success_result.expires_at > session.expires_at
        {
            return Err(StoreError::Permanent(
                "recovery result does not match recovery authority".to_string(),
            ));
        }

        for attempt in 0..TRANSACTION_RETRY_ATTEMPTS {
            let Some((mut record, version)) =
                self.load(request.tenant, request.user_lookup).await?
            else {
                return Ok(RecoveryAuthorityConsume::NotFound);
            };
            if record.user_id != request.user_id {
                return Ok(RecoveryAuthorityConsume::AuthorityChanged);
            }
            if is_locked(record.locked_until, request.now) {
                return Ok(RecoveryAuthorityConsume::Locked {
                    retry_after_secs: record.locked_until - request.now,
                });
            }
            let result = if let Some(entry) = record.code_hashes.iter_mut().find(|entry| {
                !entry.consumed && hash_eq_b64(&entry.hash_b64, request.presented_hash)
            }) {
                entry.consumed = true;
                record.attempt_count = 0;
                record.locked_until = 0;
                RecoveryConsume::Valid
            } else {
                let (attempt_count, locked_until) =
                    on_failed_attempt(record.attempt_count, request.now);
                record.attempt_count = attempt_count;
                record.locked_until = locked_until;
                if is_locked(locked_until, request.now) {
                    RecoveryConsume::Locked {
                        retry_after_secs: locked_until - request.now,
                    }
                } else {
                    RecoveryConsume::Invalid
                }
            };
            if result == RecoveryConsume::Valid
                && !passwords
                    .permits_recovered_session(request.tenant, request.user_id)
                    .await?
            {
                return Ok(RecoveryAuthorityConsume::PasswordChangeRequired);
            }

            let mut item = self.record_to_item(request.tenant, &record, version + 1);
            item.insert(
                "version".to_string(),
                AttributeValue::N((version + 1).to_string()),
            );
            let recovery_put = Put::builder()
                .table_name(&self.table)
                .set_item(Some(item))
                .condition_expression("attribute_not_exists(#version) OR #version = :version")
                .expression_attribute_names("#version", "version")
                .expression_attribute_values(":version", AttributeValue::N(version.to_string()))
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!("build recovery epoch-guarded consume: {error}"))
                })?;
            let epoch_condition = if request.expected_epoch == 0 {
                "(attribute_not_exists(credential_epoch) OR credential_epoch = :epoch)"
            } else {
                "credential_epoch = :epoch"
            };
            let user_condition = format!(
                "attribute_exists(user_id) AND \
                 (attribute_not_exists(#status) OR #status = :active) AND \
                 (attribute_not_exists(revocation_pending) OR revocation_pending = :false) AND \
                 email = :expected_email AND \
                 {epoch_condition}"
            );
            let user_key = AttributeValue::S(tpk(request.tenant, request.user_id));
            let user_authority = if result == RecoveryConsume::Valid {
                let update = Update::builder()
                    .table_name(&users.table)
                    .key("user_id", user_key)
                    .update_expression("SET credential_epoch = :next, updated_at = :now")
                    .condition_expression(user_condition)
                    .expression_attribute_names("#status", "status")
                    .expression_attribute_values(":active", AttributeValue::S("active".to_string()))
                    .expression_attribute_values(":false", AttributeValue::Bool(false))
                    .expression_attribute_values(
                        ":expected_email",
                        AttributeValue::S(tpk(request.tenant, request.expected_email)),
                    )
                    .expression_attribute_values(
                        ":epoch",
                        AttributeValue::N(request.expected_epoch.to_string()),
                    )
                    .expression_attribute_values(":next", AttributeValue::N(next_epoch.to_string()))
                    .expression_attribute_values(":now", AttributeValue::N(request.now.to_string()))
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!("build recovery authority advance: {error}"))
                    })?;
                TransactWriteItem::builder().update(update).build()
            } else {
                let check = ConditionCheck::builder()
                    .table_name(&users.table)
                    .key("user_id", user_key)
                    .condition_expression(user_condition)
                    .expression_attribute_names("#status", "status")
                    .expression_attribute_values(":active", AttributeValue::S("active".to_string()))
                    .expression_attribute_values(":false", AttributeValue::Bool(false))
                    .expression_attribute_values(
                        ":expected_email",
                        AttributeValue::S(tpk(request.tenant, request.expected_email)),
                    )
                    .expression_attribute_values(
                        ":epoch",
                        AttributeValue::N(request.expected_epoch.to_string()),
                    )
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!(
                            "build recovery user authority condition: {error}"
                        ))
                    })?;
                TransactWriteItem::builder().condition_check(check).build()
            };
            let mut transaction = self
                .db
                .transact_write_items()
                .transact_items(user_authority)
                .transact_items(TransactWriteItem::builder().put(recovery_put).build());
            if result == RecoveryConsume::Valid {
                let (generation_update, session_put) = sessions
                    .recovery_commit_items(request.tenant, &session)
                    .await?;
                let success_result_put = Put::builder()
                    .table_name(&self.table)
                    .set_item(Some(
                        self.success_result_to_item(request.tenant, &success_result),
                    ))
                    .condition_expression("attribute_not_exists(user_lookup)")
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!("build recovery success result put: {error}"))
                    })?;
                transaction = transaction
                    .transact_items(
                        passwords.recovered_session_condition(request.tenant, request.user_id)?,
                    )
                    .transact_items(generation_update)
                    .transact_items(session_put)
                    .transact_items(TransactWriteItem::builder().put(success_result_put).build());
            } else {
                let operation_absent = ConditionCheck::builder()
                    .table_name(&self.table)
                    .key(
                        "user_lookup",
                        AttributeValue::S(Self::success_result_key(
                            request.tenant,
                            &success_result.operation_key,
                        )),
                    )
                    .condition_expression("attribute_not_exists(user_lookup)")
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!(
                            "build recovery success result absence check: {error}"
                        ))
                    })?;
                transaction = transaction.transact_items(
                    TransactWriteItem::builder()
                        .condition_check(operation_absent)
                        .build(),
                );
            }
            let transaction = send_idempotent_transaction(transaction).await;
            match transaction {
                Ok(true) => {
                    return Ok(match result {
                        RecoveryConsume::Valid => RecoveryAuthorityConsume::Valid {
                            credential_epoch: next_epoch,
                        },
                        RecoveryConsume::Invalid => RecoveryAuthorityConsume::Invalid,
                        RecoveryConsume::Locked { retry_after_secs } => {
                            RecoveryAuthorityConsume::Locked { retry_after_secs }
                        }
                        RecoveryConsume::NotFound => RecoveryAuthorityConsume::NotFound,
                        RecoveryConsume::AuthorityChanged => {
                            RecoveryAuthorityConsume::AuthorityChanged
                        }
                    })
                }
                outcome => {
                    let (action, classified) = match outcome {
                        Ok(false) => (
                            TransactionCancelAction::RetryCondition,
                            StoreError::Transient(
                                "DynamoDB transaction condition changed".to_string(),
                            ),
                        ),
                        Err(classified @ StoreError::Permanent(_)) => return Err(classified),
                        Err(classified) => (TransactionCancelAction::Transient, classified),
                        Ok(true) => unreachable!("committed transaction returned above"),
                    };
                    if let Some(outcome) = self
                        .reconcile_success_result(
                            users,
                            passwords,
                            sessions,
                            request,
                            &success_result.operation_key,
                        )
                        .await?
                    {
                        return Ok(outcome);
                    }
                    let authority = users.get_by_id(request.tenant, request.user_id).await?;
                    if !authority.is_some_and(|user| {
                        user.status == crate::ports::UserStatus::Active
                            && !user.revocation_pending
                            && user.credential_epoch == request.expected_epoch
                            && user.email == request.expected_email
                    }) {
                        return Ok(RecoveryAuthorityConsume::AuthorityChanged);
                    }
                    if result == RecoveryConsume::Valid
                        && !passwords
                            .permits_recovered_session(request.tenant, request.user_id)
                            .await?
                    {
                        return Ok(RecoveryAuthorityConsume::PasswordChangeRequired);
                    }
                    if matches!(
                        action,
                        TransactionCancelAction::RetryCondition
                            | TransactionCancelAction::Transient
                    ) {
                        if let Some(delay) = transaction_retry_delay(attempt) {
                            tokio::time::sleep(delay).await;
                        } else {
                            return Err(classified);
                        }
                    }
                }
            }
        }
        Err(StoreError::Transient(
            "recovery epoch-guarded consume retries exhausted".to_string(),
        ))
    }
}

impl RecoveryStore for DynamoRecoveryStore {
    async fn put(&self, tenant: &str, record: RecoveryRecord) -> Result<(), StoreError> {
        // 下发/regenerate:version 从 0 起(覆盖旧集使旧码失效)。
        let item = self.record_to_item(tenant, &record, 0);
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
        user_lookup: &str,
    ) -> Result<Option<RecoveryRecord>, StoreError> {
        Ok(self.load(tenant, user_lookup).await?.map(|(r, _)| r))
    }
    async fn get_success_result(
        &self,
        tenant: &str,
        operation_key: &str,
    ) -> Result<Option<RecoverySuccessResult>, StoreError> {
        self.load_success_result(tenant, operation_key).await
    }
    async fn verify_and_consume(
        &self,
        tenant: &str,
        user_lookup: &str,
        presented_hash: &str,
        now: i64,
    ) -> Result<RecoveryConsume, StoreError> {
        use agent_auth_authn::recovery::{hash_eq_b64, is_locked, on_failed_attempt};
        // 读→改→条件写(乐观并发)。并发冲突(ConditionalCheckFailed)时**重试**整个循环,
        // 而非直接判 Invalid——否则并发错码只有一个写成功、其余静默丢失,失败计数被绕过
        // (评审 codex#5)。重试上界防活锁;每轮重新 load 拿最新 version + consumed 状态。
        const MAX_RETRY: u32 = 5;
        for _ in 0..MAX_RETRY {
            let Some((mut rec, version)) = self.load(tenant, user_lookup).await? else {
                return Ok(RecoveryConsume::NotFound);
            };
            if is_locked(rec.locked_until, now) {
                return Ok(RecoveryConsume::Locked {
                    retry_after_secs: rec.locked_until - now,
                });
            }
            // 常量时间比对未消费码(避免用 `==` 早退泄露时序,评审 codex#6)。
            let hit = rec
                .code_hashes
                .iter_mut()
                .find(|e| !e.consumed && hash_eq_b64(&e.hash_b64, presented_hash));
            let result = if let Some(e) = hit {
                e.consumed = true;
                rec.attempt_count = 0;
                rec.locked_until = 0;
                RecoveryConsume::Valid
            } else {
                let (c, l) = on_failed_attempt(rec.attempt_count, now);
                rec.attempt_count = c;
                rec.locked_until = l;
                if is_locked(l, now) {
                    RecoveryConsume::Locked {
                        retry_after_secs: l - now,
                    }
                } else {
                    RecoveryConsume::Invalid
                }
            };
            // 乐观并发条件写:仅当 version 未变才写(并发验同码只一个成功,防双消费)。
            let mut item = self.record_to_item(tenant, &rec, version + 1);
            item.insert(
                "version".to_string(),
                AttributeValue::N((version + 1).to_string()),
            );
            // `version` 是 DynamoDB 保留字 → 用别名。首次(无 version 属性)也允许写。
            let res = self
                .db
                .put_item()
                .table_name(&self.table)
                .set_item(Some(item))
                .condition_expression("attribute_not_exists(#v) OR #v = :v")
                .expression_attribute_names("#v", "version")
                .expression_attribute_values(":v", AttributeValue::N(version.to_string()))
                .send()
                .await;
            match res {
                Ok(_) => return Ok(result),
                Err(e) => {
                    let code = e.code().unwrap_or("");
                    if code.contains("ConditionalCheckFailed") {
                        continue; // 并发改动 → 重读重试(不丢失失败计数,不误判)
                    }
                    return Err(ddb_err(e));
                }
            }
        }
        // 重试仍冲突(高并发)→ 保守判瞬时失败,上层可让用户重试。
        Err(StoreError::Transient(
            "recovery verify_and_consume: too many CAS conflicts".into(),
        ))
    }
    async fn delete_by_lookup(&self, tenant: &str, user_lookup: &str) -> Result<(), StoreError> {
        // admin disable/delete 级联(§1.4):DeleteItem 主键 user_lookup。不存在幂等(DeleteItem 天然幂等)。
        self.db
            .delete_item()
            .table_name(&self.table)
            .key("user_lookup", AttributeValue::S(tpk(tenant, user_lookup)))
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(())
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        governance_delete_by_tenant_key(&self.db, &self.table, "user_lookup", tenant).await
    }
}

/// DynamoDB passkey challenge 存储(spec 003 §3)。pk=challenge;TTL=expires_at(短命 GC)。
/// consume = 条件删(DeleteItem ReturnValues=ALL_OLD,一次性防重放)。
#[derive(Clone)]
pub struct DynamoPasskeyChallengeStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
}

impl DynamoPasskeyChallengeStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        DynamoPasskeyChallengeStore {
            db,
            table: table.into(),
        }
    }
}

impl crate::ports::PasskeyChallengeStore for DynamoPasskeyChallengeStore {
    async fn put(&self, ch: crate::ports::PasskeyChallenge) -> Result<(), StoreError> {
        let mut item = HashMap::from([
            (
                "challenge".to_string(),
                AttributeValue::S(ch.challenge_b64url),
            ),
            ("tenant".to_string(), AttributeValue::S(ch.tenant)),
            (
                "ceremony".to_string(),
                AttributeValue::S(ch.ceremony.as_str().to_string()),
            ),
            ("rp_id".to_string(), AttributeValue::S(ch.rp_id)),
            ("origin".to_string(), AttributeValue::S(ch.origin)),
            (
                "expires_at".to_string(),
                AttributeValue::N(ch.expires_at.to_string()),
            ),
        ]);
        if let Some(uid) = ch.user_id {
            item.insert("user_id".to_string(), AttributeValue::S(uid));
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
    async fn consume(
        &self,
        tenant: &str,
        challenge_b64url: &str,
    ) -> Result<Option<crate::ports::PasskeyChallenge>, StoreError> {
        // 条件删:取出旧值同时删(一次性,防重放)。
        let mut request = self
            .db
            .delete_item()
            .table_name(&self.table)
            .key("challenge", AttributeValue::S(challenge_b64url.to_string()))
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllOld)
            .expression_attribute_names("#tenant", "tenant")
            .expression_attribute_values(":tenant", AttributeValue::S(tenant.to_string()));
        request = if tenant.is_empty() {
            request.condition_expression("#tenant = :tenant OR attribute_not_exists(#tenant)")
        } else {
            request.condition_expression("#tenant = :tenant")
        };
        let out = match request.send().await {
            Ok(output) => output,
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|service| service.is_conditional_check_failed_exception()) =>
            {
                return Ok(None)
            }
            Err(error) => return Err(ddb_err(error)),
        };
        let Some(item) = out.attributes() else {
            return Ok(None); // 不存在/已消费
        };
        let now = crate::token::current_unix_secs_pub();
        let exp = n_i64(item.get("expires_at")).unwrap_or(0);
        if exp <= now {
            return Ok(None); // 过期(已删,fail-closed)
        }
        let Some(ceremony) = s(item.get("ceremony"))
            .as_deref()
            .and_then(crate::ports::PasskeyCeremony::parse)
        else {
            return Ok(None);
        };
        let (Some(rp_id), Some(origin)) = (s(item.get("rp_id")), s(item.get("origin"))) else {
            return Ok(None);
        };
        Ok(Some(crate::ports::PasskeyChallenge {
            challenge_b64url: s(item.get("challenge")).unwrap_or_default(),
            tenant: s(item.get("tenant")).unwrap_or_default(),
            user_id: s(item.get("user_id")),
            ceremony,
            rp_id,
            origin,
            expires_at: exp,
        }))
    }

    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        let mut deleted = 0;
        let mut start_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let tenant_filter = if tenant.is_empty() {
                "(#tenant = :tenant OR attribute_not_exists(#tenant))"
            } else {
                "#tenant = :tenant"
            };
            let output = self
                .db
                .scan()
                .table_name(&self.table)
                .projection_expression("challenge")
                .filter_expression(format!("{tenant_filter} AND user_id = :user_id"))
                .expression_attribute_names("#tenant", "tenant")
                .expression_attribute_values(":tenant", AttributeValue::S(tenant.to_string()))
                .expression_attribute_values(":user_id", AttributeValue::S(user_id.to_string()))
                .set_exclusive_start_key(start_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in output.items() {
                let challenge = s(item.get("challenge")).ok_or_else(|| {
                    StoreError::Permanent(
                        "passkey challenge governance row is missing challenge".into(),
                    )
                })?;
                let mut request = self
                    .db
                    .delete_item()
                    .table_name(&self.table)
                    .key("challenge", AttributeValue::S(challenge))
                    .expression_attribute_names("#tenant", "tenant")
                    .expression_attribute_values(":tenant", AttributeValue::S(tenant.to_string()))
                    .expression_attribute_values(
                        ":user_id",
                        AttributeValue::S(user_id.to_string()),
                    );
                request = if tenant.is_empty() {
                    request.condition_expression(
                        "(#tenant = :tenant OR attribute_not_exists(#tenant)) \
                         AND user_id = :user_id",
                    )
                } else {
                    request.condition_expression("#tenant = :tenant AND user_id = :user_id")
                };
                request.send().await.map_err(ddb_err)?;
                deleted += 1;
            }
            match output.last_evaluated_key() {
                Some(key) if !key.is_empty() => start_key = Some(key.clone()),
                _ => break,
            }
        }
        Ok(deleted)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut candidates = Vec::new();
        let mut start_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let tenant_filter = if tenant.is_empty() {
                "#tenant = :tenant OR attribute_not_exists(#tenant)"
            } else {
                "#tenant = :tenant"
            };
            let output = self
                .db
                .scan()
                .table_name(&self.table)
                .projection_expression("challenge")
                .filter_expression(tenant_filter)
                .expression_attribute_names("#tenant", "tenant")
                .expression_attribute_values(":tenant", AttributeValue::S(tenant.to_string()))
                .consistent_read(true)
                .set_exclusive_start_key(start_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in output.items() {
                let challenge = item.get("challenge").cloned().ok_or_else(|| {
                    StoreError::Permanent(
                        "passkey challenge governance row is missing challenge".into(),
                    )
                })?;
                candidates.push(challenge);
            }
            match output.last_evaluated_key() {
                Some(key) if !key.is_empty() => start_key = Some(key.clone()),
                _ => break,
            }
        }

        let mut deleted = 0usize;
        for challenge in candidates {
            let mut request = self
                .db
                .delete_item()
                .table_name(&self.table)
                .key("challenge", challenge)
                .expression_attribute_names("#tenant", "tenant")
                .expression_attribute_values(":tenant", AttributeValue::S(tenant.to_string()));
            request = if tenant.is_empty() {
                request.condition_expression("#tenant = :tenant OR attribute_not_exists(#tenant)")
            } else {
                request.condition_expression("#tenant = :tenant")
            };
            match request.send().await {
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

/// DynamoDB password credentials. Partition key is the tenant-prefixed
/// `user_id`; the table is persistent and intentionally has no TTL.
#[derive(Clone)]
pub struct DynamoPasswordStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
}

impl DynamoPasswordStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        Self {
            db,
            table: table.into(),
        }
    }

    fn from_item(
        item: &HashMap<String, AttributeValue>,
    ) -> Result<crate::ports::PasswordCredential, StoreError> {
        let user_id = s(item.get("user_id"))
            .map(|value| strip_tpk(&value))
            .ok_or_else(|| StoreError::Permanent("password credential missing user_id".into()))?;
        let encoded = s(item.get("password_hash"))
            .ok_or_else(|| StoreError::Permanent("password credential missing hash".into()))?;
        let password_hash = agent_auth_authn::password::EncodedPasswordHash::from_storage(encoded)
            .map_err(|_| StoreError::Permanent("invalid password hash profile".into()))?;
        let must_change = item
            .get("must_change")
            .and_then(|v| v.as_bool().ok())
            .copied()
            .ok_or_else(|| {
                StoreError::Permanent("password credential missing must_change".into())
            })?;
        // Backward-compatible with credentials written before reset revocation
        // gained a durable completion marker.
        let revocation_pending = item
            .get("revocation_pending")
            .and_then(|v| v.as_bool().ok())
            .copied()
            .unwrap_or(false);
        let credential_change_id = s(item.get("credential_change_id"));
        let version = item
            .get("version")
            .and_then(|v| v.as_n().ok())
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| StoreError::Permanent("password credential missing version".into()))?;
        let updated_at = item
            .get("updated_at")
            .and_then(|v| v.as_n().ok())
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| {
                StoreError::Permanent("password credential missing updated_at".into())
            })?;
        Ok(crate::ports::PasswordCredential {
            user_id,
            password_hash,
            must_change,
            revocation_pending,
            credential_change_id,
            version,
            updated_at,
        })
    }

    async fn permits_recovered_session(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<bool, StoreError> {
        Ok(match self.get(tenant, user_id).await? {
            Some(credential) => {
                credential.user_id == user_id
                    && !credential.must_change
                    && !credential.revocation_pending
            }
            None => true,
        })
    }

    fn recovered_session_condition(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<aws_sdk_dynamodb::types::TransactWriteItem, StoreError> {
        use aws_sdk_dynamodb::types::{ConditionCheck, TransactWriteItem};

        let check = ConditionCheck::builder()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .condition_expression(
                "attribute_not_exists(user_id) OR \
                 (must_change = :false AND \
                  (attribute_not_exists(revocation_pending) OR revocation_pending = :false))",
            )
            .expression_attribute_values(":false", AttributeValue::Bool(false))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "build recovered session password authority condition: {error}"
                ))
            })?;
        Ok(TransactWriteItem::builder().condition_check(check).build())
    }

    pub(crate) async fn commit_credential_change(
        &self,
        users: &DynamoUsersStore,
        mutation: crate::ports::FencedPasswordMutation<'_>,
        owner: crate::ports::CredentialChangeOwner<'_>,
    ) -> Result<bool, StoreError> {
        use aws_sdk_dynamodb::types::{Put, TransactWriteItem, Update};

        let crate::ports::FencedPasswordMutation {
            tenant,
            user_id,
            password_hash: new_hash,
            expected_version,
            credential_epoch: epoch,
            updated_at,
        } = mutation;
        if epoch != owner.epoch {
            return Ok(false);
        }
        let user_update = credential_change_completion_update(
            users,
            tenant,
            user_id,
            owner.epoch,
            owner.operation_id,
            updated_at,
            None,
        )?;
        let expected_hash = new_hash.expose().to_string();
        let (credential_write, committed_version) = match expected_version {
            Some(expected) => {
                let next = expected.checked_add(1).ok_or_else(|| {
                    StoreError::Permanent("password version overflow".to_string())
                })?;
                let update = Update::builder()
                    .table_name(&self.table)
                    .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
                    .update_expression(
                        "SET password_hash = :hash, version = :next, updated_at = :now \
                         REMOVE credential_change_id",
                    )
                    .condition_expression(
                        "version = :expected AND must_change = :false AND \
                         (attribute_not_exists(revocation_pending) OR revocation_pending = :false)",
                    )
                    .expression_attribute_values(":hash", AttributeValue::S(expected_hash.clone()))
                    .expression_attribute_values(":next", AttributeValue::N(next.to_string()))
                    .expression_attribute_values(
                        ":expected",
                        AttributeValue::N(expected.to_string()),
                    )
                    .expression_attribute_values(":false", AttributeValue::Bool(false))
                    .expression_attribute_values(":now", AttributeValue::N(updated_at.to_string()))
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!(
                            "build self-service password rotation: {error}"
                        ))
                    })?;
                (TransactWriteItem::builder().update(update).build(), next)
            }
            None => {
                let item = HashMap::from([
                    (
                        "user_id".to_string(),
                        AttributeValue::S(tpk(tenant, user_id)),
                    ),
                    (
                        "password_hash".to_string(),
                        AttributeValue::S(expected_hash.clone()),
                    ),
                    ("must_change".to_string(), AttributeValue::Bool(false)),
                    (
                        "revocation_pending".to_string(),
                        AttributeValue::Bool(false),
                    ),
                    ("version".to_string(), AttributeValue::N("1".to_string())),
                    (
                        "updated_at".to_string(),
                        AttributeValue::N(updated_at.to_string()),
                    ),
                ]);
                let put = Put::builder()
                    .table_name(&self.table)
                    .set_item(Some(item))
                    .condition_expression("attribute_not_exists(user_id)")
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!(
                            "build self-service password enrollment: {error}"
                        ))
                    })?;
                (TransactWriteItem::builder().put(put).build(), 1)
            }
        };
        let request = self
            .db
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().update(user_update).build())
            .transact_items(credential_write);
        match send_idempotent_transaction(request).await {
            Ok(committed) => Ok(committed),
            Err(error @ StoreError::Transient(_)) => {
                let credential = self.get(tenant, user_id).await?;
                if credential_change_completed(users, tenant, user_id, owner.epoch).await?
                    && credential.is_some_and(|credential| {
                        credential.password_hash.expose() == expected_hash
                            && credential.version == committed_version
                            && !credential.must_change
                            && !credential.revocation_pending
                    })
                {
                    Ok(true)
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) async fn stage_admin_reset(
        &self,
        users: &DynamoUsersStore,
        mutation: crate::ports::FencedPasswordMutation<'_>,
        owner: crate::ports::CredentialChangeOwner<'_>,
    ) -> Result<Option<u64>, StoreError> {
        use aws_sdk_dynamodb::types::{ConditionCheck, TransactWriteItem, Update};

        let crate::ports::FencedPasswordMutation {
            tenant,
            user_id,
            password_hash: new_hash,
            expected_version,
            credential_epoch: epoch,
            updated_at,
        } = mutation;
        if epoch != owner.epoch {
            return Ok(None);
        }
        let expected_hash = new_hash.expose().to_string();
        let epoch_condition = if epoch == 0 {
            "(attribute_not_exists(credential_epoch) OR credential_epoch = :epoch)"
        } else {
            "credential_epoch = :epoch"
        };
        let user_check = ConditionCheck::builder()
            .table_name(&users.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .condition_expression(format!(
                "attribute_exists(user_id) AND \
                 (attribute_not_exists(#status) OR #status <> :tomb) AND \
                 revocation_pending = :true AND credential_change_id = :operation AND \
                 {epoch_condition}"
            ))
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":tomb", AttributeValue::S("tombstoned".to_string()))
            .expression_attribute_values(":true", AttributeValue::Bool(true))
            .expression_attribute_values(":epoch", AttributeValue::N(epoch.to_string()))
            .expression_attribute_values(
                ":operation",
                AttributeValue::S(owner.operation_id.to_string()),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build admin reset user condition: {error}"))
            })?;
        let next_version = match expected_version {
            Some(version) => version
                .checked_add(1)
                .ok_or_else(|| StoreError::Permanent("password version overflow".into()))?,
            None => 1,
        };
        let mut password_update = Update::builder()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .update_expression(
                "SET password_hash = :hash, must_change = :true, \
                 revocation_pending = :true, credential_change_id = :operation, \
                 version = :next, updated_at = :now",
            )
            .expression_attribute_values(":hash", AttributeValue::S(expected_hash.clone()))
            .expression_attribute_values(":true", AttributeValue::Bool(true))
            .expression_attribute_values(
                ":operation",
                AttributeValue::S(owner.operation_id.to_string()),
            )
            .expression_attribute_values(":next", AttributeValue::N(next_version.to_string()))
            .expression_attribute_values(":now", AttributeValue::N(updated_at.to_string()));
        password_update = match expected_version {
            Some(version) => password_update
                .condition_expression("version = :expected")
                .expression_attribute_values(":expected", AttributeValue::N(version.to_string())),
            None => password_update.condition_expression("attribute_not_exists(user_id)"),
        };
        let password_update = password_update.build().map_err(|error| {
            StoreError::Permanent(format!("build fenced admin password reset: {error}"))
        })?;
        let request = self
            .db
            .transact_write_items()
            .transact_items(
                TransactWriteItem::builder()
                    .condition_check(user_check)
                    .build(),
            )
            .transact_items(TransactWriteItem::builder().update(password_update).build());
        match send_idempotent_transaction(request).await {
            Ok(true) => Ok(Some(next_version)),
            Ok(false) => Ok(None),
            Err(error @ StoreError::Transient(_)) => {
                let user_owned = users
                    .credential_change_is_owned(tenant, user_id, owner)
                    .await?;
                let credential = self.get(tenant, user_id).await?;
                if user_owned
                    && credential.is_some_and(|credential| {
                        credential.password_hash.expose() == expected_hash
                            && credential.must_change
                            && credential.revocation_pending
                            && credential.credential_change_id.as_deref()
                                == Some(owner.operation_id)
                            && credential.version == next_version
                    })
                {
                    Ok(Some(next_version))
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) async fn complete_admin_reset(
        &self,
        users: &DynamoUsersStore,
        tenant: &str,
        user_id: &str,
        expected_version: u64,
        owner: crate::ports::CredentialChangeOwner<'_>,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        use aws_sdk_dynamodb::types::{TransactWriteItem, Update};

        let user_update = Update::builder()
            .table_name(&users.table)
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
            .expression_attribute_values(":now", AttributeValue::N(updated_at.to_string()))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build admin reset authority completion: {error}"))
            })?;
        let password_update = Update::builder()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .update_expression("SET revocation_pending = :false REMOVE credential_change_id")
            .condition_expression(
                "version = :expected AND must_change = :true AND revocation_pending = :true AND \
                 credential_change_id = :operation",
            )
            .expression_attribute_values(
                ":expected",
                AttributeValue::N(expected_version.to_string()),
            )
            .expression_attribute_values(":true", AttributeValue::Bool(true))
            .expression_attribute_values(":false", AttributeValue::Bool(false))
            .expression_attribute_values(
                ":operation",
                AttributeValue::S(owner.operation_id.to_string()),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build admin reset completion: {error}"))
            })?;
        let result = self
            .db
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().update(user_update).build())
            .transact_items(TransactWriteItem::builder().update(password_update).build())
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error) => match classify_transact_write_error(&error) {
                Some((TransactionCancelAction::RetryCondition, _)) => Ok(false),
                Some((_, classified)) => Err(classified),
                None => Err(ddb_err(error)),
            },
        }
    }
}

impl crate::ports::PasswordStore for DynamoPasswordStore {
    async fn get(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<Option<crate::ports::PasswordCredential>, StoreError> {
        let out = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        out.item().map(Self::from_item).transpose()
    }

    async fn create_if_absent(
        &self,
        tenant: &str,
        credential: crate::ports::PasswordCredential,
    ) -> Result<bool, StoreError> {
        let mut put = self
            .db
            .put_item()
            .table_name(&self.table)
            .item(
                "user_id",
                AttributeValue::S(tpk(tenant, &credential.user_id)),
            )
            .item(
                "password_hash",
                AttributeValue::S(credential.password_hash.expose().to_string()),
            )
            .item("must_change", AttributeValue::Bool(credential.must_change))
            .item(
                "revocation_pending",
                AttributeValue::Bool(credential.revocation_pending),
            )
            .item("version", AttributeValue::N(credential.version.to_string()))
            .item(
                "updated_at",
                AttributeValue::N(credential.updated_at.to_string()),
            )
            .condition_expression("attribute_not_exists(user_id)");
        if let Some(operation_id) = credential.credential_change_id {
            put = put.item("credential_change_id", AttributeValue::S(operation_id));
        }
        let result = put.send().await;
        match result {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .code()
                    .unwrap_or("")
                    .contains("ConditionalCheckFailed") =>
            {
                Ok(false)
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn delete_if_version(
        &self,
        tenant: &str,
        user_id: &str,
        expected_version: u64,
    ) -> Result<bool, StoreError> {
        let result = self
            .db
            .delete_item()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .condition_expression("version = :expected")
            .expression_attribute_values(
                ":expected",
                AttributeValue::N(expected_version.to_string()),
            )
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .code()
                    .unwrap_or("")
                    .contains("ConditionalCheckFailed") =>
            {
                Ok(false)
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn replace_if_version_and_temporary(
        &self,
        tenant: &str,
        user_id: &str,
        new_hash: agent_auth_authn::password::EncodedPasswordHash,
        expected_version: u64,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        let result = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .update_expression(
                "SET password_hash = :hash, must_change = :false, version = :next, \
                 updated_at = :now REMOVE credential_change_id",
            )
            .condition_expression(
                "version = :expected AND must_change = :true AND (attribute_not_exists(revocation_pending) OR revocation_pending = :false)",
            )
            .expression_attribute_values(
                ":hash",
                AttributeValue::S(new_hash.expose().to_string()),
            )
            .expression_attribute_values(":false", AttributeValue::Bool(false))
            .expression_attribute_values(
                ":next",
                AttributeValue::N((expected_version + 1).to_string()),
            )
            .expression_attribute_values(":now", AttributeValue::N(updated_at.to_string()))
            .expression_attribute_values(
                ":expected",
                AttributeValue::N(expected_version.to_string()),
            )
            .expression_attribute_values(":true", AttributeValue::Bool(true))
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .code()
                    .unwrap_or("")
                    .contains("ConditionalCheckFailed") =>
            {
                Ok(false)
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn reset_temporary(
        &self,
        tenant: &str,
        user_id: &str,
        new_hash: agent_auth_authn::password::EncodedPasswordHash,
        expected_version: Option<u64>,
        updated_at: i64,
    ) -> Result<Option<u64>, StoreError> {
        let next_version = match expected_version {
            Some(version) => version
                .checked_add(1)
                .ok_or_else(|| StoreError::Permanent("password version overflow".into()))?,
            None => 1,
        };
        let mut update = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .update_expression(
                "SET password_hash = :hash, must_change = :true, revocation_pending = :true, \
                 version = :next, updated_at = :now REMOVE credential_change_id",
            )
            .expression_attribute_values(":hash", AttributeValue::S(new_hash.expose().to_string()))
            .expression_attribute_values(":true", AttributeValue::Bool(true))
            .expression_attribute_values(":next", AttributeValue::N(next_version.to_string()))
            .expression_attribute_values(":now", AttributeValue::N(updated_at.to_string()))
            .return_values(aws_sdk_dynamodb::types::ReturnValue::UpdatedNew);
        update = match expected_version {
            Some(version) => update
                .condition_expression("version = :expected")
                .expression_attribute_values(":expected", AttributeValue::N(version.to_string())),
            None => update.condition_expression("attribute_not_exists(user_id)"),
        };
        match update.send().await {
            Ok(out) => out
                .attributes()
                .and_then(|attributes| n_u64(attributes.get("version")))
                .map(Some)
                .ok_or_else(|| StoreError::Permanent("password reset missing new version".into())),
            Err(error)
                if error
                    .code()
                    .unwrap_or("")
                    .contains("ConditionalCheckFailed") =>
            {
                Ok(None)
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn complete_reset_revocation(
        &self,
        tenant: &str,
        user_id: &str,
        expected_version: u64,
    ) -> Result<bool, StoreError> {
        let result = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .update_expression("SET revocation_pending = :false REMOVE credential_change_id")
            .condition_expression(
                "version = :expected AND must_change = :true AND revocation_pending = :true",
            )
            .expression_attribute_values(
                ":expected",
                AttributeValue::N(expected_version.to_string()),
            )
            .expression_attribute_values(":true", AttributeValue::Bool(true))
            .expression_attribute_values(":false", AttributeValue::Bool(false))
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .code()
                    .unwrap_or("")
                    .contains("ConditionalCheckFailed") =>
            {
                Ok(false)
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn delete(&self, tenant: &str, user_id: &str) -> Result<(), StoreError> {
        self.db
            .delete_item()
            .table_name(&self.table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(())
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        governance_delete_by_tenant_key(&self.db, &self.table, "user_id", tenant).await
    }
}

/// Dedicated one-time invitation table. Issuance and acceptance use DynamoDB
/// transactions spanning user, password, invitation, and login-session state;
/// no magic-link table or notifier participates.
#[derive(Clone)]
pub struct DynamoInvitationStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
    pub(super) users_table: String,
    pub(super) passwords_table: String,
    pub(super) sessions: DynamoSessionStore,
}

impl DynamoInvitationStore {
    pub fn new(
        db: aws_sdk_dynamodb::Client,
        table: impl Into<String>,
        users_table: impl Into<String>,
        passwords_table: impl Into<String>,
        sessions_table: impl Into<String>,
    ) -> Self {
        let sessions_table = sessions_table.into();
        Self {
            sessions: DynamoSessionStore::new(db.clone(), sessions_table),
            db,
            table: table.into(),
            users_table: users_table.into(),
            passwords_table: passwords_table.into(),
        }
    }

    fn record_item(tenant: &str, record: &InvitationRecord) -> HashMap<String, AttributeValue> {
        HashMap::from([
            (
                "locator".to_string(),
                AttributeValue::S(tpk(tenant, &record.locator)),
            ),
            (
                "activation_id".to_string(),
                AttributeValue::S(record.activation_id.clone()),
            ),
            (
                "user_id".to_string(),
                AttributeValue::S(tpk(tenant, &record.user_id)),
            ),
            (
                "email".to_string(),
                AttributeValue::S(tpk(tenant, &record.email)),
            ),
            (
                "verifier_hash".to_string(),
                AttributeValue::S(record.verifier_hash.clone()),
            ),
            (
                "credential_epoch".to_string(),
                AttributeValue::N(record.credential_epoch.to_string()),
            ),
            (
                "issued_at".to_string(),
                AttributeValue::N(record.issued_at.to_string()),
            ),
            (
                "expires_at".to_string(),
                AttributeValue::N(record.expires_at.to_string()),
            ),
        ])
    }

    fn record_is_local(record: &InvitationRecord) -> bool {
        crate::local_identity::is_valid_email(&record.email)
            && crate::local_identity::is_password_capable_user_id(&record.user_id)
    }

    fn from_item(item: &HashMap<String, AttributeValue>) -> Result<InvitationRecord, StoreError> {
        let required = |name: &str| {
            s(item.get(name))
                .ok_or_else(|| StoreError::Permanent(format!("invitation missing {name}")))
        };
        Ok(InvitationRecord {
            locator: strip_tpk(&required("locator")?),
            activation_id: s(item.get("activation_id")).unwrap_or_else(|| "invitation".to_string()),
            user_id: strip_tpk(&required("user_id")?),
            email: strip_tpk(&required("email")?),
            verifier_hash: required("verifier_hash")?,
            credential_epoch: n_u64(item.get("credential_epoch")).ok_or_else(|| {
                StoreError::Permanent("invitation missing credential_epoch".to_string())
            })?,
            issued_at: n_i64(item.get("issued_at"))
                .ok_or_else(|| StoreError::Permanent("invitation missing issued_at".to_string()))?,
            expires_at: n_i64(item.get("expires_at")).ok_or_else(|| {
                StoreError::Permanent("invitation missing expires_at".to_string())
            })?,
        })
    }

    async fn get(
        &self,
        tenant: &str,
        locator: &str,
    ) -> Result<Option<InvitationRecord>, StoreError> {
        let output = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("locator", AttributeValue::S(tpk(tenant, locator)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        output.item().map(Self::from_item).transpose()
    }

    fn user_condition(record: &InvitationRecord) -> String {
        let epoch = if record.credential_epoch == 0 {
            "(attribute_not_exists(credential_epoch) OR credential_epoch = :epoch)"
        } else {
            "credential_epoch = :epoch"
        };
        format!(
            "attribute_exists(user_id) AND \
             (attribute_not_exists(#status) OR #status = :active) AND \
             (attribute_not_exists(revocation_pending) OR revocation_pending = :false) AND \
             email = :email AND {epoch}"
        )
    }

    fn user_condition_check(
        &self,
        tenant: &str,
        record: &InvitationRecord,
    ) -> Result<aws_sdk_dynamodb::types::TransactWriteItem, StoreError> {
        use aws_sdk_dynamodb::types::{ConditionCheck, TransactWriteItem};
        let check = ConditionCheck::builder()
            .table_name(&self.users_table)
            .key("user_id", AttributeValue::S(tpk(tenant, &record.user_id)))
            .condition_expression(Self::user_condition(record))
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":active", AttributeValue::S("active".to_string()))
            .expression_attribute_values(":false", AttributeValue::Bool(false))
            .expression_attribute_values(":email", AttributeValue::S(tpk(tenant, &record.email)))
            .expression_attribute_values(
                ":epoch",
                AttributeValue::N(record.credential_epoch.to_string()),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build invitation user condition: {error}"))
            })?;
        Ok(TransactWriteItem::builder().condition_check(check).build())
    }

    fn password_absent_check(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<aws_sdk_dynamodb::types::TransactWriteItem, StoreError> {
        use aws_sdk_dynamodb::types::{ConditionCheck, TransactWriteItem};
        let check = ConditionCheck::builder()
            .table_name(&self.passwords_table)
            .key("user_id", AttributeValue::S(tpk(tenant, user_id)))
            .condition_expression("attribute_not_exists(user_id)")
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build invitation password condition: {error}"))
            })?;
        Ok(TransactWriteItem::builder().condition_check(check).build())
    }

    async fn authority_is_current(
        &self,
        tenant: &str,
        record: &InvitationRecord,
    ) -> Result<bool, StoreError> {
        let users = DynamoUsersStore::new(self.db.clone(), self.users_table.clone());
        let passwords = DynamoPasswordStore::new(self.db.clone(), self.passwords_table.clone());
        let user = users.get_by_id(tenant, &record.user_id).await?;
        let password = passwords.get(tenant, &record.user_id).await?;
        Ok(user.is_some_and(|user| {
            user.status == crate::ports::UserStatus::Active
                && !user.revocation_pending
                && user.user_id == record.user_id
                && user.email == record.email
                && user.credential_epoch == record.credential_epoch
                && crate::local_identity::is_valid_email(&user.email)
                && crate::local_identity::is_password_capable_user_id(&user.user_id)
        }) && password.is_none())
    }
}

impl InvitationStore for DynamoInvitationStore {
    async fn issue(
        &self,
        tenant: &str,
        record: InvitationRecord,
    ) -> Result<InvitationIssueOutcome, StoreError> {
        use aws_sdk_dynamodb::types::{Put, TransactWriteItem};
        if !Self::record_is_local(&record) {
            return Ok(InvitationIssueOutcome::Ineligible);
        }
        let put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(Self::record_item(tenant, &record)))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build invitation issuance: {error}"))
            })?;
        let transaction = self
            .db
            .transact_write_items()
            .transact_items(self.user_condition_check(tenant, &record)?)
            .transact_items(self.password_absent_check(tenant, &record.user_id)?)
            .transact_items(TransactWriteItem::builder().put(put).build());
        match send_idempotent_transaction(transaction).await {
            Ok(true) => Ok(InvitationIssueOutcome::Issued),
            Ok(false) => {
                let password = self
                    .db
                    .get_item()
                    .table_name(&self.passwords_table)
                    .key("user_id", AttributeValue::S(tpk(tenant, &record.user_id)))
                    .consistent_read(true)
                    .send()
                    .await
                    .map_err(ddb_err)?;
                if password.item().is_some() {
                    Ok(InvitationIssueOutcome::PasswordConfigured)
                } else {
                    Ok(InvitationIssueOutcome::Ineligible)
                }
            }
            Err(error) => {
                // A transport failure can arrive after DynamoDB committed. The
                // exact record proves this secret is still the active result.
                if self.get(tenant, &record.locator).await?.as_ref() == Some(&record) {
                    Ok(InvitationIssueOutcome::Issued)
                } else {
                    Err(error)
                }
            }
        }
    }

    async fn accept(
        &self,
        tenant: &str,
        request: InvitationAcceptRequest,
    ) -> Result<InvitationAcceptOutcome, StoreError> {
        use aws_sdk_dynamodb::types::{ConditionCheck, Delete, Put, TransactWriteItem};

        let Some(snapshot) = self.get(tenant, &request.locator).await? else {
            return Ok(InvitationAcceptOutcome::Invalid);
        };
        if !crate::invitation::verifier_matches(&snapshot.verifier_hash, &request.verifier_hash) {
            return Ok(InvitationAcceptOutcome::Invalid);
        }
        if snapshot.activation_id != request.activation_id {
            return Ok(InvitationAcceptOutcome::Invalid);
        }
        if !Self::record_is_local(&snapshot) {
            return Ok(InvitationAcceptOutcome::Ineligible {
                user_id: snapshot.user_id,
            });
        }
        if snapshot.expires_at <= request.now {
            return Ok(InvitationAcceptOutcome::Expired {
                user_id: snapshot.user_id,
            });
        }

        for _ in 0..3 {
            let generation = self
                .sessions
                .current_generation(tenant, &snapshot.user_id)
                .await?;
            let session = SessionRecord {
                session_id: request.session_id.clone(),
                user_id: snapshot.user_id.clone(),
                credential_epoch: snapshot.credential_epoch,
                auth_time: request.now,
                created_at: request.now,
                last_used_at: request.now,
                device: request.device.clone(),
                expires_at: request.now + crate::login::SESSION_TTL_SECS,
                acr: None,
                amr: vec!["invite".to_string()],
            };
            let delete = Delete::builder()
                .table_name(&self.table)
                .key("locator", AttributeValue::S(tpk(tenant, &snapshot.locator)))
                .condition_expression(
                    "verifier_hash = :verifier AND expires_at > :now AND \
                     credential_epoch = :epoch AND user_id = :user AND \
                     activation_id = :activation",
                )
                .expression_attribute_values(
                    ":verifier",
                    AttributeValue::S(snapshot.verifier_hash.clone()),
                )
                .expression_attribute_values(":now", AttributeValue::N(request.now.to_string()))
                .expression_attribute_values(
                    ":epoch",
                    AttributeValue::N(snapshot.credential_epoch.to_string()),
                )
                .expression_attribute_values(
                    ":user",
                    AttributeValue::S(tpk(tenant, &snapshot.user_id)),
                )
                .expression_attribute_values(
                    ":activation",
                    AttributeValue::S(request.activation_id.clone()),
                )
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!("build invitation consume: {error}"))
                })?;
            let generation_check = ConditionCheck::builder()
                .table_name(&self.sessions.table)
                .key(
                    "session_id",
                    AttributeValue::S(DynamoSessionStore::generation_key(
                        tenant,
                        &snapshot.user_id,
                    )),
                )
                .condition_expression(DynamoSessionStore::generation_marker_condition(generation))
                .expression_attribute_names("#generation", "generation")
                .expression_attribute_values(":expected", AttributeValue::N(generation.to_string()))
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!(
                        "build invitation session generation condition: {error}"
                    ))
                })?;
            let session_put = Put::builder()
                .table_name(&self.sessions.table)
                .set_item(Some(DynamoSessionStore::session_item(
                    tenant, &session, generation,
                )))
                .condition_expression("attribute_not_exists(session_id)")
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!("build invitation session: {error}"))
                })?;
            let transaction = self
                .db
                .transact_write_items()
                .transact_items(self.user_condition_check(tenant, &snapshot)?)
                .transact_items(self.password_absent_check(tenant, &snapshot.user_id)?)
                .transact_items(TransactWriteItem::builder().delete(delete).build())
                .transact_items(
                    TransactWriteItem::builder()
                        .condition_check(generation_check)
                        .build(),
                )
                .transact_items(TransactWriteItem::builder().put(session_put).build());
            match send_idempotent_transaction(transaction).await {
                Ok(true) => {
                    return Ok(InvitationAcceptOutcome::Accepted {
                        user_id: snapshot.user_id,
                        session_id: request.session_id,
                    })
                }
                Ok(false) => {
                    if self.get(tenant, &request.locator).await?.as_ref() != Some(&snapshot) {
                        return Ok(InvitationAcceptOutcome::Invalid);
                    }
                    if !self.authority_is_current(tenant, &snapshot).await? {
                        return Ok(InvitationAcceptOutcome::Ineligible {
                            user_id: snapshot.user_id,
                        });
                    }
                }
                Err(error) => {
                    // The transaction may have committed before its response
                    // was lost. Only this request can create this exact random
                    // session id and record, so a strong read safely recovers
                    // the success and lets the handler deliver its cookie.
                    if self
                        .sessions
                        .get_stored(tenant, &request.session_id)
                        .await?
                        .is_some_and(|stored| {
                            stored.generation == generation && stored.record == session
                        })
                    {
                        return Ok(InvitationAcceptOutcome::Accepted {
                            user_id: snapshot.user_id,
                            session_id: request.session_id,
                        });
                    }
                    return Err(error);
                }
            }
        }
        Err(StoreError::Transient(
            "invitation session generation changed repeatedly".to_string(),
        ))
    }

    async fn invalidate(&self, tenant: &str, locator: &str) -> Result<(), StoreError> {
        self.db
            .delete_item()
            .table_name(&self.table)
            .key("locator", AttributeValue::S(tpk(tenant, locator)))
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(())
    }
}

/// DynamoDB passkey 凭证存储(spec 003 §3)。pk=credential_id + GSI user_id-index。凭证存 serde JSON。
/// put_new 条件写(credential_id 唯一);update_sign_count 条件 UpdateItem(CAS 防克隆)。
const PASSKEY_SIGN_COUNT_SNAPSHOT_CONDITION: &str = "sign_count = :prev AND cred_json = :snapshot";
const PASSKEY_RENAME_SNAPSHOT_CONDITION: &str =
    "user_id = :user AND sign_count = :count AND cred_json = :snapshot";

#[derive(Clone)]
pub struct DynamoPasskeyStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
    pub(super) user_index: String,
}

impl DynamoPasskeyStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        DynamoPasskeyStore {
            db,
            table: table.into(),
            user_index: "user_id-index".to_string(),
        }
    }
    fn to_item(
        tenant: &str,
        c: &agent_auth_authn::passkey::PasskeyCredential,
    ) -> Result<HashMap<String, AttributeValue>, StoreError> {
        // cred_json 存**逻辑**凭证;仅 pk credential_id + GSI user_id 属性 tenant 化(codex B1)。
        let json = serde_json::to_string(c)
            .map_err(|e| StoreError::Permanent(format!("serialize passkey cred: {e}")))?;
        Ok(HashMap::from([
            (
                "credential_id".to_string(),
                AttributeValue::S(tpk(tenant, &c.credential_id)),
            ),
            (
                "user_id".to_string(),
                AttributeValue::S(tpk(tenant, &c.user_id)),
            ),
            (
                "sign_count".to_string(),
                AttributeValue::N(c.sign_count.to_string()),
            ),
            ("cred_json".to_string(), AttributeValue::S(json)),
        ]))
    }
    async fn get_with_snapshot(
        &self,
        tenant: &str,
        credential_id: &str,
    ) -> Result<Option<(agent_auth_authn::passkey::PasskeyCredential, String)>, StoreError> {
        let out = self
            .db
            .get_item()
            .table_name(&self.table)
            .key(
                "credential_id",
                AttributeValue::S(tpk(tenant, credential_id)),
            )
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        let Some(item) = out.item() else {
            return Ok(None);
        };
        let snapshot = s(item.get("cred_json"))
            .ok_or_else(|| StoreError::Permanent("passkey item missing cred_json".to_string()))?;
        let credential = serde_json::from_str(&snapshot)
            .map_err(|error| StoreError::Permanent(format!("parse passkey cred: {error}")))?;
        Ok(Some((credential, snapshot)))
    }

    pub(crate) async fn put_new_authorized(
        &self,
        users: &DynamoUsersStore,
        sessions: &DynamoSessionStore,
        tenant: &str,
        session: &SessionRecord,
        credential: agent_auth_authn::passkey::PasskeyCredential,
        now: i64,
    ) -> Result<PasskeyRegistrationOutcome, StoreError> {
        use aws_sdk_dynamodb::types::{ConditionCheck, Put, TransactWriteItem};

        if credential.user_id != session.user_id
            || !crate::account_credentials::session_is_reauthenticated(session, now)
            || session.expires_at <= now
        {
            return Ok(PasskeyRegistrationOutcome::AuthorityChanged);
        }
        let item = Self::to_item(tenant, &credential)?;
        for _ in 0..TRANSACTION_RETRY_ATTEMPTS {
            let generation = sessions
                .current_generation(tenant, &session.user_id)
                .await?;
            let epoch_condition = if session.credential_epoch == 0 {
                "(attribute_not_exists(credential_epoch) OR credential_epoch = :epoch)"
            } else {
                "credential_epoch = :epoch"
            };
            let user_condition = format!(
                "attribute_exists(user_id) AND \
                 (attribute_not_exists(#status) OR #status = :active) AND \
                 (attribute_not_exists(revocation_pending) OR revocation_pending = :false) AND \
                 {epoch_condition}"
            );
            let user_check = ConditionCheck::builder()
                .table_name(&users.table)
                .key("user_id", AttributeValue::S(tpk(tenant, &session.user_id)))
                .condition_expression(user_condition)
                .expression_attribute_names("#status", "status")
                .expression_attribute_values(":active", AttributeValue::S("active".to_string()))
                .expression_attribute_values(":false", AttributeValue::Bool(false))
                .expression_attribute_values(
                    ":epoch",
                    AttributeValue::N(session.credential_epoch.to_string()),
                )
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!(
                        "build passkey registration user condition: {error}"
                    ))
                })?;
            let generation_check = ConditionCheck::builder()
                .table_name(&sessions.table)
                .key(
                    "session_id",
                    AttributeValue::S(DynamoSessionStore::generation_key(tenant, &session.user_id)),
                )
                .condition_expression(DynamoSessionStore::generation_marker_condition(generation))
                .expression_attribute_names("#generation", "generation")
                .expression_attribute_values(":expected", AttributeValue::N(generation.to_string()))
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!(
                        "build passkey registration generation condition: {error}"
                    ))
                })?;
            let session_epoch_condition = if session.credential_epoch == 0 {
                "(attribute_not_exists(credential_epoch) OR credential_epoch = :epoch)"
            } else {
                "credential_epoch = :epoch"
            };
            let session_condition = format!(
                "({}) AND {session_epoch_condition} AND \
                 auth_time >= :fresh_after AND auth_time <= :now AND expires_at > :now",
                DynamoSessionStore::authoritative_session_condition(generation)
            );
            let session_check = ConditionCheck::builder()
                .table_name(&sessions.table)
                .key(
                    "session_id",
                    AttributeValue::S(tpk(tenant, &session.session_id)),
                )
                .condition_expression(session_condition)
                .expression_attribute_values(":u", AttributeValue::S(tpk(tenant, &session.user_id)))
                .expression_attribute_values(":expected", AttributeValue::N(generation.to_string()))
                .expression_attribute_values(
                    ":epoch",
                    AttributeValue::N(session.credential_epoch.to_string()),
                )
                .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
                .expression_attribute_values(
                    ":fresh_after",
                    AttributeValue::N(
                        now.saturating_sub(crate::account_credentials::REAUTH_MAX_AGE_SECS)
                            .to_string(),
                    ),
                )
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!(
                        "build passkey registration session condition: {error}"
                    ))
                })?;
            let passkey_put = Put::builder()
                .table_name(&self.table)
                .set_item(Some(item.clone()))
                .condition_expression("attribute_not_exists(credential_id)")
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!("build authorized passkey put: {error}"))
                })?;
            let request = self
                .db
                .transact_write_items()
                .transact_items(
                    TransactWriteItem::builder()
                        .condition_check(user_check)
                        .build(),
                )
                .transact_items(
                    TransactWriteItem::builder()
                        .condition_check(generation_check)
                        .build(),
                )
                .transact_items(
                    TransactWriteItem::builder()
                        .condition_check(session_check)
                        .build(),
                )
                .transact_items(TransactWriteItem::builder().put(passkey_put).build());
            match send_idempotent_transaction(request).await {
                Ok(true) => return Ok(PasskeyRegistrationOutcome::Created),
                Ok(false) => {
                    if self.get(tenant, &credential.credential_id).await?.is_some() {
                        return Ok(PasskeyRegistrationOutcome::CredentialExists);
                    }
                    let user = users.get_by_id(tenant, &session.user_id).await?;
                    let current_session = sessions.get(tenant, &session.session_id).await?;
                    let authority_remains = user.is_some_and(|user| {
                        user.status == crate::ports::UserStatus::Active
                            && !user.revocation_pending
                            && user.credential_epoch == session.credential_epoch
                    }) && current_session.is_some_and(|current| {
                        current.user_id == session.user_id
                            && current.credential_epoch == session.credential_epoch
                            && current.expires_at > now
                            && crate::account_credentials::session_is_reauthenticated(&current, now)
                    });
                    if !authority_remains {
                        return Ok(PasskeyRegistrationOutcome::AuthorityChanged);
                    }
                }
                Err(error @ StoreError::Transient(_)) => {
                    match self.get(tenant, &credential.credential_id).await? {
                        Some(stored) if stored == credential => {
                            return Ok(PasskeyRegistrationOutcome::Created)
                        }
                        Some(_) => {
                            return Ok(PasskeyRegistrationOutcome::CredentialExists);
                        }
                        None => return Err(error),
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(StoreError::Transient(
            "authorized passkey registration retries exhausted".to_string(),
        ))
    }

    pub(crate) async fn delete_owned_and_complete(
        &self,
        users: &DynamoUsersStore,
        tenant: &str,
        user_id: &str,
        credential_id: &str,
        owner: crate::ports::CredentialChangeOwner<'_>,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        use aws_sdk_dynamodb::types::{Delete, TransactWriteItem};

        let user_update = credential_change_completion_update(
            users,
            tenant,
            user_id,
            owner.epoch,
            owner.operation_id,
            updated_at,
            None,
        )?;
        let passkey_delete = Delete::builder()
            .table_name(&self.table)
            .key(
                "credential_id",
                AttributeValue::S(tpk(tenant, credential_id)),
            )
            .condition_expression("user_id = :user")
            .expression_attribute_values(":user", AttributeValue::S(tpk(tenant, user_id)))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build fenced passkey delete: {error}"))
            })?;
        let request = self
            .db
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().update(user_update).build())
            .transact_items(TransactWriteItem::builder().delete(passkey_delete).build());
        match send_idempotent_transaction(request).await {
            Ok(committed) => Ok(committed),
            Err(error @ StoreError::Transient(_)) => {
                if credential_change_completed(users, tenant, user_id, owner.epoch).await?
                    && self.get(tenant, credential_id).await?.is_none()
                {
                    Ok(true)
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }
}

impl crate::ports::PasskeyStore for DynamoPasskeyStore {
    async fn put_new(
        &self,
        tenant: &str,
        cred: agent_auth_authn::passkey::PasskeyCredential,
    ) -> Result<bool, StoreError> {
        let item = Self::to_item(tenant, &cred)?;
        // 条件写:credential_id 不存在才写(唯一;已存在 → ConditionalCheckFailed → false,防覆盖)。
        let res = self
            .db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(credential_id)")
            .send()
            .await;
        match res {
            // ConditionalCheckFailed = credential_id 已存在 → 拒覆盖(Ok(false));其余经 ddb_err
            // 结构化分类(评审 Kiro L1:不 Debug 字符串匹配 + 不一律 Transient,免把永久性误配
            // [表名错/GSI 缺失/ValidationException] 判成可重试 503 掩盖配置错)。
            Ok(_) => Ok(true),
            Err(e) if e.code().unwrap_or("").contains("ConditionalCheckFailed") => Ok(false),
            Err(e) => Err(ddb_err(e)),
        }
    }
    async fn get(
        &self,
        tenant: &str,
        credential_id: &str,
    ) -> Result<Option<agent_auth_authn::passkey::PasskeyCredential>, StoreError> {
        Ok(self
            .get_with_snapshot(tenant, credential_id)
            .await?
            .map(|(credential, _)| credential))
    }
    async fn list_by_user(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<Vec<agent_auth_authn::passkey::PasskeyCredential>, StoreError> {
        let mut out = Vec::new();
        let mut last: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let q = self
                .db
                .query()
                .table_name(&self.table)
                .index_name(&self.user_index)
                .key_condition_expression("user_id = :u")
                // GSI user_id 值 tenant 化 → 只命中本租户凭证(codex B1)。
                .expression_attribute_values(":u", AttributeValue::S(tpk(tenant, user_id)))
                .set_exclusive_start_key(last.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in q.items() {
                let credential_id = s(item.get("credential_id")).ok_or_else(|| {
                    StoreError::Permanent(
                        "passkey user_id-index item missing credential_id".to_string(),
                    )
                })?;
                if let Some(credential) = self.get(tenant, &strip_tpk(&credential_id)).await? {
                    if credential.user_id == user_id {
                        out.push(credential);
                    }
                }
            }
            match q.last_evaluated_key() {
                Some(k) if !k.is_empty() => last = Some(k.clone()),
                _ => break,
            }
        }
        Ok(out)
    }
    async fn update_sign_count(
        &self,
        tenant: &str,
        credential_id: &str,
        new_count: u32,
        expected_prev: u32,
    ) -> Result<bool, StoreError> {
        // 条件 UpdateItem CAS:仅当 sign_count == expected_prev 才写 new(防克隆并发/回退)。
        // 同步更新 cred_json 里的 sign_count 需读-改-写;为原子性,这里只更新独立 sign_count 属性,
        // 且 from_item 以 cred_json 为准——故 CAS 后须回写 json。简化:读当前、CAS 校验、条件写整条。
        let Some((mut cred, expected_json)) = self.get_with_snapshot(tenant, credential_id).await?
        else {
            return Ok(false);
        };
        if cred.sign_count != expected_prev {
            return Ok(false); // 已被并发改(竞态)
        }
        cred.sign_count = new_count;
        let item = Self::to_item(tenant, &cred)?;
        // Include the complete snapshot so a concurrent rename cannot be lost.
        let res = self
            .db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression(PASSKEY_SIGN_COUNT_SNAPSHOT_CONDITION)
            .expression_attribute_values(":prev", AttributeValue::N(expected_prev.to_string()))
            .expression_attribute_values(":snapshot", AttributeValue::S(expected_json))
            .send()
            .await;
        match res {
            // ConditionalCheckFailed = sign_count 已被并发改/回退 → 拒(Ok(false));其余经 ddb_err
            // 结构化分类(评审 Kiro L1:免永久性误配被判可重试 Transient 而掩盖)。
            Ok(_) => Ok(true),
            Err(e) if e.code().unwrap_or("").contains("ConditionalCheckFailed") => Ok(false),
            Err(e) => Err(ddb_err(e)),
        }
    }
    async fn rename_owned(
        &self,
        tenant: &str,
        user_id: &str,
        credential_id: &str,
        name: &str,
    ) -> Result<bool, StoreError> {
        let Some((mut credential, expected_json)) =
            self.get_with_snapshot(tenant, credential_id).await?
        else {
            return Ok(false);
        };
        if credential.user_id != user_id {
            return Ok(false);
        }
        credential.name = name.to_string();
        let item = Self::to_item(tenant, &credential)?;
        let result = self
            .db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression(PASSKEY_RENAME_SNAPSHOT_CONDITION)
            .expression_attribute_values(":user", AttributeValue::S(tpk(tenant, user_id)))
            .expression_attribute_values(
                ":count",
                AttributeValue::N(credential.sign_count.to_string()),
            )
            .expression_attribute_values(":snapshot", AttributeValue::S(expected_json))
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .code()
                    .unwrap_or("")
                    .contains("ConditionalCheckFailed") =>
            {
                Ok(false)
            }
            Err(error) => {
                let classified = ddb_err(error);
                if !matches!(&classified, StoreError::Transient(_)) {
                    return Err(classified);
                }
                match self.get_with_snapshot(tenant, credential_id).await {
                    Ok(Some((stored, _))) if stored.user_id == user_id && stored.name == name => {
                        Ok(true)
                    }
                    Ok(_) => Err(classified),
                    Err(read_error) => Err(read_error),
                }
            }
        }
    }
    async fn delete_owned(
        &self,
        tenant: &str,
        user_id: &str,
        credential_id: &str,
    ) -> Result<bool, StoreError> {
        let result = self
            .db
            .delete_item()
            .table_name(&self.table)
            .key(
                "credential_id",
                AttributeValue::S(tpk(tenant, credential_id)),
            )
            .condition_expression("user_id = :user")
            .expression_attribute_values(":user", AttributeValue::S(tpk(tenant, user_id)))
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .code()
                    .unwrap_or("")
                    .contains("ConditionalCheckFailed") =>
            {
                Ok(false)
            }
            Err(error) => Err(ddb_err(error)),
        }
    }
    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        // admin disable/delete 级联(§1.4):走 GSI(user_id-index)Query 拿全部 credential_id 再逐个
        // DeleteItem(pk=credential_id)。分页消费 LastEvaluatedKey。返回删除数。
        let mut n = 0usize;
        let mut last: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let q = self
                .db
                .query()
                .table_name(&self.table)
                .index_name(&self.user_index)
                .key_condition_expression("user_id = :u")
                // GSI user_id 值 tenant 化 → 只删本租户凭证(codex B1)。
                .expression_attribute_values(":u", AttributeValue::S(tpk(tenant, user_id)))
                .set_exclusive_start_key(last.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in q.items() {
                // fail-closed(评审 Kiro H1):credential_id 缺失/非串(数据损坏)→ **Permanent 报错**,
                // 不静默 skip(否则 tombstone 级联少删一条 passkey 却报成功 → 部分成功,违 fail-closed)。
                let cid = s(item.get("credential_id")).ok_or_else(|| {
                    StoreError::Permanent(
                        "passkey record missing credential_id (corrupt); cascade abort".into(),
                    )
                })?;
                self.db
                    .delete_item()
                    .table_name(&self.table)
                    .key("credential_id", AttributeValue::S(cid))
                    .send()
                    .await
                    .map_err(ddb_err)?;
                n += 1;
            }
            match q.last_evaluated_key() {
                Some(k) if !k.is_empty() => last = Some(k.clone()),
                _ => break,
            }
        }
        Ok(n)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        governance_delete_by_tenant_key(&self.db, &self.table, "credential_id", tenant).await
    }
}

#[cfg(test)]
mod passkey_snapshot_condition_tests {
    use super::{PASSKEY_RENAME_SNAPSHOT_CONDITION, PASSKEY_SIGN_COUNT_SNAPSHOT_CONDITION};

    #[test]
    fn sign_count_and_rename_compare_the_complete_credential_snapshot() {
        for condition in [
            PASSKEY_SIGN_COUNT_SNAPSHOT_CONDITION,
            PASSKEY_RENAME_SNAPSHOT_CONDITION,
        ] {
            assert!(
                condition.contains("cred_json = :snapshot"),
                "whole-item writes must reject a concurrent change to any credential field"
            );
        }
        assert!(PASSKEY_SIGN_COUNT_SNAPSHOT_CONDITION.contains("sign_count = :prev"));
        assert!(PASSKEY_RENAME_SNAPSHOT_CONDITION.contains("user_id = :user"));
    }

    #[test]
    fn legacy_snapshot_must_not_be_reconstructed_for_compare_and_swap() {
        let legacy = r#"{"credential_id":"legacy","user_id":"user:legacy@example.com","rp_id":"localhost","public_key_sec1":[4],"sign_count":0}"#;
        let credential: agent_auth_authn::passkey::PasskeyCredential =
            serde_json::from_str(legacy).unwrap();
        assert_eq!(credential.name, "Passkey");
        assert_eq!(credential.created_at, 0);
        assert_ne!(
            serde_json::to_string(&credential).unwrap(),
            legacy,
            "defaulted fields change the serialized shape, so CAS must use the raw stored JSON"
        );
    }
}

#[cfg(test)]
mod live_credential_authority_tests {
    use super::{
        tpk, DynamoPasskeyStore, DynamoPasswordStore, DynamoRecoveryStore, DynamoSessionStore,
        DynamoUsersStore,
    };
    use crate::ports::{
        PasskeyRegistrationOutcome, PasskeyStore, RecoveryAuthorityConsume, RecoveryCodeEntry,
        RecoveryConsumeRequest, RecoveryRecord, RecoveryStore, RecoverySuccessResult,
        SessionRecord, SessionStore, StoreError, UsersStore,
    };
    use aws_sdk_dynamodb::types::AttributeValue;
    use base64::Engine as _;

    #[tokio::test]
    #[ignore = "requires AGENT_AUTH_LIVE_DYNAMO_RACES=1 and disposable AWS DynamoDB tables"]
    async fn live_passkey_registration_rejects_invalid_epoch_and_session_generation() {
        assert_eq!(
            std::env::var("AGENT_AUTH_LIVE_DYNAMO_RACES").as_deref(),
            Ok("1"),
            "set AGENT_AUTH_LIVE_DYNAMO_RACES=1 to acknowledge live AWS writes"
        );
        let users_table =
            std::env::var("USERS_TABLE").expect("USERS_TABLE is required for the live test");
        let sessions_table =
            std::env::var("SESSIONS_TABLE").expect("SESSIONS_TABLE is required for the live test");
        let passkeys_table =
            std::env::var("PASSKEY_TABLE").expect("PASSKEY_TABLE is required for the live test");
        let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region))
            .load()
            .await;
        let db = aws_sdk_dynamodb::Client::new(&config);
        let users = DynamoUsersStore::new(db.clone(), &users_table);
        let sessions = DynamoSessionStore::new(db.clone(), &sessions_table);
        let passkeys = DynamoPasskeyStore::new(db.clone(), &passkeys_table);

        let nonce = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let epoch_user = format!("user:live-epoch-{nonce}@example.com");
        let session_user = format!("user:live-session-{nonce}@example.com");
        let epoch_session = format!("live-epoch-session-{nonce}");
        let stale_session = format!("live-stale-session-{nonce}");
        let epoch_credential = format!("live-epoch-credential-{nonce}");
        let session_credential = format!("live-session-credential-{nonce}");
        let now = crate::current_unix_secs();

        let result: Result<_, StoreError> = async {
            users
                .create_or_get_by_email(
                    "",
                    epoch_user.trim_start_matches("user:"),
                    &epoch_user,
                    now,
                )
                .await?;
            users
                .create_or_get_by_email(
                    "",
                    session_user.trim_start_matches("user:"),
                    &session_user,
                    now,
                )
                .await?;
            let epoch_record = SessionRecord {
                session_id: epoch_session.clone(),
                user_id: epoch_user.clone(),
                credential_epoch: 0,
                auth_time: now,
                created_at: now,
                last_used_at: now,
                device: "Live Dynamo authority test".to_string(),
                expires_at: now + 600,
                acr: None,
                amr: vec!["email".to_string()],
            };
            let session_record = SessionRecord {
                session_id: stale_session.clone(),
                user_id: session_user.clone(),
                ..epoch_record.clone()
            };
            sessions.create("", epoch_record.clone()).await?;
            sessions.create("", session_record.clone()).await?;

            let started = users
                .begin_credential_change("", &epoch_user, 0, "aws-test-owner", now + 1)
                .await?;
            if started != (crate::ports::CredentialChangeStart::Started { epoch: 1 }) {
                return Err(StoreError::Permanent(format!(
                    "unexpected live credential fence outcome: {started:?}"
                )));
            }
            let epoch_outcome = passkeys
                .put_new_authorized(
                    &users,
                    &sessions,
                    "",
                    &epoch_record,
                    agent_auth_authn::passkey::PasskeyCredential {
                        credential_id: epoch_credential.clone(),
                        user_id: epoch_user.clone(),
                        rp_id: "localhost".to_string(),
                        public_key_sec1: vec![0x04; 65],
                        sign_count: 0,
                        name: "Live epoch race".to_string(),
                        created_at: now,
                    },
                    now + 2,
                )
                .await?;

            if !sessions
                .revoke_all_by_actor("", &session_user, &stale_session)
                .await?
            {
                return Err(StoreError::Permanent(
                    "live session generation fence did not commit".to_string(),
                ));
            }
            let session_outcome = passkeys
                .put_new_authorized(
                    &users,
                    &sessions,
                    "",
                    &session_record,
                    agent_auth_authn::passkey::PasskeyCredential {
                        credential_id: session_credential.clone(),
                        user_id: session_user.clone(),
                        rp_id: "localhost".to_string(),
                        public_key_sec1: vec![0x04; 65],
                        sign_count: 0,
                        name: "Live session race".to_string(),
                        created_at: now,
                    },
                    now + 2,
                )
                .await?;
            let epoch_exists = passkeys.get("", &epoch_credential).await?.is_some();
            let session_exists = passkeys.get("", &session_credential).await?.is_some();
            Ok((epoch_outcome, session_outcome, epoch_exists, session_exists))
        }
        .await;

        for credential_id in [&epoch_credential, &session_credential] {
            let _ = db
                .delete_item()
                .table_name(&passkeys_table)
                .key("credential_id", AttributeValue::S(tpk("", credential_id)))
                .send()
                .await;
        }
        for session_id in [&epoch_session, &stale_session] {
            let _ = db
                .delete_item()
                .table_name(&sessions_table)
                .key("session_id", AttributeValue::S(tpk("", session_id)))
                .send()
                .await;
        }
        for user_id in [&epoch_user, &session_user] {
            let _ = db
                .delete_item()
                .table_name(&sessions_table)
                .key(
                    "session_id",
                    AttributeValue::S(DynamoSessionStore::generation_key("", user_id)),
                )
                .send()
                .await;
            let _ = db
                .delete_item()
                .table_name(&users_table)
                .key("user_id", AttributeValue::S(tpk("", user_id)))
                .send()
                .await;
        }

        let (epoch_outcome, session_outcome, epoch_exists, session_exists) = result.unwrap();
        assert_eq!(epoch_outcome, PasskeyRegistrationOutcome::AuthorityChanged);
        assert_eq!(
            session_outcome,
            PasskeyRegistrationOutcome::AuthorityChanged
        );
        assert!(!epoch_exists);
        assert!(!session_exists);
    }

    #[tokio::test]
    #[ignore = "requires AGENT_AUTH_LIVE_DYNAMO_RACES=1 and a disposable AWS passkey table"]
    async fn live_passkey_snapshot_cas_handles_legacy_rows_and_concurrent_updates() {
        assert_eq!(
            std::env::var("AGENT_AUTH_LIVE_DYNAMO_RACES").as_deref(),
            Ok("1"),
            "set AGENT_AUTH_LIVE_DYNAMO_RACES=1 to acknowledge live AWS writes"
        );
        let passkeys_table =
            std::env::var("PASSKEY_TABLE").expect("PASSKEY_TABLE is required for the live test");
        let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region))
            .load()
            .await;
        let db = aws_sdk_dynamodb::Client::new(&config);
        let passkeys = DynamoPasskeyStore::new(db.clone(), &passkeys_table);
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let user_id = format!("user:live-snapshot-{nonce}@example.com");
        let legacy_rename_id = format!("live-legacy-rename-{nonce}");
        let legacy_count_id = format!("live-legacy-count-{nonce}");
        let concurrent_id = format!("live-concurrent-{nonce}");

        let put_legacy = |credential_id: &str| {
            let raw = serde_json::json!({
                "credential_id": credential_id,
                "user_id": user_id,
                "rp_id": "localhost",
                "public_key_sec1": vec![4_u8; 65],
                "sign_count": 0,
            })
            .to_string();
            db.put_item()
                .table_name(&passkeys_table)
                .item("credential_id", AttributeValue::S(tpk("", credential_id)))
                .item("user_id", AttributeValue::S(tpk("", &user_id)))
                .item("sign_count", AttributeValue::N("0".to_string()))
                .item("cred_json", AttributeValue::S(raw))
                .send()
        };
        put_legacy(&legacy_rename_id).await.unwrap();
        put_legacy(&legacy_count_id).await.unwrap();
        passkeys
            .put_new(
                "",
                agent_auth_authn::passkey::PasskeyCredential {
                    credential_id: concurrent_id.clone(),
                    user_id: user_id.clone(),
                    rp_id: "localhost".to_string(),
                    public_key_sec1: vec![4; 65],
                    sign_count: 0,
                    name: "Concurrent".to_string(),
                    created_at: crate::current_unix_secs(),
                },
            )
            .await
            .unwrap();

        let result: Result<_, StoreError> = async {
            let legacy_renamed = passkeys
                .rename_owned("", &user_id, &legacy_rename_id, "Legacy renamed")
                .await?;
            let legacy_counted = passkeys
                .update_sign_count("", &legacy_count_id, 1, 0)
                .await?;

            let (renamed, counted) = tokio::join!(
                passkeys.rename_owned("", &user_id, &concurrent_id, "Concurrent renamed"),
                passkeys.update_sign_count("", &concurrent_id, 7, 0),
            );
            let renamed = renamed?;
            let counted = counted?;
            if !renamed
                && !passkeys
                    .rename_owned("", &user_id, &concurrent_id, "Concurrent renamed")
                    .await?
            {
                return Err(StoreError::Permanent(
                    "concurrent rename retry did not commit".to_string(),
                ));
            }
            if !counted {
                let current = passkeys.get("", &concurrent_id).await?.ok_or_else(|| {
                    StoreError::Permanent("concurrent credential disappeared".to_string())
                })?;
                if !passkeys
                    .update_sign_count("", &concurrent_id, 7, current.sign_count)
                    .await?
                {
                    return Err(StoreError::Permanent(
                        "concurrent sign-count retry did not commit".to_string(),
                    ));
                }
            }
            let concurrent = passkeys.get("", &concurrent_id).await?.ok_or_else(|| {
                StoreError::Permanent("concurrent credential missing after retries".to_string())
            })?;
            Ok((legacy_renamed, legacy_counted, concurrent))
        }
        .await;

        for credential_id in [&legacy_rename_id, &legacy_count_id, &concurrent_id] {
            let _ = db
                .delete_item()
                .table_name(&passkeys_table)
                .key("credential_id", AttributeValue::S(tpk("", credential_id)))
                .send()
                .await;
        }

        let (legacy_renamed, legacy_counted, concurrent) = result.unwrap();
        assert!(legacy_renamed);
        assert!(legacy_counted);
        assert_eq!(concurrent.name, "Concurrent renamed");
        assert_eq!(concurrent.sign_count, 7);
    }

    #[tokio::test]
    #[ignore = "requires AGENT_AUTH_LIVE_DYNAMO_RACES=1 and disposable AWS user/recovery tables"]
    async fn live_recovery_consumption_advances_user_authority_atomically() {
        assert_eq!(
            std::env::var("AGENT_AUTH_LIVE_DYNAMO_RACES").as_deref(),
            Ok("1"),
            "set AGENT_AUTH_LIVE_DYNAMO_RACES=1 to acknowledge live AWS writes"
        );
        let users_table =
            std::env::var("USERS_TABLE").expect("USERS_TABLE is required for the live test");
        let recovery_table =
            std::env::var("RECOVERY_TABLE").expect("RECOVERY_TABLE is required for the live test");
        let password_table =
            std::env::var("PASSWORD_TABLE").expect("PASSWORD_TABLE is required for the live test");
        let sessions_table =
            std::env::var("SESSIONS_TABLE").expect("SESSIONS_TABLE is required for the live test");
        let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region))
            .load()
            .await;
        let db = aws_sdk_dynamodb::Client::new(&config);
        let users = DynamoUsersStore::new(db.clone(), &users_table);
        let recovery = DynamoRecoveryStore::new(db.clone(), &recovery_table);
        let passwords = DynamoPasswordStore::new(db.clone(), &password_table);
        let sessions = DynamoSessionStore::new(db.clone(), &sessions_table);
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let user_id = format!("user:live-recovery-{nonce}@example.com");
        let lookup = format!("live-recovery-{nonce}");
        let presented_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let session_id = format!("live-recovery-session-{nonce}");
        let now = crate::current_unix_secs();

        let result: Result<_, StoreError> =
            async {
                users
                    .create_or_get_by_email("", user_id.trim_start_matches("user:"), &user_id, now)
                    .await?;
                recovery
                    .put(
                        "",
                        RecoveryRecord {
                            user_lookup: lookup.clone(),
                            user_id: user_id.clone(),
                            activation_id: "recovery".to_string(),
                            code_hashes: vec![RecoveryCodeEntry {
                                hash_b64: presented_hash.clone(),
                                consumed: false,
                            }],
                            attempt_count: 0,
                            locked_until: 0,
                        },
                    )
                    .await?;
                let outcome = recovery
                    .verify_and_consume_at_epoch(
                        &users,
                        &passwords,
                        &sessions,
                        RecoveryConsumeRequest {
                            tenant: "",
                            user_lookup: &lookup,
                            user_id: &user_id,
                            expected_email: user_id.trim_start_matches("user:"),
                            expected_epoch: 0,
                            presented_hash: &presented_hash,
                            now,
                        },
                        SessionRecord {
                            session_id: session_id.clone(),
                            user_id: user_id.clone(),
                            credential_epoch: 1,
                            auth_time: now,
                            created_at: now,
                            last_used_at: now,
                            device: "Live Dynamo test".to_string(),
                            expires_at: now + 300,
                            acr: None,
                            amr: vec!["recovery_code".to_string()],
                        },
                        RecoverySuccessResult {
                            operation_key: "live-recovery-operation".to_string(),
                            user_lookup: lookup.clone(),
                            user_id: user_id.clone(),
                            presented_hash: presented_hash.clone(),
                            credential_epoch: 1,
                            session_id: session_id.clone(),
                            created_at: now,
                            expires_at: now + 60,
                        },
                    )
                    .await?;
                let user = users.get_by_id("", &user_id).await?.ok_or_else(|| {
                    StoreError::Permanent("live recovery user missing".to_string())
                })?;
                let record = recovery.get("", &lookup).await?.ok_or_else(|| {
                    StoreError::Permanent("live recovery record missing".to_string())
                })?;
                let session = sessions.get("", &session_id).await?.ok_or_else(|| {
                    StoreError::Permanent("live recovered session missing".to_string())
                })?;
                Ok((outcome, user, record, session))
            }
            .await;

        let _ = db
            .delete_item()
            .table_name(&recovery_table)
            .key("user_lookup", AttributeValue::S(tpk("", &lookup)))
            .send()
            .await;
        let _ = db
            .delete_item()
            .table_name(&sessions_table)
            .key("session_id", AttributeValue::S(tpk("", &session_id)))
            .send()
            .await;
        let _ = db
            .delete_item()
            .table_name(&sessions_table)
            .key(
                "session_id",
                AttributeValue::S(DynamoSessionStore::generation_key("", &user_id)),
            )
            .send()
            .await;
        let _ = db
            .delete_item()
            .table_name(&users_table)
            .key("user_id", AttributeValue::S(tpk("", &user_id)))
            .send()
            .await;

        let (outcome, user, record, session) = result.unwrap();
        assert_eq!(
            outcome,
            RecoveryAuthorityConsume::Valid {
                credential_epoch: 1
            }
        );
        assert_eq!(user.credential_epoch, 1);
        assert!(!user.revocation_pending);
        assert!(record.code_hashes[0].consumed);
        assert_eq!(session.credential_epoch, 1);
        assert_eq!(session.amr, ["recovery_code"]);
    }
}

#[cfg(test)]
mod invitation_eligibility_tests {
    use super::DynamoInvitationStore;
    use crate::ports::InvitationRecord;

    fn record(user_id: &str, email: &str) -> InvitationRecord {
        InvitationRecord {
            locator: "locator".to_string(),
            activation_id: "invitation".to_string(),
            user_id: user_id.to_string(),
            email: email.to_string(),
            verifier_hash: "verifier".to_string(),
            credential_epoch: 0,
            issued_at: 1,
            expires_at: 2,
        }
    }

    #[test]
    fn dynamo_invitation_rejects_non_local_or_invalid_identity_records() {
        assert!(DynamoInvitationStore::record_is_local(&record(
            "user:alice@example.com",
            "alice@example.com"
        )));
        assert!(DynamoInvitationStore::record_is_local(&record(
            "user:scim:opaque",
            "alice@example.com"
        )));
        assert!(!DynamoInvitationStore::record_is_local(&record(
            "user:fed:subject",
            "alice@example.com"
        )));
        assert!(!DynamoInvitationStore::record_is_local(&record(
            "agent:alice",
            "alice@example.com"
        )));
        assert!(!DynamoInvitationStore::record_is_local(&record(
            "user:alice",
            "not-an-email"
        )));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DynamoCodeStore, DynamoInvitationStore, DynamoMagicLinkStore, DynamoPasswordStore,
        DynamoRefreshStore, DynamoSessionStore, REFRESH_FINALIZE_CONDITION_EXPRESSION,
        REFRESH_FINALIZE_UPDATE_EXPRESSION, REFRESH_LEASE_CONDITION_EXPRESSION,
        REFRESH_LEASE_UPDATE_EXPRESSION, REFRESH_RELEASE_CONDITION_EXPRESSION,
        REFRESH_RELEASE_UPDATE_EXPRESSION,
    };
    use crate::ports::{
        CodeStore, InvitationAcceptOutcome, InvitationAcceptRequest, InvitationIssueOutcome,
        InvitationRecord, InvitationStore, LeaseAcquire, MagicLinkRecord, MagicLinkStore,
        PasswordCredential, PasswordStore, RefreshLeaseAcquire, RefreshStore,
    };
    use aws_smithy_http_client::test_util::{ReplayEvent, StaticReplayClient};
    use aws_smithy_types::body::SdkBody;
    use serde_json::{json, Value};
    use std::collections::BTreeSet;

    fn response(status: u16, body: Value) -> axum::http::Response<SdkBody> {
        let mut builder = axum::http::Response::builder()
            .status(status)
            .header("content-type", "application/x-amz-json-1.0");
        if status == 400 {
            builder = builder.header("x-amzn-errortype", "ConditionalCheckFailedException");
        } else if status >= 500 {
            builder = builder.header("x-amzn-errortype", "InternalServerError");
        }
        builder.body(SdkBody::from(body.to_string())).unwrap()
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
                .retry_config(
                    aws_sdk_dynamodb::config::retry::RetryConfig::standard().with_max_attempts(1),
                )
                .http_client(http)
                .build(),
        )
    }

    fn stored_link() -> Value {
        json!({
            "pk": {"S": "tenant-a\u{1f}link#link-1"},
            "link_id": {"S": "link-1"},
            "user_id": {"S": "user:alice@example.com"},
            "email": {"S": "alice@example.com"},
            "session_nonce": {"S": "nonce-a"},
            "authorize_query": {"S": "client_id=client-1"},
            "next": {"S": "/account"},
            "expires_at": {"N": "1700000600"}
        })
    }

    #[tokio::test]
    async fn dynamo_password_store_is_tenant_scoped_hash_only_and_strongly_consistent() {
        let password = "Dynamo contract password 123!";
        let password_hash = agent_auth_authn::password::hash_password(password).unwrap();
        let encoded_hash = password_hash.expose().to_string();
        let http = StaticReplayClient::new(vec![
            ReplayEvent::new(placeholder_request(), response(200, json!({}))),
            ReplayEvent::new(
                placeholder_request(),
                response(
                    200,
                    json!({
                        "Item": {
                            "user_id": {"S": "tenant-b\u{1f}user:alice@example.com"},
                            "password_hash": {"S": encoded_hash},
                            "must_change": {"BOOL": true},
                            "revocation_pending": {"BOOL": true},
                            "credential_change_id": {"S": "operation-1"},
                            "version": {"N": "7"},
                            "updated_at": {"N": "1700000000"}
                        }
                    }),
                ),
            ),
        ]);
        let store = DynamoPasswordStore::new(dynamo_client(http.clone()), "passwords-table");

        assert!(store
            .create_if_absent(
                "tenant-a",
                PasswordCredential {
                    user_id: "user:alice@example.com".to_string(),
                    password_hash,
                    must_change: true,
                    revocation_pending: true,
                    credential_change_id: Some("operation-1".to_string()),
                    version: 7,
                    updated_at: 1_700_000_000,
                },
            )
            .await
            .unwrap());
        let stored = store
            .get("tenant-b", "user:alice@example.com")
            .await
            .unwrap()
            .expect("tenant-scoped password row");
        assert_eq!(stored.user_id, "user:alice@example.com");
        assert!(
            agent_auth_authn::password::verify_password(password, &stored.password_hash).unwrap()
        );

        let requests: Vec<_> = http.actual_requests().collect();
        assert_eq!(requests.len(), 2);
        let bodies: Vec<Value> = requests
            .iter()
            .map(|request| {
                serde_json::from_slice(request.body().bytes().expect("AWS request body"))
                    .expect("AWS request JSON")
            })
            .collect();
        assert_eq!(bodies[0]["TableName"], "passwords-table");
        assert_eq!(
            bodies[0]["ConditionExpression"],
            "attribute_not_exists(user_id)"
        );
        assert_eq!(
            bodies[0]["Item"]["user_id"]["S"],
            "tenant-a\u{1f}user:alice@example.com"
        );
        assert_eq!(bodies[0]["Item"]["password_hash"]["S"], encoded_hash);
        let item_fields: BTreeSet<_> = bodies[0]["Item"]
            .as_object()
            .expect("Dynamo item")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            item_fields,
            BTreeSet::from([
                "credential_change_id",
                "must_change",
                "password_hash",
                "revocation_pending",
                "updated_at",
                "user_id",
                "version",
            ])
        );
        assert!(!bodies[0].to_string().contains(password));
        assert_eq!(bodies[1]["TableName"], "passwords-table");
        assert_eq!(bodies[1]["ConsistentRead"], true);
        assert_eq!(
            bodies[1]["Key"]["user_id"]["S"],
            "tenant-b\u{1f}user:alice@example.com"
        );
    }

    fn expired_consumed_code() -> Value {
        json!({
            "code": {"S": "tenant-a\u{1f}code-1"},
            "client_id": {"S": "tenant-a\u{1f}client-1"},
            "redirect_uri": {"S": "https://client.example/callback"},
            "code_challenge": {"S": "challenge"},
            "resources": {"L": [{"S": "https://api.example"}]},
            "user_id": {"S": "user:alice@example.com"},
            "scope": {"L": [{"S": "openid"}]},
            "expires_at": {"N": "1000"},
            "auth_time": {"N": "900"},
            "consumed": {"BOOL": true},
            "issued_grant_id": {"S": "grant-1"}
        })
    }

    fn tenant_code_record() -> crate::ports::CodeRecord {
        crate::ports::CodeRecord {
            code: "shared-code".to_string(),
            client_id: "shared-client".to_string(),
            cimd_snapshot: None,
            redirect_uri: "https://client.example/callback".to_string(),
            code_challenge: "challenge".to_string(),
            resources: vec!["https://api.example".to_string()],
            user_id: "user:alice@example.com".to_string(),
            scope: vec!["openid".to_string()],
            expires_at: 1_700_000_600,
            authz_session_id: None,
            nonce: None,
            auth_time: 1_700_000_000,
            authorization_details: vec![],
            acr: None,
            amr: vec![],
            credential_epoch: Some(0),
            password_credential_version: None,
        }
    }

    fn stored_invitation() -> Value {
        json!({
            "locator": {"S": "tenant-a\u{1f}locator-1"},
            "activation_id": {"S": "r1_us-east-1_1_invitation"},
            "user_id": {"S": "tenant-a\u{1f}user:alice@example.com"},
            "email": {"S": "tenant-a\u{1f}alice@example.com"},
            "verifier_hash": {"S": "verifier-1"},
            "credential_epoch": {"N": "7"},
            "issued_at": {"N": "1000"},
            "expires_at": {"N": "2000"}
        })
    }

    fn invitation_record() -> InvitationRecord {
        InvitationRecord {
            locator: "locator-1".to_string(),
            activation_id: "r1_us-east-1_1_invitation".to_string(),
            user_id: "user:alice@example.com".to_string(),
            email: "alice@example.com".to_string(),
            verifier_hash: "verifier-1".to_string(),
            credential_epoch: 7,
            issued_at: 1_000,
            expires_at: 2_000,
        }
    }

    fn stored_invite_session() -> Value {
        json!({
            "session_id": {"S": "tenant-a\u{1f}session-1"},
            "user_id": {"S": "tenant-a\u{1f}user:alice@example.com"},
            "credential_epoch": {"N": "7"},
            "session_generation": {"N": "0"},
            "auth_time": {"N": "1100"},
            "created_at": {"N": "1100"},
            "last_used_at": {"N": "1100"},
            "device": {"S": "Invitation browser"},
            "expires_at": {"N": (1_100 + crate::login::SESSION_TTL_SECS).to_string()},
            "amr": {"L": [{"S": "invite"}]}
        })
    }

    #[tokio::test]
    async fn dynamo_invitation_record_is_verifier_only_and_tenant_scoped() {
        let http = StaticReplayClient::new(vec![ReplayEvent::new(
            placeholder_request(),
            response(200, json!({})),
        )]);
        let store = DynamoInvitationStore::new(
            dynamo_client(http.clone()),
            "invitations",
            "users",
            "passwords",
            "sessions",
        );
        let record = InvitationRecord {
            locator: "locator-1".to_string(),
            activation_id: "r1_us-east-1_1_invitation".to_string(),
            user_id: "user:alice@example.com".to_string(),
            email: "alice@example.com".to_string(),
            verifier_hash: "sha256-verifier-only".to_string(),
            credential_epoch: 7,
            issued_at: 1_000,
            expires_at: 2_000,
        };
        assert_eq!(
            store.issue("tenant-a", record).await.unwrap(),
            InvitationIssueOutcome::Issued
        );

        let requests: Vec<_> = http.actual_requests().collect();
        assert_eq!(requests.len(), 1);
        let request: Value = serde_json::from_slice(requests[0].body().bytes().unwrap()).unwrap();
        assert_eq!(request["ClientRequestToken"].as_str().unwrap().len(), 36);
        let items = request["TransactItems"].as_array().unwrap();
        assert_eq!(items.len(), 3);
        let item = items
            .iter()
            .find_map(|item| item.get("Put"))
            .filter(|put| put["TableName"] == "invitations")
            .and_then(|put| put["Item"].as_object())
            .expect("invitation put");
        assert_eq!(
            item.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "activation_id",
                "credential_epoch",
                "email",
                "expires_at",
                "issued_at",
                "locator",
                "user_id",
                "verifier_hash",
            ])
        );
        assert_eq!(
            item["locator"]["S"]
                .as_str()
                .expect("tenant-scoped locator"),
            "tenant-a\u{1f}locator-1"
        );
        let serialized = format!("{item:?}");
        for forbidden in ["invitation_url", "token", "secret"] {
            assert!(
                !serialized.contains(forbidden),
                "the persisted invitation record must not contain {forbidden}"
            );
        }
        let user_check = items
            .iter()
            .filter_map(|item| item.get("ConditionCheck"))
            .find(|check| check["TableName"] == "users")
            .expect("user authority condition");
        assert_eq!(
            user_check["ConditionExpression"],
            "attribute_exists(user_id) AND (attribute_not_exists(#status) OR #status = :active) AND (attribute_not_exists(revocation_pending) OR revocation_pending = :false) AND email = :email AND credential_epoch = :epoch"
        );
        let password_check = items
            .iter()
            .filter_map(|item| item.get("ConditionCheck"))
            .find(|check| check["TableName"] == "passwords")
            .expect("password absence condition");
        assert_eq!(
            password_check["ConditionExpression"],
            "attribute_not_exists(user_id)"
        );
    }

    #[tokio::test]
    async fn dynamo_invitation_issue_replays_ambiguous_commit_and_reconciles_exact_record() {
        let failure = || {
            response(
                500,
                json!({
                    "__type": "com.amazonaws.dynamodb.v20120810#InternalServerError",
                    "message": "response lost after commit"
                }),
            )
        };
        let http = StaticReplayClient::new(vec![
            ReplayEvent::new(placeholder_request(), failure()),
            ReplayEvent::new(placeholder_request(), failure()),
            ReplayEvent::new(
                placeholder_request(),
                response(200, json!({"Item": stored_invitation()})),
            ),
        ]);
        let store = DynamoInvitationStore::new(
            dynamo_client(http.clone()),
            "invitations",
            "users",
            "passwords",
            "sessions",
        );

        assert_eq!(
            store.issue("tenant-a", invitation_record()).await.unwrap(),
            InvitationIssueOutcome::Issued
        );
        let requests: Vec<Value> = http
            .actual_requests()
            .map(|request| serde_json::from_slice(request.body().bytes().unwrap()).unwrap())
            .collect();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0], requests[1]);
        assert_eq!(
            requests[0]["ClientRequestToken"].as_str().unwrap().len(),
            36
        );
        assert_eq!(requests[2]["ConsistentRead"], true);
    }

    #[tokio::test]
    async fn dynamo_invitation_issue_rejects_mismatched_ambiguous_commit_reconciliation() {
        let failure = || {
            response(
                500,
                json!({
                    "__type": "com.amazonaws.dynamodb.v20120810#InternalServerError",
                    "message": "response lost after commit"
                }),
            )
        };
        let mut mismatched = stored_invitation();
        mismatched["verifier_hash"] = json!({"S": "different-verifier"});
        let http = StaticReplayClient::new(vec![
            ReplayEvent::new(placeholder_request(), failure()),
            ReplayEvent::new(placeholder_request(), failure()),
            ReplayEvent::new(
                placeholder_request(),
                response(200, json!({"Item": mismatched})),
            ),
        ]);
        let store = DynamoInvitationStore::new(
            dynamo_client(http.clone()),
            "invitations",
            "users",
            "passwords",
            "sessions",
        );

        assert!(store.issue("tenant-a", invitation_record()).await.is_err());
        let requests: Vec<Value> = http
            .actual_requests()
            .map(|request| serde_json::from_slice(request.body().bytes().unwrap()).unwrap())
            .collect();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0], requests[1]);
        assert_eq!(requests[2]["ConsistentRead"], true);
    }

    #[tokio::test]
    async fn refresh_lease_requests_are_owner_fenced_and_finalize_grace_atomically() {
        use aws_sdk_dynamodb::types::AttributeValue;
        use std::collections::HashMap;

        let conditional = || {
            response(
                400,
                json!({
                    "__type": "com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException",
                    "message": "refresh lease conflict"
                }),
            )
        };
        let http = StaticReplayClient::new(vec![
            ReplayEvent::new(placeholder_request(), response(200, json!({}))),
            ReplayEvent::new(placeholder_request(), conditional()),
            ReplayEvent::new(
                placeholder_request(),
                response(
                    200,
                    json!({
                        "Item": {
                            "family_id": {"S": "tenant-a\u{1f}family-1"},
                            "current_version": {"N": "0"},
                            "revoked": {"BOOL": false},
                            "signing_lease_owner": {"S": "owner-a"},
                            "signing_lease_expires_at": {"N": "130"}
                        }
                    }),
                ),
            ),
            ReplayEvent::new(placeholder_request(), response(200, json!({}))),
            ReplayEvent::new(placeholder_request(), conditional()),
            ReplayEvent::new(placeholder_request(), response(200, json!({}))),
        ]);
        let store = DynamoRefreshStore::new(
            dynamo_client(http.clone()),
            "refresh",
            "clients",
            "authority-refs",
            "client-authority-refs-v1:test",
        );

        assert_eq!(
            store
                .acquire_lease("tenant-a", "family-1", 0, "owner-a", 100, 130)
                .await
                .unwrap(),
            RefreshLeaseAcquire::Acquired
        );
        assert_eq!(
            store
                .acquire_lease("tenant-a", "family-1", 0, "owner-b", 110, 140)
                .await
                .unwrap(),
            RefreshLeaseAcquire::Locked {
                retry_after_secs: 20
            }
        );
        assert_eq!(
            store
                .acquire_lease("tenant-a", "family-1", 0, "owner-b", 130, 160)
                .await
                .unwrap(),
            RefreshLeaseAcquire::Acquired
        );
        assert!(!store
            .release_lease("tenant-a", "family-1", 0, "owner-a")
            .await
            .unwrap());
        assert!(store
            .finalize_rotation_transaction(
                "tenant-a",
                "family-1",
                0,
                "owner-b",
                131,
                Some((
                    "grace",
                    HashMap::from([
                        (
                            "family_id".to_string(),
                            AttributeValue::S("family-1".to_string()),
                        ),
                        ("version".to_string(), AttributeValue::N("0".to_string())),
                        (
                            "ciphertext".to_string(),
                            AttributeValue::B(aws_sdk_dynamodb::primitives::Blob::new([7, 8, 9])),
                        ),
                    ]),
                )),
            )
            .await
            .unwrap());

        let requests: Vec<Value> = http
            .actual_requests()
            .map(|request| serde_json::from_slice(request.body().bytes().unwrap()).unwrap())
            .collect();
        assert_eq!(requests.len(), 6);
        assert_eq!(
            requests[0]["UpdateExpression"],
            REFRESH_LEASE_UPDATE_EXPRESSION
        );
        assert_eq!(
            requests[0]["ConditionExpression"],
            REFRESH_LEASE_CONDITION_EXPRESSION
        );
        assert_eq!(
            requests[0]["Key"]["family_id"]["S"],
            "tenant-a\u{1f}family-1"
        );
        assert_eq!(requests[2]["ConsistentRead"], true);
        assert_eq!(
            requests[4]["UpdateExpression"],
            REFRESH_RELEASE_UPDATE_EXPRESSION
        );
        assert_eq!(
            requests[4]["ConditionExpression"],
            REFRESH_RELEASE_CONDITION_EXPRESSION
        );

        let transaction = &requests[5];
        assert_eq!(
            transaction["ClientRequestToken"].as_str().unwrap().len(),
            36
        );
        let items = transaction["TransactItems"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        let update = &items[0]["Update"];
        assert_eq!(
            update["UpdateExpression"],
            REFRESH_FINALIZE_UPDATE_EXPRESSION
        );
        assert_eq!(
            update["ConditionExpression"],
            REFRESH_FINALIZE_CONDITION_EXPRESSION
        );
        assert_eq!(
            update["ExpressionAttributeValues"][":owner"]["S"],
            "owner-b"
        );
        assert_eq!(update["ExpressionAttributeValues"][":now"]["N"], "131");
        let put = &items[1]["Put"];
        assert_eq!(put["TableName"], "grace");
        assert_eq!(
            put["ConditionExpression"],
            "attribute_not_exists(family_id) AND attribute_not_exists(#version)"
        );
        assert_eq!(put["Item"]["family_id"]["S"], "family-1");
        assert_eq!(put["Item"]["version"]["N"], "0");
    }

    #[tokio::test]
    async fn dynamo_code_writes_atomically_fence_expiry() {
        let http = StaticReplayClient::new(vec![
            ReplayEvent::new(
                placeholder_request(),
                response(
                    400,
                    json!({
                        "__type": "com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException",
                        "message": "authorization code is no longer leasable"
                    }),
                ),
            ),
            ReplayEvent::new(
                placeholder_request(),
                response(200, json!({"Item": expired_consumed_code()})),
            ),
            ReplayEvent::new(placeholder_request(), response(200, json!({}))),
            ReplayEvent::new(placeholder_request(), response(200, json!({}))),
            ReplayEvent::new(
                placeholder_request(),
                response(
                    400,
                    json!({
                        "__type": "com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException",
                        "message": "authorization code is no longer replay-markable"
                    }),
                ),
            ),
        ]);
        let store = DynamoCodeStore::new(
            dynamo_client(http.clone()),
            "codes",
            "clients",
            "authority-refs",
            "client-authority-refs-v1:test",
        );

        assert_eq!(
            store
                .acquire_lease("tenant-a", "code-1", "owner-1", 1_000, 1_030)
                .await
                .unwrap(),
            LeaseAcquire::NotFound
        );
        store
            .finalize(
                "tenant-a",
                "code-2",
                "client-1",
                1_100,
                1_000,
                "owner-2",
                Some("grant-2"),
            )
            .await
            .unwrap();
        store
            .release_lease("tenant-a", "code-3", "owner-3", 1_000)
            .await
            .unwrap();
        assert!(!store
            .record_replay("tenant-a", "code-4", 1_000)
            .await
            .unwrap());

        let requests: Vec<_> = http.actual_requests().collect();
        assert_eq!(requests.len(), 5);
        let bodies: Vec<Value> = requests
            .iter()
            .map(|request| {
                serde_json::from_slice(request.body().bytes().expect("AWS request body"))
                    .expect("AWS request JSON")
            })
            .collect();

        assert_eq!(
            bodies[0]["ConditionExpression"],
            "attribute_exists(code) AND attribute_not_exists(#consumed) AND expires_at > :now AND (attribute_not_exists(#lease) OR #lease <= :now)"
        );
        assert_eq!(bodies[0]["ExpressionAttributeValues"][":now"]["N"], "1000");
        assert_eq!(bodies[1]["ConsistentRead"], true);

        let finalize = &bodies[2]["TransactItems"][0]["Update"];
        assert!(finalize["ConditionExpression"]
            .as_str()
            .unwrap()
            .contains("expires_at > :now"));
        assert!(finalize["ConditionExpression"]
            .as_str()
            .unwrap()
            .contains("#owner = :owner"));
        assert_eq!(
            finalize["ExpressionAttributeValues"][":owner"]["S"],
            "owner-2"
        );
        assert_eq!(finalize["ExpressionAttributeValues"][":now"]["N"], "1000");

        assert!(bodies[3]["ConditionExpression"]
            .as_str()
            .unwrap()
            .contains("expires_at > :now"));
        assert!(bodies[3]["ConditionExpression"]
            .as_str()
            .unwrap()
            .contains("#owner = :owner"));
        assert_eq!(
            bodies[3]["ExpressionAttributeValues"][":owner"]["S"],
            "owner-3"
        );
        assert_eq!(bodies[3]["ExpressionAttributeValues"][":now"]["N"], "1000");
        assert_eq!(
            bodies[4]["ConditionExpression"],
            "attribute_exists(#consumed) AND expires_at > :now"
        );
        assert_eq!(bodies[4]["ExpressionAttributeValues"][":now"]["N"], "1000");
    }

    #[tokio::test]
    async fn dynamo_code_primary_and_client_reference_keys_are_tenant_scoped() {
        let http = StaticReplayClient::new(vec![
            ReplayEvent::new(placeholder_request(), response(200, json!({}))),
            ReplayEvent::new(placeholder_request(), response(200, json!({}))),
        ]);
        let store = DynamoCodeStore::new(
            dynamo_client(http.clone()),
            "codes",
            "clients",
            "authority-refs",
            "client-authority-refs-v1:test",
        );

        store.put("tenant-a", tenant_code_record()).await.unwrap();
        store.put("tenant-b", tenant_code_record()).await.unwrap();

        let requests: Vec<_> = http.actual_requests().collect();
        assert_eq!(requests.len(), 2);
        let bodies: Vec<Value> = requests
            .iter()
            .map(|request| {
                serde_json::from_slice(request.body().bytes().expect("AWS request body"))
                    .expect("AWS request JSON")
            })
            .collect();

        for (body, tenant) in bodies.iter().zip(["tenant-a", "tenant-b"]) {
            let items = body["TransactItems"].as_array().unwrap();
            assert_eq!(items.len(), 3);
            let code_put = items
                .iter()
                .find_map(|item| {
                    let put = item.get("Put")?;
                    (put["TableName"] == "codes").then_some(put)
                })
                .expect("authorization-code Put");
            let reference_put = items
                .iter()
                .find_map(|item| {
                    let put = item.get("Put")?;
                    (put["TableName"] == "authority-refs").then_some(put)
                })
                .expect("authority-reference Put");
            let client_touch = items
                .iter()
                .find_map(|item| {
                    let update = item.get("Update")?;
                    (update["TableName"] == "clients").then_some(update)
                })
                .expect("registered-client authority touch");

            assert_eq!(
                code_put["Item"]["code"]["S"],
                format!("{tenant}\u{1f}shared-code")
            );
            assert_eq!(
                code_put["Item"]["client_id"]["S"],
                format!("{tenant}\u{1f}shared-client")
            );
            assert_eq!(
                reference_put["Item"]["client_key"]["S"],
                format!("client#00000008{tenant}0000000dshared-client")
            );
            assert_eq!(
                reference_put["Item"]["source_id"]["S"],
                format!("{tenant}\u{1f}shared-code")
            );
            assert_eq!(reference_put["Item"]["tenant_id"]["S"], tenant);
            assert_eq!(
                client_touch["Key"]["client_id"]["S"],
                format!("{tenant}\u{1f}shared-client")
            );
        }

        assert_ne!(
            bodies[0]["TransactItems"][0]["Put"]["Item"]["code"]["S"],
            bodies[1]["TransactItems"][0]["Put"]["Item"]["code"]["S"]
        );
    }

    #[tokio::test]
    async fn dynamo_session_primary_reads_use_distinct_tenant_qualified_keys() {
        let http = StaticReplayClient::new(vec![
            ReplayEvent::new(placeholder_request(), response(200, json!({}))),
            ReplayEvent::new(placeholder_request(), response(200, json!({}))),
        ]);
        let store = DynamoSessionStore::new(dynamo_client(http.clone()), "sessions");

        assert!(store
            .get_stored("tenant-a", "shared-session")
            .await
            .unwrap()
            .is_none());
        assert!(store
            .get_stored("tenant-b", "shared-session")
            .await
            .unwrap()
            .is_none());

        let requests: Vec<Value> = http
            .actual_requests()
            .map(|request| serde_json::from_slice(request.body().bytes().unwrap()).unwrap())
            .collect();
        assert_eq!(requests.len(), 2);
        for request in &requests {
            assert_eq!(request["TableName"], "sessions");
            assert_eq!(request["ConsistentRead"], true);
        }
        assert_eq!(
            requests[0]["Key"]["session_id"]["S"],
            "tenant-a\u{1f}shared-session"
        );
        assert_eq!(
            requests[1]["Key"]["session_id"]["S"],
            "tenant-b\u{1f}shared-session"
        );
        assert_ne!(
            requests[0]["Key"]["session_id"]["S"],
            requests[1]["Key"]["session_id"]["S"]
        );
    }

    #[tokio::test]
    async fn dynamo_refresh_primary_reads_use_distinct_tenant_qualified_keys() {
        let http = StaticReplayClient::new(vec![
            ReplayEvent::new(placeholder_request(), response(200, json!({}))),
            ReplayEvent::new(placeholder_request(), response(200, json!({}))),
        ]);
        let store = DynamoRefreshStore::new(
            dynamo_client(http.clone()),
            "refresh",
            "clients",
            "authority-refs",
            "client-authority-refs-v1:test",
        );

        assert!(RefreshStore::get(&store, "tenant-a", "shared-family")
            .await
            .unwrap()
            .is_none());
        assert!(RefreshStore::get(&store, "tenant-b", "shared-family")
            .await
            .unwrap()
            .is_none());

        let requests: Vec<Value> = http
            .actual_requests()
            .map(|request| serde_json::from_slice(request.body().bytes().unwrap()).unwrap())
            .collect();
        assert_eq!(requests.len(), 2);
        for request in &requests {
            assert_eq!(request["TableName"], "refresh");
            assert_eq!(request["ConsistentRead"], true);
        }
        assert_eq!(
            requests[0]["Key"]["family_id"]["S"],
            "tenant-a\u{1f}shared-family"
        );
        assert_eq!(
            requests[1]["Key"]["family_id"]["S"],
            "tenant-b\u{1f}shared-family"
        );
        assert_ne!(
            requests[0]["Key"]["family_id"]["S"],
            requests[1]["Key"]["family_id"]["S"]
        );
    }

    #[tokio::test]
    async fn dynamo_code_release_classifies_lost_lease_as_transient() {
        let http = StaticReplayClient::new(vec![ReplayEvent::new(
            placeholder_request(),
            response(
                400,
                json!({
                    "__type": "com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException",
                    "message": "authorization code lease ownership was lost"
                }),
            ),
        )]);
        let store = DynamoCodeStore::new(
            dynamo_client(http),
            "codes",
            "clients",
            "authority-refs",
            "client-authority-refs-v1:test",
        );

        assert_eq!(
            store
                .release_lease("tenant-a", "code-1", "stale-owner", 1_000)
                .await,
            Err(crate::ports::StoreError::Transient(
                "authorization code lease ownership was lost".into()
            ))
        );
    }

    #[tokio::test]
    async fn dynamo_invitation_acceptance_atomically_consumes_verifier_and_creates_invite_session()
    {
        let http = StaticReplayClient::new(vec![
            ReplayEvent::new(
                placeholder_request(),
                response(200, json!({"Item": stored_invitation()})),
            ),
            ReplayEvent::new(placeholder_request(), response(200, json!({}))),
            ReplayEvent::new(placeholder_request(), response(200, json!({}))),
        ]);
        let store = DynamoInvitationStore::new(
            dynamo_client(http.clone()),
            "invitations",
            "users",
            "passwords",
            "sessions",
        );

        assert_eq!(
            store
                .accept(
                    "tenant-a",
                    InvitationAcceptRequest {
                        locator: "locator-1".to_string(),
                        activation_id: "r1_us-east-1_1_invitation".to_string(),
                        verifier_hash: "verifier-1".to_string(),
                        session_id: "session-1".to_string(),
                        device: "Invitation browser".to_string(),
                        now: 1_100,
                    },
                )
                .await
                .unwrap(),
            InvitationAcceptOutcome::Accepted {
                user_id: "user:alice@example.com".to_string(),
                session_id: "session-1".to_string(),
            }
        );

        let requests: Vec<_> = http.actual_requests().collect();
        assert_eq!(requests.len(), 3);
        let transaction: Value = serde_json::from_slice(
            requests[2]
                .body()
                .bytes()
                .expect("Dynamo transaction request body"),
        )
        .expect("Dynamo transaction request JSON");
        assert_eq!(
            transaction["ClientRequestToken"]
                .as_str()
                .expect("idempotency token")
                .len(),
            36
        );
        let items = transaction["TransactItems"]
            .as_array()
            .expect("transaction items");
        assert_eq!(items.len(), 5);
        let user_check = items
            .iter()
            .filter_map(|item| item.get("ConditionCheck"))
            .find(|check| check["TableName"] == "users")
            .expect("user authority check");
        assert_eq!(
            user_check["ConditionExpression"],
            "attribute_exists(user_id) AND (attribute_not_exists(#status) OR #status = :active) AND (attribute_not_exists(revocation_pending) OR revocation_pending = :false) AND email = :email AND credential_epoch = :epoch"
        );
        assert_eq!(
            user_check["ExpressionAttributeValues"][":email"]["S"],
            "tenant-a\u{1f}alice@example.com"
        );
        assert_eq!(user_check["ExpressionAttributeValues"][":epoch"]["N"], "7");
        let password_check = items
            .iter()
            .filter_map(|item| item.get("ConditionCheck"))
            .find(|check| check["TableName"] == "passwords")
            .expect("password absence check");
        assert_eq!(
            password_check["ConditionExpression"],
            "attribute_not_exists(user_id)"
        );
        let invitation_delete = items
            .iter()
            .find_map(|item| item.get("Delete"))
            .filter(|delete| delete["TableName"] == "invitations")
            .expect("invitation delete in the acceptance transaction");
        assert_eq!(
            invitation_delete["ConditionExpression"],
            "verifier_hash = :verifier AND expires_at > :now AND credential_epoch = :epoch AND user_id = :user AND activation_id = :activation"
        );
        assert_eq!(
            invitation_delete["ExpressionAttributeValues"][":verifier"]["S"],
            "verifier-1"
        );
        assert_eq!(
            invitation_delete["ExpressionAttributeValues"][":now"]["N"],
            "1100"
        );
        assert_eq!(
            invitation_delete["ExpressionAttributeValues"][":epoch"]["N"],
            "7"
        );
        assert_eq!(
            invitation_delete["ExpressionAttributeValues"][":user"]["S"],
            "tenant-a\u{1f}user:alice@example.com"
        );
        assert_eq!(
            invitation_delete["ExpressionAttributeValues"][":activation"]["S"],
            "r1_us-east-1_1_invitation"
        );
        let generation_check = items
            .iter()
            .filter_map(|item| item.get("ConditionCheck"))
            .find(|check| check["TableName"] == "sessions")
            .expect("session generation check");
        assert_eq!(
            generation_check["ConditionExpression"],
            "attribute_not_exists(session_id) OR #generation = :expected"
        );
        assert_eq!(
            generation_check["ExpressionAttributeValues"][":expected"]["N"],
            "0"
        );
        let session_put = items
            .iter()
            .find_map(|item| item.get("Put"))
            .filter(|put| put["TableName"] == "sessions")
            .expect("login-session put in the acceptance transaction");
        assert_eq!(
            session_put["Item"]["session_id"]["S"],
            "tenant-a\u{1f}session-1"
        );
        assert_eq!(
            session_put["ConditionExpression"],
            "attribute_not_exists(session_id)"
        );
        assert_eq!(
            session_put["Item"]["user_id"]["S"],
            "tenant-a\u{1f}user:alice@example.com"
        );
        assert_eq!(session_put["Item"]["credential_epoch"]["N"], "7");
        assert_eq!(session_put["Item"]["session_generation"]["N"], "0");
        assert_eq!(session_put["Item"]["auth_time"]["N"], "1100");
        assert_eq!(session_put["Item"]["created_at"]["N"], "1100");
        assert_eq!(session_put["Item"]["last_used_at"]["N"], "1100");
        assert_eq!(session_put["Item"]["device"]["S"], "Invitation browser");
        assert_eq!(
            session_put["Item"]["expires_at"]["N"],
            (1_100 + crate::login::SESSION_TTL_SECS).to_string()
        );
        assert_eq!(session_put["Item"]["amr"]["L"][0]["S"], "invite");
    }

    #[tokio::test]
    async fn dynamo_invitation_accept_replays_ambiguous_commit_and_reconciles_exact_session() {
        let failure = || {
            response(
                500,
                json!({
                    "__type": "com.amazonaws.dynamodb.v20120810#InternalServerError",
                    "message": "response lost after commit"
                }),
            )
        };
        let http = StaticReplayClient::new(vec![
            ReplayEvent::new(
                placeholder_request(),
                response(200, json!({"Item": stored_invitation()})),
            ),
            ReplayEvent::new(placeholder_request(), response(200, json!({}))),
            ReplayEvent::new(placeholder_request(), failure()),
            ReplayEvent::new(placeholder_request(), failure()),
            ReplayEvent::new(
                placeholder_request(),
                response(200, json!({"Item": stored_invite_session()})),
            ),
        ]);
        let store = DynamoInvitationStore::new(
            dynamo_client(http.clone()),
            "invitations",
            "users",
            "passwords",
            "sessions",
        );

        assert_eq!(
            store
                .accept(
                    "tenant-a",
                    InvitationAcceptRequest {
                        locator: "locator-1".to_string(),
                        activation_id: "r1_us-east-1_1_invitation".to_string(),
                        verifier_hash: "verifier-1".to_string(),
                        session_id: "session-1".to_string(),
                        device: "Invitation browser".to_string(),
                        now: 1_100,
                    },
                )
                .await
                .unwrap(),
            InvitationAcceptOutcome::Accepted {
                user_id: "user:alice@example.com".to_string(),
                session_id: "session-1".to_string(),
            }
        );
        let requests: Vec<Value> = http
            .actual_requests()
            .map(|request| serde_json::from_slice(request.body().bytes().unwrap()).unwrap())
            .collect();
        assert_eq!(requests.len(), 5);
        assert_eq!(requests[2], requests[3]);
        assert_eq!(
            requests[2]["ClientRequestToken"].as_str().unwrap().len(),
            36
        );
        assert_eq!(requests[4]["ConsistentRead"], true);
        assert_eq!(
            requests[4]["Key"]["session_id"]["S"],
            "tenant-a\u{1f}session-1"
        );
    }

    #[tokio::test]
    async fn dynamo_invitation_accept_rejects_mismatched_ambiguous_commit_reconciliation() {
        let failure = || {
            response(
                500,
                json!({
                    "__type": "com.amazonaws.dynamodb.v20120810#InternalServerError",
                    "message": "response lost after commit"
                }),
            )
        };
        let mut mismatched = stored_invite_session();
        mismatched["amr"] = json!({"L": [{"S": "email"}]});
        let http = StaticReplayClient::new(vec![
            ReplayEvent::new(
                placeholder_request(),
                response(200, json!({"Item": stored_invitation()})),
            ),
            ReplayEvent::new(placeholder_request(), response(200, json!({}))),
            ReplayEvent::new(placeholder_request(), failure()),
            ReplayEvent::new(placeholder_request(), failure()),
            ReplayEvent::new(
                placeholder_request(),
                response(200, json!({"Item": mismatched})),
            ),
        ]);
        let store = DynamoInvitationStore::new(
            dynamo_client(http.clone()),
            "invitations",
            "users",
            "passwords",
            "sessions",
        );

        assert!(store
            .accept(
                "tenant-a",
                InvitationAcceptRequest {
                    locator: "locator-1".to_string(),
                    activation_id: "r1_us-east-1_1_invitation".to_string(),
                    verifier_hash: "verifier-1".to_string(),
                    session_id: "session-1".to_string(),
                    device: "Invitation browser".to_string(),
                    now: 1_100,
                },
            )
            .await
            .is_err());
        let requests: Vec<Value> = http
            .actual_requests()
            .map(|request| serde_json::from_slice(request.body().bytes().unwrap()).unwrap())
            .collect();
        assert_eq!(requests.len(), 5);
        assert_eq!(requests[2], requests[3]);
        assert_eq!(requests[4]["ConsistentRead"], true);
    }

    #[tokio::test]
    async fn dynamo_exchange_failure_atomically_fences_expiry() {
        super::exchange_failure_atomicity_tests::
            assert_exchange_failure_uses_one_transaction_for_code_and_session()
            .await;
    }

    #[tokio::test]
    async fn dynamo_exchange_failure_condition_cancel_is_retryable() {
        super::exchange_failure_atomicity_tests::
            assert_exchange_failure_condition_cancel_is_retryable()
            .await;
    }

    #[tokio::test]
    async fn dynamo_exchange_failure_resamples_expiry_after_session_authority_read() {
        super::exchange_failure_atomicity_tests::
            assert_exchange_failure_resamples_expiry_after_session_authority_read()
            .await;
    }

    #[tokio::test]
    async fn dynamo_magic_link_reads_strongly_and_consumes_only_the_bound_nonce_once() {
        let item = stored_link();
        let http = StaticReplayClient::new(vec![
            ReplayEvent::new(
                placeholder_request(),
                response(200, json!({"Item": item.clone()})),
            ),
            ReplayEvent::new(
                placeholder_request(),
                response(
                    400,
                    json!({
                        "__type": "com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException",
                        "message": "wrong browser nonce"
                    }),
                ),
            ),
            ReplayEvent::new(
                placeholder_request(),
                response(200, json!({"Attributes": item})),
            ),
            ReplayEvent::new(
                placeholder_request(),
                response(
                    400,
                    json!({
                        "__type": "com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException",
                        "message": "magic link already consumed"
                    }),
                ),
            ),
            ReplayEvent::new(
                placeholder_request(),
                response(
                    500,
                    json!({
                        "__type": "com.amazonaws.dynamodb.v20120810#InternalServerError",
                        "message": "transient failure"
                    }),
                ),
            ),
        ]);
        let store = DynamoMagicLinkStore::new(dynamo_client(http.clone()), "magic-links");

        assert_eq!(
            store.get("tenant-a", "link-1").await.unwrap(),
            Some(MagicLinkRecord {
                link_id: "link-1".to_string(),
                user_id: "user:alice@example.com".to_string(),
                email: "alice@example.com".to_string(),
                session_nonce: "nonce-a".to_string(),
                authorize_query: "client_id=client-1".to_string(),
                next: "/account".to_string(),
                expires_at: 1_700_000_600,
            })
        );
        assert!(store
            .consume_bound("tenant-b", "link-1", "wrong-nonce")
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .consume_bound("tenant-a", "link-1", "nonce-a")
                .await
                .unwrap()
                .expect("matching browser consumes the link")
                .session_nonce,
            "nonce-a"
        );
        assert!(store
            .consume_bound("tenant-a", "link-1", "nonce-a")
            .await
            .unwrap()
            .is_none());
        assert!(store
            .consume_bound("tenant-a", "link-1", "nonce-a")
            .await
            .is_err());

        let requests: Vec<_> = http.actual_requests().collect();
        assert_eq!(requests.len(), 5);
        let bodies: Vec<Value> = requests
            .iter()
            .map(|request| {
                serde_json::from_slice(request.body().bytes().expect("AWS request body"))
                    .expect("AWS request JSON")
            })
            .collect();
        assert_eq!(bodies[0]["TableName"], "magic-links");
        assert_eq!(bodies[0]["ConsistentRead"], true);
        assert_eq!(bodies[0]["Key"]["pk"]["S"], "tenant-a\u{1f}link#link-1");
        assert_eq!(bodies[1]["Key"]["pk"]["S"], "tenant-b\u{1f}link#link-1");
        for body in &bodies[1..] {
            assert_eq!(
                body["ConditionExpression"],
                "session_nonce = :expected_session_nonce"
            );
            assert_eq!(body["ReturnValues"], "ALL_OLD");
        }
        assert_eq!(
            bodies[1]["ExpressionAttributeValues"][":expected_session_nonce"]["S"],
            "wrong-nonce"
        );
        assert_eq!(
            bodies[2]["ExpressionAttributeValues"][":expected_session_nonce"]["S"],
            "nonce-a"
        );
    }
}

#[cfg(test)]
#[path = "passkey_idempotency_tests.rs"]
mod passkey_idempotency_tests;
#[cfg(test)]
#[path = "session_fence_idempotency_tests.rs"]
mod session_fence_idempotency_tests;

#[cfg(test)]
#[path = "exchange_failure_atomicity_tests.rs"]
mod exchange_failure_atomicity_tests;

#[cfg(test)]
mod dynamo_login_session_record_tests {
    use super::DynamoSessionStore;
    use aws_sdk_dynamodb::types::AttributeValue;
    use std::collections::HashMap;

    #[test]
    fn legacy_items_default_generation_times_and_device_without_losing_identity() {
        let item = HashMap::from([
            (
                "session_id".to_string(),
                AttributeValue::S("legacy-session".to_string()),
            ),
            (
                "user_id".to_string(),
                AttributeValue::S("user:legacy@example.com".to_string()),
            ),
            (
                "auth_time".to_string(),
                AttributeValue::N("1234".to_string()),
            ),
            (
                "expires_at".to_string(),
                AttributeValue::N("5678".to_string()),
            ),
        ]);

        let stored = DynamoSessionStore::from_item(&item);
        assert_eq!(stored.generation, 0);
        assert_eq!(stored.record.session_id, "legacy-session");
        assert_eq!(stored.record.user_id, "user:legacy@example.com");
        assert_eq!(stored.record.created_at, 1234);
        assert_eq!(stored.record.last_used_at, 1234);
        assert_eq!(stored.record.device, "Unknown device");
    }

    #[test]
    fn generation_conditions_allow_legacy_zero_but_require_existing_markers_afterward() {
        assert!(DynamoSessionStore::generation_marker_condition(0)
            .contains("attribute_not_exists(session_id)"));
        assert_eq!(
            DynamoSessionStore::generation_marker_condition(1),
            "#generation = :expected"
        );
        assert!(DynamoSessionStore::authoritative_session_condition(0)
            .contains("attribute_not_exists(session_generation)"));
        assert_eq!(
            DynamoSessionStore::authoritative_session_condition(1),
            "user_id = :u AND session_generation = :expected"
        );
    }
}
