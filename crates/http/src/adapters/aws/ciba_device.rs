//! AWS CIBA and device authorization adapters.

use super::*;

/// DynamoDB CIBA 授权请求存储(spec 013)。表主键 = `auth_req_id`(S)。
#[derive(Clone)]
pub struct DynamoCibaStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
    /// 信封加密 client_notification_token 用的独立 KMS CMK(SYMMETRIC_DEFAULT)。
    pub(super) kms: aws_sdk_kms::Client,
    pub(super) key_id: String,
}

impl DynamoCibaStore {
    pub fn new(
        db: aws_sdk_dynamodb::Client,
        kms: aws_sdk_kms::Client,
        table: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Self {
        DynamoCibaStore {
            db,
            table: table.into(),
            kms,
            key_id: key_id.into(),
        }
    }
    /// 同步字段(非加密)映射;client_notification_token 的加密在 put() 里单独做(需 KMS await)。
    /// **tenant 分区(spec 020 §2.3,照 DynamoDeviceStore)**:主键 `auth_req_id` 值 tpk 化 → 按 tenant
    /// 物理隔离(空 tenant 透传单租户);额外存 `tenant` attr(from_item 读回 tenant 字段)。
    fn to_item(tenant: &str, r: &crate::ports::CibaAuthRequest) -> HashMap<String, AttributeValue> {
        let mut m = HashMap::from([
            (
                "auth_req_id".to_string(),
                AttributeValue::S(tpk(tenant, &r.auth_req_id)),
            ),
            ("tenant".to_string(), AttributeValue::S(tenant.to_string())),
            (
                "client_id".to_string(),
                AttributeValue::S(r.client_id.clone()),
            ),
            ("user_id".to_string(), AttributeValue::S(r.user_id.clone())),
            (
                "scope".to_string(),
                AttributeValue::L(r.scope.iter().cloned().map(AttributeValue::S).collect()),
            ),
            (
                "resources".to_string(),
                AttributeValue::L(r.resources.iter().cloned().map(AttributeValue::S).collect()),
            ),
            (
                "interval".to_string(),
                AttributeValue::N(r.interval.to_string()),
            ),
            (
                "expires_at".to_string(),
                AttributeValue::N(r.expires_at.to_string()),
            ),
            ("status".to_string(), AttributeValue::S(r.status.clone())),
            ("consumed".to_string(), AttributeValue::Bool(r.consumed)),
        ]);
        if let Some(sid) = &r.authz_session_id {
            m.insert(
                "authz_session_id".to_string(),
                AttributeValue::S(sid.clone()),
            );
        }
        if let Some(bm) = &r.binding_message {
            m.insert("binding_message".to_string(), AttributeValue::S(bm.clone()));
        }
        if let Some(lp) = r.last_poll_at {
            m.insert(
                "last_poll_at".to_string(),
                AttributeValue::N(lp.to_string()),
            );
        }
        // ping/push 快照(delivery_mode/endpoint 非敏感,明文;token 单独加密,见 put)。
        if let Some(dm) = &r.delivery_mode {
            m.insert("delivery_mode".to_string(), AttributeValue::S(dm.clone()));
        }
        if let Some(ep) = &r.notification_endpoint {
            m.insert(
                "notification_endpoint".to_string(),
                AttributeValue::S(ep.clone()),
            );
        }
        if let Some(version) = r.password_credential_version {
            m.insert(
                "password_credential_version".to_string(),
                AttributeValue::N(version.to_string()),
            );
        }
        m
    }
    /// 从 item 还原(client_notification_token 明文由 put 侧解密后回填;此处不含它)。
    /// strip_tpk 还原逻辑 auth_req_id(去 tenant 前缀);tenant 字段读回存的 `tenant` attr。
    fn from_item(item: &HashMap<String, AttributeValue>) -> crate::ports::CibaAuthRequest {
        crate::ports::CibaAuthRequest {
            auth_req_id: strip_tpk(&s(item.get("auth_req_id")).unwrap_or_default()),
            tenant: s(item.get("tenant")).unwrap_or_default(),
            client_id: s(item.get("client_id")).unwrap_or_default(),
            user_id: s(item.get("user_id")).unwrap_or_default(),
            authz_session_id: s(item.get("authz_session_id")),
            scope: ss(item.get("scope")),
            resources: ss(item.get("resources")),
            binding_message: s(item.get("binding_message")),
            interval: n_i64(item.get("interval")).unwrap_or(5),
            last_poll_at: n_i64(item.get("last_poll_at")),
            expires_at: n_i64(item.get("expires_at")).unwrap_or(0),
            status: s(item.get("status")).unwrap_or_default(),
            consumed: item
                .get("consumed")
                .and_then(|v| v.as_bool().ok())
                .copied()
                .unwrap_or(false),
            delivery_mode: s(item.get("delivery_mode")),
            notification_endpoint: s(item.get("notification_endpoint")),
            // 明文 token 由 get() 解密后回填(from_item 无 KMS,不在此解);put 外的 CAS 更新路径不碰它。
            client_notification_token: None,
            password_credential_version: n_u64(item.get("password_credential_version")),
        }
    }
}

/// AAD:把 client_notification_token 密文钉死在其 auth_req_id 行(既作 KMS EncryptionContext 又作 GCM AAD)。
fn ciba_token_aad(auth_req_id: &str) -> String {
    format!("ciba_notif_token|{auth_req_id}")
}

impl crate::ports::CibaStore for DynamoCibaStore {
    async fn put(&self, tenant: &str, r: crate::ports::CibaAuthRequest) -> Result<(), StoreError> {
        let mut item = Self::to_item(tenant, &r);
        // client_notification_token 信封加密(spec 013 §4:禁明文落库;独立 CMK + AES-256-GCM)。
        if let Some(tok) = &r.client_notification_token {
            use aes_gcm::aead::{Aead, KeyInit, Payload};
            use aes_gcm::{Aes256Gcm, Nonce};
            use aws_sdk_dynamodb::primitives::Blob;
            let aad = ciba_token_aad(&r.auth_req_id);
            let dk = self
                .kms
                .generate_data_key()
                .key_id(&self.key_id)
                .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
                .encryption_context("auth_req_id", &r.auth_req_id)
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
            let cipher = Aes256Gcm::new_from_slice(&plaintext_dk)
                .map_err(|e| StoreError::Permanent(format!("AES key: {e}")))?;
            let mut nonce_bytes = [0u8; 12];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
            let ct = cipher
                .encrypt(
                    Nonce::from_slice(&nonce_bytes),
                    Payload {
                        msg: tok.as_bytes(),
                        aad: aad.as_bytes(),
                    },
                )
                .map_err(|e| StoreError::Permanent(format!("AES-GCM 加密: {e}")))?;
            item.insert(
                "cnt_enc_dk".to_string(),
                AttributeValue::B(Blob::new(enc_dk)),
            );
            item.insert(
                "cnt_nonce".to_string(),
                AttributeValue::B(Blob::new(nonce_bytes.to_vec())),
            );
            item.insert("cnt_ct".to_string(), AttributeValue::B(Blob::new(ct)));
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
        auth_req_id: &str,
    ) -> Result<Option<crate::ports::CibaAuthRequest>, StoreError> {
        let out = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("auth_req_id", AttributeValue::S(tpk(tenant, auth_req_id)))
            .send()
            .await
            .map_err(ddb_err)?;
        let Some(item) = out.item() else {
            return Ok(None);
        };
        let mut rec = Self::from_item(item);
        // 解密 client_notification_token(若有密文;投递时需明文放 Authorization: Bearer)。
        if let (Some(enc_dk), Some(nonce), Some(ct)) = (
            item.get("cnt_enc_dk").and_then(|a| a.as_b().ok()),
            item.get("cnt_nonce").and_then(|a| a.as_b().ok()),
            item.get("cnt_ct").and_then(|a| a.as_b().ok()),
        ) {
            use aes_gcm::aead::{Aead, KeyInit, Payload};
            use aes_gcm::{Aes256Gcm, Nonce};
            let aad = ciba_token_aad(auth_req_id);
            let dec = self
                .kms
                .decrypt()
                .ciphertext_blob(aws_sdk_dynamodb::primitives::Blob::new(
                    enc_dk.as_ref().to_vec(),
                ))
                .encryption_context("auth_req_id", auth_req_id)
                .send()
                .await
                .map_err(|e| StoreError::Transient(format!("KMS Decrypt: {e:?}")))?;
            let plaintext_dk = dec
                .plaintext()
                .ok_or_else(|| StoreError::Permanent("KMS 未返回明文数据密钥".into()))?
                .as_ref()
                .to_vec();
            let cipher = Aes256Gcm::new_from_slice(&plaintext_dk)
                .map_err(|e| StoreError::Permanent(format!("AES key: {e}")))?;
            let pt = cipher
                .decrypt(
                    Nonce::from_slice(nonce.as_ref()),
                    Payload {
                        msg: ct.as_ref(),
                        aad: aad.as_bytes(),
                    },
                )
                .map_err(|e| StoreError::Permanent(format!("AES-GCM 解密: {e}")))?;
            rec.client_notification_token = String::from_utf8(pt).ok();
        }
        Ok(Some(rec))
    }
    async fn update(
        &self,
        tenant: &str,
        r: crate::ports::CibaAuthRequest,
    ) -> Result<(), StoreError> {
        self.put(tenant, r).await
    }
    async fn consume(&self, tenant: &str, auth_req_id: &str) -> Result<bool, StoreError> {
        // 原子 CAS(同 device):仅当未消费时置真。ConditionalCheckFailed→已消费/不存在→false。
        let res = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("auth_req_id", AttributeValue::S(tpk(tenant, auth_req_id)))
            .update_expression("SET #consumed = :t")
            .condition_expression(
                "attribute_exists(auth_req_id) \
                 AND (attribute_not_exists(#consumed) OR #consumed = :f)",
            )
            .expression_attribute_names("#consumed", "consumed")
            .expression_attribute_values(":t", AttributeValue::Bool(true))
            .expression_attribute_values(":f", AttributeValue::Bool(false))
            .send()
            .await;
        match res {
            Ok(_) => Ok(true),
            Err(e) if e.code().unwrap_or("").contains("ConditionalCheckFailed") => Ok(false),
            Err(e) => Err(ddb_err(e)),
        }
    }
    async fn claim_poll(
        &self,
        tenant: &str,
        auth_req_id: &str,
        observed_last_poll_at: Option<i64>,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut update = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("auth_req_id", AttributeValue::S(tpk(tenant, auth_req_id)))
            .update_expression("SET last_poll_at = :now")
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()));
        update = match observed_last_poll_at {
            Some(observed) => update
                .condition_expression("attribute_exists(auth_req_id) AND last_poll_at = :observed")
                .expression_attribute_values(":observed", AttributeValue::N(observed.to_string())),
            None => update.condition_expression(
                "attribute_exists(auth_req_id) AND attribute_not_exists(last_poll_at)",
            ),
        };
        let res = update.send().await;
        match res {
            Ok(_) => Ok(true),
            Err(e) if e.code().unwrap_or("").contains("ConditionalCheckFailed") => Ok(false),
            Err(e) => Err(ddb_err(e)),
        }
    }
    async fn decide(
        &self,
        tenant: &str,
        auth_req_id: &str,
        password_credential_version: Option<u64>,
        approve: bool,
    ) -> Result<bool, StoreError> {
        // 原子 CAS:仅当 status=="pending" 时转 approved/denied;不碰 consumed/last_poll_at。
        let next = if approve { "approved" } else { "denied" };
        let mut update = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("auth_req_id", AttributeValue::S(tpk(tenant, auth_req_id)))
            .update_expression(if password_credential_version.is_some() {
                "SET #status = :next, password_credential_version = :password_version"
            } else {
                "SET #status = :next"
            })
            .condition_expression("attribute_exists(auth_req_id) AND #status = :pending")
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":next", AttributeValue::S(next.to_string()))
            .expression_attribute_values(":pending", AttributeValue::S("pending".to_string()));
        if let Some(version) = password_credential_version {
            update = update.expression_attribute_values(
                ":password_version",
                AttributeValue::N(version.to_string()),
            );
        }
        let res = update.send().await;
        match res {
            Ok(_) => Ok(true),
            Err(e) if e.code().unwrap_or("").contains("ConditionalCheckFailed") => Ok(false),
            Err(e) => Err(ddb_err(e)),
        }
    }
    async fn release_consume(&self, tenant: &str, auth_req_id: &str) -> Result<(), StoreError> {
        let res = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("auth_req_id", AttributeValue::S(tpk(tenant, auth_req_id)))
            .update_expression("SET #consumed = :f")
            .condition_expression("attribute_exists(auth_req_id)")
            .expression_attribute_names("#consumed", "consumed")
            .expression_attribute_values(":f", AttributeValue::Bool(false))
            .send()
            .await;
        match res {
            Ok(_) => Ok(()),
            Err(e) if e.code().unwrap_or("").contains("ConditionalCheckFailed") => Ok(()),
            Err(e) => Err(ddb_err(e)),
        }
    }
    async fn try_arm_throttle(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
        window_secs: i64,
    ) -> Result<bool, StoreError> {
        // **原子占用**(评审 codex/Kiro M1:check+mark 合一,防并发突发绕过——分离的读-判-写下
        // N 个并发请求同读旧值全过闸)。throttle 项与真实 auth_req 同表,pk = "throttle#<user_id>"
        // (真实 auth_req_id 高熵 base64url、不含 '#',不冲突;user_id 已在 handler 归一)。
        // pk 亦 tpk 化(spec 020 §2.3:防跨租户冷却串扰)。
        // 条件写 CAS:仅当**无记录 或 上次受理 ≤ now-window(窗外)**才 SET last_authorize_at=now,
        // 成功=占用(true,放行);ConditionalCheckFailed=窗内(false,拒)。expires_at=TTL GC 兜底。
        let threshold = now - window_secs;
        let res = self
            .db
            .update_item()
            .table_name(&self.table)
            .key(
                "auth_req_id",
                AttributeValue::S(tpk(tenant, &format!("throttle#{user_id}"))),
            )
            .update_expression("SET last_authorize_at = :now, expires_at = :ttl")
            .condition_expression(
                "attribute_not_exists(last_authorize_at) OR last_authorize_at <= :threshold",
            )
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .expression_attribute_values(":ttl", AttributeValue::N((now + 3600).to_string()))
            .expression_attribute_values(":threshold", AttributeValue::N(threshold.to_string()))
            .send()
            .await;
        match res {
            Ok(_) => Ok(true), // 占用成功 → 放行
            Err(e) if e.code().unwrap_or("").contains("ConditionalCheckFailed") => Ok(false), // 窗内 → 拒
            Err(e) => Err(ddb_err(e)),
        }
    }

    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        let deleted = governance_delete_by_subject(
            &self.db,
            &self.table,
            "auth_req_id",
            tenant,
            "user_id",
            user_id,
        )
        .await?;
        self.db
            .delete_item()
            .table_name(&self.table)
            .key(
                "auth_req_id",
                AttributeValue::S(tpk(tenant, &format!("throttle#{user_id}"))),
            )
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(deleted)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        governance_delete_by_tenant_key(&self.db, &self.table, "auth_req_id", tenant).await
    }
}

/// DynamoDB device 授权存储(spec 013)。表主键 = `device_code`(S);GSI `user_code-index` 供验证页查。
#[derive(Clone)]
pub struct DynamoDeviceStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
    pub(super) user_code_index: String,
}

impl DynamoDeviceStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        DynamoDeviceStore {
            db,
            table: table.into(),
            user_code_index: "user_code-index".to_string(),
        }
    }
    fn to_item(tenant: &str, r: &crate::ports::DeviceAuthGrant) -> HashMap<String, AttributeValue> {
        // device_code(主键)+ user_code(GSI 键)均 tpk 化 → 按 tenant 物理隔离(评审 codex Medium:
        // user_code 8 位短码跨租户会碰撞,GSI 值 tpk 后 Query 天然只命中本租户)。空 tenant 透传单租户。
        let mut m = HashMap::from([
            (
                "device_code".to_string(),
                AttributeValue::S(tpk(tenant, &r.device_code)),
            ),
            (
                "user_code".to_string(),
                AttributeValue::S(tpk(tenant, &r.user_code)),
            ),
            (
                "client_id".to_string(),
                AttributeValue::S(r.client_id.clone()),
            ),
            (
                "scope".to_string(),
                AttributeValue::L(r.scope.iter().cloned().map(AttributeValue::S).collect()),
            ),
            (
                "resources".to_string(),
                AttributeValue::L(r.resources.iter().cloned().map(AttributeValue::S).collect()),
            ),
            (
                "interval".to_string(),
                AttributeValue::N(r.interval.to_string()),
            ),
            (
                "expires_at".to_string(),
                AttributeValue::N(r.expires_at.to_string()),
            ),
            ("status".to_string(), AttributeValue::S(r.status.clone())),
            ("consumed".to_string(), AttributeValue::Bool(r.consumed)),
        ]);
        if let Some(uid) = &r.user_id {
            m.insert("user_id".to_string(), AttributeValue::S(uid.clone()));
        }
        if let Some(sid) = &r.authz_session_id {
            m.insert(
                "authz_session_id".to_string(),
                AttributeValue::S(sid.clone()),
            );
        }
        if let Some(lp) = r.last_poll_at {
            m.insert(
                "last_poll_at".to_string(),
                AttributeValue::N(lp.to_string()),
            );
        }
        if let Some(version) = r.password_credential_version {
            m.insert(
                "password_credential_version".to_string(),
                AttributeValue::N(version.to_string()),
            );
        }
        m
    }
    fn from_item(item: &HashMap<String, AttributeValue>) -> crate::ports::DeviceAuthGrant {
        // strip_tpk 还原逻辑 device_code / user_code(去 tenant 前缀),调用方拿到的是逻辑值。
        crate::ports::DeviceAuthGrant {
            device_code: strip_tpk(&s(item.get("device_code")).unwrap_or_default()),
            user_code: strip_tpk(&s(item.get("user_code")).unwrap_or_default()),
            client_id: s(item.get("client_id")).unwrap_or_default(),
            user_id: s(item.get("user_id")),
            authz_session_id: s(item.get("authz_session_id")),
            scope: ss(item.get("scope")),
            resources: ss(item.get("resources")),
            interval: n_i64(item.get("interval")).unwrap_or(5),
            last_poll_at: n_i64(item.get("last_poll_at")),
            expires_at: n_i64(item.get("expires_at")).unwrap_or(0),
            status: s(item.get("status")).unwrap_or_default(),
            consumed: item
                .get("consumed")
                .and_then(|v| v.as_bool().ok())
                .copied()
                .unwrap_or(false),
            password_credential_version: n_u64(item.get("password_credential_version")),
        }
    }
}

impl crate::ports::DeviceStore for DynamoDeviceStore {
    async fn put(&self, tenant: &str, r: crate::ports::DeviceAuthGrant) -> Result<(), StoreError> {
        self.db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(Self::to_item(tenant, &r)))
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(())
    }
    async fn get(
        &self,
        tenant: &str,
        device_code: &str,
    ) -> Result<Option<crate::ports::DeviceAuthGrant>, StoreError> {
        let out = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("device_code", AttributeValue::S(tpk(tenant, device_code)))
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(out.item().map(Self::from_item))
    }
    async fn get_by_user_code(
        &self,
        tenant: &str,
        user_code: &str,
    ) -> Result<Option<crate::ports::DeviceAuthGrant>, StoreError> {
        // GSI user_code 值 tpk 化 → Query 只命中本租户(评审 codex Medium:8 位短码跨租户碰撞隔离)。
        let q = self
            .db
            .query()
            .table_name(&self.table)
            .index_name(&self.user_code_index)
            .key_condition_expression("user_code = :u")
            .expression_attribute_values(":u", AttributeValue::S(tpk(tenant, user_code)))
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(q.items().first().map(Self::from_item))
    }
    async fn update(
        &self,
        tenant: &str,
        r: crate::ports::DeviceAuthGrant,
    ) -> Result<(), StoreError> {
        self.put(tenant, r).await
    }
    async fn consume(&self, tenant: &str, device_code: &str, now: i64) -> Result<bool, StoreError> {
        // 原子 CAS(评审 HIGH):仅当 `consumed` 属性缺失或 false 时置 true。并发/重放只一个成功。
        // `consumed` 是保留字之外的普通名,但为稳妥用别名。
        let res = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("device_code", AttributeValue::S(tpk(tenant, device_code)))
            .update_expression("SET #consumed = :t")
            .condition_expression(
                "attribute_exists(device_code) \
                 AND expires_at > :now \
                 AND (attribute_not_exists(#consumed) OR #consumed = :f)",
            )
            .expression_attribute_names("#consumed", "consumed")
            .expression_attribute_values(":t", AttributeValue::Bool(true))
            .expression_attribute_values(":f", AttributeValue::Bool(false))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .send()
            .await;
        match res {
            Ok(_) => Ok(true),
            Err(e) => {
                let code = e.code().unwrap_or("");
                if code.contains("ConditionalCheckFailed") {
                    Ok(false) // 已消费/不存在 → 重放,拒签
                } else {
                    Err(ddb_err(e))
                }
            }
        }
    }
    async fn claim_poll(
        &self,
        tenant: &str,
        device_code: &str,
        observed_last_poll_at: Option<i64>,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut update = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("device_code", AttributeValue::S(tpk(tenant, device_code)))
            .update_expression("SET last_poll_at = :now")
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()));
        update = match observed_last_poll_at {
            Some(observed) => update
                .condition_expression(
                    "attribute_exists(device_code) AND expires_at > :now AND last_poll_at = :observed",
                )
                .expression_attribute_values(":observed", AttributeValue::N(observed.to_string())),
            None => update.condition_expression(
                "attribute_exists(device_code) AND expires_at > :now AND attribute_not_exists(last_poll_at)",
            ),
        };
        let res = update.send().await;
        match res {
            Ok(_) => Ok(true),
            Err(e) if e.code().unwrap_or("").contains("ConditionalCheckFailed") => Ok(false),
            Err(e) => Err(ddb_err(e)),
        }
    }
    async fn decide(
        &self,
        tenant: &str,
        device_code: &str,
        user_id: &str,
        password_credential_version: Option<u64>,
        approve: bool,
        now: i64,
    ) -> Result<bool, StoreError> {
        // 原子 CAS(评审 codex F1 二轮):仅当 status=="pending" 时转 approved/denied + 填 user_id。
        // **绝不 SET consumed**——避免旧快照整对象写重开已消费码。`status` 用别名(保留字保守起见)。
        let next = if approve { "approved" } else { "denied" };
        let mut update = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("device_code", AttributeValue::S(tpk(tenant, device_code)))
            .update_expression(if password_credential_version.is_some() {
                "SET #status = :next, user_id = :uid, password_credential_version = :password_version"
            } else {
                "SET #status = :next, user_id = :uid"
            })
            .condition_expression(
                "attribute_exists(device_code) AND expires_at > :now AND #status = :pending",
            )
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":next", AttributeValue::S(next.to_string()))
            .expression_attribute_values(":uid", AttributeValue::S(user_id.to_string()))
            .expression_attribute_values(":pending", AttributeValue::S("pending".to_string()))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()));
        if let Some(version) = password_credential_version {
            update = update.expression_attribute_values(
                ":password_version",
                AttributeValue::N(version.to_string()),
            );
        }
        let res = update.send().await;
        match res {
            Ok(_) => Ok(true),
            Err(e) if e.code().unwrap_or("").contains("ConditionalCheckFailed") => Ok(false),
            Err(e) => Err(ddb_err(e)),
        }
    }
    async fn release_consume(
        &self,
        tenant: &str,
        device_code: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        // 字段级 SET(评审 codex F1 二轮回滚):只 consumed=false;device_code 须仍存在且未过期。
        let res = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("device_code", AttributeValue::S(tpk(tenant, device_code)))
            .update_expression("SET #consumed = :f")
            .condition_expression("attribute_exists(device_code) AND expires_at > :now")
            .expression_attribute_names("#consumed", "consumed")
            .expression_attribute_values(":f", AttributeValue::Bool(false))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .send()
            .await;
        match res {
            Ok(_) => Ok(()),
            Err(e) if e.code().unwrap_or("").contains("ConditionalCheckFailed") => Ok(()),
            Err(e) => Err(ddb_err(e)),
        }
    }

    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        governance_delete_by_subject(
            &self.db,
            &self.table,
            "device_code",
            tenant,
            "user_id",
            user_id,
        )
        .await
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        governance_delete_by_tenant_key(&self.db, &self.table, "device_code", tenant).await
    }
}

/// CIBA ping/push 回调投递(spec 013 §4,C7b.5)——真机 reqwest 出站到 client 自注册 endpoint。
///
/// **SSRF 纵深防护(codex/Kiro 评审 Blocker/H1)**:
/// - 投递**前**用 `agent_auth_ciba::validate_endpoint_url` 复核 URL 结构(https/端口/非字面私网);
/// - `tokio::net::lookup_host` 解析所有 IP,`resolved_ips_allowed` 复校(防 **DNS rebinding**:注册时公网、
///   投递时 rebind 内网);任一非公网 → `BlockedBySsrf`(**不发出请求**);
/// - **连接固定到已校验 IP**(消除 TOCTOU):per-request `reqwest::Client` 用 `.resolve_to_addrs(host, &[ip])`
///   把该 host 钉死到刚校验的 IP,**不给 reqwest 二次 DNS 解析的窗**;
/// - `redirect::Policy::none()`(禁 30x 跳内网);≤5s 超时。
///
/// 失败区分:SSRF 复校拒 = `BlockedBySsrf`(未发出,token 安全);已发出后失败 = `Failed`(模糊态)。
#[derive(Clone, Default)]
pub struct HttpCibaCallbackDelivery;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinnedHttpsClientError {
    UnsafeTarget,
    DnsResolution,
    ClientBuild,
}

const PINNED_DNS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const PINNED_MAX_RESOLVED_ADDRESSES: usize = 16;

pub(crate) fn pinned_https_client_builder_for_addrs(
    host: &str,
    addrs: &[std::net::SocketAddr],
    timeout: std::time::Duration,
) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(3))
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, addrs)
        .no_proxy()
}

fn pinned_https_client_for_addrs(
    host: &str,
    addrs: &[std::net::SocketAddr],
    timeout: std::time::Duration,
) -> Result<reqwest::Client, PinnedHttpsClientError> {
    if addrs.len() > PINNED_MAX_RESOLVED_ADDRESSES {
        return Err(PinnedHttpsClientError::DnsResolution);
    }
    let ips = addrs.iter().map(|address| address.ip()).collect::<Vec<_>>();
    if !agent_auth_ciba::resolved_ips_allowed(&ips) {
        return Err(PinnedHttpsClientError::UnsafeTarget);
    }
    pinned_https_client_builder_for_addrs(host, addrs, timeout)
        .build()
        .map_err(|_| PinnedHttpsClientError::ClientBuild)
}

/// Build a direct HTTPS client whose connection is pinned to the exact public
/// IP set validated immediately before the request. Shared by every
/// receiver-controlled outbound callback so CIBA and SSF cannot drift onto
/// different SSRF policies.
pub(crate) async fn pinned_https_client(
    endpoint: &str,
    timeout: std::time::Duration,
) -> Result<reqwest::Client, PinnedHttpsClientError> {
    let started_at = std::time::Instant::now();
    if agent_auth_ciba::validate_endpoint_url(endpoint, None).is_err() {
        return Err(PinnedHttpsClientError::UnsafeTarget);
    }
    let url = reqwest::Url::parse(endpoint).map_err(|_| PinnedHttpsClientError::UnsafeTarget)?;
    let host = url
        .host_str()
        .ok_or(PinnedHttpsClientError::UnsafeTarget)?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs: Vec<std::net::SocketAddr> = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        vec![std::net::SocketAddr::new(ip, port)]
    } else {
        let resolved = tokio::time::timeout(
            std::cmp::min(timeout, PINNED_DNS_TIMEOUT),
            tokio::net::lookup_host((host.as_str(), port)),
        )
        .await
        .map_err(|_| PinnedHttpsClientError::DnsResolution)?
        .map_err(|_| PinnedHttpsClientError::DnsResolution)?;
        let addrs = resolved
            .take(PINNED_MAX_RESOLVED_ADDRESSES + 1)
            .collect::<Vec<_>>();
        if addrs.len() > PINNED_MAX_RESOLVED_ADDRESSES {
            return Err(PinnedHttpsClientError::DnsResolution);
        }
        addrs
    };

    let request_timeout = timeout
        .checked_sub(started_at.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(PinnedHttpsClientError::DnsResolution)?;
    pinned_https_client_for_addrs(&host, &addrs, request_timeout)
}

impl HttpCibaCallbackDelivery {
    pub fn new() -> Self {
        HttpCibaCallbackDelivery
    }
}

impl crate::ports::CibaCallbackDelivery for HttpCibaCallbackDelivery {
    async fn deliver(
        &self,
        req: crate::ports::CibaCallbackRequest,
    ) -> crate::ports::CibaDeliveryOutcome {
        use crate::ports::CibaDeliveryOutcome as O;
        let client = match pinned_https_client(
            &req.notification_endpoint,
            std::time::Duration::from_secs(5),
        )
        .await
        {
            Ok(client) => client,
            Err(PinnedHttpsClientError::ClientBuild) => return O::Failed,
            Err(PinnedHttpsClientError::UnsafeTarget | PinnedHttpsClientError::DnsResolution) => {
                return O::BlockedBySsrf
            }
        };
        match client
            .post(&req.notification_endpoint)
            .bearer_auth(&req.client_notification_token)
            .json(&req.body)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => O::Delivered,
            // 已发出请求但非 2xx / 网络失败 → 模糊态(handler 对 push 视为已消费终态)。
            Ok(_) | Err(_) => O::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        pinned_https_client_for_addrs, DynamoCibaStore, DynamoDeviceStore, PinnedHttpsClientError,
        PINNED_MAX_RESOLVED_ADDRESSES,
    };
    use crate::ports::{CibaStore, DeviceStore};
    use aws_smithy_http_client::test_util::{ReplayEvent, StaticReplayClient};
    use aws_smithy_types::body::SdkBody;
    use serde_json::Value;

    fn response(status: u16, body: &str) -> axum::http::Response<SdkBody> {
        let mut builder = axum::http::Response::builder()
            .status(status)
            .header("content-type", "application/x-amz-json-1.0");
        if status >= 400 {
            builder = builder.header("x-amzn-errortype", "ConditionalCheckFailedException");
        }
        builder.body(SdkBody::from(body)).unwrap()
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

    fn kms_client() -> aws_sdk_kms::Client {
        aws_sdk_kms::Client::from_conf(
            aws_sdk_kms::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_kms::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_kms::config::Credentials::for_tests())
                .endpoint_url("https://kms.us-east-1.amazonaws.com")
                .build(),
        )
    }

    #[tokio::test]
    async fn dynamo_poll_claims_bind_the_observed_timestamp() {
        let http = StaticReplayClient::new(vec![
            ReplayEvent::new(placeholder_request(), response(200, "{}")),
            ReplayEvent::new(placeholder_request(), response(200, "{}")),
            ReplayEvent::new(
                placeholder_request(),
                response(
                    400,
                    r#"{"__type":"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException","message":"CIBA poll already claimed"}"#,
                ),
            ),
            ReplayEvent::new(placeholder_request(), response(200, "{}")),
            ReplayEvent::new(
                placeholder_request(),
                response(
                    400,
                    r#"{"__type":"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException","message":"poll already claimed"}"#,
                ),
            ),
        ]);
        let ciba = DynamoCibaStore::new(dynamo_client(http.clone()), kms_client(), "ciba", "key-1");
        assert!(ciba
            .claim_poll("tenant-1", "auth-1", None, 1_000)
            .await
            .unwrap());
        assert!(ciba
            .claim_poll("tenant-1", "auth-1", Some(1_000), 1_005)
            .await
            .unwrap());
        assert!(!ciba
            .claim_poll("tenant-1", "auth-1", Some(1_000), 1_005)
            .await
            .unwrap());
        let device = DynamoDeviceStore::new(dynamo_client(http.clone()), "device");
        assert!(device
            .claim_poll("tenant-1", "device-1", None, 1_000)
            .await
            .unwrap());
        assert!(!device
            .claim_poll("tenant-1", "device-1", Some(1_000), 1_005)
            .await
            .unwrap());

        let requests: Vec<_> = http.actual_requests().collect();
        assert_eq!(requests.len(), 5);
        let ciba_first: Value =
            serde_json::from_slice(requests[0].body().bytes().unwrap()).unwrap();
        assert_eq!(
            ciba_first["ConditionExpression"],
            "attribute_exists(auth_req_id) AND attribute_not_exists(last_poll_at)"
        );
        let ciba_next: Value = serde_json::from_slice(requests[1].body().bytes().unwrap()).unwrap();
        assert_eq!(
            ciba_next["ConditionExpression"],
            "attribute_exists(auth_req_id) AND last_poll_at = :observed"
        );
        assert_eq!(
            ciba_next["ExpressionAttributeValues"][":observed"]["N"],
            "1000"
        );
        let ciba_conflict: Value =
            serde_json::from_slice(requests[2].body().bytes().unwrap()).unwrap();
        assert_eq!(
            ciba_conflict["ConditionExpression"],
            "attribute_exists(auth_req_id) AND last_poll_at = :observed"
        );
        assert_eq!(
            ciba_conflict["ExpressionAttributeValues"][":observed"]["N"],
            "1000"
        );
        let device_first: Value =
            serde_json::from_slice(requests[3].body().bytes().unwrap()).unwrap();
        assert_eq!(
            device_first["ConditionExpression"],
            "attribute_exists(device_code) AND expires_at > :now AND attribute_not_exists(last_poll_at)"
        );
        let device_conflict: Value =
            serde_json::from_slice(requests[4].body().bytes().unwrap()).unwrap();
        assert_eq!(
            device_conflict["ConditionExpression"],
            "attribute_exists(device_code) AND expires_at > :now AND last_poll_at = :observed"
        );
        assert_eq!(
            device_conflict["ExpressionAttributeValues"][":observed"]["N"],
            "1000"
        );
    }

    #[tokio::test]
    async fn dynamo_device_writes_atomically_fence_expiry() {
        let http = StaticReplayClient::new(vec![
            ReplayEvent::new(placeholder_request(), response(200, "{}")),
            ReplayEvent::new(placeholder_request(), response(200, "{}")),
            ReplayEvent::new(placeholder_request(), response(200, "{}")),
        ]);
        let device = DynamoDeviceStore::new(dynamo_client(http.clone()), "device");
        assert!(device
            .consume("tenant-1", "device-consume", 1_000)
            .await
            .unwrap());
        assert!(device
            .decide("tenant-1", "device-decide", "user-1", Some(7), true, 1_000,)
            .await
            .unwrap());
        device
            .release_consume("tenant-1", "device-release", 1_000)
            .await
            .unwrap();

        let requests: Vec<_> = http.actual_requests().collect();
        assert_eq!(requests.len(), 3);
        let consume: Value = serde_json::from_slice(requests[0].body().bytes().unwrap()).unwrap();
        assert_eq!(
            consume["ConditionExpression"],
            "attribute_exists(device_code) AND expires_at > :now AND (attribute_not_exists(#consumed) OR #consumed = :f)"
        );
        assert_eq!(consume["ExpressionAttributeValues"][":now"]["N"], "1000");

        let decide: Value = serde_json::from_slice(requests[1].body().bytes().unwrap()).unwrap();
        assert_eq!(
            decide["ConditionExpression"],
            "attribute_exists(device_code) AND expires_at > :now AND #status = :pending"
        );
        assert_eq!(decide["ExpressionAttributeValues"][":now"]["N"], "1000");

        let release: Value = serde_json::from_slice(requests[2].body().bytes().unwrap()).unwrap();
        assert_eq!(
            release["ConditionExpression"],
            "attribute_exists(device_code) AND expires_at > :now"
        );
        assert_eq!(release["ExpressionAttributeValues"][":now"]["N"], "1000");
    }

    #[test]
    fn pinned_client_rejects_mixed_public_private_dns_answer() {
        let public = "8.8.8.8:443".parse().unwrap();
        let private = "10.0.0.1:443".parse().unwrap();
        let loopback = "127.0.0.1:443".parse().unwrap();
        let link_local = "169.254.169.254:443".parse().unwrap();
        let ipv6_loopback = "[::1]:443".parse().unwrap();
        assert!(pinned_https_client_for_addrs(
            "client.example.com",
            &[public],
            std::time::Duration::from_secs(1),
        )
        .is_ok());
        assert_eq!(
            pinned_https_client_for_addrs(
                "client.example.com",
                &[public, private],
                std::time::Duration::from_secs(1),
            )
            .unwrap_err(),
            PinnedHttpsClientError::UnsafeTarget,
        );
        for blocked in [private, loopback, link_local, ipv6_loopback] {
            assert_eq!(
                pinned_https_client_for_addrs(
                    "client.example.com",
                    &[blocked],
                    std::time::Duration::from_secs(1),
                )
                .unwrap_err(),
                PinnedHttpsClientError::UnsafeTarget,
            );
        }
        assert_eq!(
            pinned_https_client_for_addrs(
                "client.example.com",
                &vec![public; PINNED_MAX_RESOLVED_ADDRESSES + 1],
                std::time::Duration::from_secs(1),
            )
            .unwrap_err(),
            PinnedHttpsClientError::DnsResolution,
        );
    }
}

#[cfg(test)]
mod ciba_delivery_tests {
    use super::HttpCibaCallbackDelivery;
    use crate::ports::{CibaCallbackDelivery, CibaCallbackRequest, CibaDeliveryOutcome as O};

    fn req(endpoint: &str) -> CibaCallbackRequest {
        CibaCallbackRequest {
            notification_endpoint: endpoint.to_string(),
            client_notification_token: "cnt-0123456789abcdef0123456789abcdef".to_string(),
            body: serde_json::json!({ "auth_req_id": "ar-test" }),
        }
    }

    // 评审 Kiro H1:真机 adapter 的 SSRF/钉死路径必须有测试(此前全走 Memory mock,核心裸奔)。
    // 字面私网 IP:validate_endpoint_url 结构层即拒(未发出)。
    #[tokio::test]
    async fn literal_private_ip_blocked() {
        let d = HttpCibaCallbackDelivery::new();
        assert_eq!(
            d.deliver(req("https://127.0.0.1/cb")).await,
            O::BlockedBySsrf
        );
        assert_eq!(
            d.deliver(req("https://169.254.169.254/latest")).await,
            O::BlockedBySsrf
        );
    }

    // 评审 Kiro B1 回归:**大写 host** 走 url 规范化 → localhost 解析到 127.0.0.1 → resolved_ips_allowed 拒。
    // 关键:host 取自 url.host_str()(小写化后 = "localhost"),lookup_host 用它解析到环回 → BlockedBySsrf。
    // 若仍用 validate_endpoint_url 原始切片("LOCALHOST"),lookup_host 大小写不敏感仍解析,但连接键会与
    // reqwest 规范化键不匹配——此测试确保规范化 host 一致贯穿 lookup + pin(不回退 resolver)。
    #[tokio::test]
    async fn uppercase_host_resolving_to_loopback_blocked() {
        let d = HttpCibaCallbackDelivery::new();
        // LOCALHOST(大写)→ url 规范化 localhost → 解析 127.0.0.1/::1 → 私网复校拒。
        assert_eq!(
            d.deliver(req("https://LOCALHOST/cb")).await,
            O::BlockedBySsrf,
            "大写 host 经规范化解析到环回应拒(B1 回归:规范化 host 贯穿 lookup+pin)"
        );
    }

    // 非 https / 非 443 端口 / userinfo 混淆:结构层拒(未发出)。
    #[tokio::test]
    async fn structural_rejects_blocked() {
        let d = HttpCibaCallbackDelivery::new();
        for ep in [
            "http://example.com/cb",
            "https://example.com:8080/cb",
            "https://evil.com@169.254.169.254/x",
        ] {
            assert_eq!(d.deliver(req(ep)).await, O::BlockedBySsrf, "{ep} 应拒");
        }
    }
}
