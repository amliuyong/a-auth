//! AWS client registration and DCR adapters.

use super::*;

const TOUCH_LAST_USED_UPDATE_EXPRESSION: &str = "SET last_used_day = :today";
const TOUCH_LAST_USED_CONDITION_EXPRESSION: &str = "attribute_exists(client_id) AND \
     (attribute_not_exists(last_used_day) OR last_used_day < :today)";

/// DynamoDB 客户端存储。表主键 = `client_id`(S)。
#[derive(Clone)]
pub struct DynamoClientStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
}

impl DynamoClientStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        DynamoClientStore {
            db,
            table: table.into(),
        }
    }

    fn item_to_client(item: &HashMap<String, AttributeValue>) -> ClientRecord {
        ClientRecord {
            // 物理 pk 可能带 tenant 前缀(`{tenant}\x1f{client_id}`)→ strip 回逻辑 client_id
            // (空 tenant 存的旧值无前缀,strip 原样返回;flag 关时零变化)。
            client_id: strip_tpk(&s(item.get("client_id")).unwrap_or_default()),
            redirect_uris: ss(item.get("redirect_uris")),
            application_type: s(item.get("application_type")),
            token_endpoint_auth_method: s(item.get("token_endpoint_auth_method"))
                .unwrap_or_else(|| "none".to_string()),
            client_secret: s(item.get("client_secret")),
            client_secret_credentials: json_from_attr(item.get("client_secret_credentials"))
                .unwrap_or_default(),
            jwks: item.get("jwks").and_then(registered_jwks_from_attr),
            jwks_uri: s(item.get("jwks_uri")),
            token_endpoint_auth_signing_alg: s(item.get("token_endpoint_auth_signing_alg")),
            default_resource: s(item.get("default_resource")),
            introspect_enabled: item
                .get("introspect_enabled")
                .and_then(|a| a.as_bool().ok())
                .copied()
                .unwrap_or(false),
            resource_ids: ss(item.get("resource_ids")),
            post_logout_redirect_uris: ss(item.get("post_logout_redirect_uris")),
            reg_token_hash: s(item.get("reg_token_hash")),
            registration_token_credentials: json_from_attr(
                item.get("registration_token_credentials"),
            )
            .unwrap_or_default(),
            client_type: s(item.get("client_type")),
            id_token_signed_response_alg: s(item.get("id_token_signed_response_alg")),
            oidc_sector_identifier: s(item.get("oidc_sector_identifier")),
            allowed_resources: ss(item.get("allowed_resources")),
            allowed_scopes: ss(item.get("allowed_scopes")),
            redirect_mode: s(item.get("redirect_mode")),
            // 回收元数据(spec 005 §9,C10.5):旧记录缺 → 0/None(不参与判定,向后兼容)。
            created_at: n_i64(item.get("created_at")).unwrap_or(0),
            last_used_day: n_i64(item.get("last_used_day")),
            authority_revision: n_u64(item.get("authority_revision")).unwrap_or(0),
            tombstoned_at: n_i64(item.get("tombstoned_at")),
            // CIBA 投递模式(spec 013 §4;稀疏属性,旧记录/poll client 缺 → None=poll)。
            backchannel_token_delivery_mode: s(item.get("backchannel_token_delivery_mode")),
            backchannel_client_notification_endpoint: s(
                item.get("backchannel_client_notification_endpoint")
            ),
            // require DPoP(spec 010 §5.2;旧记录缺 → false=opt-in,后向兼容)。
            require_dpop: item
                .get("require_dpop")
                .and_then(|a| a.as_bool().ok())
                .copied()
                .unwrap_or(false),
            // BYOD 已登记域名(spec 010 §5.4;旧记录缺 → 空,后向兼容)。
            prm_domains: ss(item.get("prm_domains")),
        }
    }

    fn client_to_item(
        tenant: &str,
        r: ClientRecord,
    ) -> Result<HashMap<String, AttributeValue>, StoreError> {
        let mut item = HashMap::from([
            (
                "client_id".to_string(),
                AttributeValue::S(tpk(tenant, &r.client_id)),
            ),
            (
                "redirect_uris".to_string(),
                AttributeValue::L(r.redirect_uris.into_iter().map(AttributeValue::S).collect()),
            ),
            (
                "token_endpoint_auth_method".to_string(),
                AttributeValue::S(r.token_endpoint_auth_method),
            ),
        ]);
        if let Some(sec) = r.client_secret {
            item.insert("client_secret".to_string(), AttributeValue::S(sec));
        }
        if let Some(application_type) = r.application_type {
            item.insert(
                "application_type".to_string(),
                AttributeValue::S(application_type),
            );
        }
        if r.client_secret_credentials != crate::credential::CredentialSet::default() {
            item.insert(
                "client_secret_credentials".to_string(),
                json_attr(&r.client_secret_credentials)?,
            );
            item.insert(
                "client_secret_credentials_version".to_string(),
                AttributeValue::N(r.client_secret_credentials.version.to_string()),
            );
        }
        if let Some(jwks) = r.jwks {
            item.insert("jwks".to_string(), registered_jwks_to_attr(jwks));
        }
        if let Some(uri) = r.jwks_uri {
            item.insert("jwks_uri".to_string(), AttributeValue::S(uri));
        }
        if let Some(alg) = r.token_endpoint_auth_signing_alg {
            item.insert(
                "token_endpoint_auth_signing_alg".to_string(),
                AttributeValue::S(alg),
            );
        }
        if let Some(dr) = r.default_resource {
            item.insert("default_resource".to_string(), AttributeValue::S(dr));
        }
        if r.introspect_enabled {
            item.insert("introspect_enabled".to_string(), AttributeValue::Bool(true));
        }
        if !r.resource_ids.is_empty() {
            item.insert(
                "resource_ids".to_string(),
                AttributeValue::L(r.resource_ids.into_iter().map(AttributeValue::S).collect()),
            );
        }
        if !r.post_logout_redirect_uris.is_empty() {
            item.insert(
                "post_logout_redirect_uris".to_string(),
                AttributeValue::L(
                    r.post_logout_redirect_uris
                        .into_iter()
                        .map(AttributeValue::S)
                        .collect(),
                ),
            );
        }
        if let Some(h) = r.reg_token_hash {
            item.insert("reg_token_hash".to_string(), AttributeValue::S(h));
        }
        if r.registration_token_credentials != crate::credential::CredentialSet::default() {
            item.insert(
                "registration_token_credentials".to_string(),
                json_attr(&r.registration_token_credentials)?,
            );
            item.insert(
                "registration_token_credentials_version".to_string(),
                AttributeValue::N(r.registration_token_credentials.version.to_string()),
            );
        }
        if let Some(ct) = r.client_type {
            item.insert("client_type".to_string(), AttributeValue::S(ct));
        }
        if let Some(alg) = r.id_token_signed_response_alg {
            item.insert(
                "id_token_signed_response_alg".to_string(),
                AttributeValue::S(alg),
            );
        }
        if let Some(sec) = r.oidc_sector_identifier {
            item.insert("oidc_sector_identifier".to_string(), AttributeValue::S(sec));
        }
        if !r.allowed_resources.is_empty() {
            item.insert(
                "allowed_resources".to_string(),
                AttributeValue::L(
                    r.allowed_resources
                        .into_iter()
                        .map(AttributeValue::S)
                        .collect(),
                ),
            );
        }
        if !r.allowed_scopes.is_empty() {
            item.insert(
                "allowed_scopes".to_string(),
                AttributeValue::L(
                    r.allowed_scopes
                        .into_iter()
                        .map(AttributeValue::S)
                        .collect(),
                ),
            );
        }
        if let Some(rm) = r.redirect_mode {
            item.insert("redirect_mode".to_string(), AttributeValue::S(rm));
        }
        if r.created_at != 0 {
            item.insert(
                "created_at".to_string(),
                AttributeValue::N(r.created_at.to_string()),
            );
        }
        if let Some(day) = r.last_used_day {
            item.insert(
                "last_used_day".to_string(),
                AttributeValue::N(day.to_string()),
            );
        }
        if r.authority_revision != 0 {
            item.insert(
                "authority_revision".to_string(),
                AttributeValue::N(r.authority_revision.to_string()),
            );
        }
        if let Some(ts) = r.tombstoned_at {
            item.insert(
                "tombstoned_at".to_string(),
                AttributeValue::N(ts.to_string()),
            );
        }
        if let Some(mode) = r.backchannel_token_delivery_mode {
            item.insert(
                "backchannel_token_delivery_mode".to_string(),
                AttributeValue::S(mode),
            );
        }
        if let Some(ep) = r.backchannel_client_notification_endpoint {
            item.insert(
                "backchannel_client_notification_endpoint".to_string(),
                AttributeValue::S(ep),
            );
        }
        if r.require_dpop {
            item.insert("require_dpop".to_string(), AttributeValue::Bool(true));
        }
        if !r.prm_domains.is_empty() {
            item.insert(
                "prm_domains".to_string(),
                AttributeValue::L(r.prm_domains.into_iter().map(AttributeValue::S).collect()),
            );
        }
        Ok(item)
    }

    async fn all_clients_for_migration(&self) -> Result<Vec<(String, ClientRecord)>, StoreError> {
        let mut clients = Vec::new();
        let mut last_key = None;
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
                let Some(physical) = s(item.get("client_id")) else {
                    continue;
                };
                if strip_tpk(&physical).starts_with("reclaim-audit#") {
                    continue;
                }
                clients.push((tenant_from_tpk(&physical), Self::item_to_client(item)));
            }
            match output.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        Ok(clients)
    }

    fn legacy_migration_replacement(
        client: &ClientRecord,
        kind: crate::credential::CredentialKind,
        tenant: &str,
        server_secret: &[u8],
        now: i64,
    ) -> Result<Option<(u64, crate::credential::CredentialSet)>, StoreError> {
        let (legacy_value, existing, ttl) = match kind {
            crate::credential::CredentialKind::ClientSecret => (
                client.client_secret.as_deref(),
                &client.client_secret_credentials,
                crate::credential::DEFAULT_CLIENT_SECRET_TTL_SECS,
            ),
            crate::credential::CredentialKind::RegistrationAccessToken => (
                client.reg_token_hash.as_deref(),
                &client.registration_token_credentials,
                crate::credential::DEFAULT_REGISTRATION_TOKEN_TTL_SECS,
            ),
            crate::credential::CredentialKind::InitialAccessToken => return Ok(None),
        };
        let Some(legacy_value) = legacy_value else {
            return Ok(None);
        };
        let expected_version = existing.version;
        let next_version = expected_version.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("legacy credential migration version overflow".into())
        })?;

        // A versioned lifecycle record is authoritative. Remove only the redundant legacy field
        // while bumping the version so a stale whole-record writer cannot reintroduce plaintext.
        if expected_version > 0 || existing.has_credential_state() {
            let mut replacement = existing.clone();
            replacement.version = next_version;
            return Ok(Some((expected_version, replacement)));
        }

        let created_at = if client.created_at > 0 {
            client.created_at
        } else {
            now
        };
        let expires_at = now.checked_add(ttl).ok_or_else(|| {
            StoreError::Permanent("legacy credential migration expiry overflow".into())
        })?;
        let current = match kind {
            crate::credential::CredentialKind::ClientSecret => {
                crate::credential::new_credential_record(
                    server_secret,
                    kind,
                    tenant,
                    format!("cred_{}", crate::register::rand_token(12)),
                    client.client_id.clone(),
                    legacy_value,
                    created_at,
                    expires_at,
                    "system:legacy-migration".into(),
                    None,
                )
            }
            crate::credential::CredentialKind::RegistrationAccessToken => {
                crate::credential::CredentialRecord {
                    credential_id: format!("cred_{}", crate::register::rand_token(12)),
                    owner: client.client_id.clone(),
                    verifier: legacy_value.to_string(),
                    verifier_version: crate::credential::VerifierVersion::LegacyRegistrationTokenV0,
                    created_at,
                    expires_at,
                    status: crate::credential::CredentialStatus::Active,
                    audit_identity: "system:legacy-migration".into(),
                    rotation_request_id: None,
                }
            }
            crate::credential::CredentialKind::InitialAccessToken => unreachable!(),
        };
        Ok(Some((
            expected_version,
            crate::credential::CredentialSet {
                current: Some(current),
                version: next_version,
                ..Default::default()
            },
        )))
    }

    async fn migrate_legacy_credential(
        &self,
        tenant: &str,
        client_id: &str,
        kind: crate::credential::CredentialKind,
        server_secret: &[u8],
        now: i64,
    ) -> Result<bool, StoreError> {
        for _ in 0..3 {
            let Some(client) = self.get(tenant, client_id).await? else {
                return Ok(false);
            };
            let Some((expected_version, replacement)) =
                Self::legacy_migration_replacement(&client, kind, tenant, server_secret, now)?
            else {
                return Ok(false);
            };
            if self
                .replace_credential_set(tenant, client_id, kind, expected_version, replacement)
                .await?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// One-time migration for every row in the Clients table, including retained historical
    /// tenant partitions. Each write is version-CAS guarded and the final strong scan fails unless
    /// all directly usable legacy fields have been removed.
    pub async fn migrate_legacy_credentials(
        &self,
        server_secret: &[u8],
        now: i64,
    ) -> Result<usize, StoreError> {
        let mut migrated = 0usize;
        for (tenant, client) in self.all_clients_for_migration().await? {
            for kind in [
                crate::credential::CredentialKind::ClientSecret,
                crate::credential::CredentialKind::RegistrationAccessToken,
            ] {
                if self
                    .migrate_legacy_credential(&tenant, &client.client_id, kind, server_secret, now)
                    .await?
                {
                    migrated += 1;
                }
            }
        }

        let remaining = self
            .all_clients_for_migration()
            .await?
            .into_iter()
            .filter(|(_tenant, client)| {
                client.client_secret.is_some() || client.reg_token_hash.is_some()
            })
            .count();
        if remaining > 0 {
            return Err(StoreError::Permanent(format!(
                "legacy credential migration incomplete: {remaining} client rows retain legacy fields"
            )));
        }
        Ok(migrated)
    }
}

impl ClientStore for DynamoClientStore {
    async fn get(&self, tenant: &str, client_id: &str) -> Result<Option<ClientRecord>, StoreError> {
        let out = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("client_id", AttributeValue::S(tpk(tenant, client_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(out.item().map(Self::item_to_client))
    }

    async fn put(&self, tenant: &str, r: ClientRecord) -> Result<(), StoreError> {
        // 物理 pk = tpk(tenant, client_id);读回时 item_to_client 用 strip_tpk 还原逻辑 client_id。
        let item = Self::client_to_item(tenant, r)?;
        self.db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(())
    }

    async fn put_if_credential_versions(
        &self,
        tenant: &str,
        record: ClientRecord,
        expected_client_secret_version: u64,
        expected_registration_token_version: u64,
    ) -> Result<bool, StoreError> {
        let expected_authority_revision = record.authority_revision;
        let expected_last_used_day = record.last_used_day;
        let item = Self::client_to_item(tenant, record)?;
        let client_condition = if expected_client_secret_version == 0 {
            "attribute_not_exists(#client_version)"
        } else {
            "#client_version = :client_version"
        };
        let registration_condition = if expected_registration_token_version == 0 {
            "attribute_not_exists(#registration_version)"
        } else {
            "#registration_version = :registration_version"
        };
        let authority_condition = if expected_authority_revision == 0 {
            "(attribute_not_exists(authority_revision) OR \
             authority_revision = :authority_revision)"
        } else {
            "authority_revision = :authority_revision"
        };
        let last_used_condition = if expected_last_used_day.is_some() {
            "last_used_day = :last_used_day"
        } else {
            "attribute_not_exists(last_used_day)"
        };
        let mut put = self
            .db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression(format!(
                "attribute_exists(client_id) AND attribute_not_exists(tombstoned_at) AND \
                 {client_condition} AND {registration_condition} AND {authority_condition} AND \
                 {last_used_condition}"
            ))
            .expression_attribute_names("#client_version", "client_secret_credentials_version")
            .expression_attribute_names(
                "#registration_version",
                "registration_token_credentials_version",
            )
            .expression_attribute_values(
                ":authority_revision",
                AttributeValue::N(expected_authority_revision.to_string()),
            );
        if let Some(expected_last_used_day) = expected_last_used_day {
            put = put.expression_attribute_values(
                ":last_used_day",
                AttributeValue::N(expected_last_used_day.to_string()),
            );
        }
        if expected_client_secret_version != 0 {
            put = put.expression_attribute_values(
                ":client_version",
                AttributeValue::N(expected_client_secret_version.to_string()),
            );
        }
        if expected_registration_token_version != 0 {
            put = put.expression_attribute_values(
                ":registration_version",
                AttributeValue::N(expected_registration_token_version.to_string()),
            );
        }
        match put.send().await {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|service| service.is_conditional_check_failed_exception()) =>
            {
                Ok(false)
            }
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn replace_credential_set(
        &self,
        tenant: &str,
        client_id: &str,
        kind: crate::credential::CredentialKind,
        expected_version: u64,
        credentials: crate::credential::CredentialSet,
    ) -> Result<bool, StoreError> {
        let (credentials_attr, version_attr, legacy_attr) = match kind {
            crate::credential::CredentialKind::ClientSecret => (
                "client_secret_credentials",
                "client_secret_credentials_version",
                "client_secret",
            ),
            crate::credential::CredentialKind::RegistrationAccessToken => (
                "registration_token_credentials",
                "registration_token_credentials_version",
                "reg_token_hash",
            ),
            crate::credential::CredentialKind::InitialAccessToken => return Ok(false),
        };
        let condition = if expected_version == 0 {
            "attribute_exists(client_id) AND \
             attribute_not_exists(tombstoned_at) AND \
             (attribute_not_exists(#version) OR #version = :expected)"
        } else {
            "attribute_exists(client_id) AND attribute_not_exists(tombstoned_at) AND \
             #version = :expected"
        };
        let update = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("client_id", AttributeValue::S(tpk(tenant, client_id)))
            .update_expression(
                "SET #credentials = :credentials, #version = :version REMOVE #legacy",
            )
            .condition_expression(condition)
            .expression_attribute_names("#credentials", credentials_attr)
            .expression_attribute_names("#version", version_attr)
            .expression_attribute_names("#legacy", legacy_attr)
            .expression_attribute_values(":credentials", json_attr(&credentials)?)
            .expression_attribute_values(
                ":version",
                AttributeValue::N(credentials.version.to_string()),
            )
            .expression_attribute_values(
                ":expected",
                AttributeValue::N(expected_version.to_string()),
            );
        match update.send().await {
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

    async fn list(&self, tenant: &str) -> Result<Vec<ClientRecord>, StoreError> {
        // P1:分页 Scan 全量;按 client_id 字典序稳定(量大改 GSI,见 spec 020)。
        // **tenant 隔离**:Scan 全表后按物理 pk 的 tenant 前缀过滤(空 tenant = 现网单租户全量;
        // 非空 = 仅该租户;主表 pk 前缀天然分隔)。P1 admin 列表量小可接受;量大改 Query by tenant。
        let mut out = Vec::new();
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        let want_prefix = if tenant.is_empty() {
            None
        } else {
            Some(format!("{tenant}\u{1f}"))
        };
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
                let phys = s(item.get("client_id")).unwrap_or_default();
                // 跳过审计行(逻辑 pk=`reclaim-audit#...`,非 client;strip 掉可能的 tenant 前缀后判)。
                if strip_tpk(&phys).starts_with("reclaim-audit#") {
                    continue;
                }
                match &want_prefix {
                    // 非空 tenant:只收本租户前缀的行。
                    Some(p) if !phys.starts_with(p.as_str()) => continue,
                    // 空 tenant(现网单租户):只收**无前缀**行(不含他租户 `t\x1f*`,防跨租户串)。
                    None if phys.contains('\u{1f}') => continue,
                    _ => {}
                }
                out.push(Self::item_to_client(item));
            }
            match scan.last_evaluated_key() {
                Some(k) if !k.is_empty() => last_key = Some(k.clone()),
                _ => break,
            }
        }
        out.sort_by(|a, b| a.client_id.cmp(&b.client_id));
        Ok(out)
    }

    async fn delete(&self, tenant: &str, client_id: &str) -> Result<(), StoreError> {
        self.db
            .delete_item()
            .table_name(&self.table)
            .key("client_id", AttributeValue::S(tpk(tenant, client_id)))
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(())
    }

    async fn touch_last_used(
        &self,
        tenant: &str,
        client_id: &str,
        today: i64,
    ) -> Result<(), StoreError> {
        // 条件 UpdateItem:仅当缺失或 < today 才写(同日仅一次,防热路径写放大,spec 005 §9.2)。
        // ConditionalCheckFailed = 今天已记(常态),视作 Ok(无写)。client 不存在也不建(client 必先存)。
        let res = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("client_id", AttributeValue::S(tpk(tenant, client_id)))
            .update_expression(TOUCH_LAST_USED_UPDATE_EXPRESSION)
            .condition_expression(TOUCH_LAST_USED_CONDITION_EXPRESSION)
            .expression_attribute_values(":today", AttributeValue::N(today.to_string()))
            .send()
            .await;
        match res {
            Ok(_) => Ok(()),
            // 今天已记 / client 不存在 → 不是错误(幂等 no-op)。
            Err(e) if e.code().unwrap_or("").contains("ConditionalCheckFailed") => Ok(()),
            Err(e) => Err(ddb_err(e)),
        }
    }

    async fn convert_to_tombstone(
        &self,
        tenant: &str,
        client_id: &str,
        tombstoned_at: i64,
        snapshot_day: Option<i64>,
        snapshot_authority_revision: u64,
    ) -> Result<bool, StoreError> {
        // 并发守卫条件写(spec 005 §9.5):仅当未 tombstone 且 last_used_day <= snapshot(扫描读快照后
        // 无并发 touch 推进)才写。条件不满足(已 tombstone / 已被并发使用)→ Ok(false) 跳过(方向安全)。
        let mut update = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("client_id", AttributeValue::S(tpk(tenant, client_id)))
            .update_expression("SET tombstoned_at = :ts")
            .expression_attribute_values(":ts", AttributeValue::N(tombstoned_at.to_string()))
            .expression_attribute_values(
                ":authority_revision",
                AttributeValue::N(snapshot_authority_revision.to_string()),
            );
        let authority_condition = if snapshot_authority_revision == 0 {
            "(attribute_not_exists(authority_revision) OR \
             authority_revision = :authority_revision)"
        } else {
            "authority_revision = :authority_revision"
        };
        // last_used_day <= snapshot:snapshot 为 None(client 从未使用)时,要求 last_used_day 也仍缺失
        // (否则期间有 touch 写了值 = 被用过 → 跳过)。有值 snapshot 则 last_used_day <= :snap。
        update = match snapshot_day {
            Some(snap) => update
                .condition_expression(format!(
                    "attribute_exists(client_id) AND attribute_not_exists(tombstoned_at) AND \
                     (attribute_not_exists(last_used_day) OR last_used_day <= :snap) AND \
                     {authority_condition}"
                ))
                .expression_attribute_values(":snap", AttributeValue::N(snap.to_string())),
            None => update.condition_expression(format!(
                "attribute_exists(client_id) AND attribute_not_exists(tombstoned_at) AND \
                 attribute_not_exists(last_used_day) AND {authority_condition}"
            )),
        };
        match update.send().await {
            Ok(_) => Ok(true),
            // 已 tombstone / 被并发 touch 推进 / client 不存在 → 跳过(fail-safe:不误回收)。
            Err(e) if e.code().unwrap_or("").contains("ConditionalCheckFailed") => Ok(false),
            Err(e) => Err(ddb_err(e)),
        }
    }

    async fn list_reclaim_candidates(
        &self,
        tenant: &str,
        older_than_day: i64,
    ) -> Result<Vec<(String, ClientRecord)>, StoreError> {
        // 走 GSI last_used_day-index(稀疏:仅有 last_used_day 的行进索引,远少于全表)。GSI pk 是 last_used_day,
        // 无法对 pk 做 <= Query,故用 GSI **Scan + Filter**(仍只扫索引投影的稀疏子集,非全主表 Scan)。
        // KEYS_ONLY 索引只投影 key(client_id[物理,可能带 tenant 前缀] + last_used_day)→ 命中后回主表取全记录。
        // **tenant(spec 020 §2.3 D3b)**:reclaim 无请求 Host——空 tenant = **跨租户全量维护扫描**
        // (GSI 天然扫全表,含所有租户);非空 = 仅该租户(前缀过滤)。返回 (记录所属 tenant, 记录),
        // 供调用方按记录 tenant 回写(convert_to_tombstone/hard_delete 用正确物理键,不能用空 tenant)。
        let mut out = Vec::new();
        let mut last_key: Option<HashMap<String, AttributeValue>> = None;
        let want_prefix = if tenant.is_empty() {
            None
        } else {
            Some(format!("{tenant}\u{1f}"))
        };
        loop {
            let scan = self
                .db
                .scan()
                .table_name(&self.table)
                .index_name("last_used_day-index")
                .filter_expression("last_used_day <= :d")
                .expression_attribute_values(":d", AttributeValue::N(older_than_day.to_string()))
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in scan.items() {
                // GSI key = 物理 client_id(可能带 tenant 前缀)+ last_used_day。
                if let Some(phys) = s(item.get("client_id")) {
                    // 非空 tenant:只收本租户前缀;空 tenant 维护扫描:全收(每条按其自身 tenant 回写)。
                    if let Some(p) = &want_prefix {
                        if !phys.starts_with(p.as_str()) {
                            continue;
                        }
                    }
                    // 记录所属 tenant = 物理 pk 分隔符前段(无前缀 = 空 tenant)。
                    let rec_tenant = match phys.split_once('\u{1f}') {
                        Some((t, _)) => t.to_string(),
                        None => String::new(),
                    };
                    let logical = strip_tpk(&phys);
                    // 回主表取全记录(含 tombstoned_at,判猶予期);用记录 tenant 构造物理键。
                    if let Some(full) = self.get(&rec_tenant, &logical).await? {
                        out.push((rec_tenant, full));
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

    async fn hard_delete_with_audit(
        &self,
        tenant: &str,
        record: &ClientRecord,
        hard_deleted_at: i64,
    ) -> Result<(), StoreError> {
        // 原子(TransactWriteItems):DeleteItem client 行 + PutItem 审计行(同表 pk=`reclaim-audit#<id>`,
        // 无 TTL 持久留存,不随 client 行消失,C10.5)。事务失败(含审计写失败)→ 整体不删,返 Err 留 tombstone
        // 下轮重试(不出现"删了 client 但没留审计")。
        use aws_sdk_dynamodb::types::{Delete, Put, TransactWriteItem};
        // 审计行 pk 也 tenant 化(`tpk(tenant, "reclaim-audit#<id>")`):同租户分区留存,不串租户;
        // audit_of 存逻辑 client_id(可读)。
        let mut audit_item = HashMap::from([
            (
                "client_id".to_string(),
                AttributeValue::S(tpk(tenant, &format!("reclaim-audit#{}", record.client_id))),
            ),
            (
                "audit_of".to_string(),
                AttributeValue::S(record.client_id.clone()),
            ),
            (
                "hard_deleted_at".to_string(),
                AttributeValue::N(hard_deleted_at.to_string()),
            ),
        ]);
        if record.created_at != 0 {
            audit_item.insert(
                "created_at".to_string(),
                AttributeValue::N(record.created_at.to_string()),
            );
        }
        if let Some(ts) = record.tombstoned_at {
            audit_item.insert(
                "tombstoned_at".to_string(),
                AttributeValue::N(ts.to_string()),
            );
        }
        // ⚠️ 审计行**不写 `last_used_day`**——否则它会进 last_used_day-index 稀疏 GSI 被回收扫描当候选反复处理。
        // 用 `last_used_day_audit` 另名留存该信息(不进回收 GSI)。
        if let Some(day) = record.last_used_day {
            audit_item.insert(
                "last_used_day_audit".to_string(),
                AttributeValue::N(day.to_string()),
            );
        }
        let del = Delete::builder()
            .table_name(&self.table)
            .key(
                "client_id",
                AttributeValue::S(tpk(tenant, &record.client_id)),
            )
            .build()
            .map_err(|e| StoreError::Permanent(format!("build delete: {e}")))?;
        let put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(audit_item))
            .build()
            .map_err(|e| StoreError::Permanent(format!("build put: {e}")))?;
        self.db
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().delete(del).build())
            .transact_items(TransactWriteItem::builder().put(put).build())
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct DynamoInitialAccessTokenStore {
    pub(super) db: aws_sdk_dynamodb::Client,
    pub(super) table: String,
}

impl DynamoInitialAccessTokenStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        Self {
            db,
            table: table.into(),
        }
    }

    fn from_item(
        item: &HashMap<String, AttributeValue>,
    ) -> Option<crate::credential::InitialAccessTokenRecord> {
        json_from_attr(item.get("payload"))
    }

    async fn cas_put(
        &self,
        tenant: &str,
        expected_version: u64,
        record: &crate::credential::InitialAccessTokenRecord,
    ) -> Result<bool, StoreError> {
        let response = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("token_id", AttributeValue::S(tpk(tenant, &record.token_id)))
            .update_expression(
                "SET payload = :payload, #status = :status, #version = :version, \
                 expires_at = :expires_at",
            )
            .condition_expression("attribute_exists(token_id) AND #version = :expected")
            .expression_attribute_names("#status", "status")
            .expression_attribute_names("#version", "version")
            .expression_attribute_values(":payload", json_attr(record)?)
            .expression_attribute_values(
                ":status",
                AttributeValue::S(
                    serde_json::to_value(record.credential.status)
                        .ok()
                        .and_then(|value| value.as_str().map(str::to_string))
                        .unwrap_or_else(|| "revoked".to_string()),
                ),
            )
            .expression_attribute_values(":version", AttributeValue::N(record.version.to_string()))
            .expression_attribute_values(
                ":expected",
                AttributeValue::N(expected_version.to_string()),
            )
            .expression_attribute_values(
                ":expires_at",
                AttributeValue::N(record.credential.expires_at.to_string()),
            )
            .send()
            .await;
        match response {
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
}

impl InitialAccessTokenStore for DynamoInitialAccessTokenStore {
    async fn get(
        &self,
        tenant: &str,
        token_id: &str,
    ) -> Result<Option<crate::credential::InitialAccessTokenRecord>, StoreError> {
        let output = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("token_id", AttributeValue::S(tpk(tenant, token_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(output.item().and_then(Self::from_item))
    }

    async fn put_new(
        &self,
        tenant: &str,
        record: crate::credential::InitialAccessTokenRecord,
    ) -> Result<bool, StoreError> {
        let status = serde_json::to_value(record.credential.status)
            .ok()
            .and_then(|value| value.as_str().map(str::to_string))
            .unwrap_or_else(|| "active".to_string());
        let item = HashMap::from([
            (
                "token_id".to_string(),
                AttributeValue::S(tpk(tenant, &record.token_id)),
            ),
            ("payload".to_string(), json_attr(&record)?),
            ("status".to_string(), AttributeValue::S(status)),
            (
                "version".to_string(),
                AttributeValue::N(record.version.to_string()),
            ),
            (
                "expires_at".to_string(),
                AttributeValue::N(record.credential.expires_at.to_string()),
            ),
        ]);
        let result = self
            .db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(token_id)")
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

    async fn list(
        &self,
        tenant: &str,
    ) -> Result<Vec<crate::credential::InitialAccessTokenRecord>, StoreError> {
        let mut records = Vec::new();
        let mut last_key = None;
        let want_prefix = if tenant.is_empty() {
            None
        } else {
            Some(format!("{tenant}\u{1f}"))
        };
        loop {
            let output = self
                .db
                .scan()
                .table_name(&self.table)
                .set_exclusive_start_key(last_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in output.items() {
                let physical = s(item.get("token_id")).unwrap_or_default();
                match &want_prefix {
                    Some(prefix) if !physical.starts_with(prefix) => continue,
                    None if physical.contains('\u{1f}') => continue,
                    _ => {}
                }
                if let Some(record) = Self::from_item(item) {
                    records.push(record);
                }
            }
            match output.last_evaluated_key() {
                Some(key) if !key.is_empty() => last_key = Some(key.clone()),
                _ => break,
            }
        }
        records.sort_by(|a, b| a.token_id.cmp(&b.token_id));
        Ok(records)
    }

    async fn revoke(
        &self,
        tenant: &str,
        token_id: &str,
        expected_version: u64,
        revoked_at: i64,
    ) -> Result<bool, StoreError> {
        let Some(mut record) = self.get(tenant, token_id).await? else {
            return Ok(false);
        };
        if record.credential.status == crate::credential::CredentialStatus::Revoked {
            return Ok(true);
        }
        if record.version != expected_version {
            return Ok(false);
        }
        record.credential.status = crate::credential::CredentialStatus::Revoked;
        record.credential.expires_at = record.credential.expires_at.min(revoked_at);
        record.version = record.version.saturating_add(1);
        self.cas_put(tenant, expected_version, &record).await
    }

    async fn consume_once(
        &self,
        tenant: &str,
        token_id: &str,
        expected_version: u64,
        used_at: i64,
    ) -> Result<bool, StoreError> {
        let Some(mut record) = self.get(tenant, token_id).await? else {
            return Ok(false);
        };
        if record.version != expected_version
            || !record.one_time
            || record.used_at.is_some()
            || record.credential.status != crate::credential::CredentialStatus::Active
            || record.credential.expires_at <= used_at
        {
            return Ok(false);
        }
        record.used_at = Some(used_at);
        record.credential.status = crate::credential::CredentialStatus::Consumed;
        record.version = record.version.saturating_add(1);
        self.cas_put(tenant, expected_version, &record).await
    }

    async fn delete(&self, tenant: &str, token_id: &str) -> Result<(), StoreError> {
        self.db
            .delete_item()
            .table_name(&self.table)
            .key("token_id", AttributeValue::S(tpk(tenant, token_id)))
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(())
    }
}

fn registered_jwks_to_attr(jwks: crate::ports::RegisteredClientJwks) -> AttributeValue {
    AttributeValue::L(
        jwks.keys
            .into_iter()
            .map(|key| {
                let mut fields = HashMap::from([
                    ("kty".to_string(), AttributeValue::S(key.kty)),
                    ("alg".to_string(), AttributeValue::S(key.alg)),
                ]);
                if !key.kid.is_empty() {
                    fields.insert("kid".to_string(), AttributeValue::S(key.kid));
                }
                for (name, value) in [
                    ("use", key.public_key_use),
                    ("crv", key.crv),
                    ("n", key.n),
                    ("e", key.e),
                    ("x", key.x),
                    ("y", key.y),
                ] {
                    if let Some(value) = value {
                        fields.insert(name.to_string(), AttributeValue::S(value));
                    }
                }
                AttributeValue::M(fields)
            })
            .collect(),
    )
}

fn registered_jwks_from_attr(value: &AttributeValue) -> Option<crate::ports::RegisteredClientJwks> {
    let keys = value
        .as_l()
        .ok()?
        .iter()
        .map(|value| {
            let fields = value.as_m().ok()?;
            Some(crate::ports::RegisteredClientJwk {
                kid: s(fields.get("kid")).unwrap_or_default(),
                kty: s(fields.get("kty"))?,
                alg: s(fields.get("alg"))?,
                public_key_use: s(fields.get("use")),
                crv: s(fields.get("crv")),
                n: s(fields.get("n")),
                e: s(fields.get("e")),
                x: s(fields.get("x")),
                y: s(fields.get("y")),
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(crate::ports::RegisteredClientJwks { keys })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ClientStore;
    use aws_smithy_http_client::test_util::capture_request;
    use aws_smithy_types::body::SdkBody;

    fn dynamo_response(body: serde_json::Value) -> axum::http::Response<SdkBody> {
        axum::http::Response::builder()
            .status(200)
            .header("content-type", "application/x-amz-json-1.0")
            .body(SdkBody::from(body.to_string()))
            .unwrap()
    }

    async fn captured_client_read(tenant: &str) -> serde_json::Value {
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
        assert!(ClientStore::get(
            &DynamoClientStore::new(db, "clients-table"),
            tenant,
            "shared-client"
        )
        .await
        .expect("client authority read")
        .is_none());

        let request = request.expect_request();
        serde_json::from_slice(
            request
                .body()
                .bytes()
                .expect("captured Dynamo request body is in memory"),
        )
        .expect("captured Dynamo request is JSON")
    }

    async fn captured_credential_migration_update(
        kind: crate::credential::CredentialKind,
        expected_version: u64,
        credentials: crate::credential::CredentialSet,
    ) -> serde_json::Value {
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
        assert!(ClientStore::replace_credential_set(
            &DynamoClientStore::new(db, "clients-table"),
            "tenant-a",
            "client-a",
            kind,
            expected_version,
            credentials,
        )
        .await
        .expect("credential migration update"));

        let request = request.expect_request();
        serde_json::from_slice(
            request
                .body()
                .bytes()
                .expect("captured Dynamo request body is in memory"),
        )
        .expect("captured Dynamo request is JSON")
    }

    #[tokio::test]
    async fn dynamo_credential_migration_atomically_replaces_legacy_fields_with_verifiers() {
        let client_secret = "legacy-client-plaintext";
        let client = ClientRecord {
            client_id: "client-a".into(),
            token_endpoint_auth_method: "client_secret_basic".into(),
            client_secret: Some(client_secret.into()),
            created_at: 1_000,
            ..Default::default()
        };
        let (expected, replacement) = DynamoClientStore::legacy_migration_replacement(
            &client,
            crate::credential::CredentialKind::ClientSecret,
            "tenant-a",
            b"pepper",
            1_500,
        )
        .unwrap()
        .unwrap();
        let client_body = captured_credential_migration_update(
            crate::credential::CredentialKind::ClientSecret,
            expected,
            replacement,
        )
        .await;
        assert_eq!(client_body["TableName"], "clients-table");
        assert_eq!(
            client_body["Key"]["client_id"]["S"],
            "tenant-a\u{1f}client-a"
        );
        assert_eq!(
            client_body["UpdateExpression"],
            "SET #credentials = :credentials, #version = :version REMOVE #legacy"
        );
        assert_eq!(
            client_body["ExpressionAttributeNames"]["#legacy"],
            "client_secret"
        );
        let serialized = client_body["ExpressionAttributeValues"][":credentials"]["S"]
            .as_str()
            .unwrap();
        assert!(!serialized.contains(client_secret));
        let migrated: crate::credential::CredentialSet = serde_json::from_str(serialized).unwrap();
        let current = migrated.current.unwrap();
        assert_eq!(current.owner, "client-a");
        assert_eq!(
            current.verifier_version,
            crate::credential::VerifierVersion::HmacSha256V1
        );

        let registration_verifier = "legacy-registration-verifier";
        let client = ClientRecord {
            client_id: "client-a".into(),
            reg_token_hash: Some(registration_verifier.into()),
            created_at: 1_000,
            ..Default::default()
        };
        let (expected, replacement) = DynamoClientStore::legacy_migration_replacement(
            &client,
            crate::credential::CredentialKind::RegistrationAccessToken,
            "tenant-a",
            b"pepper",
            1_500,
        )
        .unwrap()
        .unwrap();
        let registration_body = captured_credential_migration_update(
            crate::credential::CredentialKind::RegistrationAccessToken,
            expected,
            replacement,
        )
        .await;
        assert_eq!(
            registration_body["ExpressionAttributeNames"]["#legacy"],
            "reg_token_hash"
        );
        let serialized = registration_body["ExpressionAttributeValues"][":credentials"]["S"]
            .as_str()
            .unwrap();
        let migrated: crate::credential::CredentialSet = serde_json::from_str(serialized).unwrap();
        let current = migrated.current.unwrap();
        assert_eq!(current.owner, "client-a");
        assert_eq!(current.verifier, registration_verifier);
        assert_eq!(
            current.verifier_version,
            crate::credential::VerifierVersion::LegacyRegistrationTokenV0
        );
    }

    #[tokio::test]
    async fn dynamo_client_primary_reads_use_distinct_tenant_qualified_keys() {
        let tenant_a = captured_client_read("tenant-a").await;
        let tenant_b = captured_client_read("tenant-b").await;

        for body in [&tenant_a, &tenant_b] {
            assert_eq!(body["TableName"], "clients-table");
            assert_eq!(body["ConsistentRead"], true);
        }
        assert_eq!(
            tenant_a["Key"]["client_id"]["S"],
            "tenant-a\u{1f}shared-client"
        );
        assert_eq!(
            tenant_b["Key"]["client_id"]["S"],
            "tenant-b\u{1f}shared-client"
        );
        assert_ne!(
            tenant_a["Key"]["client_id"]["S"],
            tenant_b["Key"]["client_id"]["S"]
        );
    }

    #[tokio::test]
    async fn touch_last_used_contract_is_monotonic_and_existing_only() {
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
        DynamoClientStore::new(db, "clients-table")
            .touch_last_used("tenant-a", "client-a", 20_000)
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
        assert_eq!(body["TableName"], "clients-table");
        assert_eq!(body["Key"]["client_id"]["S"], "tenant-a\u{1f}client-a");
        assert_eq!(body["UpdateExpression"], "SET last_used_day = :today");
        assert_eq!(
            body["ConditionExpression"],
            "attribute_exists(client_id) AND \
             (attribute_not_exists(last_used_day) OR last_used_day < :today)"
        );
        assert_eq!(body["ExpressionAttributeValues"][":today"]["N"], "20000");
    }

    #[tokio::test]
    async fn hard_delete_with_audit_is_atomic_tenant_scoped_and_durable() {
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
        let record = ClientRecord {
            client_id: "client-a".to_string(),
            created_at: 1_700_000_000,
            last_used_day: Some(19_675),
            tombstoned_at: Some(1_700_000_100),
            ..Default::default()
        };
        DynamoClientStore::new(db, "clients-table")
            .hard_delete_with_audit("tenant-a", &record, 1_700_003_700)
            .await
            .expect("hard delete transaction");

        let request = request.expect_request();
        let body: serde_json::Value = serde_json::from_slice(
            request
                .body()
                .bytes()
                .expect("captured Dynamo request body is in memory"),
        )
        .expect("captured Dynamo request is JSON");
        assert_eq!(body["TransactItems"].as_array().unwrap().len(), 2);
        assert_eq!(
            body["TransactItems"][0]["Delete"]["TableName"],
            "clients-table"
        );
        assert_eq!(
            body["TransactItems"][0]["Delete"]["Key"]["client_id"]["S"],
            "tenant-a\u{1f}client-a"
        );
        let audit = &body["TransactItems"][1]["Put"];
        assert_eq!(audit["TableName"], "clients-table");
        assert_eq!(
            audit["Item"]["client_id"]["S"],
            "tenant-a\u{1f}reclaim-audit#client-a"
        );
        assert_eq!(audit["Item"]["audit_of"]["S"], "client-a");
        assert_eq!(audit["Item"]["hard_deleted_at"]["N"], "1700003700");
        assert_eq!(audit["Item"]["created_at"]["N"], "1700000000");
        assert_eq!(audit["Item"]["tombstoned_at"]["N"], "1700000100");
        assert_eq!(audit["Item"]["last_used_day_audit"]["N"], "19675");
        assert!(
            audit["Item"].get("last_used_day").is_none(),
            "audit rows must stay outside the reclaim candidate index"
        );
        assert!(
            audit["Item"].get("expires_at").is_none(),
            "hard-delete audit rows must not expire through TTL"
        );
    }

    #[test]
    fn application_type_round_trips_and_legacy_or_unknown_default_to_web() {
        let native = ClientRecord {
            client_id: "client".to_string(),
            redirect_uris: vec!["http://127.0.0.1/callback".to_string()],
            application_type: Some("native".to_string()),
            token_endpoint_auth_method: "none".to_string(),
            ..Default::default()
        };
        let item = DynamoClientStore::client_to_item("tenant", native).unwrap();
        let decoded = DynamoClientStore::item_to_client(&item);
        assert_eq!(decoded.application_type.as_deref(), Some("native"));
        assert_eq!(decoded.application_type(), "native");

        let legacy = HashMap::from([
            (
                "client_id".to_string(),
                AttributeValue::S("tenant\u{1f}legacy".to_string()),
            ),
            ("redirect_uris".to_string(), AttributeValue::L(Vec::new())),
            (
                "token_endpoint_auth_method".to_string(),
                AttributeValue::S("none".to_string()),
            ),
        ]);
        let decoded = DynamoClientStore::item_to_client(&legacy);
        assert!(decoded.application_type.is_none());
        assert_eq!(decoded.application_type(), "web");

        let mut unknown = legacy;
        unknown.insert(
            "application_type".to_string(),
            AttributeValue::S("desktop".to_string()),
        );
        let decoded = DynamoClientStore::item_to_client(&unknown);
        assert_eq!(decoded.application_type.as_deref(), Some("desktop"));
        assert_eq!(decoded.application_type(), "web");
    }
}

#[cfg(test)]
mod registered_client_jwks_dynamo_tests {
    use super::*;
    use crate::ports::{RegisteredClientJwk, RegisteredClientJwks};

    #[test]
    fn private_key_jwt_metadata_round_trips_through_dynamo_attributes() {
        let jwks = RegisteredClientJwks {
            keys: vec![RegisteredClientJwk {
                kid: "rsa-2026-07".to_string(),
                kty: "RSA".to_string(),
                alg: "RS256".to_string(),
                public_key_use: Some("sig".to_string()),
                crv: None,
                n: Some("modulus".to_string()),
                e: Some("AQAB".to_string()),
                x: None,
                y: None,
            }],
        };
        let mut item = HashMap::from([
            (
                "client_id".to_string(),
                AttributeValue::S("tenant\u{1f}client".to_string()),
            ),
            (
                "token_endpoint_auth_method".to_string(),
                AttributeValue::S("private_key_jwt".to_string()),
            ),
            ("jwks".to_string(), registered_jwks_to_attr(jwks.clone())),
            (
                "token_endpoint_auth_signing_alg".to_string(),
                AttributeValue::S("RS256".to_string()),
            ),
        ]);
        item.insert("redirect_uris".to_string(), AttributeValue::L(Vec::new()));

        let decoded = DynamoClientStore::item_to_client(&item);
        assert_eq!(decoded.client_id, "client");
        assert!(decoded.application_type.is_none());
        assert_eq!(decoded.application_type(), "web");
        assert_eq!(decoded.jwks, Some(jwks));
        assert_eq!(
            decoded.token_endpoint_auth_signing_alg.as_deref(),
            Some("RS256")
        );
        assert!(decoded.jwks_uri.is_none());
    }

    #[test]
    fn jwks_without_kid_round_trips_without_an_empty_dynamo_attribute() {
        let jwks = RegisteredClientJwks {
            keys: vec![RegisteredClientJwk {
                kid: String::new(),
                kty: "RSA".to_string(),
                alg: "RS256".to_string(),
                public_key_use: Some("sig".to_string()),
                crv: None,
                n: Some("modulus".to_string()),
                e: Some("AQAB".to_string()),
                x: None,
                y: None,
            }],
        };

        let encoded = registered_jwks_to_attr(jwks.clone());
        let key = encoded.as_l().unwrap()[0].as_m().unwrap();
        assert!(
            !key.contains_key("kid"),
            "an absent RFC 7517 kid must be stored as an absent attribute"
        );
        assert_eq!(registered_jwks_from_attr(&encoded), Some(jwks));
    }
}

#[cfg(test)]
mod cimd_snapshot_dynamo_tests {
    use super::*;
    use crate::ports::{RegisteredClientJwk, RegisteredClientJwks};

    fn snapshot() -> crate::cimd::CimdClientSnapshot {
        crate::cimd::CimdClientSnapshot {
            client_id: "https://client.example.com/oauth/client.json".to_string(),
            client_name: "Example MCP Client".to_string(),
            redirect_uris: vec!["https://app.example.com/callback".to_string()],
            token_endpoint_auth_method: "private_key_jwt".to_string(),
            jwks: Some(RegisteredClientJwks {
                keys: vec![RegisteredClientJwk {
                    kid: "client-key-1".to_string(),
                    kty: "EC".to_string(),
                    alg: "ES256".to_string(),
                    public_key_use: Some("sig".to_string()),
                    crv: Some("P-256".to_string()),
                    n: None,
                    e: None,
                    x: Some("x-coordinate".to_string()),
                    y: Some("y-coordinate".to_string()),
                }],
            }),
            token_endpoint_auth_signing_alg: Some("ES256".to_string()),
            default_resource: Some("https://api.example.com".to_string()),
            id_token_signed_response_alg: Some("ES256".to_string()),
        }
    }

    #[test]
    fn cimd_snapshot_round_trips_for_code_and_refresh_attributes() {
        for record_type in ["authorization code", "refresh family"] {
            let expected = snapshot();
            let mut item = HashMap::new();
            insert_cimd_snapshot(&mut item, Some(expected.clone()), record_type).unwrap();
            assert_eq!(
                read_cimd_snapshot(&item, record_type).unwrap(),
                Some(expected)
            );
        }
    }

    #[test]
    fn malformed_cimd_snapshot_attributes_fail_closed() {
        for value in [
            AttributeValue::Bool(true),
            AttributeValue::S("{\"client_id\":\"incomplete\"}".to_string()),
        ] {
            let item = HashMap::from([("cimd_snapshot".to_string(), value)]);
            assert!(matches!(
                read_cimd_snapshot(&item, "authorization code"),
                Err(StoreError::Permanent(_))
            ));
            assert!(matches!(
                read_cimd_snapshot(&item, "refresh family"),
                Err(StoreError::Permanent(_))
            ));
        }
    }

    #[test]
    fn missing_cimd_snapshot_remains_backward_compatible() {
        assert_eq!(
            read_cimd_snapshot(&HashMap::new(), "authorization code").unwrap(),
            None
        );
    }
}

#[cfg(test)]
mod credential_migration_tests {
    use super::*;

    #[test]
    fn migration_discovers_retained_tenant_from_physical_key() {
        assert_eq!(
            tenant_from_tpk("retired-tenant\u{1f}client-a"),
            "retired-tenant"
        );
        assert_eq!(tenant_from_tpk("legacy-unpartitioned-client"), "");
    }

    #[test]
    fn migration_removes_redundant_plaintext_without_overwriting_versioned_state() {
        let current = crate::credential::new_credential_record(
            b"pepper",
            crate::credential::CredentialKind::ClientSecret,
            "tenant-a",
            "cred-current".into(),
            "client-a".into(),
            "new-secret",
            1_000,
            2_000,
            "admin:test".into(),
            None,
        );
        let client = ClientRecord {
            client_id: "client-a".into(),
            token_endpoint_auth_method: "client_secret_basic".into(),
            client_secret: Some("stale-legacy-plaintext".into()),
            client_secret_credentials: crate::credential::CredentialSet {
                current: Some(current.clone()),
                version: 4,
                ..Default::default()
            },
            ..Default::default()
        };

        let (expected, replacement) = DynamoClientStore::legacy_migration_replacement(
            &client,
            crate::credential::CredentialKind::ClientSecret,
            "tenant-a",
            b"pepper",
            1_500,
        )
        .unwrap()
        .unwrap();

        assert_eq!(expected, 4);
        assert_eq!(replacement.version, 5);
        assert_eq!(replacement.current, Some(current));
    }

    #[test]
    fn migration_converts_unversioned_legacy_registration_verifier() {
        let client = ClientRecord {
            client_id: "client-a".into(),
            reg_token_hash: Some("legacy-verifier".into()),
            created_at: 1_000,
            ..Default::default()
        };

        let (expected, replacement) = DynamoClientStore::legacy_migration_replacement(
            &client,
            crate::credential::CredentialKind::RegistrationAccessToken,
            "tenant-a",
            b"pepper",
            1_500,
        )
        .unwrap()
        .unwrap();
        let current = replacement.current.unwrap();

        assert_eq!(expected, 0);
        assert_eq!(replacement.version, 1);
        assert_eq!(current.verifier, "legacy-verifier");
        assert_eq!(
            current.verifier_version,
            crate::credential::VerifierVersion::LegacyRegistrationTokenV0
        );
        assert_eq!(current.created_at, 1_000);
    }
}
