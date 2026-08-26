#[cfg(test)]
use super::authorization::jti_pk;
use super::identity_federation::{admin_config_key, FlowStateSer};
use super::*;
use std::collections::BTreeSet;

pub(super) async fn governance_delete_by_subject(
    db: &aws_sdk_dynamodb::Client,
    table: &str,
    key_name: &str,
    tenant: &str,
    subject_name: &str,
    subject_value: &str,
) -> Result<usize, StoreError> {
    let mut deleted = 0;
    let mut start_key: Option<HashMap<String, AttributeValue>> = None;
    loop {
        let mut scan = db
            .scan()
            .table_name(table)
            .projection_expression("#key")
            .filter_expression(if tenant.is_empty() {
                "#subject = :subject"
            } else {
                "#subject = :subject AND begins_with(#key, :tenant_prefix)"
            })
            .expression_attribute_names("#key", key_name)
            .expression_attribute_names("#subject", subject_name)
            .expression_attribute_values(":subject", AttributeValue::S(subject_value.to_string()))
            .set_exclusive_start_key(start_key.clone());
        if !tenant.is_empty() {
            scan = scan
                .expression_attribute_values(":tenant_prefix", AttributeValue::S(tpk(tenant, "")));
        }
        let output = scan.send().await.map_err(ddb_err)?;
        for item in output.items() {
            let key = item.get(key_name).cloned().ok_or_else(|| {
                StoreError::Permanent(format!(
                    "{table} governance inventory row is missing {key_name}"
                ))
            })?;
            db.delete_item()
                .table_name(table)
                .key(key_name, key)
                .send()
                .await
                .map_err(ddb_err)?;
            deleted += 1;
        }
        match output.last_evaluated_key() {
            Some(key) if !key.is_empty() => start_key = Some(key.clone()),
            _ => break,
        }
    }
    Ok(deleted)
}

pub(super) async fn governance_delete_by_tenant_key(
    db: &aws_sdk_dynamodb::Client,
    table: &str,
    key_name: &str,
    tenant: &str,
) -> Result<usize, StoreError> {
    Ok(
        governance_delete_by_tenant_key_values(db, table, key_name, tenant)
            .await?
            .len(),
    )
}

pub(super) async fn governance_delete_by_tenant_key_values(
    db: &aws_sdk_dynamodb::Client,
    table: &str,
    key_name: &str,
    tenant: &str,
) -> Result<Vec<String>, StoreError> {
    let mut keys = Vec::new();
    let mut start_key: Option<HashMap<String, AttributeValue>> = None;
    let tenant_prefix = (!tenant.is_empty()).then(|| tpk(tenant, ""));
    loop {
        let output = db
            .scan()
            .table_name(table)
            .projection_expression("#key")
            .expression_attribute_names("#key", key_name)
            .consistent_read(true)
            .set_exclusive_start_key(start_key.clone())
            .send()
            .await
            .map_err(ddb_err)?;
        for item in output.items() {
            let key = item.get(key_name).cloned().ok_or_else(|| {
                StoreError::Permanent(format!(
                    "{table} governance inventory row is missing {key_name}"
                ))
            })?;
            let physical = key.as_s().map_err(|_| {
                StoreError::Permanent(format!("{table} governance key {key_name} is not a string"))
            })?;
            let belongs = match &tenant_prefix {
                Some(prefix) => physical.starts_with(prefix),
                None => !physical.contains(crate::tenant::SEP),
            };
            if belongs {
                let logical = strip_tpk(physical);
                keys.push((key, logical));
            }
        }
        match output.last_evaluated_key() {
            Some(key) if !key.is_empty() => start_key = Some(key.clone()),
            _ => break,
        }
    }
    for (key, _) in &keys {
        db.delete_item()
            .table_name(table)
            .key(key_name, key.clone())
            .send()
            .await
            .map_err(ddb_err)?;
    }
    Ok(keys.into_iter().map(|(_, logical)| logical).collect())
}

const GOVERNANCE_DESTRUCTIVE_TARGET_BATCH: usize = 90;

#[derive(Clone)]
struct GovernanceDeleteCandidate {
    table: String,
    key: HashMap<String, AttributeValue>,
    condition_expression: String,
    expression_attribute_names: HashMap<String, String>,
    expression_attribute_values: HashMap<String, AttributeValue>,
    logical_id: Option<String>,
}

impl GovernanceDeleteCandidate {
    fn from_item(
        table: &str,
        item: &HashMap<String, AttributeValue>,
        key_names: &[&str],
        snapshot_names: &[&str],
        logical_id: Option<String>,
    ) -> Result<Self, StoreError> {
        let mut key = HashMap::new();
        for name in key_names {
            let value = item.get(*name).cloned().ok_or_else(|| {
                StoreError::Permanent(format!(
                    "{table} governance inventory row is missing key {name}"
                ))
            })?;
            key.insert((*name).to_string(), value);
        }
        let partition_key = key_names.first().ok_or_else(|| {
            StoreError::Permanent("governance delete candidate has no key".into())
        })?;
        let mut names = HashMap::from([("#gpk".to_string(), (*partition_key).to_string())]);
        let mut values = HashMap::new();
        let mut snapshots = Vec::new();
        for (index, name) in snapshot_names.iter().enumerate() {
            let name_token = format!("#gs{index}");
            names.insert(name_token.clone(), (*name).to_string());
            if let Some(value) = item.get(*name).cloned() {
                let value_token = format!(":gs{index}");
                values.insert(value_token.clone(), value);
                snapshots.push(format!("{name_token} = {value_token}"));
            } else {
                snapshots.push(format!("attribute_not_exists({name_token})"));
            }
        }
        if snapshots.is_empty() {
            return Err(StoreError::Permanent(
                "governance delete candidate has no ownership snapshot".into(),
            ));
        }
        Ok(Self {
            table: table.to_string(),
            key,
            condition_expression: format!(
                "attribute_not_exists(#gpk) OR ({})",
                snapshots.join(" AND ")
            ),
            expression_attribute_names: names,
            expression_attribute_values: values,
            logical_id,
        })
    }

    fn transact_item(&self) -> Result<aws_sdk_dynamodb::types::TransactWriteItem, StoreError> {
        let delete = aws_sdk_dynamodb::types::Delete::builder()
            .table_name(&self.table)
            .set_key(Some(self.key.clone()))
            .condition_expression(&self.condition_expression)
            .set_expression_attribute_names(Some(self.expression_attribute_names.clone()))
            .set_expression_attribute_values(Some(self.expression_attribute_values.clone()))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "build governance fenced delete for {}: {error}",
                    self.table
                ))
            })?;
        Ok(aws_sdk_dynamodb::types::TransactWriteItem::builder()
            .delete(delete)
            .build())
    }
}

fn governance_tenant_key_matches(
    item: &HashMap<String, AttributeValue>,
    key: &str,
    tenant: &str,
) -> bool {
    let Some(physical) = s(item.get(key)) else {
        return false;
    };
    match (!tenant.is_empty()).then(|| tpk(tenant, "")) {
        Some(prefix) => physical.starts_with(&prefix),
        None => !physical.contains(crate::tenant::SEP),
    }
}

async fn governance_scan_candidates<F>(
    db: &aws_sdk_dynamodb::Client,
    table: &str,
    key_names: &[&str],
    snapshot_names: &[&str],
    mut matches: F,
) -> Result<Vec<GovernanceDeleteCandidate>, StoreError>
where
    F: FnMut(&HashMap<String, AttributeValue>) -> Result<Option<String>, StoreError>,
{
    let mut candidates = Vec::new();
    let mut start_key: Option<HashMap<String, AttributeValue>> = None;
    loop {
        let output = db
            .scan()
            .table_name(table)
            .consistent_read(true)
            .set_exclusive_start_key(start_key.clone())
            .send()
            .await
            .map_err(ddb_err)?;
        for item in output.items() {
            if let Some(logical_id) = matches(item)? {
                candidates.push(GovernanceDeleteCandidate::from_item(
                    table,
                    item,
                    key_names,
                    snapshot_names,
                    (!logical_id.is_empty()).then_some(logical_id),
                )?);
            }
        }
        match output.last_evaluated_key() {
            Some(key) if !key.is_empty() => start_key = Some(key.clone()),
            _ => break,
        }
    }
    Ok(candidates)
}

async fn governance_count_matching<F>(
    db: &aws_sdk_dynamodb::Client,
    table: &str,
    mut matches: F,
) -> Result<usize, StoreError>
where
    F: FnMut(&HashMap<String, AttributeValue>) -> bool,
{
    let mut count = 0usize;
    let mut start_key: Option<HashMap<String, AttributeValue>> = None;
    loop {
        let output = db
            .scan()
            .table_name(table)
            .consistent_read(true)
            .set_exclusive_start_key(start_key.clone())
            .send()
            .await
            .map_err(ddb_err)?;
        count = count.saturating_add(output.items().iter().filter(|item| matches(item)).count());
        match output.last_evaluated_key() {
            Some(key) if !key.is_empty() => start_key = Some(key.clone()),
            _ => break,
        }
    }
    Ok(count)
}

async fn governance_count_matching_checked<F>(
    db: &aws_sdk_dynamodb::Client,
    table: &str,
    mut matches: F,
) -> Result<usize, StoreError>
where
    F: FnMut(&HashMap<String, AttributeValue>) -> Result<bool, StoreError>,
{
    let mut count = 0usize;
    let mut start_key: Option<HashMap<String, AttributeValue>> = None;
    loop {
        let output = db
            .scan()
            .table_name(table)
            .consistent_read(true)
            .set_exclusive_start_key(start_key.clone())
            .send()
            .await
            .map_err(ddb_err)?;
        for item in output.items() {
            if matches(item)? {
                count = count.saturating_add(1);
            }
        }
        match output.last_evaluated_key() {
            Some(key) if !key.is_empty() => start_key = Some(key.clone()),
            _ => break,
        }
    }
    Ok(count)
}

async fn governance_execute_candidates(
    governance: &DynamoGovernanceStore,
    logical_tenant: &str,
    fence: &crate::governance::GovernanceDestructiveFence,
    now: i64,
    candidates: &[GovernanceDeleteCandidate],
) -> Result<usize, StoreError> {
    let mut applied = 0usize;
    for batch in candidates.chunks(GOVERNANCE_DESTRUCTIVE_TARGET_BATCH) {
        let writes = batch
            .iter()
            .map(GovernanceDeleteCandidate::transact_item)
            .collect::<Result<Vec<_>, _>>()?;
        match governance
            .execute_destructive_transaction(logical_tenant, fence.clone(), now, writes)
            .await?
        {
            governance::GovernanceDestructiveWriteOutcome::Applied => {
                applied = applied.saturating_add(batch.len());
            }
            governance::GovernanceDestructiveWriteOutcome::FenceConflict => {
                return Err(StoreError::Transient(
                    "governance destructive fence changed".into(),
                ));
            }
        }
    }
    Ok(applied)
}

async fn governance_delete_matching_fenced<F>(
    db: &aws_sdk_dynamodb::Client,
    table: &str,
    key_names: &[&str],
    snapshot_names: &[&str],
    governance: &DynamoGovernanceStore,
    logical_tenant: &str,
    fence: &crate::governance::GovernanceDestructiveFence,
    now: i64,
    matches: F,
) -> Result<(usize, Vec<String>), StoreError>
where
    F: FnMut(&HashMap<String, AttributeValue>) -> Result<Option<String>, StoreError>,
{
    let candidates =
        governance_scan_candidates(db, table, key_names, snapshot_names, matches).await?;
    let logical_ids = candidates
        .iter()
        .filter_map(|candidate| candidate.logical_id.clone())
        .collect();
    let applied =
        governance_execute_candidates(governance, logical_tenant, fence, now, &candidates).await?;
    Ok((applied, logical_ids))
}

macro_rules! impl_governance_tpk_delete_all {
    ($store:ty, $key:literal) => {
        impl $store {
            pub(crate) async fn governance_delete_all_by_tenant_fenced(
                &self,
                governance: &DynamoGovernanceStore,
                logical_tenant: &str,
                fence: &crate::governance::GovernanceDestructiveFence,
                now: i64,
                data_tenant: &str,
            ) -> Result<usize, StoreError> {
                governance_delete_matching_fenced(
                    &self.db,
                    &self.table,
                    &[$key],
                    &[$key],
                    governance,
                    logical_tenant,
                    fence,
                    now,
                    |item| {
                        Ok(
                            governance_tenant_key_matches(item, $key, data_tenant).then(|| {
                                s(item.get($key))
                                    .map(|key| strip_tpk(&key))
                                    .unwrap_or_default()
                            }),
                        )
                    },
                )
                .await
                .map(|(count, _)| count)
            }
        }
    };
}

macro_rules! impl_governance_tpk_count_all {
    ($store:ty, $key:literal) => {
        impl $store {
            pub(crate) async fn governance_count_all_by_tenant(
                &self,
                data_tenant: &str,
            ) -> Result<usize, StoreError> {
                governance_count_matching(&self.db, &self.table, |item| {
                    governance_tenant_key_matches(item, $key, data_tenant)
                })
                .await
            }
        }
    };
}

macro_rules! impl_governance_user_api {
    ($store:ty, $key:literal, $owner:literal, $qualified:expr) => {
        impl $store {
            pub(crate) async fn governance_delete_by_user_fenced(
                &self,
                governance: &DynamoGovernanceStore,
                logical_tenant: &str,
                fence: &crate::governance::GovernanceDestructiveFence,
                now: i64,
                data_tenant: &str,
                user_id: &str,
            ) -> Result<usize, StoreError> {
                let expected_owner = if $qualified {
                    tpk(data_tenant, user_id)
                } else {
                    user_id.to_string()
                };
                governance_delete_matching_fenced(
                    &self.db,
                    &self.table,
                    &[$key],
                    &[$key, $owner],
                    governance,
                    logical_tenant,
                    fence,
                    now,
                    |item| {
                        Ok((governance_tenant_key_matches(item, $key, data_tenant)
                            && s(item.get($owner)).as_deref() == Some(expected_owner.as_str()))
                        .then(|| {
                            s(item.get($key))
                                .map(|key| strip_tpk(&key))
                                .unwrap_or_default()
                        }))
                    },
                )
                .await
                .map(|(count, _)| count)
            }

            pub(crate) async fn governance_count_by_user(
                &self,
                data_tenant: &str,
                user_id: &str,
            ) -> Result<usize, StoreError> {
                let expected_owner = if $qualified {
                    tpk(data_tenant, user_id)
                } else {
                    user_id.to_string()
                };
                governance_count_matching(&self.db, &self.table, |item| {
                    governance_tenant_key_matches(item, $key, data_tenant)
                        && s(item.get($owner)).as_deref() == Some(expected_owner.as_str())
                })
                .await
            }
        }
    };
}

impl_governance_tpk_delete_all!(DynamoCodeStore, "code");
impl_governance_tpk_count_all!(DynamoCodeStore, "code");
impl_governance_user_api!(DynamoCodeStore, "code", "user_id", false);
impl_governance_tpk_count_all!(DynamoInitialAccessTokenStore, "token_id");
impl_governance_tpk_delete_all!(DynamoCibaStore, "auth_req_id");
impl_governance_tpk_count_all!(DynamoCibaStore, "auth_req_id");
impl_governance_tpk_delete_all!(DynamoDeviceStore, "device_code");
impl_governance_tpk_count_all!(DynamoDeviceStore, "device_code");
impl_governance_user_api!(DynamoDeviceStore, "device_code", "user_id", false);
impl_governance_tpk_delete_all!(DynamoRefreshStore, "family_id");
impl_governance_tpk_delete_all!(DynamoSessionStore, "session_id");
impl_governance_tpk_count_all!(DynamoSessionStore, "session_id");
impl_governance_tpk_delete_all!(DynamoMagicLinkStore, "pk");
impl_governance_tpk_count_all!(DynamoMagicLinkStore, "pk");
impl_governance_tpk_delete_all!(DynamoInvitationStore, "locator");
impl_governance_tpk_count_all!(DynamoInvitationStore, "locator");
impl_governance_user_api!(DynamoInvitationStore, "locator", "user_id", true);
impl_governance_tpk_delete_all!(DynamoRecoveryStore, "user_lookup");
impl_governance_tpk_count_all!(DynamoRecoveryStore, "user_lookup");
impl_governance_tpk_delete_all!(DynamoAuthzSessionStore, "session_id");
impl_governance_tpk_count_all!(DynamoAuthzSessionStore, "session_id");
impl_governance_tpk_delete_all!(DynamoParStore, "request_uri");
impl_governance_tpk_count_all!(DynamoParStore, "request_uri");
impl_governance_tpk_delete_all!(DynamoPasswordStore, "user_id");
impl_governance_tpk_count_all!(DynamoPasswordStore, "user_id");
impl_governance_tpk_delete_all!(DynamoPasskeyStore, "credential_id");
impl_governance_tpk_count_all!(DynamoPasskeyStore, "credential_id");
impl_governance_tpk_delete_all!(DynamoRateLimitStore, "key");
impl_governance_tpk_count_all!(DynamoRateLimitStore, "key");
impl_governance_user_api!(DynamoPasskeyStore, "credential_id", "user_id", true);

impl DynamoCodeStore {
    pub(crate) async fn governance_authz_session_ids_by_user(
        &self,
        data_tenant: &str,
        user_id: &str,
    ) -> Result<BTreeSet<String>, StoreError> {
        let candidates = governance_scan_candidates(
            &self.db,
            &self.table,
            &["code"],
            &["code", "user_id", "authz_session_id"],
            |item| {
                Ok((governance_tenant_key_matches(item, "code", data_tenant)
                    && s(item.get("user_id")).as_deref() == Some(user_id))
                .then(|| s(item.get("authz_session_id")).unwrap_or_default())
                .filter(|session_id| !session_id.is_empty()))
            },
        )
        .await?;
        Ok(candidates
            .into_iter()
            .filter_map(|candidate| candidate.logical_id)
            .collect())
    }
}

impl DynamoClientStore {
    pub(crate) async fn governance_delete_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        data_tenant: &str,
        client_id: &str,
    ) -> Result<usize, StoreError> {
        let physical = tpk(data_tenant, client_id);
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["client_id"],
            &["client_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok(
                    (s(item.get("client_id")).as_deref() == Some(physical.as_str()))
                        .then(|| client_id.to_string()),
                )
            },
        )
        .await
        .map(|(count, _)| count)
    }

    pub(crate) async fn governance_count_all_by_tenant(
        &self,
        data_tenant: &str,
    ) -> Result<usize, StoreError> {
        governance_count_matching(&self.db, &self.table, |item| {
            governance_tenant_key_matches(item, "client_id", data_tenant)
                && !s(item.get("client_id"))
                    .map(|key| strip_tpk(&key).starts_with("reclaim-audit#"))
                    .unwrap_or(false)
        })
        .await
    }
}

impl DynamoInitialAccessTokenStore {
    pub(crate) async fn governance_delete_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        data_tenant: &str,
        token_id: &str,
    ) -> Result<usize, StoreError> {
        let physical = tpk(data_tenant, token_id);
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["token_id"],
            &["token_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok(
                    (s(item.get("token_id")).as_deref() == Some(physical.as_str()))
                        .then(|| token_id.to_string()),
                )
            },
        )
        .await
        .map(|(count, _)| count)
    }
}

impl DynamoPasswordStore {
    pub(crate) async fn governance_delete_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        data_tenant: &str,
        user_id: &str,
    ) -> Result<usize, StoreError> {
        let physical = tpk(data_tenant, user_id);
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["user_id"],
            &["user_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok(
                    (s(item.get("user_id")).as_deref() == Some(physical.as_str()))
                        .then(|| user_id.to_string()),
                )
            },
        )
        .await
        .map(|(count, _)| count)
    }

    pub(crate) async fn governance_count_by_user(
        &self,
        data_tenant: &str,
        user_id: &str,
    ) -> Result<usize, StoreError> {
        let physical = tpk(data_tenant, user_id);
        governance_count_matching(&self.db, &self.table, |item| {
            s(item.get("user_id")).as_deref() == Some(physical.as_str())
        })
        .await
    }
}

impl DynamoRecoveryStore {
    pub(crate) async fn governance_delete_by_lookup_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        data_tenant: &str,
        user_lookup: &str,
        user_id: &str,
    ) -> Result<usize, StoreError> {
        let physical = tpk(data_tenant, user_lookup);
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["user_lookup"],
            &["user_lookup", "user_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok(
                    (s(item.get("user_lookup")).as_deref() == Some(physical.as_str())
                        && s(item.get("user_id")).as_deref() == Some(user_id))
                    .then(|| user_lookup.to_string()),
                )
            },
        )
        .await
        .map(|(count, _)| count)
    }

    pub(crate) async fn governance_count_by_lookup(
        &self,
        data_tenant: &str,
        user_lookup: &str,
        user_id: &str,
    ) -> Result<usize, StoreError> {
        let physical = tpk(data_tenant, user_lookup);
        governance_count_matching(&self.db, &self.table, |item| {
            s(item.get("user_lookup")).as_deref() == Some(physical.as_str())
                && s(item.get("user_id")).as_deref() == Some(user_id)
        })
        .await
    }
}

impl DynamoRefreshStore {
    fn governance_family_id_if_owned(
        item: &HashMap<String, AttributeValue>,
        data_tenant: &str,
        expected_owner: Option<&str>,
    ) -> Option<String> {
        if !governance_tenant_key_matches(item, "family_id", data_tenant) {
            return None;
        }
        if expected_owner.is_some_and(|owner| s(item.get("user_id")).as_deref() != Some(owner)) {
            return None;
        }
        s(item.get("family_id")).map(|family_id| strip_tpk(&family_id))
    }

    async fn governance_family_ids(
        &self,
        data_tenant: &str,
        expected_owner: Option<&str>,
    ) -> Result<Vec<String>, StoreError> {
        let mut family_ids = Vec::new();
        let mut start_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let output = self
                .db
                .scan()
                .table_name(&self.table)
                .projection_expression("family_id, user_id")
                .consistent_read(true)
                .set_exclusive_start_key(start_key.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            family_ids.extend(output.items().iter().filter_map(|item| {
                Self::governance_family_id_if_owned(item, data_tenant, expected_owner)
            }));
            match output.last_evaluated_key() {
                Some(key) if !key.is_empty() => start_key = Some(key.clone()),
                _ => break,
            }
        }
        Ok(family_ids)
    }

    pub(crate) async fn governance_family_ids_by_user(
        &self,
        data_tenant: &str,
        user_id: &str,
    ) -> Result<Vec<String>, StoreError> {
        let owner = tpk(data_tenant, user_id);
        self.governance_family_ids(data_tenant, Some(&owner)).await
    }

    pub(crate) async fn governance_family_ids_by_tenant(
        &self,
        data_tenant: &str,
    ) -> Result<Vec<String>, StoreError> {
        self.governance_family_ids(data_tenant, None).await
    }

    pub(crate) async fn governance_delete_by_user_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        data_tenant: &str,
        user_id: &str,
    ) -> Result<Vec<String>, StoreError> {
        let owner = tpk(data_tenant, user_id);
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["family_id"],
            &["family_id", "user_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok(
                    (governance_tenant_key_matches(item, "family_id", data_tenant)
                        && s(item.get("user_id")).as_deref() == Some(owner.as_str()))
                    .then(|| {
                        s(item.get("family_id"))
                            .map(|key| strip_tpk(&key))
                            .unwrap_or_default()
                    }),
                )
            },
        )
        .await
        .map(|(_, family_ids)| family_ids)
    }
}

impl DynamoSessionStore {
    pub(crate) async fn governance_delete_by_user_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        data_tenant: &str,
        user_id: &str,
    ) -> Result<usize, StoreError> {
        let owner = tpk(data_tenant, user_id);
        let (sessions, _) = governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["session_id"],
            &["session_id", "user_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok(
                    (governance_tenant_key_matches(item, "session_id", data_tenant)
                        && s(item.get("user_id")).as_deref() == Some(owner.as_str()))
                    .then(|| {
                        s(item.get("session_id"))
                            .map(|key| strip_tpk(&key))
                            .unwrap_or_default()
                    }),
                )
            },
        )
        .await?;
        let generation_key = Self::generation_key(data_tenant, user_id);
        let (markers, _) = governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["session_id"],
            &["session_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok(
                    (s(item.get("session_id")).as_deref() == Some(generation_key.as_str()))
                        .then(|| user_id.to_string()),
                )
            },
        )
        .await?;
        Ok(sessions.saturating_add(markers))
    }

    pub(crate) async fn governance_count_by_user(
        &self,
        data_tenant: &str,
        user_id: &str,
    ) -> Result<usize, StoreError> {
        let owner = tpk(data_tenant, user_id);
        let generation_key = Self::generation_key(data_tenant, user_id);
        governance_count_matching(&self.db, &self.table, |item| {
            s(item.get("user_id")).as_deref() == Some(owner.as_str())
                || s(item.get("session_id")).as_deref() == Some(generation_key.as_str())
        })
        .await
    }
}

impl DynamoCibaStore {
    pub(crate) async fn governance_delete_by_user_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        data_tenant: &str,
        user_id: &str,
    ) -> Result<usize, StoreError> {
        let (requests, _) = governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["auth_req_id"],
            &["auth_req_id", "user_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok(
                    (governance_tenant_key_matches(item, "auth_req_id", data_tenant)
                        && s(item.get("user_id")).as_deref() == Some(user_id))
                    .then(|| {
                        s(item.get("auth_req_id"))
                            .map(|key| strip_tpk(&key))
                            .unwrap_or_default()
                    }),
                )
            },
        )
        .await?;
        let throttle_key = tpk(data_tenant, &format!("throttle#{user_id}"));
        let (throttles, _) = governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["auth_req_id"],
            &["auth_req_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok(
                    (s(item.get("auth_req_id")).as_deref() == Some(throttle_key.as_str()))
                        .then(|| user_id.to_string()),
                )
            },
        )
        .await?;
        Ok(requests.saturating_add(throttles))
    }

    pub(crate) async fn governance_count_by_user(
        &self,
        data_tenant: &str,
        user_id: &str,
    ) -> Result<usize, StoreError> {
        let throttle_key = tpk(data_tenant, &format!("throttle#{user_id}"));
        governance_count_matching(&self.db, &self.table, |item| {
            (governance_tenant_key_matches(item, "auth_req_id", data_tenant)
                && s(item.get("user_id")).as_deref() == Some(user_id))
                || s(item.get("auth_req_id")).as_deref() == Some(throttle_key.as_str())
        })
        .await
    }
}

impl DynamoPasskeyChallengeStore {
    fn governance_belongs_to_tenant(
        item: &HashMap<String, AttributeValue>,
        data_tenant: &str,
    ) -> bool {
        match s(item.get("tenant")) {
            Some(tenant) => tenant == data_tenant,
            None => data_tenant.is_empty(),
        }
    }

    pub(crate) async fn governance_delete_by_user_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        data_tenant: &str,
        user_id: &str,
    ) -> Result<usize, StoreError> {
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["challenge"],
            &["challenge", "tenant", "user_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok((Self::governance_belongs_to_tenant(item, data_tenant)
                    && s(item.get("user_id")).as_deref() == Some(user_id))
                .then(|| s(item.get("challenge")).unwrap_or_default()))
            },
        )
        .await
        .map(|(count, _)| count)
    }

    pub(crate) async fn governance_delete_all_by_tenant_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        data_tenant: &str,
    ) -> Result<usize, StoreError> {
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["challenge"],
            &["challenge", "tenant"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok(Self::governance_belongs_to_tenant(item, data_tenant)
                    .then(|| s(item.get("challenge")).unwrap_or_default()))
            },
        )
        .await
        .map(|(count, _)| count)
    }

    pub(crate) async fn governance_count_by_user(
        &self,
        data_tenant: &str,
        user_id: &str,
    ) -> Result<usize, StoreError> {
        governance_count_matching(&self.db, &self.table, |item| {
            Self::governance_belongs_to_tenant(item, data_tenant)
                && s(item.get("user_id")).as_deref() == Some(user_id)
        })
        .await
    }

    pub(crate) async fn governance_count_all_by_tenant(
        &self,
        data_tenant: &str,
    ) -> Result<usize, StoreError> {
        governance_count_matching(&self.db, &self.table, |item| {
            Self::governance_belongs_to_tenant(item, data_tenant)
        })
        .await
    }
}

impl DynamoMagicLinkStore {
    pub(crate) async fn governance_delete_by_user_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        data_tenant: &str,
        user_id: &str,
        aliases: &[String],
    ) -> Result<usize, StoreError> {
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["pk"],
            &["pk", "user_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                let physical = s(item.get("pk")).unwrap_or_default();
                let user_link = governance_tenant_key_matches(item, "pk", data_tenant)
                    && s(item.get("user_id")).as_deref() == Some(user_id);
                let cooldown = aliases
                    .iter()
                    .any(|alias| physical == tpk(data_tenant, &format!("cool#{alias}")));
                Ok((user_link || cooldown).then(|| strip_tpk(&physical)))
            },
        )
        .await
        .map(|(count, _)| count)
    }

    pub(crate) async fn governance_count_by_user(
        &self,
        data_tenant: &str,
        user_id: &str,
        aliases: &[String],
    ) -> Result<usize, StoreError> {
        governance_count_matching(&self.db, &self.table, |item| {
            let physical = s(item.get("pk")).unwrap_or_default();
            (governance_tenant_key_matches(item, "pk", data_tenant)
                && s(item.get("user_id")).as_deref() == Some(user_id))
                || aliases
                    .iter()
                    .any(|alias| physical == tpk(data_tenant, &format!("cool#{alias}")))
        })
        .await
    }
}

impl DynamoNotifier {
    pub(crate) async fn governance_delete_by_recipients_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        data_tenant: &str,
        recipients: &[String],
    ) -> Result<usize, StoreError> {
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["message_id"],
            &["message_id", "tenant", "recipient"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                let recipient = s(item.get("recipient")).unwrap_or_default();
                Ok((s(item.get("tenant")).unwrap_or_default() == data_tenant
                    && recipients.iter().any(|alias| alias == &recipient))
                .then(|| {
                    s(item.get("message_id"))
                        .map(|key| strip_tpk(&key))
                        .unwrap_or_default()
                }))
            },
        )
        .await
        .map(|(count, _)| count)
    }

    pub(crate) async fn governance_delete_all_by_tenant_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        data_tenant: &str,
    ) -> Result<usize, StoreError> {
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["message_id"],
            &["message_id", "tenant"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok(
                    (s(item.get("tenant")).unwrap_or_default() == data_tenant).then(|| {
                        s(item.get("message_id"))
                            .map(|key| strip_tpk(&key))
                            .unwrap_or_default()
                    }),
                )
            },
        )
        .await
        .map(|(count, _)| count)
    }

    pub(crate) async fn governance_count_by_recipients(
        &self,
        data_tenant: &str,
        recipients: &[String],
    ) -> Result<usize, StoreError> {
        governance_count_matching(&self.db, &self.table, |item| {
            let recipient = s(item.get("recipient")).unwrap_or_default();
            s(item.get("tenant")).unwrap_or_default() == data_tenant
                && recipients.iter().any(|alias| alias == &recipient)
        })
        .await
    }

    pub(crate) async fn governance_count_all_by_tenant(
        &self,
        data_tenant: &str,
    ) -> Result<usize, StoreError> {
        governance_count_matching(&self.db, &self.table, |item| {
            s(item.get("tenant")).unwrap_or_default() == data_tenant
        })
        .await
    }
}

impl DynamoGrantStore {
    pub(crate) async fn governance_delete_by_user_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        data_tenant: &str,
        user_id: &str,
    ) -> Result<usize, StoreError> {
        let owner = tpk(data_tenant, user_id);
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["grant_id"],
            &["grant_id", "user_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok(
                    (governance_tenant_key_matches(item, "grant_id", data_tenant)
                        && item.contains_key("grant_json")
                        && s(item.get("user_id")).as_deref() == Some(owner.as_str()))
                    .then(|| {
                        s(item.get("grant_id"))
                            .map(|key| strip_tpk(&key))
                            .unwrap_or_default()
                    }),
                )
            },
        )
        .await
        .map(|(count, _)| count)
    }

    pub(crate) async fn governance_delete_all_by_tenant_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        data_tenant: &str,
    ) -> Result<usize, StoreError> {
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["grant_id"],
            &["grant_id", "user_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok(
                    (governance_tenant_key_matches(item, "grant_id", data_tenant)
                        && item.contains_key("grant_json"))
                    .then(|| {
                        s(item.get("grant_id"))
                            .map(|key| strip_tpk(&key))
                            .unwrap_or_default()
                    }),
                )
            },
        )
        .await
        .map(|(count, _)| count)
    }

    pub(crate) async fn governance_count_by_user(
        &self,
        data_tenant: &str,
        user_id: &str,
    ) -> Result<usize, StoreError> {
        let owner = tpk(data_tenant, user_id);
        governance_count_matching(&self.db, &self.table, |item| {
            governance_tenant_key_matches(item, "grant_id", data_tenant)
                && item.contains_key("grant_json")
                && s(item.get("user_id")).as_deref() == Some(owner.as_str())
        })
        .await
    }

    pub(crate) async fn governance_count_all_by_tenant(
        &self,
        data_tenant: &str,
    ) -> Result<usize, StoreError> {
        governance_count_matching(&self.db, &self.table, |item| {
            governance_tenant_key_matches(item, "grant_id", data_tenant)
                && item.contains_key("grant_json")
        })
        .await
    }
}

impl DynamoJtiStore {
    pub(crate) async fn governance_delete_by_user_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<usize, StoreError> {
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["pk"],
            &["pk", "tenant_id", "user_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok((s(item.get("tenant_id")).as_deref() == Some(tenant_id)
                    && s(item.get("user_id")).as_deref() == Some(user_id))
                .then(|| s(item.get("jti")).unwrap_or_default()))
            },
        )
        .await
        .map(|(count, _)| count)
    }

    pub(crate) async fn governance_delete_all_by_tenant_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        tenant_id: &str,
    ) -> Result<usize, StoreError> {
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["pk"],
            &["pk", "tenant_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok((s(item.get("tenant_id")).as_deref() == Some(tenant_id))
                    .then(|| s(item.get("jti")).unwrap_or_default()))
            },
        )
        .await
        .map(|(count, _)| count)
    }

    pub(crate) async fn governance_count_by_user(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<usize, StoreError> {
        governance_count_matching(&self.db, &self.table, |item| {
            s(item.get("tenant_id")).as_deref() == Some(tenant_id)
                && s(item.get("user_id")).as_deref() == Some(user_id)
        })
        .await
    }

    pub(crate) async fn governance_count_all_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<usize, StoreError> {
        governance_count_matching(&self.db, &self.table, |item| {
            s(item.get("tenant_id")).as_deref() == Some(tenant_id)
        })
        .await
    }
}

impl DynamoReplayStore {
    fn governance_is_replay(item: &HashMap<String, AttributeValue>, tenant: &str) -> bool {
        let Some(physical) = s(item.get("pk")) else {
            return false;
        };
        let expected_prefix = tpk(tenant, &format!("replay{}", crate::tenant::SEP));
        physical.starts_with(&expected_prefix)
    }

    pub(crate) async fn governance_delete_all_by_tenant_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        data_tenant: &str,
    ) -> Result<usize, StoreError> {
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["pk"],
            &["pk"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok(Self::governance_is_replay(item, data_tenant)
                    .then(|| s(item.get("pk")).unwrap_or_default()))
            },
        )
        .await
        .map(|(count, _)| count)
    }

    pub(crate) async fn governance_count_all_by_tenant(
        &self,
        data_tenant: &str,
    ) -> Result<usize, StoreError> {
        governance_count_matching(&self.db, &self.table, |item| {
            Self::governance_is_replay(item, data_tenant)
        })
        .await
    }
}

impl DynamoAuthzSessionStore {
    pub(crate) async fn governance_delete_by_user_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        data_tenant: &str,
        user_id: &str,
        session_ids: &BTreeSet<String>,
    ) -> Result<usize, StoreError> {
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["session_id"],
            &["session_id", "client_id", "user_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                let session_id = s(item.get("session_id")).map(|key| strip_tpk(&key));
                let owned =
                    s(item.get("user_id")).map(|key| strip_tpk(&key)).as_deref() == Some(user_id);
                Ok(
                    (governance_tenant_key_matches(item, "session_id", data_tenant)
                        && (owned
                            || session_id
                                .as_deref()
                                .is_some_and(|session_id| session_ids.contains(session_id))))
                    .then_some(session_id)
                    .flatten(),
                )
            },
        )
        .await
        .map(|(count, _)| count)
    }

    pub(crate) async fn governance_count_by_user(
        &self,
        data_tenant: &str,
        user_id: &str,
        session_ids: &BTreeSet<String>,
    ) -> Result<usize, StoreError> {
        governance_count_matching(&self.db, &self.table, |item| {
            governance_tenant_key_matches(item, "session_id", data_tenant)
                && (s(item.get("user_id")).map(|key| strip_tpk(&key)).as_deref() == Some(user_id)
                    || s(item.get("session_id"))
                        .map(|key| session_ids.contains(strip_tpk(&key).as_str()))
                        .unwrap_or(false))
        })
        .await
    }

    pub(crate) async fn governance_delete_by_client_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        data_tenant: &str,
        client_id: &str,
    ) -> Result<usize, StoreError> {
        let owner = tpk(data_tenant, client_id);
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["session_id"],
            &["session_id", "client_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok(
                    (governance_tenant_key_matches(item, "session_id", data_tenant)
                        && s(item.get("client_id")).as_deref() == Some(owner.as_str()))
                    .then(|| {
                        s(item.get("session_id"))
                            .map(|key| strip_tpk(&key))
                            .unwrap_or_default()
                    }),
                )
            },
        )
        .await
        .map(|(count, _)| count)
    }
}

impl DynamoGraceStore {
    pub(crate) async fn governance_delete_family_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        family_id: &str,
    ) -> Result<usize, StoreError> {
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["family_id", "version"],
            &["family_id", "version"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok((s(item.get("family_id")).as_deref() == Some(family_id))
                    .then(|| family_id.to_string()))
            },
        )
        .await
        .map(|(count, _)| count)
    }

    pub(crate) async fn governance_count_family(
        &self,
        family_id: &str,
    ) -> Result<usize, StoreError> {
        governance_count_matching(&self.db, &self.table, |item| {
            s(item.get("family_id")).as_deref() == Some(family_id)
        })
        .await
    }
}

impl DynamoRateLimitStore {
    pub(crate) async fn governance_delete_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        key: &str,
    ) -> Result<usize, StoreError> {
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["key"],
            &["key"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| Ok((s(item.get("key")).as_deref() == Some(key)).then(|| key.to_string())),
        )
        .await
        .map(|(count, _)| count)
    }
}

impl DynamoWorkloadTrustStore {
    pub(crate) async fn governance_delete_all_by_tenant_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        tenant_id: &str,
    ) -> Result<usize, StoreError> {
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["binding_id"],
            &["binding_id", "tenant_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok(
                    (s(item.get("tenant_id")).as_deref() == Some(tenant_id)).then(|| {
                        s(item.get("binding_id"))
                            .map(|key| strip_tpk(&key))
                            .unwrap_or_default()
                    }),
                )
            },
        )
        .await
        .map(|(count, _)| count)
    }

    pub(crate) async fn governance_count_all_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<usize, StoreError> {
        governance_count_matching(&self.db, &self.table, |item| {
            s(item.get("tenant_id")).as_deref() == Some(tenant_id)
        })
        .await
    }
}

impl DynamoFederationConfigStore {
    pub(crate) async fn governance_delete_all_by_tenant_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        tenant_id: &str,
    ) -> Result<usize, StoreError> {
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["tenant_id", "upstream_idp_id"],
            &["tenant_id", "upstream_idp_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok((s(item.get("tenant_id")).as_deref() == Some(tenant_id))
                    .then(|| s(item.get("upstream_idp_id")).unwrap_or_default()))
            },
        )
        .await
        .map(|(count, _)| count)
    }

    pub(crate) async fn governance_count_all_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<usize, StoreError> {
        governance_count_matching(&self.db, &self.table, |item| {
            s(item.get("tenant_id")).as_deref() == Some(tenant_id)
        })
        .await
    }
}

impl DynamoFederationAttributeMappingsStore {
    pub(crate) async fn governance_delete_all_by_tenant_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        tenant_id: &str,
    ) -> Result<usize, StoreError> {
        let physical_tenant = if tenant_id.is_empty() {
            "default"
        } else {
            tenant_id
        };
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["tenant_id", "lookup_key"],
            &["tenant_id", "lookup_key"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok(
                    (s(item.get("tenant_id")).as_deref() == Some(physical_tenant))
                        .then(|| s(item.get("lookup_key")).unwrap_or_default()),
                )
            },
        )
        .await
        .map(|(count, _)| count)
    }
}

impl DynamoFederationFlowStore {
    fn governance_flow_belongs(item: &HashMap<String, AttributeValue>, tenant_id: &str) -> bool {
        s(item.get("flow_json"))
            .and_then(|json| serde_json::from_str::<FlowStateSer>(&json).ok())
            .is_some_and(|flow| flow.tenant_id == tenant_id)
    }

    pub(crate) async fn governance_delete_all_by_tenant_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        tenant_id: &str,
    ) -> Result<usize, StoreError> {
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["state"],
            &["state", "flow_json"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok(Self::governance_flow_belongs(item, tenant_id)
                    .then(|| s(item.get("state")).unwrap_or_default()))
            },
        )
        .await
        .map(|(count, _)| count)
    }

    pub(crate) async fn governance_count_all_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<usize, StoreError> {
        governance_count_matching(&self.db, &self.table, |item| {
            Self::governance_flow_belongs(item, tenant_id)
        })
        .await
    }
}

impl DynamoDomainMapStore {
    pub(crate) async fn governance_delete_if_owner_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        tenant_id: &str,
        domain: &str,
        client_id: &str,
    ) -> Result<usize, StoreError> {
        let domain = domain.to_ascii_lowercase();
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["domain"],
            &["domain", "tenant_id", "client_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok((s(item.get("domain")).as_deref() == Some(domain.as_str())
                    && s(item.get("tenant_id")).as_deref() == Some(tenant_id)
                    && s(item.get("client_id")).as_deref() == Some(client_id))
                .then(|| domain.clone()))
            },
        )
        .await
        .map(|(count, _)| count)
    }

    pub(crate) async fn governance_delete_all_by_tenant_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        tenant_id: &str,
    ) -> Result<usize, StoreError> {
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["domain"],
            &["domain", "tenant_id", "client_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok((s(item.get("tenant_id")).as_deref() == Some(tenant_id))
                    .then(|| s(item.get("domain")).unwrap_or_default()))
            },
        )
        .await
        .map(|(count, _)| count)
    }

    pub(crate) async fn governance_count_all_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<usize, StoreError> {
        governance_count_matching(&self.db, &self.table, |item| {
            s(item.get("tenant_id")).as_deref() == Some(tenant_id)
        })
        .await
    }
}

impl DynamoPolicyArtifactStore {
    pub(crate) async fn governance_delete_all_by_tenant_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        data_tenant: &str,
    ) -> Result<usize, StoreError> {
        let prefix = tpk(data_tenant, "policy-artifact#");
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["grant_id"],
            &["grant_id", "policy_digest"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                let key = s(item.get("grant_id")).unwrap_or_default();
                Ok((key.starts_with(&prefix)
                    && item.contains_key("policy_text")
                    && item.contains_key("policy_digest"))
                .then(|| strip_tpk(&key)))
            },
        )
        .await
        .map(|(count, _)| count)
    }

    pub(crate) async fn governance_count_all_by_tenant(
        &self,
        data_tenant: &str,
    ) -> Result<usize, StoreError> {
        let prefix = tpk(data_tenant, "policy-artifact#");
        governance_count_matching(&self.db, &self.table, |item| {
            s(item.get("grant_id")).is_some_and(|key| key.starts_with(&prefix))
                && item.contains_key("policy_text")
        })
        .await
    }
}

impl DynamoPolicyVersionStore {
    pub(crate) async fn governance_delete_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        data_tenant: &str,
    ) -> Result<usize, StoreError> {
        let key = Self::pk(data_tenant);
        governance_delete_matching_fenced(
            &self.db,
            &self.table,
            &["grant_id"],
            &["grant_id", "policy_version"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok((s(item.get("grant_id")).as_deref() == Some(key.as_str())
                    && item.contains_key("policy_version"))
                .then(|| "policy-version".to_string()))
            },
        )
        .await
        .map(|(count, _)| count)
    }

    pub(crate) async fn governance_count(&self, data_tenant: &str) -> Result<usize, StoreError> {
        let key = Self::pk(data_tenant);
        governance_count_matching(&self.db, &self.table, |item| {
            s(item.get("grant_id")).as_deref() == Some(key.as_str())
                && item.contains_key("policy_version")
        })
        .await
    }
}

impl DynamoAdminAuthStore {
    fn governance_session_belongs_to_user(
        item: &HashMap<String, AttributeValue>,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<bool, StoreError> {
        if s(item.get("record_type")).as_deref() != Some("session")
            || s(item.get("tenant_id")).as_deref() != Some(tenant_id)
        {
            return Ok(false);
        }
        if let Some(stored_user_id) = s(item.get("user_id")) {
            return Ok(stored_user_id == user_id);
        }
        let json = s(item.get("record_json")).ok_or_else(|| {
            StoreError::Permanent("Admin session row is missing record_json".into())
        })?;
        let session: crate::ports::AdminSessionRecord =
            serde_json::from_str(&json).map_err(|error| {
                StoreError::Permanent(format!(
                    "deserialize Admin session during governance inventory: {error}"
                ))
            })?;
        if session.tenant_id != tenant_id {
            return Err(StoreError::Permanent(
                "Admin session row has inconsistent tenant identity".into(),
            ));
        }
        Ok(session.user_id == user_id)
    }

    pub(crate) async fn governance_delete_sessions_by_user_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<usize, StoreError> {
        let (removed, _) = governance_delete_matching_fenced(
            &self.db,
            &self.runtime_table,
            &["key"],
            &["key", "record_type", "tenant_id", "user_id", "record_json"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Self::governance_session_belongs_to_user(item, tenant_id, user_id)
                    .map(|matches| matches.then(|| s(item.get("key")).unwrap_or_default()))
            },
        )
        .await?;
        Ok(removed)
    }

    pub(crate) async fn governance_count_sessions_by_user(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<usize, StoreError> {
        governance_count_matching_checked(&self.db, &self.runtime_table, |item| {
            Self::governance_session_belongs_to_user(item, tenant_id, user_id)
        })
        .await
    }

    fn governance_runtime_belongs(item: &HashMap<String, AttributeValue>, tenant_id: &str) -> bool {
        match s(item.get("record_type")).as_deref() {
            Some("session") => s(item.get("tenant_id")).as_deref() == Some(tenant_id),
            Some("flow") => s(item.get("record_json"))
                .and_then(|json| serde_json::from_str::<crate::ports::AdminOidcFlow>(&json).ok())
                .is_some_and(|flow| flow.tenant_id == tenant_id),
            _ => false,
        }
    }

    pub(crate) async fn governance_delete_all_by_tenant_fenced(
        &self,
        governance: &DynamoGovernanceStore,
        logical_tenant: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
        tenant_id: &str,
    ) -> Result<usize, StoreError> {
        let config_key = admin_config_key(tenant_id);
        let (configs, _) = governance_delete_matching_fenced(
            &self.db,
            &self.config_table,
            &["key"],
            &["key", "record_type", "tenant_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok((s(item.get("key")).as_deref() == Some(config_key.as_str())
                    && s(item.get("tenant_id")).as_deref() == Some(tenant_id)
                    && s(item.get("record_type")).as_deref() == Some("config"))
                .then(|| config_key.clone()))
            },
        )
        .await?;

        let (sessions, _) = governance_delete_matching_fenced(
            &self.db,
            &self.runtime_table,
            &["key"],
            &["key", "record_type", "tenant_id"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok((s(item.get("record_type")).as_deref() == Some("session")
                    && s(item.get("tenant_id")).as_deref() == Some(tenant_id))
                .then(|| s(item.get("key")).unwrap_or_default()))
            },
        )
        .await?;

        let (flows, _) = governance_delete_matching_fenced(
            &self.db,
            &self.runtime_table,
            &["key"],
            &["key", "record_type", "record_json"],
            governance,
            logical_tenant,
            fence,
            now,
            |item| {
                Ok((s(item.get("record_type")).as_deref() == Some("flow")
                    && Self::governance_runtime_belongs(item, tenant_id))
                .then(|| s(item.get("key")).unwrap_or_default()))
            },
        )
        .await?;
        Ok(configs.saturating_add(sessions).saturating_add(flows))
    }

    pub(crate) async fn governance_count_all_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<usize, StoreError> {
        let config_key = admin_config_key(tenant_id);
        let configs = governance_count_matching(&self.db, &self.config_table, |item| {
            s(item.get("key")).as_deref() == Some(config_key.as_str())
                && s(item.get("tenant_id")).as_deref() == Some(tenant_id)
                && s(item.get("record_type")).as_deref() == Some("config")
        })
        .await?;
        let runtime = governance_count_matching(&self.db, &self.runtime_table, |item| {
            Self::governance_runtime_belongs(item, tenant_id)
        })
        .await?;
        Ok(configs.saturating_add(runtime))
    }
}

#[cfg(test)]
mod governance_fenced_adapter_tests {
    use super::*;

    #[test]
    fn destructive_candidate_allows_absence_and_pins_ownership_snapshot() {
        let item = HashMap::from([
            (
                "pk".to_string(),
                AttributeValue::S("tenant\u{1f}row".into()),
            ),
            ("tenant_id".to_string(), AttributeValue::S("tenant".into())),
            ("owner".to_string(), AttributeValue::S("user-a".into())),
        ]);
        let candidate = GovernanceDeleteCandidate::from_item(
            "table-a",
            &item,
            &["pk"],
            &["pk", "tenant_id", "owner"],
            Some("row".into()),
        )
        .unwrap();

        assert!(candidate
            .condition_expression
            .starts_with("attribute_not_exists(#gpk) OR ("));
        assert_eq!(
            candidate.expression_attribute_names.get("#gpk"),
            Some(&"pk".to_string())
        );
        assert_eq!(candidate.expression_attribute_values.len(), 3);
        assert_eq!(candidate.logical_id.as_deref(), Some("row"));
        assert!(candidate.transact_item().is_ok());

        let legacy = HashMap::from([("pk".to_string(), AttributeValue::S("legacy".into()))]);
        let legacy_candidate = GovernanceDeleteCandidate::from_item(
            "table-a",
            &legacy,
            &["pk"],
            &["pk", "tenant_id"],
            None,
        )
        .unwrap();
        assert!(legacy_candidate
            .condition_expression
            .contains("attribute_not_exists(#gs1)"));
    }

    #[test]
    fn tenant_key_matching_is_exact_for_partitioned_and_legacy_rows() {
        let partitioned =
            HashMap::from([("pk".to_string(), AttributeValue::S(tpk("tenant-a", "row")))]);
        let legacy = HashMap::from([("pk".to_string(), AttributeValue::S("legacy-row".into()))]);

        assert!(governance_tenant_key_matches(
            &partitioned,
            "pk",
            "tenant-a"
        ));
        assert!(!governance_tenant_key_matches(
            &partitioned,
            "pk",
            "tenant-b"
        ));
        assert!(!governance_tenant_key_matches(&partitioned, "pk", ""));
        assert!(governance_tenant_key_matches(&legacy, "pk", ""));
    }

    #[test]
    fn replay_inventory_does_not_claim_jti_rows_in_the_shared_table() {
        let replay = HashMap::from([(
            "pk".to_string(),
            AttributeValue::S(tpk("tenant-a", "replay\u{1f}nonce")),
        )]);
        let jti = HashMap::from([
            (
                "pk".to_string(),
                AttributeValue::S(jti_pk("tenant-a", "jti-a")),
            ),
            (
                "tenant_id".to_string(),
                AttributeValue::S("tenant-a".into()),
            ),
        ]);

        assert!(DynamoReplayStore::governance_is_replay(&replay, "tenant-a"));
        assert!(!DynamoReplayStore::governance_is_replay(&jti, "tenant-a"));
        const { assert!(GOVERNANCE_DESTRUCTIVE_TARGET_BATCH <= 96) };
    }

    #[test]
    fn refresh_family_inventory_is_tenant_and_owner_scoped() {
        let alice = HashMap::from([
            (
                "family_id".to_string(),
                AttributeValue::S(tpk("tenant-a", "family-a")),
            ),
            (
                "user_id".to_string(),
                AttributeValue::S(tpk("tenant-a", "alice")),
            ),
        ]);
        let alice_owner = tpk("tenant-a", "alice");
        let bob_owner = tpk("tenant-a", "bob");

        assert_eq!(
            DynamoRefreshStore::governance_family_id_if_owned(
                &alice,
                "tenant-a",
                Some(&alice_owner)
            )
            .as_deref(),
            Some("family-a")
        );
        assert!(DynamoRefreshStore::governance_family_id_if_owned(
            &alice,
            "tenant-a",
            Some(&bob_owner)
        )
        .is_none());
        assert!(
            DynamoRefreshStore::governance_family_id_if_owned(&alice, "tenant-b", None).is_none()
        );
    }

    fn admin_session(user_id: &str, tenant_id: &str) -> crate::ports::AdminSessionRecord {
        crate::ports::AdminSessionRecord {
            session_hash: "session-hash".into(),
            tenant_id: tenant_id.into(),
            user_id: user_id.into(),
            upstream_subject: "upstream-subject".into(),
            role: crate::ports::TenantRole::Admin,
            credential_epoch: 0,
            config_revision: 1,
            config_binding_id: "binding-1".into(),
            acr: None,
            auth_time: 100,
            created_at: 100,
            expires_at: 1_000,
        }
    }

    #[test]
    fn admin_session_governance_matching_supports_new_and_legacy_rows() {
        let indexed = HashMap::from([
            ("record_type".into(), AttributeValue::S("session".into())),
            ("tenant_id".into(), AttributeValue::S("tenant-a".into())),
            ("user_id".into(), AttributeValue::S("user-a".into())),
        ]);
        assert!(DynamoAdminAuthStore::governance_session_belongs_to_user(
            &indexed, "tenant-a", "user-a"
        )
        .unwrap());
        assert!(!DynamoAdminAuthStore::governance_session_belongs_to_user(
            &indexed, "tenant-a", "user-b"
        )
        .unwrap());

        let legacy = HashMap::from([
            ("record_type".into(), AttributeValue::S("session".into())),
            ("tenant_id".into(), AttributeValue::S("tenant-a".into())),
            (
                "record_json".into(),
                AttributeValue::S(
                    serde_json::to_string(&admin_session("user-a", "tenant-a")).unwrap(),
                ),
            ),
        ]);
        assert!(DynamoAdminAuthStore::governance_session_belongs_to_user(
            &legacy, "tenant-a", "user-a"
        )
        .unwrap());

        let inconsistent = HashMap::from([
            ("record_type".into(), AttributeValue::S("session".into())),
            ("tenant_id".into(), AttributeValue::S("tenant-a".into())),
            (
                "record_json".into(),
                AttributeValue::S(
                    serde_json::to_string(&admin_session("user-a", "tenant-b")).unwrap(),
                ),
            ),
        ]);
        assert!(matches!(
            DynamoAdminAuthStore::governance_session_belongs_to_user(
                &inconsistent,
                "tenant-a",
                "user-a"
            ),
            Err(StoreError::Permanent(_))
        ));
    }

    #[test]
    fn governance_fenced_api_surface_compiles() {
        let _ = DynamoCodeStore::governance_delete_by_user_fenced;
        let _ = DynamoCodeStore::governance_delete_all_by_tenant_fenced;
        let _ = DynamoSessionStore::governance_delete_by_user_fenced;
        let _ = DynamoSessionStore::governance_delete_all_by_tenant_fenced;
        let _ = DynamoRefreshStore::governance_delete_by_user_fenced;
        let _ = DynamoRefreshStore::governance_delete_all_by_tenant_fenced;
        let _ = DynamoRefreshStore::governance_family_ids_by_user;
        let _ = DynamoRefreshStore::governance_family_ids_by_tenant;
        let _ = DynamoGraceStore::governance_delete_family_fenced;
        let _ = DynamoPasskeyChallengeStore::governance_delete_by_user_fenced;
        let _ = DynamoPasskeyChallengeStore::governance_delete_all_by_tenant_fenced;
        let _ = DynamoPasskeyStore::governance_delete_by_user_fenced;
        let _ = DynamoPasskeyStore::governance_delete_all_by_tenant_fenced;
        let _ = DynamoGrantStore::governance_delete_by_user_fenced;
        let _ = DynamoGrantStore::governance_delete_all_by_tenant_fenced;
        let _ = DynamoJtiStore::governance_delete_by_user_fenced;
        let _ = DynamoJtiStore::governance_delete_all_by_tenant_fenced;
        let _ = DynamoCibaStore::governance_delete_by_user_fenced;
        let _ = DynamoCibaStore::governance_delete_all_by_tenant_fenced;
        let _ = DynamoDeviceStore::governance_delete_by_user_fenced;
        let _ = DynamoDeviceStore::governance_delete_all_by_tenant_fenced;
        let _ = DynamoRecoveryStore::governance_delete_by_lookup_fenced;
        let _ = DynamoRecoveryStore::governance_delete_all_by_tenant_fenced;
        let _ = DynamoPasswordStore::governance_delete_fenced;
        let _ = DynamoPasswordStore::governance_delete_all_by_tenant_fenced;
        let _ = DynamoMagicLinkStore::governance_delete_by_user_fenced;
        let _ = DynamoMagicLinkStore::governance_delete_all_by_tenant_fenced;
        let _ = DynamoInvitationStore::governance_delete_by_user_fenced;
        let _ = DynamoInvitationStore::governance_delete_all_by_tenant_fenced;
        let _ = DynamoNotifier::governance_delete_by_recipients_fenced;
        let _ = DynamoNotifier::governance_delete_all_by_tenant_fenced;
        let _ = DynamoFederationFlowStore::governance_delete_all_by_tenant_fenced;
        let _ = DynamoParStore::governance_delete_all_by_tenant_fenced;
        let _ = DynamoReplayStore::governance_delete_all_by_tenant_fenced;
        let _ = DynamoAuthzSessionStore::governance_delete_by_client_fenced;
        let _ = DynamoAuthzSessionStore::governance_delete_all_by_tenant_fenced;
        let _ = DynamoClientStore::governance_delete_fenced;
        let _ = DynamoInitialAccessTokenStore::governance_delete_fenced;
        let _ = DynamoWorkloadTrustStore::governance_delete_all_by_tenant_fenced;
        let _ = DynamoFederationConfigStore::governance_delete_all_by_tenant_fenced;
        let _ = DynamoAdminAuthStore::governance_delete_all_by_tenant_fenced;
        let _ = DynamoAdminAuthStore::governance_delete_sessions_by_user_fenced;
        let _ = DynamoDomainMapStore::governance_delete_if_owner_fenced;
        let _ = DynamoDomainMapStore::governance_delete_all_by_tenant_fenced;
        let _ = DynamoPolicyArtifactStore::governance_delete_all_by_tenant_fenced;
        let _ = DynamoPolicyVersionStore::governance_delete_fenced;
        let _ = DynamoRateLimitStore::governance_delete_fenced;
        let _ = DynamoRateLimitStore::governance_delete_all_by_tenant_fenced;

        let _ = DynamoCodeStore::governance_count_by_user;
        let _ = DynamoCodeStore::governance_count_all_by_tenant;
        let _ = DynamoSessionStore::governance_count_by_user;
        let _ = DynamoSessionStore::governance_count_all_by_tenant;
        let _ = DynamoGraceStore::governance_count_family;
        let _ = DynamoPasskeyChallengeStore::governance_count_by_user;
        let _ = DynamoPasskeyChallengeStore::governance_count_all_by_tenant;
        let _ = DynamoPasskeyStore::governance_count_by_user;
        let _ = DynamoPasskeyStore::governance_count_all_by_tenant;
        let _ = DynamoGrantStore::governance_count_by_user;
        let _ = DynamoGrantStore::governance_count_all_by_tenant;
        let _ = DynamoJtiStore::governance_count_by_user;
        let _ = DynamoJtiStore::governance_count_all_by_tenant;
        let _ = DynamoCibaStore::governance_count_by_user;
        let _ = DynamoCibaStore::governance_count_all_by_tenant;
        let _ = DynamoDeviceStore::governance_count_by_user;
        let _ = DynamoDeviceStore::governance_count_all_by_tenant;
        let _ = DynamoRecoveryStore::governance_count_by_lookup;
        let _ = DynamoRecoveryStore::governance_count_all_by_tenant;
        let _ = DynamoPasswordStore::governance_count_by_user;
        let _ = DynamoPasswordStore::governance_count_all_by_tenant;
        let _ = DynamoMagicLinkStore::governance_count_by_user;
        let _ = DynamoMagicLinkStore::governance_count_all_by_tenant;
        let _ = DynamoInvitationStore::governance_count_by_user;
        let _ = DynamoInvitationStore::governance_count_all_by_tenant;
        let _ = DynamoNotifier::governance_count_by_recipients;
        let _ = DynamoNotifier::governance_count_all_by_tenant;
        let _ = DynamoFederationFlowStore::governance_count_all_by_tenant;
        let _ = DynamoParStore::governance_count_all_by_tenant;
        let _ = DynamoReplayStore::governance_count_all_by_tenant;
        let _ = DynamoAuthzSessionStore::governance_count_all_by_tenant;
        let _ = DynamoClientStore::governance_count_all_by_tenant;
        let _ = DynamoInitialAccessTokenStore::governance_count_all_by_tenant;
        let _ = DynamoWorkloadTrustStore::governance_count_all_by_tenant;
        let _ = DynamoFederationConfigStore::governance_count_all_by_tenant;
        let _ = DynamoAdminAuthStore::governance_count_all_by_tenant;
        let _ = DynamoAdminAuthStore::governance_count_sessions_by_user;
        let _ = DynamoDomainMapStore::governance_count_all_by_tenant;
        let _ = DynamoPolicyArtifactStore::governance_count_all_by_tenant;
        let _ = DynamoPolicyVersionStore::governance_count;
        let _ = DynamoRateLimitStore::governance_count_all_by_tenant;
    }
}
