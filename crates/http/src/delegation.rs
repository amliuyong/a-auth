//! Durable delegation authority shared by token exchange and RS introspection.
//! Contract: docs/BOUNDED_DELEGATION.md (Issue #45).

use agent_auth_grant::{actor_matches, GrantConstraints};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

use crate::ports::{
    ClientStore, GrantStore, JtiRecord, JtiStore, PolicyVersionStore, RefreshStore, StoreError,
};
use crate::state::AppState;

pub(crate) const MAX_DEPTH: u32 = 8;

/// Stored only by the AS after signing. Never accepted as caller-supplied proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationRecord {
    pub version: u32,
    pub revoked: bool,
    pub credential_epoch: u64,
    pub token_sha256: String,
    pub issuer: String,
    pub subject: String,
    pub resource: String,
    pub scope: Vec<String>,
    pub actor: String,
    pub parent_jti: String,
    pub auth_grant: String,
    pub depth: u32,
    pub constraints: GrantConstraints,
    pub authorization_details: Vec<Value>,
    pub cnf_jkt: Option<String>,
    pub allowed_ip_cidrs: Vec<String>,
    pub allowed_vpce: Vec<String>,
}

pub(crate) fn token_digest(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

/// Newest-first internally; the RS contract explicitly presents oldest-first.
pub(crate) struct VerifiedLineage {
    pub records: Vec<JtiRecord>,
}

/// Authenticated introspection extension. Actor and hop order is oldest-first.
#[derive(Debug, Serialize, ToSchema)]
pub struct DelegationLineage {
    pub version: u32,
    pub issuer: String,
    pub subject: String,
    pub resource: String,
    pub current_actor: String,
    pub actors: Vec<String>,
    pub source_grant: String,
    pub checked_at: i64,
    pub hops: Vec<DelegationHop>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DelegationHop {
    pub jti: String,
    pub actor: String,
    pub parent_jti: String,
    pub auth_grant: String,
    pub resource: String,
    pub scope: Vec<String>,
    pub expires_at: i64,
}

impl VerifiedLineage {
    pub fn parent(&self) -> &DelegationRecord {
        self.records[0]
            .delegation
            .as_ref()
            .expect("validated delegation")
    }

    pub fn permits_actor(&self, actor: &str) -> bool {
        let depth = self.parent().depth + 1;
        depth <= MAX_DEPTH
            && self.records.iter().all(|record| {
                let delegation = record.delegation.as_ref().expect("validated delegation");
                depth <= delegation.constraints.max_act_chain
                    && delegation
                        .constraints
                        .actor_allowlist
                        .iter()
                        .any(|pattern| actor_matches(pattern, actor))
            })
    }

    pub fn response(&self, checked_at: i64) -> DelegationLineage {
        let current = self.parent();
        let hops = self
            .records
            .iter()
            .rev()
            .map(|record| {
                let hop = record.delegation.as_ref().expect("validated delegation");
                DelegationHop {
                    jti: record.jti.clone(),
                    actor: hop.actor.clone(),
                    parent_jti: hop.parent_jti.clone(),
                    auth_grant: hop.auth_grant.clone(),
                    resource: hop.resource.clone(),
                    scope: hop.scope.clone(),
                    expires_at: record.expires_at,
                }
            })
            .collect();
        DelegationLineage {
            version: 1,
            issuer: current.issuer.clone(),
            subject: current.subject.clone(),
            resource: current.resource.clone(),
            current_actor: current.actor.clone(),
            actors: self
                .records
                .iter()
                .rev()
                .map(|record| record.delegation.as_ref().unwrap().actor.clone())
                .collect(),
            source_grant: self.records[0]
                .grant_id
                .clone()
                .expect("validated source Grant"),
            checked_at,
            hops,
        }
    }
}

fn unavailable() -> StoreError {
    StoreError::Transient("delegation authority unavailable".into())
}

/// The caller is already authenticated and the claims already signature-verified.
/// Unknown/foreign tokens are a no-op; storage failures are never reported as success.
pub(crate) async fn revoke(
    state: &AppState,
    tenant: &str,
    caller_id: &str,
    token: &str,
    claims: &Value,
) -> Result<(), StoreError> {
    let Some(jti) = claims.get("jti").and_then(Value::as_str) else {
        return Ok(());
    };
    let tenant_id = if tenant.is_empty() { "default" } else { tenant };
    let store = state.jti_store.as_ref().ok_or_else(unavailable)?;
    let Some(record) = store.get(tenant_id, jti).await? else {
        return Ok(());
    };
    if record.tenant_id != tenant_id
        || record.jti != jti
        || !record
            .delegation
            .as_ref()
            .is_some_and(|delegation| delegation.token_sha256 == token_digest(token))
    {
        return Ok(());
    }
    let Some(family_id) = record.family_id.as_deref() else {
        return Ok(());
    };
    if state
        .refresh
        .get(tenant, family_id)
        .await?
        .is_some_and(|family| family.client_id == caller_id && family.user_id == record.user_id)
    {
        store.revoke_delegation(tenant_id, jti).await?;
    }
    Ok(())
}

/// Input claims must already have passed signature/issuer verification.
/// None means inactive, including legacy act tokens without durable lineage.
pub(crate) async fn validate(
    state: &AppState,
    tenant: &str,
    tenant_id: &str,
    token: &str,
    claims: &Value,
) -> Result<Option<VerifiedLineage>, StoreError> {
    let Some(jti) = claims.get("jti").and_then(Value::as_str) else {
        return Ok(None);
    };
    let store = state.jti_store.as_ref().ok_or_else(unavailable)?;
    let Some(mut record) = store.get(tenant_id, jti).await? else {
        return Ok(None);
    };
    let Some(leaf) = record.delegation.as_ref() else {
        return Ok(None);
    };
    if leaf.token_sha256 != token_digest(token)
        || claims.get("iss").and_then(Value::as_str) != Some(leaf.issuer.as_str())
        || claims.get("sub").and_then(Value::as_str) != Some(leaf.subject.as_str())
        || crate::verify::single_aud_strict(claims).as_deref() != Some(leaf.resource.as_str())
        || claims.get("exp").and_then(Value::as_i64) != Some(record.expires_at)
        || claims.get("scope").and_then(Value::as_str) != Some(leaf.scope.join(" ").as_str())
        || claims
            .get(agent_auth_token::NAMESPACE)
            .and_then(|ns| ns.get("auth_grant"))
            .and_then(Value::as_str)
            != Some(leaf.auth_grant.as_str())
        || agent_auth_token::act_chain_depth(claims) != leaf.depth
        || leaf.depth == 0
        || leaf.depth > MAX_DEPTH
        || record.jti != jti
        || record.tenant_id != tenant_id
        || !state.region.owns_id(jti)
    {
        return Ok(None);
    }
    let leaf = leaf.clone();
    let root_user = record.user_id.clone();
    let family_id = record.family_id.clone();
    let source_grant = record.grant_id.clone();
    let mut records: Vec<JtiRecord> = Vec::new();
    let mut act = claims.get("act");
    while let Some(hop) = record.delegation.as_ref() {
        let now = crate::token::current_unix_secs_pub();
        if records.len() >= MAX_DEPTH as usize
            || hop.version != 1
            || hop.revoked
            || record.expires_at <= now
            || record.tenant_id != tenant_id
            || record.user_id != root_user
            || record.family_id != family_id
            || record.grant_id != source_grant
            || hop.issuer != leaf.issuer
            || hop.subject != leaf.subject
            || hop.resource != leaf.resource
            || hop.auth_grant != leaf.auth_grant
            || hop.depth as usize + records.len() != leaf.depth as usize
            || act
                .and_then(|value| value.get("sub"))
                .and_then(Value::as_str)
                != Some(hop.actor.as_str())
            || !state.region.owns_id(&record.jti)
        {
            return Ok(None);
        }
        if let Some(child) = records.last() {
            let child_hop = child.delegation.as_ref().unwrap();
            if child.expires_at > record.expires_at
                || child_hop
                    .scope
                    .iter()
                    .any(|scope| !hop.scope.contains(scope))
                || !hop.authorization_details.is_empty()
                || hop.cnf_jkt.is_some()
            {
                return Ok(None);
            }
        }
        // Current authorization and the issuance-time ceiling both constrain
        // every descendant, including after an administrator widens a Grant.
        let Some(grant) = state.grants.get(tenant, &hop.auth_grant).await? else {
            return Ok(None);
        };
        if grant.user_id != root_user
            || grant.credential_epoch != hop.credential_epoch
            || grant.is_usable(now).is_err()
            || grant.constraints.expires_at < record.expires_at
            || grant.constraints.max_act_chain < leaf.depth
            || hop.constraints.max_act_chain < leaf.depth
            || grant.allowed_ip_cidrs != hop.allowed_ip_cidrs
            || grant.allowed_vpce != hop.allowed_vpce
        {
            return Ok(None);
        }
        let Some(resource) = grant.resource_grant(&hop.resource) else {
            return Ok(None);
        };
        if hop
            .scope
            .iter()
            .any(|scope| !resource.scopes.contains(scope))
            || resource.authorization_details != hop.authorization_details
        {
            return Ok(None);
        }
        if state.authz_enabled && grant.effective_pv < state.policy_versions.get(tenant).await? {
            return Err(unavailable());
        }
        for actor in records
            .iter()
            .filter_map(|record| record.delegation.as_ref())
            .map(|hop| &hop.actor)
            .chain(std::iter::once(&hop.actor))
        {
            if !grant
                .constraints
                .actor_allowlist
                .iter()
                .any(|p| actor_matches(p, actor))
                || !hop
                    .constraints
                    .actor_allowlist
                    .iter()
                    .any(|p| actor_matches(p, actor))
            {
                return Ok(None);
            }
        }
        let Some(client) = state.clients.get(tenant, &hop.actor).await? else {
            return Ok(None);
        };
        if client.is_tombstoned()
            || !client.is_workload()
            || (client.require_dpop && hop.cnf_jkt.is_none())
        {
            return Ok(None);
        }
        let parent_jti = hop.parent_jti.clone();
        act = act.and_then(|value| value.get("act"));
        records.push(record);
        let Some(parent) = store.get(tenant_id, &parent_jti).await? else {
            return Ok(None);
        };
        if parent.jti != parent_jti {
            return Ok(None);
        }
        record = parent;
    }
    let now = crate::token::current_unix_secs_pub();
    if records.len() != leaf.depth as usize
        || act.is_some()
        || record.tenant_id != tenant_id
        || record.user_id != root_user
        || record.family_id != family_id
        || record.grant_id != source_grant
        || record.expires_at <= now
        || records
            .iter()
            .any(|child| child.expires_at > record.expires_at || child.expires_at <= now)
    {
        return Ok(None);
    }
    let (Some(family_id), Some(source_grant)) = (family_id, source_grant) else {
        return Ok(None);
    };
    let Some(family) = state.refresh.get(tenant, &family_id).await? else {
        return Ok(None);
    };
    let Some(grant) = state.grants.get(tenant, &source_grant).await? else {
        return Ok(None);
    };
    if source_grant != family_id
        || family.revoked
        || family.user_id != root_user
        || grant.user_id != root_user
        || grant.credential_epoch != family.credential_epoch
        || records.iter().any(|record| {
            record.delegation.as_ref().unwrap().credential_epoch != family.credential_epoch
        })
        || grant
            .is_usable(crate::token::current_unix_secs_pub())
            .is_err()
        || records
            .iter()
            .any(|record| record.expires_at > grant.constraints.expires_at)
    {
        return Ok(None);
    }
    match crate::user_gate::require_password_authority_version(
        state,
        tenant,
        &root_user,
        family.password_credential_version,
    )
    .await
    {
        crate::user_gate::PasswordGate::Allowed => {}
        crate::user_gate::PasswordGate::ChangeRequired => return Ok(None),
        crate::user_gate::PasswordGate::Unavailable => return Err(unavailable()),
    }
    match crate::user_gate::active_existing_canonical_user_epoch(state, tenant, &root_user).await {
        Ok(epoch) if epoch == family.credential_epoch => {}
        Ok(_) => return Ok(None),
        Err(crate::user_gate::UserGate::Unavailable) => return Err(unavailable()),
        Err(_) => return Ok(None),
    }
    Ok(Some(VerifiedLineage { records }))
}
