//! MCP Client ID Metadata Document resolution.
//!
//! Registered clients always win. Unknown URL-form client IDs may be resolved
//! only when a tenant-scoped domain policy is active.

use crate::ports::{ClientRecord, ClientStore, RegisteredClientJwks, StoreError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{Mutex, Semaphore};
use url::Url;

pub const MAX_DOCUMENT_BYTES: usize = 5 * 1024;
const MAX_REDIRECTS: usize = 3;
const MAX_CACHE_ENTRIES: usize = 256;
const MAX_LOCAL_TTL_SECS: i64 = 300;
const DEFAULT_TTL_SECS: i64 = 60;
const FETCH_TIMEOUT: Duration = Duration::from_secs(6);
const MAX_CONCURRENT_FETCHES: usize = 4;
const MAX_FETCH_BUDGETS: usize = 256;
const FETCH_BURST: f64 = 8.0;
const FETCH_REFILL_PER_SEC: f64 = 0.5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CimdClientSnapshot {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<RegisteredClientJwks>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token_signed_response_alg: Option<String>,
}

impl CimdClientSnapshot {
    pub fn digest(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("CIMD snapshot is serializable");
        URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
    }

    pub fn as_client_record(&self) -> ClientRecord {
        ClientRecord {
            client_id: self.client_id.clone(),
            redirect_uris: self.redirect_uris.clone(),
            application_type: None,
            token_endpoint_auth_method: self.token_endpoint_auth_method.clone(),
            client_secret: None,
            client_secret_credentials: Default::default(),
            jwks: self.jwks.clone(),
            jwks_uri: None,
            token_endpoint_auth_signing_alg: self.token_endpoint_auth_signing_alg.clone(),
            default_resource: self.default_resource.clone(),
            introspect_enabled: false,
            resource_ids: vec![],
            post_logout_redirect_uris: vec![],
            reg_token_hash: None,
            registration_token_credentials: Default::default(),
            client_type: None,
            id_token_signed_response_alg: self.id_token_signed_response_alg.clone(),
            oidc_sector_identifier: agent_auth_token::oidc_sector_from_redirect_hosts(
                &self.redirect_uris,
            ),
            allowed_resources: vec![],
            allowed_scopes: vec![],
            redirect_mode: None,
            created_at: 0,
            last_used_day: None,
            authority_revision: 0,
            tombstoned_at: None,
            backchannel_token_delivery_mode: None,
            backchannel_client_notification_endpoint: None,
            require_dpop: false,
            prm_domains: vec![],
        }
    }

    pub fn audit_identifier(&self) -> String {
        cimd_audit_identifier(&self.client_id)
    }
}

fn continuation_nonce(client_id: &str, digest: &str) -> String {
    serde_json::to_string(&(client_id, digest)).expect("CIMD continuation tuple is serializable")
}

pub fn continuation_binding(
    secret: &[u8],
    authz_session_id: &str,
    client_id: &str,
    digest: &str,
) -> String {
    agent_auth_infra_core::websec::csrf_token(
        secret,
        authz_session_id,
        &continuation_nonce(client_id, digest),
    )
}

pub fn verify_continuation_binding(
    secret: &[u8],
    authz_session_id: &str,
    client_id: &str,
    digest: &str,
    presented: &str,
) -> bool {
    agent_auth_infra_core::websec::csrf_verify(
        secret,
        authz_session_id,
        &continuation_nonce(client_id, digest),
        presented,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientSource {
    Registered,
    Cimd,
}

#[derive(Debug, Clone)]
pub struct ResolvedClient {
    pub client: ClientRecord,
    pub source: ClientSource,
    pub cimd_snapshot: Option<CimdClientSnapshot>,
}

impl ResolvedClient {
    pub fn cimd_digest(&self) -> Option<String> {
        self.cimd_snapshot.as_ref().map(CimdClientSnapshot::digest)
    }

    pub fn audit_identifier(&self) -> String {
        match self.source {
            ClientSource::Registered => self.client.client_id.clone(),
            ClientSource::Cimd => cimd_audit_identifier(&self.client.client_id),
        }
    }
}

fn cimd_audit_identifier(client_id: &str) -> String {
    Url::parse(client_id)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .map(|host| format!("cimd-host:{host}"))
        .unwrap_or_else(|| "cimd-host:invalid".to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveClientError {
    Unknown,
    Invalid(String),
    TemporarilyUnavailable,
    Store,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CimdFetchError {
    UnsafeTarget,
    TemporarilyUnavailable,
    InvalidResponse,
}

#[derive(Debug, Clone, Default)]
pub struct CimdHttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub location: Option<String>,
    pub cache_control: Option<String>,
    pub expires: Option<String>,
    pub age: Option<u64>,
}

pub trait CimdHttpClient: Send + Sync {
    fn get<'a>(
        &'a self,
        url: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<CimdHttpResponse, CimdFetchError>> + Send + 'a>>;
}

#[derive(Debug, Clone, Default)]
pub struct CimdTrustPolicy {
    global_domains: BTreeSet<String>,
    tenant_domains: HashMap<String, BTreeSet<String>>,
}

impl CimdTrustPolicy {
    pub fn new(
        global_domains: impl IntoIterator<Item = String>,
        tenant_domains: HashMap<String, Vec<String>>,
    ) -> Result<Self, String> {
        let global_domains = normalize_domain_set(global_domains)?;
        let tenant_domains = tenant_domains
            .into_iter()
            .map(|(tenant, domains)| {
                if tenant.trim().is_empty() {
                    return Err("CIMD tenant policy key must not be empty".to_string());
                }
                Ok((tenant, normalize_domain_set(domains)?))
            })
            .collect::<Result<HashMap<_, _>, String>>()?;
        Ok(Self {
            global_domains,
            tenant_domains,
        })
    }

    pub fn has_any_domain(&self) -> bool {
        !self.global_domains.is_empty()
            || self
                .tenant_domains
                .values()
                .any(|domains| !domains.is_empty())
    }

    pub fn configured_for_tenant(&self, tenant: &str) -> bool {
        !self.global_domains.is_empty()
            || self
                .tenant_domains
                .get(tenant)
                .is_some_and(|domains| !domains.is_empty())
    }

    fn allows(&self, tenant: &str, host: &str) -> bool {
        self.global_domains.contains(host)
            || self
                .tenant_domains
                .get(tenant)
                .is_some_and(|domains| domains.contains(host))
    }
}

fn normalize_domain_set(
    domains: impl IntoIterator<Item = String>,
) -> Result<BTreeSet<String>, String> {
    domains
        .into_iter()
        .map(|domain| {
            let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
            if domain.is_empty()
                || domain.contains(['/', ':', '@', '*', '?', '#'])
                || domain.parse::<std::net::IpAddr>().is_ok()
            {
                return Err(format!("invalid CIMD allowed domain: {domain}"));
            }
            let parsed = Url::parse(&format!("https://{domain}/metadata"))
                .map_err(|_| format!("invalid CIMD allowed domain: {domain}"))?;
            let host = parsed
                .host_str()
                .ok_or_else(|| format!("invalid CIMD allowed domain: {domain}"))?;
            if host != domain {
                return Err(format!(
                    "CIMD allowed domain must use canonical ASCII form: {domain}"
                ));
            }
            Ok(domain)
        })
        .collect()
}

#[derive(Clone)]
struct CacheEntry {
    snapshot: CimdClientSnapshot,
    expires_at: i64,
    last_used_at: i64,
}

type CacheKey = (String, String);

struct FetchBudget {
    tokens: f64,
    last_refill: Instant,
    last_used: Instant,
}

pub struct CimdResolver {
    enabled: bool,
    policy: CimdTrustPolicy,
    client: Arc<dyn CimdHttpClient>,
    cache: Mutex<HashMap<CacheKey, CacheEntry>>,
    locks: Mutex<HashMap<CacheKey, Weak<Mutex<()>>>>,
    fetch_budgets: Mutex<HashMap<(String, String), FetchBudget>>,
    fetch_slots: Semaphore,
    fetch_burst: f64,
    fetch_refill_per_sec: f64,
    fetch_timeout: Duration,
}

impl CimdResolver {
    pub fn new(
        enabled: bool,
        policy: CimdTrustPolicy,
        client: Arc<dyn CimdHttpClient>,
    ) -> Result<Self, String> {
        if enabled && !policy.has_any_domain() {
            return Err(
                "AGENT_AUTH_CIMD_ENABLED=1 requires a non-empty domain allowlist".to_string(),
            );
        }
        Ok(Self {
            enabled,
            policy,
            client,
            cache: Mutex::new(HashMap::new()),
            locks: Mutex::new(HashMap::new()),
            fetch_budgets: Mutex::new(HashMap::new()),
            fetch_slots: Semaphore::new(MAX_CONCURRENT_FETCHES),
            fetch_burst: FETCH_BURST,
            fetch_refill_per_sec: FETCH_REFILL_PER_SEC,
            fetch_timeout: FETCH_TIMEOUT,
        })
    }

    pub fn disabled() -> Self {
        Self::new(
            false,
            CimdTrustPolicy::default(),
            Arc::new(MemoryCimdHttpClient::default()),
        )
        .expect("disabled CIMD config")
    }

    pub fn active_for_tenant(&self, tenant: &str) -> bool {
        self.enabled && self.policy.configured_for_tenant(tenant)
    }

    async fn cache_get(&self, key: &CacheKey, now: i64) -> Option<CimdClientSnapshot> {
        let mut cache = self.cache.lock().await;
        match cache.get_mut(key) {
            Some(entry) if entry.expires_at > now => {
                entry.last_used_at = now;
                Some(entry.snapshot.clone())
            }
            Some(_) => {
                cache.remove(key);
                None
            }
            None => None,
        }
    }

    async fn lock_for(&self, key: &CacheKey) -> Arc<Mutex<()>> {
        let mut locks = self.locks.lock().await;
        if let Some(lock) = locks.get(key).and_then(Weak::upgrade) {
            return lock;
        }
        locks.retain(|_, lock| lock.strong_count() > 0);
        let lock = Arc::new(Mutex::new(()));
        locks.insert(key.clone(), Arc::downgrade(&lock));
        lock
    }

    async fn cache_put(&self, key: CacheKey, snapshot: CimdClientSnapshot, ttl: i64, now: i64) {
        if ttl <= 0 {
            return;
        }
        let mut cache = self.cache.lock().await;
        if !cache.contains_key(&key) && cache.len() >= MAX_CACHE_ENTRIES {
            if let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.last_used_at)
                .map(|(key, _)| key.clone())
            {
                cache.remove(&oldest);
            }
        }
        cache.insert(
            key,
            CacheEntry {
                snapshot,
                expires_at: now.saturating_add(ttl),
                last_used_at: now,
            },
        );
    }

    async fn take_fetch_budget(&self, tenant: &str, url: &str) -> bool {
        let Some(host) = Url::parse(url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_string))
        else {
            return false;
        };
        let key = (tenant.to_string(), host);
        let now = Instant::now();
        let mut budgets = self.fetch_budgets.lock().await;
        if !budgets.contains_key(&key) && budgets.len() >= MAX_FETCH_BUDGETS {
            let reusable = budgets
                .iter()
                .filter(|(_, budget)| {
                    (budget.tokens
                        + now.duration_since(budget.last_refill).as_secs_f64()
                            * self.fetch_refill_per_sec)
                        .min(self.fetch_burst)
                        >= self.fetch_burst
                })
                .min_by_key(|(_, budget)| budget.last_used)
                .map(|(key, _)| key.clone());
            let Some(reusable) = reusable else {
                return false;
            };
            budgets.remove(&reusable);
        }
        let budget = budgets.entry(key).or_insert(FetchBudget {
            tokens: self.fetch_burst,
            last_refill: now,
            last_used: now,
        });
        let elapsed = now.duration_since(budget.last_refill).as_secs_f64();
        budget.tokens = (budget.tokens + elapsed * self.fetch_refill_per_sec).min(self.fetch_burst);
        budget.last_refill = now;
        budget.last_used = now;
        if budget.tokens < 1.0 {
            return false;
        }
        budget.tokens -= 1.0;
        true
    }

    pub async fn resolve(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> Result<CimdClientSnapshot, ResolveClientError> {
        if !self.active_for_tenant(tenant) {
            return Err(ResolveClientError::Unknown);
        }
        validate_metadata_url(client_id, tenant, &self.policy)?;
        let key = (tenant.to_string(), client_id.to_string());
        let now = crate::token::current_unix_secs_pub();
        if let Some(snapshot) = self.cache_get(&key, now).await {
            return Ok(snapshot);
        }
        let lock = self.lock_for(&key).await;
        tokio::time::timeout(self.fetch_timeout, async {
            let _guard = lock.lock().await;
            let now = crate::token::current_unix_secs_pub();
            if let Some(snapshot) = self.cache_get(&key, now).await {
                return Ok(snapshot);
            }
            let (snapshot, ttl) = self.fetch_document(tenant, client_id).await?;
            self.cache_put(key, snapshot.clone(), ttl, now).await;
            Ok(snapshot)
        })
        .await
        .map_err(|_| ResolveClientError::TemporarilyUnavailable)?
    }

    async fn fetch_document(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> Result<(CimdClientSnapshot, i64), ResolveClientError> {
        let mut current = client_id.to_string();
        for redirect_count in 0..=MAX_REDIRECTS {
            validate_metadata_url(&current, tenant, &self.policy)?;
            let permit = self
                .fetch_slots
                .try_acquire()
                .map_err(|_| ResolveClientError::TemporarilyUnavailable)?;
            if !self.take_fetch_budget(tenant, &current).await {
                return Err(ResolveClientError::TemporarilyUnavailable);
            }
            let response = self
                .client
                .get(&current)
                .await
                .map_err(|error| match error {
                    CimdFetchError::TemporarilyUnavailable => {
                        ResolveClientError::TemporarilyUnavailable
                    }
                    CimdFetchError::UnsafeTarget | CimdFetchError::InvalidResponse => {
                        ResolveClientError::Invalid("CIMD fetch rejected".to_string())
                    }
                })?;
            drop(permit);
            if is_redirect(response.status) {
                if redirect_count == MAX_REDIRECTS {
                    return Err(ResolveClientError::Invalid(
                        "CIMD redirect limit exceeded".to_string(),
                    ));
                }
                let location = response.location.ok_or_else(|| {
                    ResolveClientError::Invalid("CIMD redirect missing Location".to_string())
                })?;
                current = Url::parse(&current)
                    .and_then(|base| base.join(&location))
                    .map_err(|_| ResolveClientError::Invalid("invalid CIMD redirect".to_string()))?
                    .to_string();
                continue;
            }
            if response.status != 200 {
                return Err(ResolveClientError::Invalid(format!(
                    "CIMD returned HTTP {}",
                    response.status
                )));
            }
            if response.body.len() > MAX_DOCUMENT_BYTES {
                return Err(ResolveClientError::Invalid(
                    "CIMD response exceeds 5 KiB".to_string(),
                ));
            }
            let snapshot = parse_document(client_id, &response.body)?;
            let ttl = cache_ttl(&response, SystemTime::now());
            return Ok((snapshot, ttl));
        }
        unreachable!("redirect loop is bounded")
    }
}

pub async fn resolve_client(
    state: &crate::state::AppState,
    tenant: &str,
    client_id: &str,
) -> Result<ResolvedClient, ResolveClientError> {
    match state.clients.get(tenant, client_id).await {
        Ok(Some(client)) => {
            return Ok(ResolvedClient {
                client,
                source: ClientSource::Registered,
                cimd_snapshot: None,
            })
        }
        Ok(None) => {}
        Err(StoreError::Transient(_)) => return Err(ResolveClientError::TemporarilyUnavailable),
        Err(StoreError::Permanent(_)) => return Err(ResolveClientError::Store),
    }
    if !state.cimd_active_for_tenant(tenant) {
        return Err(ResolveClientError::Unknown);
    }
    let snapshot = state.cimd.resolve(tenant, client_id).await?;
    if state
        .registered_client_auth_method(&snapshot.token_endpoint_auth_method)
        .is_none()
    {
        return Err(ResolveClientError::Invalid(
            "CIMD client authentication method is unavailable".to_string(),
        ));
    }
    Ok(ResolvedClient {
        client: snapshot.as_client_record(),
        source: ClientSource::Cimd,
        cimd_snapshot: Some(snapshot),
    })
}

fn validate_metadata_url(
    value: &str,
    tenant: &str,
    policy: &CimdTrustPolicy,
) -> Result<(), ResolveClientError> {
    if value.len() > 2048 || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(ResolveClientError::Invalid(
            "invalid CIMD client ID URL".to_string(),
        ));
    }
    agent_auth_ciba::validate_endpoint_url(value, None).map_err(|_| {
        ResolveClientError::Invalid("CIMD client ID must be a safe HTTPS URL".to_string())
    })?;
    let url = Url::parse(value)
        .map_err(|_| ResolveClientError::Invalid("invalid CIMD client ID URL".to_string()))?;
    if url.path().is_empty() || url.path() == "/" || url.query().is_some() {
        return Err(ResolveClientError::Invalid(
            "CIMD client ID requires a non-root path and no query".to_string(),
        ));
    }
    if raw_path_has_dot_segment(value) {
        return Err(ResolveClientError::Invalid(
            "CIMD client ID path contains dot segments".to_string(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| ResolveClientError::Invalid("CIMD host missing".to_string()))?;
    if !policy.allows(tenant, host) {
        return Err(ResolveClientError::Invalid(
            "CIMD domain is not trusted for this tenant".to_string(),
        ));
    }
    Ok(())
}

fn raw_path_has_dot_segment(value: &str) -> bool {
    let Some(after_scheme) = value.strip_prefix("https://") else {
        return true;
    };
    let path = after_scheme
        .find('/')
        .map(|index| &after_scheme[index..])
        .unwrap_or("");
    let path = path.split('?').next().unwrap_or(path);
    path.split('/').any(|segment| {
        let decoded = percent_encoding::percent_decode_str(segment)
            .decode_utf8_lossy()
            .to_string();
        decoded == "." || decoded == ".."
    })
}

#[derive(Deserialize)]
struct CimdDocument {
    client_id: String,
    client_name: String,
    redirect_uris: Vec<String>,
    #[serde(default)]
    token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    jwks: Option<RegisteredClientJwks>,
    #[serde(default)]
    jwks_uri: Option<String>,
    #[serde(default)]
    token_endpoint_auth_signing_alg: Option<String>,
    #[serde(default)]
    default_resource: Option<String>,
    #[serde(default)]
    id_token_signed_response_alg: Option<String>,
}

fn parse_document(
    requested_client_id: &str,
    body: &[u8],
) -> Result<CimdClientSnapshot, ResolveClientError> {
    let doc: CimdDocument = serde_json::from_slice(body)
        .map_err(|_| ResolveClientError::Invalid("CIMD is not valid JSON".to_string()))?;
    if doc.client_id != requested_client_id {
        return Err(ResolveClientError::Invalid(
            "CIMD client_id does not exactly match its URL".to_string(),
        ));
    }
    if doc.client_name.trim().is_empty()
        || doc.client_name.len() > 200
        || doc
            .client_name
            .bytes()
            .any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err(ResolveClientError::Invalid(
            "CIMD client_name is invalid".to_string(),
        ));
    }
    if doc.redirect_uris.is_empty() || doc.redirect_uris.len() > 20 {
        return Err(ResolveClientError::Invalid(
            "CIMD redirect_uris must be non-empty and bounded".to_string(),
        ));
    }
    for redirect_uri in &doc.redirect_uris {
        if !matches!(
            agent_auth_client::match_redirect(
                &agent_auth_client::RedirectMode::Exact,
                redirect_uri,
                redirect_uri,
            ),
            agent_auth_client::MatchResult::Allow
        ) {
            return Err(ResolveClientError::Invalid(
                "CIMD contains an invalid redirect URI".to_string(),
            ));
        }
    }
    let auth_method = doc
        .token_endpoint_auth_method
        .unwrap_or_else(|| "none".to_string());
    match auth_method.as_str() {
        "none" => {
            if doc.jwks.is_some()
                || doc.jwks_uri.is_some()
                || doc.token_endpoint_auth_signing_alg.is_some()
            {
                return Err(ResolveClientError::Invalid(
                    "public CIMD client must not declare key authentication metadata".to_string(),
                ));
            }
        }
        "private_key_jwt" => {
            if doc.jwks_uri.is_some() {
                return Err(ResolveClientError::Invalid(
                    "CIMD private_key_jwt currently requires inline jwks".to_string(),
                ));
            }
            crate::client_auth::validate_registration_key_config(
                &auth_method,
                doc.jwks.clone(),
                None,
                doc.token_endpoint_auth_signing_alg.clone(),
            )
            .map_err(|message| ResolveClientError::Invalid(message.to_string()))?;
        }
        _ => {
            return Err(ResolveClientError::Invalid(
                "CIMD shared-secret authentication methods are forbidden".to_string(),
            ))
        }
    }
    if doc
        .id_token_signed_response_alg
        .as_deref()
        .is_some_and(|alg| alg != "RS256" && alg != "ES256")
    {
        return Err(ResolveClientError::Invalid(
            "unsupported CIMD id_token signing algorithm".to_string(),
        ));
    }
    Ok(CimdClientSnapshot {
        client_id: doc.client_id,
        client_name: doc.client_name,
        redirect_uris: doc.redirect_uris,
        token_endpoint_auth_method: auth_method,
        jwks: doc.jwks,
        token_endpoint_auth_signing_alg: doc.token_endpoint_auth_signing_alg,
        default_resource: doc.default_resource.filter(|value| !value.is_empty()),
        id_token_signed_response_alg: doc.id_token_signed_response_alg,
    })
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn cache_ttl(response: &CimdHttpResponse, now: SystemTime) -> i64 {
    let directives = response
        .cache_control
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(|directive| directive.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    if directives.iter().any(|directive| {
        directive == "no-store"
            || directive == "private"
            || directive.starts_with("private=")
            || directive == "no-cache"
            || directive.starts_with("no-cache=")
    }) {
        return 0;
    }
    let age = response.age.unwrap_or(0).min(i64::MAX as u64) as i64;
    let directive_seconds = |name: &str| -> Result<Option<i64>, ()> {
        let mut parsed = None;
        for directive in &directives {
            let Some((directive_name, raw_value)) = directive.split_once('=') else {
                if directive.trim() == name {
                    return Err(());
                }
                continue;
            };
            if directive_name.trim() != name {
                continue;
            }
            if parsed.is_some() {
                return Err(());
            }
            let raw_value = raw_value.trim();
            let value = match (raw_value.strip_prefix('"'), raw_value.strip_suffix('"')) {
                (Some(without_prefix), Some(_)) => without_prefix.strip_suffix('"').ok_or(())?,
                (Some(_), None) | (None, Some(_)) => return Err(()),
                (None, None) => raw_value,
            };
            parsed = Some(
                value
                    .parse::<i64>()
                    .ok()
                    .filter(|seconds| *seconds >= 0)
                    .ok_or(())?,
            );
        }
        Ok(parsed)
    };
    let s_maxage = match directive_seconds("s-maxage") {
        Ok(value) => value,
        Err(()) => return 0,
    };
    let max_age = match directive_seconds("max-age") {
        Ok(value) => value,
        Err(()) => return 0,
    };
    let ttl = s_maxage
        .or(max_age)
        .map(|max_age| max_age.saturating_sub(age))
        .or_else(|| {
            response.expires.as_deref().and_then(|expires| {
                httpdate::parse_http_date(expires)
                    .ok()
                    .map(|expires_at| {
                        expires_at
                            .duration_since(now)
                            .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
                            .unwrap_or(0)
                    })
                    .map(|expires_ttl| expires_ttl.saturating_sub(age))
            })
        })
        .unwrap_or_else(|| DEFAULT_TTL_SECS.saturating_sub(age));
    ttl.clamp(0, MAX_LOCAL_TTL_SECS)
}

#[derive(Clone, Default)]
pub struct MemoryCimdHttpClient {
    responses: Arc<Mutex<MemoryCimdResponses>>,
    requests: Arc<Mutex<HashMap<String, usize>>>,
}

type MemoryCimdResponses = HashMap<String, VecDeque<Result<CimdHttpResponse, CimdFetchError>>>;

impl MemoryCimdHttpClient {
    pub async fn set(&self, url: impl Into<String>, response: CimdHttpResponse) {
        self.responses
            .lock()
            .await
            .insert(url.into(), VecDeque::from([Ok(response)]));
    }

    pub async fn set_sequence(
        &self,
        url: impl Into<String>,
        responses: Vec<Result<CimdHttpResponse, CimdFetchError>>,
    ) {
        self.responses
            .lock()
            .await
            .insert(url.into(), responses.into());
    }

    pub async fn request_count(&self, url: &str) -> usize {
        self.requests.lock().await.get(url).copied().unwrap_or(0)
    }
}

impl CimdHttpClient for MemoryCimdHttpClient {
    fn get<'a>(
        &'a self,
        url: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<CimdHttpResponse, CimdFetchError>> + Send + 'a>> {
        Box::pin(async move {
            *self
                .requests
                .lock()
                .await
                .entry(url.to_string())
                .or_insert(0) += 1;
            let mut responses = self.responses.lock().await;
            let queue = responses
                .get_mut(url)
                .ok_or(CimdFetchError::TemporarilyUnavailable)?;
            if queue.len() > 1 {
                queue
                    .pop_front()
                    .unwrap_or(Err(CimdFetchError::TemporarilyUnavailable))
            } else {
                queue
                    .front()
                    .cloned()
                    .unwrap_or(Err(CimdFetchError::TemporarilyUnavailable))
            }
        })
    }
}

#[cfg(feature = "aws")]
#[derive(Clone, Default)]
pub struct HttpCimdHttpClient;

#[cfg(feature = "aws")]
fn combined_cache_control(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let mut values = headers
        .get_all(reqwest::header::CACHE_CONTROL)
        .iter()
        .peekable();
    values.peek()?;
    let mut combined = String::new();
    for value in values {
        let Ok(value) = value.to_str() else {
            return Some("no-store".to_string());
        };
        if !combined.is_empty() {
            combined.push_str(", ");
        }
        combined.push_str(value);
    }
    Some(combined)
}

#[cfg(feature = "aws")]
async fn fetch_cimd_http_response(
    client: &reqwest::Client,
    url: &str,
) -> Result<CimdHttpResponse, CimdFetchError> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| CimdFetchError::TemporarilyUnavailable)?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_DOCUMENT_BYTES as u64)
    {
        return Err(CimdFetchError::InvalidResponse);
    }
    let status = response.status().as_u16();
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let cache_control = combined_cache_control(response.headers());
    let expires = response
        .headers()
        .get(reqwest::header::EXPIRES)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let age = response
        .headers()
        .get(reqwest::header::AGE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| CimdFetchError::TemporarilyUnavailable)?
    {
        if body.len() + chunk.len() > MAX_DOCUMENT_BYTES {
            return Err(CimdFetchError::InvalidResponse);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(CimdHttpResponse {
        status,
        body,
        location,
        cache_control,
        expires,
        age,
    })
}

#[cfg(feature = "aws")]
impl CimdHttpClient for HttpCimdHttpClient {
    fn get<'a>(
        &'a self,
        url: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<CimdHttpResponse, CimdFetchError>> + Send + 'a>> {
        Box::pin(async move {
            let client = crate::adapters::aws::pinned_https_client(url, Duration::from_secs(3))
                .await
                .map_err(|error| match error {
                    crate::adapters::aws::PinnedHttpsClientError::UnsafeTarget => {
                        CimdFetchError::UnsafeTarget
                    }
                    crate::adapters::aws::PinnedHttpsClientError::DnsResolution
                    | crate::adapters::aws::PinnedHttpsClientError::ClientBuild => {
                        CimdFetchError::TemporarilyUnavailable
                    }
                })?;
            fetch_cimd_http_response(&client, url).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://client.example.com/oauth/client.json";

    fn document(client_id: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "client_id": client_id,
            "client_name": "Example MCP Client",
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "none"
        }))
        .unwrap()
    }

    fn named_document(client_id: &str, client_name: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "client_id": client_id,
            "client_name": client_name,
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "none"
        }))
        .unwrap()
    }

    fn resolver(client: Arc<MemoryCimdHttpClient>) -> CimdResolver {
        CimdResolver::new(
            true,
            CimdTrustPolicy::new(vec!["client.example.com".to_string()], HashMap::new()).unwrap(),
            client,
        )
        .unwrap()
    }

    #[cfg(feature = "transport-test")]
    async fn spawn_cimd_tls_server() -> (
        std::net::SocketAddr,
        reqwest::Certificate,
        tokio::task::JoinHandle<()>,
    ) {
        use rcgen::{generate_simple_self_signed, CertifiedKey};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio_rustls::rustls::ServerConfig;
        use tokio_rustls::TlsAcceptor;

        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["client.example.com".to_string()]).unwrap();
        let trusted_cert = reqwest::Certificate::from_der(cert.der().as_ref()).unwrap();
        let private_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let tls = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], private_key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut request = Vec::new();
                    let mut buffer = [0_u8; 1024];
                    loop {
                        let Ok(read) = stream.read(&mut buffer).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&buffer[..read]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let path = std::str::from_utf8(&request)
                        .ok()
                        .and_then(|request| request.lines().next())
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/");
                    match path {
                        "/ok" => {
                            let response =
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                            let _ = stream.write_all(response).await;
                        }
                        "/redirect" => {
                            let response = format!(
                                "HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:{}/ok\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                address.port()
                            );
                            let _ = stream.write_all(response.as_bytes()).await;
                        }
                        "/oversize" => {
                            let _ = stream
                                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                                .await;
                            let _ = stream.write_all(&vec![b'x'; MAX_DOCUMENT_BYTES + 1]).await;
                        }
                        "/cache" => {
                            let response = b"HTTP/1.1 200 OK\r\nCache-Control: max-age=300\r\nCache-Control: no-store\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                            let _ = stream.write_all(response).await;
                        }
                        "/slow" => {
                            tokio::time::sleep(Duration::from_millis(300)).await;
                            let response =
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                            let _ = stream.write_all(response).await;
                        }
                        _ => {
                            let response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                            let _ = stream.write_all(response).await;
                        }
                    }
                    let _ = stream.shutdown().await;
                });
            }
        });
        (address, trusted_cert, server)
    }

    #[cfg(feature = "transport-test")]
    #[tokio::test]
    async fn http_transport_pins_tls_and_enforces_redirect_size_and_timeout() {
        let (address, trusted_cert, server) = spawn_cimd_tls_server().await;
        let build_client = |timeout| {
            crate::adapters::aws::pinned_https_client_builder_for_addrs(
                "client.example.com",
                &[address],
                timeout,
            )
            .add_root_certificate(trusted_cert.clone())
            .build()
            .unwrap()
        };
        let base_url = format!("https://client.example.com:{}", address.port());
        let client = build_client(Duration::from_secs(2));

        let response = fetch_cimd_http_response(&client, &format!("{base_url}/ok"))
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");

        let response = fetch_cimd_http_response(&client, &format!("{base_url}/redirect"))
            .await
            .unwrap();
        assert_eq!(response.status, 302);
        assert_eq!(
            response.location.as_deref(),
            Some(format!("https://127.0.0.1:{}/ok", address.port()).as_str())
        );

        assert!(matches!(
            fetch_cimd_http_response(&client, &format!("{base_url}/oversize")).await,
            Err(CimdFetchError::InvalidResponse)
        ));

        let response = fetch_cimd_http_response(&client, &format!("{base_url}/cache"))
            .await
            .unwrap();
        assert_eq!(
            cache_ttl(&response, SystemTime::now()),
            0,
            "all Cache-Control field lines must participate in cache policy"
        );

        let short_client = build_client(Duration::from_millis(50));
        assert!(matches!(
            fetch_cimd_http_response(&short_client, &format!("{base_url}/slow")).await,
            Err(CimdFetchError::TemporarilyUnavailable)
        ));
        server.abort();
    }

    #[test]
    fn rejects_root_query_dot_segments_and_untrusted_domains() {
        let policy =
            CimdTrustPolicy::new(vec!["client.example.com".to_string()], HashMap::new()).unwrap();
        for value in [
            "https://client.example.com/",
            "https://client.example.com/meta?secret=x",
            "https://client.example.com/meta#fragment",
            "https://user@client.example.com/meta",
            "https://client.example.com/a/../meta",
            "https://client.example.com/a/%2e%2e/meta",
            "https://client.example.com:8443/meta",
            "https://other.example.com/meta",
            "http://client.example.com/meta",
        ] {
            assert!(
                validate_metadata_url(value, "", &policy).is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn rejects_private_loopback_and_link_local_literal_targets() {
        let policy = CimdTrustPolicy::new(
            vec!["client.example.com".to_string(), "localhost".to_string()],
            HashMap::new(),
        )
        .unwrap();
        for value in [
            "https://127.0.0.1/client.json",
            "https://[::1]/client.json",
            "https://169.254.169.254/client.json",
            "https://10.0.0.1/client.json",
        ] {
            assert!(
                validate_metadata_url(value, "", &policy).is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn parser_requires_exact_document_and_forbids_shared_secrets() {
        assert!(parse_document(URL, &document(URL)).is_ok());
        assert!(parse_document(URL, &document("https://client.example.com/other")).is_err());
        let boundary_document = serde_json::json!({
            "client_id": URL,
            "client_name": "x".repeat(200),
            "redirect_uris": (0..20)
                .map(|index| format!("https://client.example.com/callback/{index}"))
                .collect::<Vec<_>>()
        });
        assert!(
            parse_document(URL, &serde_json::to_vec(&boundary_document).unwrap()).is_ok(),
            "the documented inclusive client-name and redirect-count bounds must remain valid"
        );
        let signing_key = p256::ecdsa::SigningKey::from_bytes((&[7_u8; 32]).into()).unwrap();
        let point = signing_key.verifying_key().to_encoded_point(false);
        let private_key_jwt = serde_json::json!({
            "client_id": URL,
            "client_name": "Example",
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "jwks": {
                "keys": [{
                    "kid": "cimd-key-1",
                    "kty": "EC",
                    "alg": "ES256",
                    "use": "sig",
                    "crv": "P-256",
                    "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                    "y": URL_SAFE_NO_PAD.encode(point.y().unwrap())
                }]
            }
        });
        assert!(parse_document(URL, &serde_json::to_vec(&private_key_jwt).unwrap()).is_ok());
        for invalid in [
            serde_json::json!({
                "client_id": URL,
                "client_name": " ",
                "redirect_uris": ["https://client.example.com/callback"]
            }),
            serde_json::json!({
                "client_id": URL,
                "client_name": "x".repeat(201),
                "redirect_uris": ["https://client.example.com/callback"]
            }),
            serde_json::json!({
                "client_id": URL,
                "client_name": "Example",
                "redirect_uris": []
            }),
            serde_json::json!({
                "client_id": URL,
                "client_name": "Example",
                "redirect_uris": (0..21)
                    .map(|index| format!("https://client.example.com/callback/{index}"))
                    .collect::<Vec<_>>()
            }),
            serde_json::json!({
                "client_id": URL,
                "client_name": "Example",
                "redirect_uris": ["https://user@client.example.com/callback"]
            }),
            serde_json::json!({
                "client_id": URL,
                "client_name": "Example",
                "redirect_uris": ["https://client.example.com/callback"],
                "token_endpoint_auth_method": "none",
                "jwks": {"keys": []}
            }),
            serde_json::json!({
                "client_id": URL,
                "client_name": "Example",
                "redirect_uris": ["https://client.example.com/callback"],
                "token_endpoint_auth_method": "private_key_jwt"
            }),
            serde_json::json!({
                "client_id": URL,
                "client_name": "Example",
                "redirect_uris": ["https://client.example.com/callback"],
                "token_endpoint_auth_method": "private_key_jwt",
                "token_endpoint_auth_signing_alg": "ES256",
                "jwks_uri": "https://keys.example.com/client.jwks"
            }),
        ] {
            assert!(parse_document(URL, &serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        let shared_secret = serde_json::to_vec(&serde_json::json!({
            "client_id": URL,
            "client_name": "Example",
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "client_secret_post"
        }))
        .unwrap();
        assert!(parse_document(URL, &shared_secret).is_err());
    }

    #[test]
    fn continuation_binding_covers_session_client_and_digest() {
        let binding = continuation_binding(b"secret", "session-a", URL, "digest-a");
        assert!(verify_continuation_binding(
            b"secret",
            "session-a",
            URL,
            "digest-a",
            &binding
        ));
        assert!(!verify_continuation_binding(
            b"secret",
            "session-b",
            URL,
            "digest-a",
            &binding
        ));
        assert!(!verify_continuation_binding(
            b"secret",
            "session-a",
            "https://client.example.com/oauth/other.json",
            "digest-a",
            &binding
        ));
        assert!(!verify_continuation_binding(
            b"secret",
            "session-a",
            URL,
            "digest-b",
            &binding
        ));
    }

    #[test]
    fn cimd_audit_identifier_contains_host_but_not_path() {
        let snapshot = parse_document(URL, &document(URL)).unwrap();
        let resolved = ResolvedClient {
            client: snapshot.as_client_record(),
            source: ClientSource::Cimd,
            cimd_snapshot: Some(snapshot),
        };
        assert_eq!(resolved.audit_identifier(), "cimd-host:client.example.com");
        assert!(!resolved.audit_identifier().contains("/oauth/"));
    }

    #[tokio::test]
    async fn cache_is_exact_url_scoped_and_honors_no_store() {
        let client = Arc::new(MemoryCimdHttpClient::default());
        client
            .set(
                URL,
                CimdHttpResponse {
                    status: 200,
                    body: document(URL),
                    cache_control: Some("max-age=120".into()),
                    ..Default::default()
                },
            )
            .await;
        let resolver = resolver(client.clone());
        resolver.resolve("", URL).await.unwrap();
        resolver.resolve("", URL).await.unwrap();
        assert_eq!(client.request_count(URL).await, 1);

        let no_store_url = "https://client.example.com/oauth/no-store.json";
        client
            .set(
                no_store_url,
                CimdHttpResponse {
                    status: 200,
                    body: document(no_store_url),
                    cache_control: Some("no-store".into()),
                    ..Default::default()
                },
            )
            .await;
        resolver.resolve("", no_store_url).await.unwrap();
        resolver.resolve("", no_store_url).await.unwrap();
        assert_eq!(client.request_count(no_store_url).await, 2);
    }

    #[tokio::test]
    async fn cache_expires_and_fetches_a_fresh_document() {
        let client = Arc::new(MemoryCimdHttpClient::default());
        client
            .set_sequence(
                URL,
                vec![
                    Ok(CimdHttpResponse {
                        status: 200,
                        body: named_document(URL, "First"),
                        cache_control: Some("max-age=1".into()),
                        ..Default::default()
                    }),
                    Ok(CimdHttpResponse {
                        status: 200,
                        body: named_document(URL, "Second"),
                        cache_control: Some("max-age=1".into()),
                        ..Default::default()
                    }),
                ],
            )
            .await;
        let resolver = resolver(client.clone());
        assert_eq!(
            resolver.resolve("", URL).await.unwrap().client_name,
            "First"
        );
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        assert_eq!(
            resolver.resolve("", URL).await.unwrap().client_name,
            "Second"
        );
        assert_eq!(client.request_count(URL).await, 2);
    }

    #[test]
    fn cache_directives_are_bounded_and_account_for_age() {
        let now = SystemTime::now();
        assert_eq!(
            cache_ttl(
                &CimdHttpResponse {
                    cache_control: Some("public, max-age=9999".into()),
                    ..Default::default()
                },
                now
            ),
            MAX_LOCAL_TTL_SECS
        );
        assert_eq!(
            cache_ttl(
                &CimdHttpResponse {
                    cache_control: Some("max-age=120".into()),
                    age: Some(30),
                    ..Default::default()
                },
                now
            ),
            90
        );
        assert_eq!(
            cache_ttl(
                &CimdHttpResponse {
                    age: Some(30),
                    ..Default::default()
                },
                now
            ),
            30,
            "Age also reduces the bounded fallback freshness lifetime"
        );
        assert_eq!(
            cache_ttl(
                &CimdHttpResponse {
                    age: Some(60),
                    ..Default::default()
                },
                now
            ),
            0
        );
        assert_eq!(
            cache_ttl(
                &CimdHttpResponse {
                    cache_control: Some("no-cache=\"set-cookie\", max-age=120".into()),
                    ..Default::default()
                },
                now
            ),
            0
        );
        assert_eq!(
            cache_ttl(
                &CimdHttpResponse {
                    cache_control: Some("private, max-age=120".into()),
                    ..Default::default()
                },
                now
            ),
            0
        );
        assert_eq!(
            cache_ttl(
                &CimdHttpResponse {
                    cache_control: Some("max-age=120, s-maxage=10".into()),
                    age: Some(3),
                    ..Default::default()
                },
                now
            ),
            7
        );
        assert_eq!(
            cache_ttl(
                &CimdHttpResponse {
                    cache_control: Some("max-age=120, s-maxage=invalid".into()),
                    ..Default::default()
                },
                now
            ),
            0
        );
        assert_eq!(
            cache_ttl(
                &CimdHttpResponse {
                    cache_control: Some("max-age=120, max-age=300".into()),
                    ..Default::default()
                },
                now
            ),
            0,
            "duplicate freshness directives are invalid and must not extend cache lifetime"
        );

        let fixed_now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(
            cache_ttl(
                &CimdHttpResponse {
                    expires: Some(httpdate::fmt_http_date(
                        fixed_now + Duration::from_secs(120)
                    )),
                    age: Some(30),
                    ..Default::default()
                },
                fixed_now
            ),
            90
        );
        assert_eq!(
            cache_ttl(
                &CimdHttpResponse {
                    expires: Some(httpdate::fmt_http_date(fixed_now - Duration::from_secs(1))),
                    ..Default::default()
                },
                fixed_now
            ),
            0,
            "an explicitly expired response must not fall back to the default TTL"
        );
    }

    #[tokio::test]
    async fn cache_entries_are_isolated_by_tenant_and_exact_url() {
        let second_url = "https://client.example.com/oauth/second.json";
        let client = Arc::new(MemoryCimdHttpClient::default());
        client
            .set(
                URL,
                CimdHttpResponse {
                    status: 200,
                    body: named_document(URL, "First"),
                    cache_control: Some("max-age=120".into()),
                    ..Default::default()
                },
            )
            .await;
        client
            .set(
                second_url,
                CimdHttpResponse {
                    status: 200,
                    body: named_document(second_url, "Second"),
                    cache_control: Some("max-age=120".into()),
                    ..Default::default()
                },
            )
            .await;
        let policy = CimdTrustPolicy::new(
            Vec::new(),
            HashMap::from([
                ("t1".to_string(), vec!["client.example.com".to_string()]),
                ("t2".to_string(), vec!["client.example.com".to_string()]),
            ]),
        )
        .unwrap();
        let resolver = CimdResolver::new(true, policy, client.clone()).unwrap();
        assert_eq!(
            resolver.resolve("t1", URL).await.unwrap().client_name,
            "First"
        );
        assert_eq!(
            resolver.resolve("t1", URL).await.unwrap().client_name,
            "First"
        );
        assert_eq!(
            resolver
                .resolve("t1", second_url)
                .await
                .unwrap()
                .client_name,
            "Second"
        );
        assert_eq!(
            resolver
                .resolve("t1", second_url)
                .await
                .unwrap()
                .client_name,
            "Second"
        );
        assert_eq!(
            resolver.resolve("t2", URL).await.unwrap().client_name,
            "First"
        );
        assert_eq!(client.request_count(URL).await, 2);
        assert_eq!(client.request_count(second_url).await, 1);
        assert_eq!(
            resolver.resolve("t3", URL).await,
            Err(ResolveClientError::Unknown)
        );
    }

    #[tokio::test]
    async fn redirect_target_must_remain_in_policy() {
        let client = Arc::new(MemoryCimdHttpClient::default());
        client
            .set(
                URL,
                CimdHttpResponse {
                    status: 302,
                    location: Some("https://metadata.evil.example/client.json".into()),
                    ..Default::default()
                },
            )
            .await;
        assert!(resolver(client).resolve("", URL).await.is_err());
    }

    #[tokio::test]
    async fn bounded_redirect_chain_can_resolve_the_original_client_id() {
        let redirected = "https://client.example.com/metadata/final.json";
        let client = Arc::new(MemoryCimdHttpClient::default());
        client
            .set(
                URL,
                CimdHttpResponse {
                    status: 302,
                    location: Some("/metadata/final.json".into()),
                    ..Default::default()
                },
            )
            .await;
        client
            .set(
                redirected,
                CimdHttpResponse {
                    status: 200,
                    body: document(URL),
                    ..Default::default()
                },
            )
            .await;
        assert_eq!(
            resolver(client).resolve("", URL).await.unwrap().client_id,
            URL
        );
    }

    #[tokio::test]
    async fn redirect_limit_is_enforced() {
        let client = Arc::new(MemoryCimdHttpClient::default());
        let redirects = [
            (URL, "/one.json"),
            ("https://client.example.com/one.json", "/two.json"),
            ("https://client.example.com/two.json", "/three.json"),
            ("https://client.example.com/three.json", "/four.json"),
        ];
        for (url, location) in redirects {
            client
                .set(
                    url,
                    CimdHttpResponse {
                        status: 302,
                        location: Some(location.to_string()),
                        ..Default::default()
                    },
                )
                .await;
        }
        assert!(matches!(
            resolver(client).resolve("", URL).await,
            Err(ResolveClientError::Invalid(message))
                if message == "CIMD redirect limit exceeded"
        ));
    }

    #[tokio::test]
    async fn errors_and_malformed_documents_are_not_cached() {
        let client = Arc::new(MemoryCimdHttpClient::default());
        client
            .set_sequence(
                URL,
                vec![
                    Ok(CimdHttpResponse {
                        status: 200,
                        body: b"not-json".to_vec(),
                        ..Default::default()
                    }),
                    Ok(CimdHttpResponse {
                        status: 200,
                        body: document(URL),
                        ..Default::default()
                    }),
                ],
            )
            .await;
        let resolver = resolver(client.clone());
        assert!(resolver.resolve("", URL).await.is_err());
        assert!(resolver.resolve("", URL).await.is_ok());
        assert_eq!(client.request_count(URL).await, 2);
    }

    #[tokio::test]
    async fn oversized_documents_are_rejected_and_not_cached() {
        let client = Arc::new(MemoryCimdHttpClient::default());
        client
            .set_sequence(
                URL,
                vec![
                    Ok(CimdHttpResponse {
                        status: 200,
                        body: vec![b'x'; MAX_DOCUMENT_BYTES + 1],
                        ..Default::default()
                    }),
                    Ok(CimdHttpResponse {
                        status: 200,
                        body: document(URL),
                        ..Default::default()
                    }),
                ],
            )
            .await;
        let resolver = resolver(client.clone());
        assert!(resolver.resolve("", URL).await.is_err());
        assert!(resolver.resolve("", URL).await.is_ok());
        assert_eq!(client.request_count(URL).await, 2);
    }

    #[tokio::test]
    async fn unsafe_dns_resolution_is_fail_closed() {
        let client = Arc::new(MemoryCimdHttpClient::default());
        client
            .set_sequence(URL, vec![Err(CimdFetchError::UnsafeTarget)])
            .await;
        assert!(matches!(
            resolver(client).resolve("", URL).await,
            Err(ResolveClientError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn outbound_fetch_budget_is_scoped_by_tenant_and_host() {
        let second_url = "https://client.example.com/oauth/second.json";
        let client = Arc::new(MemoryCimdHttpClient::default());
        client
            .set(
                URL,
                CimdHttpResponse {
                    status: 200,
                    body: document(URL),
                    ..Default::default()
                },
            )
            .await;
        client
            .set(
                second_url,
                CimdHttpResponse {
                    status: 200,
                    body: document(second_url),
                    ..Default::default()
                },
            )
            .await;
        let mut resolver = CimdResolver::new(
            true,
            CimdTrustPolicy::new(vec!["client.example.com".to_string()], HashMap::new()).unwrap(),
            client.clone(),
        )
        .unwrap();
        resolver.fetch_burst = 1.0;
        resolver.fetch_refill_per_sec = 0.0;
        assert!(resolver.resolve("tenant-a", URL).await.is_ok());
        assert_eq!(
            resolver.resolve("tenant-a", second_url).await,
            Err(ResolveClientError::TemporarilyUnavailable)
        );
        assert_eq!(client.request_count(second_url).await, 0);
        assert!(resolver.resolve("tenant-b", second_url).await.is_ok());
    }

    #[tokio::test]
    async fn fetch_budget_capacity_does_not_reset_live_buckets() {
        let client = Arc::new(MemoryCimdHttpClient::default());
        let mut resolver = resolver(client);
        resolver.fetch_refill_per_sec = 0.0;
        for tenant_index in 0..MAX_FETCH_BUDGETS {
            let tenant = format!("tenant-{tenant_index}");
            for _ in 0..FETCH_BURST as usize {
                assert!(resolver.take_fetch_budget(&tenant, URL).await);
            }
        }
        assert!(
            !resolver.take_fetch_budget("overflow-tenant", URL).await,
            "a new key must fail closed while every bounded bucket is depleted"
        );
        assert!(
            !resolver.take_fetch_budget("tenant-0", URL).await,
            "capacity pressure must not evict and reset a live depleted bucket"
        );
    }

    #[derive(Clone)]
    struct SlowClient;

    impl CimdHttpClient for SlowClient {
        fn get<'a>(
            &'a self,
            _url: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<CimdHttpResponse, CimdFetchError>> + Send + 'a>>
        {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                Err(CimdFetchError::TemporarilyUnavailable)
            })
        }
    }

    #[tokio::test]
    async fn total_fetch_timeout_is_fail_closed() {
        let mut resolver = CimdResolver::new(
            true,
            CimdTrustPolicy::new(vec!["client.example.com".to_string()], HashMap::new()).unwrap(),
            Arc::new(SlowClient),
        )
        .unwrap();
        resolver.fetch_timeout = Duration::from_millis(10);
        assert_eq!(
            resolver.resolve("", URL).await,
            Err(ResolveClientError::TemporarilyUnavailable)
        );
    }

    #[derive(Clone)]
    struct BlockingClient {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        requests: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl CimdHttpClient for BlockingClient {
        fn get<'a>(
            &'a self,
            url: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<CimdHttpResponse, CimdFetchError>> + Send + 'a>>
        {
            Box::pin(async move {
                self.requests
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.entered.notify_one();
                self.release.notified().await;
                Ok(CimdHttpResponse {
                    status: 200,
                    body: document(url),
                    ..Default::default()
                })
            })
        }
    }

    #[tokio::test]
    async fn singleflight_wait_is_included_in_total_fetch_timeout() {
        let client = Arc::new(BlockingClient {
            entered: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
            requests: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        });
        let mut resolver = CimdResolver::new(
            true,
            CimdTrustPolicy::new(vec!["client.example.com".to_string()], HashMap::new()).unwrap(),
            client.clone(),
        )
        .unwrap();
        resolver.fetch_timeout = Duration::from_millis(100);
        let resolver = Arc::new(resolver);
        let entered = client.entered.notified();
        let first = tokio::spawn({
            let resolver = resolver.clone();
            async move { resolver.resolve("", URL).await }
        });
        entered.await;

        let second =
            tokio::time::timeout(Duration::from_millis(150), resolver.resolve("", URL)).await;
        assert_eq!(
            second,
            Ok(Err(ResolveClientError::TemporarilyUnavailable)),
            "the same-URL singleflight wait must not receive a fresh timeout window"
        );
        assert_eq!(
            first.await.unwrap(),
            Err(ResolveClientError::TemporarilyUnavailable)
        );
    }

    #[tokio::test]
    async fn outbound_fetch_concurrency_is_bounded_without_queueing() {
        let second_url = "https://client.example.com/oauth/second.json";
        let client = Arc::new(BlockingClient {
            entered: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
            requests: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        });
        let mut resolver = CimdResolver::new(
            true,
            CimdTrustPolicy::new(vec!["client.example.com".to_string()], HashMap::new()).unwrap(),
            client.clone(),
        )
        .unwrap();
        resolver.fetch_slots = Semaphore::new(1);
        let resolver = Arc::new(resolver);
        let entered = client.entered.notified();
        let first = tokio::spawn({
            let resolver = resolver.clone();
            async move { resolver.resolve("", URL).await }
        });
        entered.await;
        assert_eq!(
            resolver.resolve("", second_url).await,
            Err(ResolveClientError::TemporarilyUnavailable)
        );
        assert_eq!(client.requests.load(std::sync::atomic::Ordering::SeqCst), 1);
        client.release.notify_one();
        assert!(first.await.unwrap().is_ok());
    }
}
