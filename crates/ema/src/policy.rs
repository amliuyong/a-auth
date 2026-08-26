use http::Uri;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_URI_BYTES: usize = 2048;
const MAX_RESOURCES: usize = 32;
const MAX_SCOPES_PER_RESOURCE: usize = 64;
const MAX_ASSERTION_LIFETIME_SECS: i64 = 3600;
const MAX_CLOCK_SKEW_SECS: i64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SigningAlgorithm {
    #[serde(rename = "RS256")]
    Rs256,
    #[serde(rename = "ES256")]
    Es256,
}

impl SigningAlgorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcePolicyConfig {
    pub resource: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub policy_id: String,
    pub trusted_issuer: String,
    #[serde(default)]
    pub issuer_tenant: Option<String>,
    pub jwks_uri: String,
    pub allowed_algorithms: Vec<SigningAlgorithm>,
    pub authenticated_client_id: String,
    pub assertion_client_id: String,
    pub resources: Vec<ResourcePolicyConfig>,
    #[serde(default)]
    pub allow_legacy_missing_resource: bool,
    pub max_assertion_lifetime_secs: i64,
    pub allowed_clock_skew_secs: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    InvalidIdentifier(&'static str),
    InvalidIssuer,
    InvalidJwksUri,
    InvalidAlgorithmSet,
    InvalidResource,
    InvalidScope,
    AmbiguousLegacyTarget,
    InvalidTimeBounds,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePolicy {
    resource: String,
    scopes: Vec<String>,
}

impl ResourcePolicy {
    pub fn resource(&self) -> &str {
        &self.resource
    }

    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    pub(crate) fn allows_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|allowed| allowed == scope)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmaPolicy {
    policy_id: String,
    trusted_issuer: String,
    issuer_tenant: Option<String>,
    jwks_uri: String,
    allowed_algorithms: BTreeSet<SigningAlgorithm>,
    authenticated_client_id: String,
    assertion_client_id: String,
    resources: BTreeMap<String, ResourcePolicy>,
    allow_legacy_missing_resource: bool,
    max_assertion_lifetime_secs: i64,
    allowed_clock_skew_secs: i64,
}

impl EmaPolicy {
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    pub fn trusted_issuer(&self) -> &str {
        &self.trusted_issuer
    }

    pub fn issuer_tenant(&self) -> Option<&str> {
        self.issuer_tenant.as_deref()
    }

    pub fn jwks_uri(&self) -> &str {
        &self.jwks_uri
    }

    pub fn authenticated_client_id(&self) -> &str {
        &self.authenticated_client_id
    }

    pub fn assertion_client_id(&self) -> &str {
        &self.assertion_client_id
    }

    pub fn resource(&self, resource: &str) -> Option<&ResourcePolicy> {
        self.resources.get(resource)
    }

    pub fn resources(&self) -> impl ExactSizeIterator<Item = &ResourcePolicy> {
        self.resources.values()
    }

    pub fn allows_algorithm(&self, algorithm: SigningAlgorithm) -> bool {
        self.allowed_algorithms.contains(&algorithm)
    }

    pub fn allow_legacy_missing_resource(&self) -> bool {
        self.allow_legacy_missing_resource
    }

    pub fn max_assertion_lifetime_secs(&self) -> i64 {
        self.max_assertion_lifetime_secs
    }

    pub fn allowed_clock_skew_secs(&self) -> i64 {
        self.allowed_clock_skew_secs
    }
}

impl TryFrom<PolicyConfig> for EmaPolicy {
    type Error = PolicyError;

    fn try_from(config: PolicyConfig) -> Result<Self, Self::Error> {
        validate_identifier(&config.policy_id, "policy_id")?;
        validate_identifier(&config.authenticated_client_id, "authenticated_client_id")?;
        validate_identifier(&config.assertion_client_id, "assertion_client_id")?;
        if let Some(tenant) = config.issuer_tenant.as_deref() {
            validate_identifier(tenant, "issuer_tenant")?;
        }
        if !valid_absolute_https_uri(&config.trusted_issuer, false) {
            return Err(PolicyError::InvalidIssuer);
        }
        if !valid_absolute_https_uri(&config.jwks_uri, true)
            || agent_auth_ciba::validate_endpoint_url(&config.jwks_uri, None).is_err()
        {
            return Err(PolicyError::InvalidJwksUri);
        }

        let allowed_algorithms: BTreeSet<_> = config.allowed_algorithms.iter().copied().collect();
        if allowed_algorithms.is_empty()
            || allowed_algorithms.len() != config.allowed_algorithms.len()
        {
            return Err(PolicyError::InvalidAlgorithmSet);
        }
        if config.resources.is_empty() || config.resources.len() > MAX_RESOURCES {
            return Err(PolicyError::InvalidResource);
        }
        if config.allow_legacy_missing_resource && config.resources.len() != 1 {
            return Err(PolicyError::AmbiguousLegacyTarget);
        }
        if !(1..=MAX_ASSERTION_LIFETIME_SECS).contains(&config.max_assertion_lifetime_secs)
            || !(0..=MAX_CLOCK_SKEW_SECS).contains(&config.allowed_clock_skew_secs)
        {
            return Err(PolicyError::InvalidTimeBounds);
        }

        let mut resources = BTreeMap::new();
        for configured in config.resources {
            if !valid_absolute_https_uri(&configured.resource, true)
                || configured.scopes.is_empty()
                || configured.scopes.len() > MAX_SCOPES_PER_RESOURCE
            {
                return Err(PolicyError::InvalidResource);
            }
            let scope_set: BTreeSet<_> = configured.scopes.iter().map(String::as_str).collect();
            if scope_set.len() != configured.scopes.len()
                || configured
                    .scopes
                    .iter()
                    .any(|scope| !valid_scope_token(scope))
            {
                return Err(PolicyError::InvalidScope);
            }
            let resource = configured.resource.clone();
            let policy = ResourcePolicy {
                resource: configured.resource,
                scopes: configured.scopes,
            };
            if resources.insert(resource, policy).is_some() {
                return Err(PolicyError::InvalidResource);
            }
        }

        Ok(Self {
            policy_id: config.policy_id,
            trusted_issuer: config.trusted_issuer,
            issuer_tenant: config.issuer_tenant,
            jwks_uri: config.jwks_uri,
            allowed_algorithms,
            authenticated_client_id: config.authenticated_client_id,
            assertion_client_id: config.assertion_client_id,
            resources,
            allow_legacy_missing_resource: config.allow_legacy_missing_resource,
            max_assertion_lifetime_secs: config.max_assertion_lifetime_secs,
            allowed_clock_skew_secs: config.allowed_clock_skew_secs,
        })
    }
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), PolicyError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(PolicyError::InvalidIdentifier(field));
    }
    Ok(())
}

pub(crate) fn valid_absolute_https_uri(raw: &str, allow_query: bool) -> bool {
    if raw.len() > MAX_URI_BYTES || !raw.starts_with("https://") || raw.contains('#') {
        return false;
    }
    let Ok(uri) = raw.parse::<Uri>() else {
        return false;
    };
    uri.scheme_str() == Some("https")
        && uri.authority().is_some_and(|authority| {
            !authority.host().is_empty() && !authority.as_str().contains('@')
        })
        && (allow_query || uri.query().is_none())
}

pub(crate) fn valid_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope.bytes().all(|byte| {
            byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
        })
}
