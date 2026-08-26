use crate::policy::{valid_absolute_https_uri, valid_scope_token};
use crate::{EmaPolicy, StringListClaim, VerifiedIdJag};
use std::collections::BTreeSet;

const MAX_CLAIM_IDENTIFIER_BYTES: usize = 2048;
const MAX_SCOPE_BYTES: usize = 4096;
const MAX_CNF_JKT_BYTES: usize = 256;

#[derive(Debug, Clone, Copy)]
pub struct AuthorizationRequest<'a> {
    pub agent_auth_tenant: &'a str,
    pub as_issuer: &'a str,
    pub authenticated_client_id: &'a str,
    pub resource: &'a str,
    pub requested_scope: &'a str,
    pub request_has_authorization_details: bool,
    pub presented_dpop_jkt: Option<&'a str>,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationDecision {
    pub policy_id: String,
    pub trusted_issuer: String,
    pub issuer_tenant: Option<String>,
    pub subject: String,
    pub authenticated_client_id: String,
    pub assertion_client_id: String,
    pub resource: String,
    pub scopes: Vec<String>,
    pub jwt_id: String,
    pub replay_expires_at: i64,
    pub cnf_jkt: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthErrorCode {
    InvalidGrant,
    InvalidTarget,
    InvalidScope,
    InvalidAuthorizationDetails,
}

impl OAuthErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidGrant => "invalid_grant",
            Self::InvalidTarget => "invalid_target",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidAuthorizationDetails => "invalid_authorization_details",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationError {
    RequestAuthorizationDetailsUnsupported,
    InvalidRequestResource,
    ResourceNotAllowed,
    InvalidRequestedScope,
    ScopeExceedsAssertion,
    ScopeExceedsPolicy,
    AlgorithmNotAllowed,
    ClientBindingMismatch,
    MissingClaim(&'static str),
    InvalidClaim(&'static str),
    IssuerMismatch,
    IssuerTenantMismatch,
    AudienceMismatch,
    AssertionClientMismatch,
    InvalidTime,
    AssertionResourceMismatch,
    UnsupportedAuthorizationDetails,
    UnsupportedActor,
    DpopBindingMismatch,
    AudienceTenantMismatch,
}

impl AuthorizationError {
    pub const fn oauth_error(&self) -> OAuthErrorCode {
        match self {
            Self::RequestAuthorizationDetailsUnsupported => {
                OAuthErrorCode::InvalidAuthorizationDetails
            }
            Self::InvalidRequestResource | Self::ResourceNotAllowed => {
                OAuthErrorCode::InvalidTarget
            }
            Self::InvalidRequestedScope
            | Self::ScopeExceedsAssertion
            | Self::ScopeExceedsPolicy => OAuthErrorCode::InvalidScope,
            _ => OAuthErrorCode::InvalidGrant,
        }
    }
}

pub fn authorize_verified_id_jag(
    policy: &EmaPolicy,
    assertion: &VerifiedIdJag,
    request: &AuthorizationRequest<'_>,
) -> Result<AuthorizationDecision, AuthorizationError> {
    if request.request_has_authorization_details {
        return Err(AuthorizationError::RequestAuthorizationDetailsUnsupported);
    }
    if request.authenticated_client_id != policy.authenticated_client_id() {
        return Err(AuthorizationError::ClientBindingMismatch);
    }
    if !policy.allows_algorithm(assertion.header().algorithm) {
        return Err(AuthorizationError::AlgorithmNotAllowed);
    }

    let claims = assertion.claims();
    let issuer = required_identifier(claims.issuer.as_deref(), "iss")?;
    if issuer != policy.trusted_issuer() {
        return Err(AuthorizationError::IssuerMismatch);
    }
    match (policy.issuer_tenant(), claims.tenant.as_deref()) {
        (Some(expected), Some(actual)) if expected == actual => {}
        (None, None) => {}
        _ => return Err(AuthorizationError::IssuerTenantMismatch),
    }
    let subject = required_identifier(claims.subject.as_deref(), "sub")?;
    let assertion_client_id = required_identifier(claims.client_id.as_deref(), "client_id")?;
    if assertion_client_id != policy.assertion_client_id() {
        return Err(AuthorizationError::AssertionClientMismatch);
    }
    let jwt_id = required_identifier(claims.jwt_id.as_deref(), "jti")?;

    let audience = claims
        .audience
        .as_ref()
        .ok_or(AuthorizationError::MissingClaim("aud"))?;
    if audience.values().len() != 1 || audience.values()[0] != request.as_issuer {
        return Err(AuthorizationError::AudienceMismatch);
    }
    if claims
        .audience_tenant
        .as_deref()
        .is_some_and(|tenant| tenant != request.agent_auth_tenant)
    {
        return Err(AuthorizationError::AudienceTenantMismatch);
    }

    let expires_at = claims
        .expires_at
        .ok_or(AuthorizationError::MissingClaim("exp"))?;
    let issued_at = claims
        .issued_at
        .ok_or(AuthorizationError::MissingClaim("iat"))?;
    let skew = policy.allowed_clock_skew_secs();
    let replay_expires_at = expires_at
        .checked_add(skew)
        .ok_or(AuthorizationError::InvalidTime)?;
    let latest_acceptable_iat = request
        .now
        .checked_add(skew)
        .ok_or(AuthorizationError::InvalidTime)?;
    let assertion_lifetime = expires_at
        .checked_sub(issued_at)
        .ok_or(AuthorizationError::InvalidTime)?;
    if request.now >= replay_expires_at
        || issued_at > latest_acceptable_iat
        || expires_at <= issued_at
        || assertion_lifetime > policy.max_assertion_lifetime_secs()
        || claims.not_before.is_some_and(|not_before| {
            not_before > latest_acceptable_iat || not_before >= expires_at
        })
    {
        return Err(AuthorizationError::InvalidTime);
    }

    if !valid_absolute_https_uri(request.resource, true) {
        return Err(AuthorizationError::InvalidRequestResource);
    }
    let resource_policy = policy
        .resource(request.resource)
        .ok_or(AuthorizationError::ResourceNotAllowed)?;
    validate_assertion_resource(policy, claims.resource.as_ref(), request.resource)?;

    let asserted_scopes = parse_scope(
        claims
            .scope
            .as_deref()
            .ok_or(AuthorizationError::MissingClaim("scope"))?,
    )
    .map_err(|_| AuthorizationError::InvalidClaim("scope"))?;
    let requested_scopes = parse_scope(request.requested_scope)
        .map_err(|_| AuthorizationError::InvalidRequestedScope)?;
    let asserted: BTreeSet<_> = asserted_scopes.iter().map(String::as_str).collect();
    if requested_scopes
        .iter()
        .any(|scope| !asserted.contains(scope.as_str()))
    {
        return Err(AuthorizationError::ScopeExceedsAssertion);
    }
    if requested_scopes
        .iter()
        .any(|scope| !resource_policy.allows_scope(scope))
    {
        return Err(AuthorizationError::ScopeExceedsPolicy);
    }

    match claims.authorization_details.as_ref() {
        None => {}
        Some(serde_json::Value::Array(values)) if values.is_empty() => {}
        Some(serde_json::Value::Array(values))
            if values.iter().any(|value| {
                value
                    .as_object()
                    .and_then(|detail| detail.get("type"))
                    .and_then(serde_json::Value::as_str)
                    .is_none_or(str::is_empty)
            }) =>
        {
            return Err(AuthorizationError::InvalidClaim("authorization_details"))
        }
        Some(serde_json::Value::Array(_)) => {
            return Err(AuthorizationError::UnsupportedAuthorizationDetails)
        }
        Some(_) => return Err(AuthorizationError::InvalidClaim("authorization_details")),
    }
    if claims.actor.is_some() {
        return Err(AuthorizationError::UnsupportedActor);
    }
    let cnf_jkt = confirmation_jkt(claims.confirmation.as_ref())?;
    if cnf_jkt
        .as_deref()
        .is_some_and(|expected| request.presented_dpop_jkt != Some(expected))
    {
        return Err(AuthorizationError::DpopBindingMismatch);
    }
    let effective_jkt = cnf_jkt
        .as_deref()
        .or(request.presented_dpop_jkt)
        .map(str::to_string);

    Ok(AuthorizationDecision {
        policy_id: policy.policy_id().to_string(),
        trusted_issuer: issuer.to_string(),
        issuer_tenant: claims.tenant.clone(),
        subject: subject.to_string(),
        authenticated_client_id: request.authenticated_client_id.to_string(),
        assertion_client_id: assertion_client_id.to_string(),
        resource: request.resource.to_string(),
        scopes: requested_scopes,
        jwt_id: jwt_id.to_string(),
        replay_expires_at,
        cnf_jkt: effective_jkt,
    })
}

fn required_identifier<'a>(
    value: Option<&'a str>,
    claim: &'static str,
) -> Result<&'a str, AuthorizationError> {
    let value = value.ok_or(AuthorizationError::MissingClaim(claim))?;
    if value.is_empty()
        || value.len() > MAX_CLAIM_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(AuthorizationError::InvalidClaim(claim));
    }
    Ok(value)
}

fn validate_assertion_resource(
    policy: &EmaPolicy,
    claim: Option<&StringListClaim>,
    requested: &str,
) -> Result<(), AuthorizationError> {
    let Some(claim) = claim else {
        if policy.allow_legacy_missing_resource()
            && policy.resources().len() == 1
            && policy.resource(requested).is_some()
        {
            return Ok(());
        }
        return Err(AuthorizationError::AssertionResourceMismatch);
    };
    let values = claim.values();
    let unique: BTreeSet<_> = values.iter().map(String::as_str).collect();
    if values.is_empty()
        || unique.len() != values.len()
        || values
            .iter()
            .any(|resource| !valid_absolute_https_uri(resource, true))
        || !unique.contains(requested)
    {
        return Err(AuthorizationError::AssertionResourceMismatch);
    }
    Ok(())
}

fn parse_scope(scope: &str) -> Result<Vec<String>, ()> {
    if scope.is_empty() || scope.len() > MAX_SCOPE_BYTES {
        return Err(());
    }
    let values: Vec<_> = scope.split(' ').map(str::to_string).collect();
    let unique: BTreeSet<_> = values.iter().map(String::as_str).collect();
    if values.is_empty()
        || unique.len() != values.len()
        || values.iter().any(|value| !valid_scope_token(value))
    {
        return Err(());
    }
    Ok(values)
}

fn confirmation_jkt(
    value: Option<&serde_json::Value>,
) -> Result<Option<String>, AuthorizationError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let object = value
        .as_object()
        .ok_or(AuthorizationError::InvalidClaim("cnf"))?;
    if object.len() != 1 {
        return Err(AuthorizationError::InvalidClaim("cnf"));
    }
    let jkt = object
        .get("jkt")
        .and_then(serde_json::Value::as_str)
        .filter(|jkt| {
            !jkt.is_empty()
                && jkt.len() <= MAX_CNF_JKT_BYTES
                && !jkt.bytes().any(|byte| byte.is_ascii_control())
        })
        .ok_or(AuthorizationError::InvalidClaim("cnf"))?;
    Ok(Some(jkt.to_string()))
}
