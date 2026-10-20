//! Administrator-only diagnostics for an already registered OIDC provider.
//! Diagnostic success never enables a provider or asserts a successful login.

use agent_auth_authn::federation::{FederationConfig, OidcRpConfigError};
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    ports::{FederationConfigStore, JwksFetcher, OidcMetadataFetcher, PlatformJwk, StoreError},
    state::AppState,
    tenant_admin::{AdminAction, TenantAdminContext},
};

/// Apply structural restrictions before DNS resolution or any HTTP request.
pub(crate) fn validate_public_endpoint(value: &str, issuer: bool) -> Result<(), ()> {
    if value.len() > 2048 || value != value.trim() {
        return Err(());
    }
    let parsed = url::Url::parse(value).map_err(|_| ())?;
    agent_auth_ciba::validate_endpoint_url(parsed.as_str(), None).map_err(|_| ())?;
    agent_auth_ciba::validate_endpoint_url(value, None).map_err(|_| ())?;
    if issuer && parsed.query().is_some() {
        return Err(());
    }
    let host = parsed
        .host_str()
        .ok_or(())?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if matches!(parsed.host(), Some(url::Host::Domain(_)))
        && (host == "localhost"
            || !host.contains('.')
            || [".localhost", ".local", ".internal", ".test"]
                .iter()
                .any(|suffix| host.ends_with(suffix))
            || (host.contains(".lambda-url.") && host.ends_with(".on.aws")))
    {
        return Err(());
    }
    Ok(())
}

fn tenant_owns_secret_ref(reference: &str, tenant: &str) -> bool {
    let name = if reference.starts_with("arn:") {
        let parts: Vec<_> = reference.splitn(6, ':').collect();
        if parts.len() != 6
            || !matches!(parts[1], "aws" | "aws-cn" | "aws-us-gov")
            || parts[2] != "secretsmanager"
            || parts[3].is_empty()
            || parts[4].len() != 12
            || !parts[4].bytes().all(|byte| byte.is_ascii_digit())
        {
            return false;
        }
        let Some(name) = parts[5].strip_prefix("secret:") else {
            return false;
        };
        name
    } else {
        reference
    };
    let prefix = format!("agent-auth/federation/{tenant}/");
    name.strip_prefix(&prefix)
        .is_some_and(|suffix| !suffix.is_empty())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/_+=.@-".contains(&byte))
}

/// Return only a field identifier, never configuration or secret material.
pub(crate) fn invalid_config_field(
    config: &FederationConfig,
    form: &agent_auth_discovery::Form,
) -> Option<&'static str> {
    if let Err(error) = config.validate() {
        return Some(match error {
            OidcRpConfigError::EmptyField(field) | OidcRpConfigError::EndpointNotHttps(field) => {
                field
            }
            OidcRpConfigError::MissingOpenidScope => "scopes",
            OidcRpConfigError::InvalidStrongAcrValue => "strong_acr_values",
            OidcRpConfigError::ProtocolParamsMismatch => "protocol",
        });
    }
    let params = config.oidc.as_ref()?;
    for (field, value) in [
        ("upstream_idp_id", &config.upstream_idp_id),
        ("client_id", &params.client_id),
        ("client_secret_ref", &params.client_secret_ref),
    ] {
        if value.is_empty() || value != value.trim() {
            return Some(field);
        }
    }
    if params.client_secret_ref.len() > 1024
        || params.client_secret_ref.chars().any(char::is_whitespace)
        || (matches!(form, agent_auth_discovery::Form::Saas { .. })
            && !tenant_owns_secret_ref(&params.client_secret_ref, &config.tenant_id))
    {
        return Some("client_secret_ref");
    }
    for (field, value, issuer) in [
        ("upstream_issuer", &config.upstream_issuer, true),
        (
            "authorization_endpoint",
            &params.authorization_endpoint,
            false,
        ),
        ("token_endpoint", &params.token_endpoint, false),
        ("jwks_uri", &params.jwks_uri, false),
    ] {
        if validate_public_endpoint(value, issuer).is_err() {
            return Some(field);
        }
    }
    None
}

#[derive(Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckStatus {
    Pass,
    Fail,
    Unknown,
    NotRun,
}

#[derive(Serialize, ToSchema)]
pub struct FederationConfigValidationError {
    pub error: String,
    pub field: String,
}

#[derive(Serialize, ToSchema)]
pub struct FederationCheckStep {
    pub status: CheckStatus,
    /// Stable reason code; provider responses and URLs are never echoed.
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

impl FederationCheckStep {
    fn new(status: CheckStatus, reason: &str, field: Option<&str>) -> Self {
        Self {
            status,
            reason: reason.into(),
            field: field.map(String::from),
        }
    }

    fn network_error(error: &StoreError) -> Self {
        match error {
            StoreError::Transient(_) => {
                Self::new(CheckStatus::Unknown, "network_unavailable", None)
            }
            StoreError::Permanent(_) => {
                Self::new(CheckStatus::Fail, "invalid_or_blocked_response", None)
            }
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct FederationChecks {
    pub checked_at: i64,
    pub format: FederationCheckStep,
    pub discovery: FederationCheckStep,
    pub jwks: FederationCheckStep,
    pub login: FederationCheckStep,
}

// Federation callback currently supports RS256. A reachable EC-only document
// cannot be reported as usable by that callback.
fn has_usable_rsa_key(keys: &[PlatformJwk]) -> bool {
    keys.iter().any(|key| {
        if !matches!(key.kty.as_deref(), None | Some("RSA"))
            || !matches!(key.alg.as_deref(), None | Some("RS256"))
        {
            return false;
        }
        let (Ok(n), Ok(e)) = (
            URL_SAFE_NO_PAD.decode(&key.n),
            URL_SAFE_NO_PAD.decode(&key.e),
        ) else {
            return false;
        };
        rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(&n),
            rsa::BigUint::from_bytes_be(&e),
        )
        .is_ok()
    })
}

#[utoipa::path(get, path = "/admin/federation/{tenant_id}/{upstream_idp_id}/checks", tag = "admin",
    params(("tenant_id" = String, Path), ("upstream_idp_id" = String, Path)),
    responses((status = 200, body = FederationChecks, description = "Separated diagnostics; login remains NOT_RUN"),
        (status = 401), (status = 403), (status = 404), (status = 409, description = "Configuration changed during checks"),
        (status = 503, description = "Configuration store unavailable")))]
pub async fn check_federation_idp(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((tenant_id, upstream_idp_id)): Path<(String, String)>,
) -> Response {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Read).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    if let Err(response) = admin.require_tenant(&state, &tenant_id).await {
        return response;
    }
    let config = match state
        .federation_config
        .get(&tenant_id, &upstream_idp_id)
        .await
    {
        Ok(Some(config))
            if config.tenant_id == tenant_id && config.upstream_idp_id == upstream_idp_id =>
        {
            config
        }
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let mut checks = FederationChecks {
        checked_at: crate::token::current_unix_secs_pub(),
        format: FederationCheckStep::new(CheckStatus::Pass, "valid_format", None),
        discovery: FederationCheckStep::new(CheckStatus::NotRun, "previous_step_failed", None),
        jwks: FederationCheckStep::new(CheckStatus::NotRun, "previous_step_failed", None),
        login: FederationCheckStep::new(CheckStatus::NotRun, "real_login_required", None),
    };
    if let Some(field) = invalid_config_field(&config, &state.form) {
        checks.format = FederationCheckStep::new(CheckStatus::Fail, "invalid_config", Some(field));
    } else if let Some(params) = &config.oidc {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            config.upstream_issuer.trim_end_matches('/')
        );
        match state.oidc_metadata_fetcher.fetch(&discovery_url).await {
            Err(error) => checks.discovery = FederationCheckStep::network_error(&error),
            Ok(metadata) => {
                let mismatch = [
                    (
                        "issuer",
                        metadata.issuer.as_deref(),
                        config.upstream_issuer.as_str(),
                    ),
                    (
                        "authorization_endpoint",
                        metadata.authorization_endpoint.as_deref(),
                        params.authorization_endpoint.as_str(),
                    ),
                    (
                        "token_endpoint",
                        metadata.token_endpoint.as_deref(),
                        params.token_endpoint.as_str(),
                    ),
                    (
                        "jwks_uri",
                        metadata.jwks_uri.as_deref(),
                        params.jwks_uri.as_str(),
                    ),
                ]
                .into_iter()
                .find(|(_, actual, expected)| *actual != Some(*expected));
                if let Some((field, _, _)) = mismatch {
                    checks.discovery = FederationCheckStep::new(
                        CheckStatus::Fail,
                        "metadata_mismatch",
                        Some(field),
                    );
                } else {
                    checks.discovery = FederationCheckStep::new(
                        CheckStatus::Pass,
                        "registered_endpoints_match",
                        None,
                    );
                    checks.jwks = match state.jwks_fetcher.fetch_fresh(&params.jwks_uri).await {
                        Ok(keys) if has_usable_rsa_key(&keys) => {
                            FederationCheckStep::new(CheckStatus::Pass, "usable_rs256_key", None)
                        }
                        Ok(_) => FederationCheckStep::new(
                            CheckStatus::Fail,
                            "no_usable_rs256_key",
                            Some("jwks_uri"),
                        ),
                        Err(error) => FederationCheckStep::network_error(&error),
                    };
                }
            }
        }
    } else {
        checks.format =
            FederationCheckStep::new(CheckStatus::Fail, "oidc_required", Some("protocol"));
    }
    // Results belong to this complete snapshot, not a replacement configuration.
    match state
        .federation_config
        .get(&tenant_id, &upstream_idp_id)
        .await
    {
        Ok(Some(current)) if current == config => {}
        Ok(_) => return StatusCode::CONFLICT.into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
    ([(header::CACHE_CONTROL, "no-store")], Json(checks)).into_response()
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(check_federation_idp))
}
