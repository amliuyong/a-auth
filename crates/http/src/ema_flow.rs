use agent_auth_ema::{
    authorize_verified_id_jag, derive_enterprise_user_id, derive_replay_key, parse_compact_id_jag,
    verify_parsed_id_jag, AuthorizationRequest, EmaJwk, EmaPolicy, IdJagVerificationError,
};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use std::collections::BTreeSet;

use crate::ports::{
    ClientStore, JtiStore, PlatformJwk, ReplayStore, StoreError, UserRecord, UserStatus, UsersStore,
};
use crate::state::AppState;
use crate::token::{AccessTokenClaims, TokenRequest, TokenResponse};

const EMA_AUTH_GRANT: &str = "id-jag";
const MAX_TENANT_POLICIES: usize = 64;

#[derive(Debug, Clone)]
pub struct TenantEmaPolicy {
    pub agent_auth_tenant: String,
    pub policy: EmaPolicy,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantEmaPolicyConfig {
    tenant: String,
    policy: agent_auth_ema::PolicyConfig,
}

pub fn parse_tenant_policies(
    raw: Option<&str>,
    form: &agent_auth_discovery::Form,
    saas_tenants: &[String],
) -> Result<Vec<TenantEmaPolicy>, String> {
    let Some(raw) = raw.filter(|value| !value.trim().is_empty()) else {
        return Ok(Vec::new());
    };
    let configured: Vec<TenantEmaPolicyConfig> = serde_json::from_str(raw)
        .map_err(|error| format!("AGENT_AUTH_EMA_POLICIES invalid JSON: {error}"))?;
    if configured.is_empty() || configured.len() > MAX_TENANT_POLICIES {
        return Err(format!(
            "AGENT_AUTH_EMA_POLICIES must contain 1..={MAX_TENANT_POLICIES} policies"
        ));
    }

    let known_saas_tenants: BTreeSet<&str> = saas_tenants.iter().map(String::as_str).collect();
    let mut lookup_keys = BTreeSet::new();
    let mut policy_ids = BTreeSet::new();
    let mut policies = Vec::with_capacity(configured.len());
    for configured in configured {
        let tenant = match form {
            agent_auth_discovery::Form::SelfHosted { .. } if configured.tenant == "default" => {
                String::new()
            }
            agent_auth_discovery::Form::SelfHosted { .. } => {
                return Err("self-hosted EMA policies must use tenant=\"default\"".to_string())
            }
            agent_auth_discovery::Form::Saas { .. }
                if known_saas_tenants.contains(configured.tenant.as_str()) =>
            {
                configured.tenant
            }
            agent_auth_discovery::Form::Saas { .. } => {
                return Err(format!(
                    "EMA policy references unknown SaaS tenant {:?}",
                    configured.tenant
                ))
            }
        };
        let policy = EmaPolicy::try_from(configured.policy)
            .map_err(|error| format!("invalid EMA policy for tenant {tenant:?}: {error:?}"))?;
        let lookup_key = (
            tenant.clone(),
            policy.trusted_issuer().to_string(),
            policy.issuer_tenant().map(str::to_string),
            policy.authenticated_client_id().to_string(),
        );
        if !lookup_keys.insert(lookup_key) {
            return Err(format!(
                "duplicate EMA policy lookup key for tenant {tenant:?}"
            ));
        }
        if !policy_ids.insert((tenant.clone(), policy.policy_id().to_string())) {
            return Err(format!(
                "duplicate EMA policy_id {:?} for tenant {tenant:?}",
                policy.policy_id()
            ));
        }
        policies.push(TenantEmaPolicy {
            agent_auth_tenant: tenant,
            policy,
        });
    }
    Ok(policies)
}

pub async fn handle(state: &AppState, headers: &HeaderMap, req: &TokenRequest) -> Response {
    let tenant = match crate::tenant::tenant_or_400(state, headers) {
        Ok(tenant) => tenant,
        Err(response) => return no_store(response),
    };
    let client_id = match crate::client_auth::resolve_client_id_with_assertion(
        req.client_id.as_deref(),
        headers,
        req.client_assertion.as_deref(),
    ) {
        Ok(Some(client_id)) => client_id,
        Ok(None) => return invalid_client(headers, "client authentication is required"),
        Err(error) => return invalid_client(headers, error.description()),
    };
    let client = match state.clients.get(&tenant, &client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => return invalid_client(headers, "client authentication failed"),
        Err(error) => return store_error(error, "client store unavailable"),
    };
    let client = match crate::client_auth::authenticate_loaded_snapshot(
        state,
        &tenant,
        crate::client_auth::ClientAuthEndpoint::Token,
        &client,
        headers,
        crate::client_auth::PresentedClientAuth::new(
            req.client_secret.as_deref(),
            req.client_assertion_type.as_deref(),
            req.client_assertion.as_deref(),
        ),
    )
    .await
    {
        Ok(client) => client,
        Err(error) => {
            return match error {
                crate::client_auth::ClientAuthError::InvalidClient(_) => {
                    invalid_client(headers, error.description())
                }
                crate::client_auth::ClientAuthError::InvalidRequest(_) => oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    error.description(),
                ),
                crate::client_auth::ClientAuthError::TemporarilyUnavailable => {
                    oauth_error_with_retry(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        error.description(),
                    )
                }
                crate::client_auth::ClientAuthError::ServerMisconfigured => oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    error.description(),
                ),
            }
        }
    };
    if !client.is_confidential_auth_client() {
        return invalid_client(headers, "EMA requires a confidential client");
    }
    if let Some(response) = crate::ratelimit_gate::check(state, &tenant, &client_id).await {
        return no_store(response);
    }

    if req.authorization_details.is_some() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_authorization_details",
            "authorization_details is not supported for EMA",
        );
    }
    let assertion = match req.assertion.as_deref() {
        Some(assertion) => assertion,
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "assertion is required",
            )
        }
    };
    let parsed = match parse_compact_id_jag(assertion) {
        Ok(parsed) => parsed,
        Err(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "identity assertion rejected",
            )
        }
    };
    let policy = match select_policy(state, &tenant, &client_id, &parsed) {
        Some(policy) => policy,
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "identity assertion rejected",
            )
        }
    };
    if !policy.allows_algorithm(parsed.header().algorithm) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "identity assertion rejected",
        );
    }

    let verified = match verify_from_fixed_jwks(state, &policy, parsed).await {
        Ok(verified) => verified,
        Err(VerifyFlowError::Rejected) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "identity assertion rejected",
            )
        }
        Err(VerifyFlowError::Store(error)) => {
            return store_error(error, "enterprise JWKS unavailable")
        }
    };
    let issuer = match crate::hostutil::issuer_host(headers)
        .and_then(|host| agent_auth_discovery::derive_issuer(&host, &state.form).ok())
    {
        Some(issuer) => issuer,
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "invalid request host",
            )
        }
    };
    if !crate::tenant::issuer_belongs_to_request_tenant(
        state,
        headers,
        issuer.as_str(),
        crate::security_event::SecurityActor::system("ema-token"),
    )
    .await
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "issuer does not belong to tenant",
        );
    }

    let dpop_jkt = match crate::dpop::resolve_dpop_binding_for_ema(
        state,
        headers,
        &tenant,
        issuer.as_str(),
        client.require_dpop,
    )
    .await
    {
        Ok(jkt) => jkt,
        Err(response) if response.status().is_server_error() => return no_store(response),
        Err(_response) if verified.claims().confirmation.is_some() => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "identity assertion proof binding rejected",
            )
        }
        Err(response) => return no_store(response),
    };
    let resource = req.resource.as_deref().unwrap_or("");
    let requested_scope = req.scope.as_deref().unwrap_or("");
    let now = crate::token::current_unix_secs_pub();
    let decision = match authorize_verified_id_jag(
        &policy,
        &verified,
        &AuthorizationRequest {
            agent_auth_tenant: &tenant,
            as_issuer: issuer.as_str(),
            authenticated_client_id: &client_id,
            resource,
            requested_scope,
            request_has_authorization_details: false,
            presented_dpop_jkt: dpop_jkt.as_deref(),
            now,
        },
    ) {
        Ok(decision) => decision,
        Err(error) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                error.oauth_error().as_str(),
                "identity assertion authorization rejected",
            )
        }
    };

    let user_id = derive_enterprise_user_id(
        &state.server_secret,
        &tenant,
        &decision.trusted_issuer,
        decision.issuer_tenant.as_deref(),
        &decision.subject,
    );
    let existing_user = match state.users.get_by_id(&tenant, &user_id).await {
        Ok(user) => user,
        Err(error) => return store_error(error, "user store unavailable"),
    };
    if existing_user
        .as_ref()
        .is_some_and(|record| !valid_enterprise_user(record, &user_id))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "enterprise identity is not active",
        );
    }

    if let Some(response) = crate::ratelimit_gate::kms_sign_tenant_gate(state, &tenant).await {
        return no_store(response);
    }
    if let Some(response) = crate::ratelimit_gate::kms_sign_gate(state).await {
        return no_store(response);
    }

    let replay_key = derive_replay_key(
        &state.server_secret,
        &tenant,
        &decision.trusted_issuer,
        decision.issuer_tenant.as_deref(),
        &decision.jwt_id,
    );
    let replay_store = match state.replay_store.as_ref() {
        Some(store) => store,
        None => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "EMA replay protection is not configured",
            )
        }
    };
    match replay_store
        .check_and_set(&tenant, &replay_key, decision.replay_expires_at)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "identity assertion replayed",
            )
        }
        Err(error) => return store_error(error, "replay store unavailable"),
    }

    if existing_user.is_none() {
        if let Err(error) = state
            .users
            .create_or_get_by_id(&tenant, &user_id, now)
            .await
        {
            return store_error(error, "enterprise user provisioning failed");
        }
    }
    match state.users.get_by_id(&tenant, &user_id).await {
        Ok(Some(user)) if valid_enterprise_user(&user, &user_id) => {}
        Ok(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "enterprise identity is not active",
            )
        }
        Err(error) => return store_error(error, "user store unavailable"),
    }
    if !crate::tenant::issuer_belongs_to_request_tenant(
        state,
        headers,
        issuer.as_str(),
        crate::security_event::SecurityActor::system("ema-token"),
    )
    .await
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "issuer does not belong to tenant",
        );
    }

    let access_sub = agent_auth_token::derive_user_sub(
        crate::token::subject_mode(state.subject_type_for_tenant(&tenant)),
        &state.server_secret,
        &user_id,
        &decision.resource,
    );
    let scope = decision.scopes.join(" ");
    let access_jti = crate::token::new_jti(state);
    let tenant_signer = match crate::tenant_keys::signer_or_503(state, &tenant).await {
        Ok(signer) => signer,
        Err(response) => return no_store(response),
    };
    let access_token = match crate::token::sign_tenant_access_token(
        state,
        headers,
        tenant_signer.as_ref(),
        &AccessTokenClaims {
            issuer: issuer.as_str(),
            sub: &access_sub,
            aud: &decision.resource,
            client_id: &client_id,
            scope: &scope,
            jti: &access_jti,
            auth_grant: EMA_AUTH_GRANT,
            sub_type: agent_auth_token::SubType::User,
            authorization_details: &[],
            cnf_jkt: decision.cnf_jkt.as_deref(),
            auth_time: None,
            acr: None,
            now,
        },
        crate::security_event::SecurityActor::system("ema-token"),
    )
    .await
    {
        Ok(token) => token,
        Err(crate::token::TokenSignError::Transient) => {
            return oauth_error_with_retry(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "signing dependency unavailable",
            )
        }
        Err(crate::token::TokenSignError::TooLarge) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                crate::token::TOKEN_TOO_LARGE_ERROR_DESCRIPTION,
            )
        }
        Err(crate::token::TokenSignError::IssuerMismatch) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "issuer does not belong to tenant",
            )
        }
        Err(crate::token::TokenSignError::Permanent) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "token signing failed",
            )
        }
    };

    let jti_store = match state.jti_store.as_ref() {
        Some(store) => store,
        None => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "user token mapping is not configured",
            )
        }
    };
    let jti_tenant = if tenant.is_empty() {
        "default".to_string()
    } else {
        tenant.clone()
    };
    if let Err(error) = jti_store
        .put(crate::ports::JtiRecord {
            jti: access_jti,
            tenant_id: jti_tenant,
            user_id: user_id.clone(),
            family_id: None,
            grant_id: None,
            expires_at: now + crate::token::ACCESS_TTL,
        })
        .await
    {
        return store_error(error, "user token mapping unavailable");
    }
    crate::token::touch_client_last_used(state, &tenant, &client_id, now).await;

    match state.users.get_by_id(&tenant, &user_id).await {
        Ok(Some(current)) if valid_enterprise_user(&current, &user_id) => {}
        Ok(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "enterprise identity changed during issuance",
            )
        }
        Err(error) => return store_error(error, "user store unavailable"),
    }

    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(TokenResponse {
            access_token,
            token_type: crate::token::token_type_for(decision.cnf_jkt.as_deref()),
            expires_in: crate::token::ACCESS_TTL,
            scope: Some(scope),
            refresh_token: None,
            id_token: None,
            resource: Some(decision.resource),
        }),
    )
        .into_response()
}

fn select_policy(
    state: &AppState,
    tenant: &str,
    client_id: &str,
    parsed: &agent_auth_ema::ParsedIdJag,
) -> Option<EmaPolicy> {
    let issuer = parsed.claims().issuer.as_deref()?;
    let issuer_tenant = parsed.claims().tenant.as_deref();
    let mut matches = state.ema_policies.iter().filter(|configured| {
        configured.agent_auth_tenant == tenant
            && configured.policy.authenticated_client_id() == client_id
            && configured.policy.trusted_issuer() == issuer
            && configured.policy.issuer_tenant() == issuer_tenant
    });
    let policy = matches.next()?.policy.clone();
    matches.next().is_none().then_some(policy)
}

enum VerifyFlowError {
    Rejected,
    Store(StoreError),
}

async fn verify_from_fixed_jwks(
    state: &AppState,
    policy: &EmaPolicy,
    parsed: agent_auth_ema::ParsedIdJag,
) -> Result<agent_auth_ema::VerifiedIdJag, VerifyFlowError> {
    use crate::ports::JwksFetcher;

    let keys = state
        .jwks_fetcher
        .fetch(policy.jwks_uri())
        .await
        .map_err(VerifyFlowError::Store)?;
    match verify_parsed_id_jag(parsed.clone(), &ema_jwks(keys)) {
        Ok(verified) => Ok(verified),
        Err(IdJagVerificationError::UnknownKid) => {
            let fresh = state
                .jwks_fetcher
                .fetch_fresh(policy.jwks_uri())
                .await
                .map_err(VerifyFlowError::Store)?;
            verify_parsed_id_jag(parsed, &ema_jwks(fresh)).map_err(|_| VerifyFlowError::Rejected)
        }
        Err(_) => Err(VerifyFlowError::Rejected),
    }
}

fn ema_jwks(keys: Vec<PlatformJwk>) -> Vec<EmaJwk> {
    keys.into_iter()
        .map(|key| {
            let is_rsa = key.kty.as_deref() == Some("RSA");
            EmaJwk {
                kid: key.kid,
                kty: key.kty.unwrap_or_else(|| "RSA".to_string()),
                alg: key.alg,
                crv: key.crv,
                n: is_rsa.then_some(key.n),
                e: is_rsa.then_some(key.e),
                x: key.x,
                y: key.y,
            }
        })
        .collect()
}

fn valid_enterprise_user(record: &UserRecord, expected_user_id: &str) -> bool {
    record.user_id == expected_user_id
        && record.user_id.starts_with("user:ema:v1:")
        && record.email.is_empty()
        && record.status == UserStatus::Active
        && !record.revocation_pending
        && record.scim_external_id.is_none()
        && record.scim_user_name.is_none()
        && record.scim_display_name.is_none()
}

fn invalid_client(headers: &HeaderMap, description: &str) -> Response {
    no_store(crate::token::invalid_client_response(
        headers,
        StatusCode::UNAUTHORIZED,
        description,
    ))
}

fn oauth_error(status: StatusCode, code: &str, description: &str) -> Response {
    no_store(crate::token::err(status, code, description).into_response())
}

fn oauth_error_with_retry(status: StatusCode, code: &str, description: &str) -> Response {
    no_store(crate::token::err_retry_after(status, code, description, 1).into_response())
}

fn store_error(error: StoreError, description: &str) -> Response {
    match error {
        StoreError::Transient(_) => oauth_error_with_retry(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            description,
        ),
        StoreError::Permanent(_) => oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            description,
        ),
    }
}

pub(crate) fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use super::parse_tenant_policies;
    use agent_auth_discovery::Form;
    use serde_json::json;

    fn policy(tenant: &str, policy_id: &str, client_id: &str) -> serde_json::Value {
        json!({
            "tenant": tenant,
            "policy": {
                "policy_id": policy_id,
                "trusted_issuer": "https://login.example.com/acme/v2.0",
                "issuer_tenant": "acme",
                "jwks_uri": "https://login.example.com/acme/discovery/keys",
                "allowed_algorithms": ["RS256", "ES256"],
                "authenticated_client_id": client_id,
                "assertion_client_id": "enterprise-mcp-client",
                "resources": [{
                    "resource": "https://mcp.example.com",
                    "scopes": ["mcp:read"]
                }],
                "max_assertion_lifetime_secs": 300,
                "allowed_clock_skew_secs": 30
            }
        })
    }

    #[test]
    fn parses_self_hosted_default_tenant_and_rejects_duplicate_lookup_keys() {
        let form = Form::SelfHosted {
            configured_host: "auth.example.com".into(),
        };
        let raw = json!([policy("default", "entra-acme", "ema-client")]).to_string();
        let parsed = parse_tenant_policies(Some(&raw), &form, &[]).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].agent_auth_tenant, "");

        let duplicate = json!([
            policy("default", "entra-acme", "ema-client"),
            policy("default", "entra-acme-2", "ema-client")
        ])
        .to_string();
        assert!(parse_tenant_policies(Some(&duplicate), &form, &[])
            .unwrap_err()
            .contains("duplicate EMA policy lookup key"));
    }

    #[test]
    fn validates_policy_json_and_saas_tenant_registry() {
        let form = Form::Saas {
            zone: "auth.example.com".into(),
            control_host: "c.auth.example.com".into(),
        };
        let raw = json!([policy("t1", "entra-acme", "ema-client")]).to_string();
        assert_eq!(
            parse_tenant_policies(Some(&raw), &form, &["t1".into()])
                .unwrap()
                .len(),
            1
        );
        assert!(parse_tenant_policies(Some(&raw), &form, &["t2".into()])
            .unwrap_err()
            .contains("unknown SaaS tenant"));

        let invalid = json!([{
            "tenant": "t1",
            "policy": {
                "policy_id": "bad",
                "trusted_issuer": "http://login.example.com",
                "jwks_uri": "https://login.example.com/keys",
                "allowed_algorithms": ["RS256"],
                "authenticated_client_id": "ema-client",
                "assertion_client_id": "enterprise-client",
                "resources": [{"resource": "https://mcp.example.com", "scopes": ["read"]}],
                "max_assertion_lifetime_secs": 300,
                "allowed_clock_skew_secs": 30
            }
        }])
        .to_string();
        assert!(parse_tenant_policies(Some(&invalid), &form, &["t1".into()])
            .unwrap_err()
            .contains("invalid EMA policy"));
    }
}
