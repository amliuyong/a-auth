//! Tenant Admin OIDC SSO and short-lived management sessions (C12.3).
//!
//! This control-plane identity domain is separate from user login sessions and
//! OAuth authorization sessions. Upstream claims may only locate an existing
//! active SCIM user; the management role always comes from tenant Group role
//! mappings and is revalidated by `TenantAdminContext` on every request.

use agent_auth_authn::{
    assurance::{
        authentication_is_fresh, classify_upstream, normalize_auth_time, requested_class,
        AssuranceClass,
    },
    federation::{verify_upstream_id_token_claims, IdTokenExpectations},
};
use agent_auth_discovery::Form;
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::ports::{
    AdminAuthStore, AdminIdentityField, AdminOidcConfig, AdminOidcConfigDeleteOutcome,
    AdminOidcConfigPutOutcome, AdminOidcFlow, AdminSessionRecord, JwksFetcher, ScimGroupsStore,
    SecretResolver, UpstreamTokenExchangeRequest, UpstreamTokenExchanger, UserStatus, UsersStore,
};
use crate::state::AppState;
use crate::tenant_admin::{
    admin_flow_cookie, admin_flow_cookie_name, admin_flow_hash, admin_session_cookie,
    admin_session_cookie_name, admin_session_hash, role_name, AdminAction, TenantAdminContext,
};

const FLOW_TTL_SECS: i64 = 10 * 60;
const SESSION_TTL_SECS: i64 = 15 * 60;
const CLOCK_SKEW_SECS: i64 = 60;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AdminOidcConfigRequest {
    pub issuer: String,
    pub client_id: String,
    pub client_secret_ref: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub strong_acr_values: Vec<String>,
    pub identity_claim: String,
    pub identity_field: AdminIdentityField,
    #[serde(default)]
    pub expected_revision: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AdminOidcConfigView {
    pub tenant_id: String,
    pub issuer: String,
    pub client_id: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub strong_acr_values: Vec<String>,
    pub identity_claim: String,
    pub identity_field: AdminIdentityField,
    pub client_secret_configured: bool,
    pub revision: u64,
    pub updated_at: i64,
}

impl From<AdminOidcConfig> for AdminOidcConfigView {
    fn from(config: AdminOidcConfig) -> Self {
        Self {
            tenant_id: config.tenant_id,
            issuer: config.issuer,
            client_id: config.client_id,
            authorization_endpoint: config.authorization_endpoint,
            token_endpoint: config.token_endpoint,
            jwks_uri: config.jwks_uri,
            redirect_uri: config.redirect_uri,
            scopes: config.scopes,
            strong_acr_values: config.strong_acr_values,
            identity_claim: config.identity_claim,
            identity_field: config.identity_field,
            client_secret_configured: !config.client_secret_ref.is_empty(),
            revision: config.revision,
            updated_at: config.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AdminSessionView {
    pub tenant_id: String,
    pub actor: String,
    pub auth_type: String,
    #[schema(required = true)]
    pub role: Option<String>,
    #[schema(required = true)]
    pub expires_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct DeleteConfigQuery {
    pub expected_revision: u64,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct StartQuery {
    pub acr_values: Option<String>,
    pub max_age: Option<i64>,
}

fn now_secs() -> i64 {
    crate::token::current_unix_secs_pub()
}

fn random_b64(bytes: usize) -> String {
    let mut value = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "status": status.as_u16(),
            "message": message
        })),
    )
        .into_response()
}

async fn audit_admin_oidc_rejection(
    state: &AppState,
    tenant_id: &str,
    response: Response,
) -> Response {
    let outcome = if response.status().is_server_error() {
        crate::security_event::SecurityEventOutcome::Failure
    } else {
        crate::security_event::SecurityEventOutcome::Denied
    };
    state
        .record_security_event(crate::security_event::SecurityEventDraft::authentication(
            tenant_id,
            None,
            crate::security_event::AuthenticationMethod::AdminOidc,
            outcome,
        ))
        .await;
    response
}

async fn audit_admin_oidc_config(
    state: &AppState,
    tenant_id: &str,
    actor: &str,
    action: &'static str,
    outcome: crate::security_event::SecurityEventOutcome,
) {
    state
        .record_security_event(crate::security_event::SecurityEventDraft::new(
            tenant_id,
            crate::security_event::SecurityActor::admin(actor),
            Some(crate::security_event::SecuritySubject::tenant(tenant_id)),
            crate::security_event::SecurityEventCategory::KeySecret,
            action,
            outcome,
        ))
        .await;
}

fn tenant_context(state: &AppState, headers: &HeaderMap) -> Option<(String, String)> {
    let storage = crate::tenant::tenant_or_400(state, headers).ok()?;
    let logical = match &state.form {
        Form::SelfHosted { .. } => "default".to_string(),
        Form::Saas { .. } => storage.clone(),
    };
    Some((logical, storage))
}

fn valid_https_uri(raw: &str, issuer: bool) -> bool {
    let Ok(uri) = raw.parse::<Uri>() else {
        return false;
    };
    uri.scheme_str() == Some("https")
        && uri.authority().is_some_and(|authority| {
            !authority.host().is_empty() && !authority.as_str().contains('@')
        })
        && (!issuer || uri.query().is_none())
}

fn valid_identity_claim(claim: &str) -> bool {
    !claim.is_empty()
        && claim.len() <= 128
        && !claim.starts_with('.')
        && !claim.ends_with('.')
        && claim
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_strong_acr_values(values: &[String]) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    !values.iter().any(|value| {
        value.is_empty()
            || value.len() > 256
            || value.chars().any(char::is_whitespace)
            || !seen.insert(value)
    })
}

fn validate_request(
    request: &AdminOidcConfigRequest,
    expected_redirect: &str,
) -> Result<(), &'static str> {
    if !valid_https_uri(&request.issuer, true) {
        return Err("issuer must be an absolute HTTPS URI without a query");
    }
    if request.client_id.is_empty()
        || request.client_id.len() > 256
        || request.client_id.chars().any(char::is_whitespace)
    {
        return Err("client_id is invalid");
    }
    if request.client_secret_ref.is_empty()
        || request.client_secret_ref.len() > 1024
        || request.client_secret_ref.chars().any(char::is_whitespace)
    {
        return Err("client_secret_ref is invalid");
    }
    if !valid_https_uri(&request.authorization_endpoint, false)
        || !valid_https_uri(&request.token_endpoint, false)
        || !valid_https_uri(&request.jwks_uri, false)
    {
        return Err("OIDC endpoints must be absolute HTTPS URIs");
    }
    if agent_auth_ciba::validate_endpoint_url(&request.token_endpoint, None).is_err()
        || agent_auth_ciba::validate_endpoint_url(&request.jwks_uri, None).is_err()
    {
        return Err("token_endpoint and jwks_uri must pass the public HTTPS SSRF policy");
    }
    if request.redirect_uri != expected_redirect {
        return Err("redirect_uri must exactly match this tenant Admin callback");
    }
    if request.scopes.is_empty()
        || !request.scopes.iter().any(|scope| scope == "openid")
        || request
            .scopes
            .iter()
            .any(|scope| scope.is_empty() || scope.chars().any(char::is_whitespace))
    {
        return Err("scopes must contain openid and use individual scope tokens");
    }
    if !valid_strong_acr_values(&request.strong_acr_values) {
        return Err("strong_acr_values must contain unique non-empty ACR tokens");
    }
    if !valid_identity_claim(&request.identity_claim) {
        return Err("identity_claim is invalid");
    }
    if request.identity_field == AdminIdentityField::UserName && request.identity_claim != "email" {
        return Err("user_name identity mapping requires the verified email claim");
    }
    Ok(())
}

fn callback_uri(state: &AppState, headers: &HeaderMap) -> Option<String> {
    crate::hostutil::browser_origin(state, headers)
        .map(|origin| format!("{origin}/admin/sso/callback"))
}

fn required_client_secret_ref(tenant_id: &str) -> String {
    format!("agent-auth/admin-oidc/{tenant_id}")
}

#[utoipa::path(
    get,
    path = "/admin/oidc",
    tag = "admin",
    responses(
        (status = 200, description = "Tenant Admin OIDC configuration", body = AdminOidcConfigView),
        (status = 401, description = "Admin authentication required"),
        (status = 403, description = "Role is not permitted"),
        (status = 404, description = "No Admin OIDC configuration")
    )
)]
pub async fn get_config(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Read).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    match state.admin_auth.get_config(admin.tenant_id()).await {
        Ok(Some(config)) => Json(AdminOidcConfigView::from(config)).into_response(),
        Ok(None) => json_error(StatusCode::NOT_FOUND, "Admin OIDC is not configured"),
        Err(_) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Admin auth store unavailable",
        ),
    }
}

#[utoipa::path(
    put,
    path = "/admin/oidc",
    tag = "admin",
    request_body = AdminOidcConfigRequest,
    responses(
        (status = 200, description = "Admin OIDC configuration stored", body = AdminOidcConfigView),
        (status = 400, description = "Invalid issuer, client, redirect, endpoint, or identity mapping"),
        (status = 401, description = "Admin authentication required"),
        (status = 403, description = "Only owner or break-glass may manage Admin access"),
        (status = 409, description = "Configuration revision conflict")
    )
)]
pub async fn put_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AdminOidcConfigRequest>,
) -> Response {
    let admin =
        match TenantAdminContext::authenticate(&state, &headers, AdminAction::ManageAccess).await {
            Ok(admin) => admin,
            Err(response) => return response,
        };
    let Some(expected_redirect) = callback_uri(&state, &headers) else {
        return json_error(StatusCode::BAD_REQUEST, "invalid tenant origin");
    };
    if let Err(message) = validate_request(&request, &expected_redirect) {
        return json_error(StatusCode::BAD_REQUEST, message);
    }
    if request.client_secret_ref != required_client_secret_ref(admin.tenant_id()) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "client_secret_ref must use this tenant's fixed Admin OIDC secret name",
        );
    }
    match state
        .secret_resolver
        .resolve(&request.client_secret_ref)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            return json_error(StatusCode::BAD_REQUEST, "client secret reference not found")
        }
        Err(_) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "client secret store unavailable",
            )
        }
    }
    let Some(revision) = request.expected_revision.checked_add(1) else {
        return json_error(StatusCode::BAD_REQUEST, "expected_revision is invalid");
    };
    let config = AdminOidcConfig {
        tenant_id: admin.tenant_id().to_string(),
        binding_id: random_b64(32),
        issuer: request.issuer,
        client_id: request.client_id,
        client_secret_ref: request.client_secret_ref,
        authorization_endpoint: request.authorization_endpoint,
        token_endpoint: request.token_endpoint,
        jwks_uri: request.jwks_uri,
        redirect_uri: request.redirect_uri,
        scopes: request.scopes,
        strong_acr_values: request.strong_acr_values,
        identity_claim: request.identity_claim,
        identity_field: request.identity_field,
        revision,
        updated_at: now_secs(),
    };
    match state
        .admin_auth
        .put_config(config, request.expected_revision)
        .await
    {
        Ok(AdminOidcConfigPutOutcome::Stored(config)) => {
            audit_admin_oidc_config(
                &state,
                admin.tenant_id(),
                &admin.audit_identity(),
                "secret.admin_oidc.configure",
                crate::security_event::SecurityEventOutcome::Success,
            )
            .await;
            Json(AdminOidcConfigView::from(config)).into_response()
        }
        Ok(AdminOidcConfigPutOutcome::Conflict) => {
            audit_admin_oidc_config(
                &state,
                admin.tenant_id(),
                &admin.audit_identity(),
                "secret.admin_oidc.configure",
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            json_error(StatusCode::CONFLICT, "Admin OIDC configuration changed")
        }
        Err(_) => {
            audit_admin_oidc_config(
                &state,
                admin.tenant_id(),
                &admin.audit_identity(),
                "secret.admin_oidc.configure",
                crate::security_event::SecurityEventOutcome::Failure,
            )
            .await;
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Admin auth store unavailable",
            )
        }
    }
}

#[utoipa::path(
    delete,
    path = "/admin/oidc",
    tag = "admin",
    params(DeleteConfigQuery),
    responses(
        (status = 204, description = "Admin OIDC configuration removed and existing sessions invalidated"),
        (status = 401, description = "Admin authentication required"),
        (status = 403, description = "Only owner or break-glass may manage Admin access"),
        (status = 409, description = "Configuration revision conflict"),
        (status = 503, description = "Admin auth store unavailable")
    )
)]
pub async fn delete_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DeleteConfigQuery>,
) -> Response {
    let admin =
        match TenantAdminContext::authenticate(&state, &headers, AdminAction::ManageAccess).await {
            Ok(admin) => admin,
            Err(response) => return response,
        };
    match state
        .admin_auth
        .delete_config(admin.tenant_id(), query.expected_revision)
        .await
    {
        Ok(AdminOidcConfigDeleteOutcome::Deleted) => {
            audit_admin_oidc_config(
                &state,
                admin.tenant_id(),
                &admin.audit_identity(),
                "secret.admin_oidc.delete",
                crate::security_event::SecurityEventOutcome::Success,
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(AdminOidcConfigDeleteOutcome::Conflict) => {
            audit_admin_oidc_config(
                &state,
                admin.tenant_id(),
                &admin.audit_identity(),
                "secret.admin_oidc.delete",
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            json_error(StatusCode::CONFLICT, "Admin OIDC configuration changed")
        }
        Err(_) => {
            audit_admin_oidc_config(
                &state,
                admin.tenant_id(),
                &admin.audit_identity(),
                "secret.admin_oidc.delete",
                crate::security_event::SecurityEventOutcome::Failure,
            )
            .await;
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Admin auth store unavailable",
            )
        }
    }
}

#[utoipa::path(
    get,
    path = "/admin/sso/start",
    tag = "admin",
    params(StartQuery),
    responses(
        (status = 303, description = "Redirect to the tenant-approved OIDC authorization endpoint"),
        (status = 400, description = "Tenant origin or stored redirect is invalid"),
        (status = 404, description = "Admin OIDC is not configured"),
        (status = 503, description = "Admin auth store unavailable")
    )
)]
pub async fn start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<StartQuery>,
) -> Response {
    let Some((tenant_id, _)) = tenant_context(&state, &headers) else {
        return json_error(StatusCode::BAD_REQUEST, "invalid tenant origin");
    };
    let config = match state.admin_auth.get_config(&tenant_id).await {
        Ok(Some(config)) => config,
        Ok(None) => {
            return audit_admin_oidc_rejection(
                &state,
                &tenant_id,
                json_error(StatusCode::NOT_FOUND, "Admin OIDC is not configured"),
            )
            .await
        }
        Err(_) => {
            return audit_admin_oidc_rejection(
                &state,
                &tenant_id,
                json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Admin auth store unavailable",
                ),
            )
            .await
        }
    };
    let Some(redirect_uri) = callback_uri(&state, &headers) else {
        return audit_admin_oidc_rejection(
            &state,
            &tenant_id,
            json_error(StatusCode::BAD_REQUEST, "invalid tenant origin"),
        )
        .await;
    };
    if config.tenant_id != tenant_id || config.redirect_uri != redirect_uri {
        return audit_admin_oidc_rejection(
            &state,
            &tenant_id,
            json_error(StatusCode::BAD_REQUEST, "Admin OIDC redirect mismatch"),
        )
        .await;
    }
    if query.max_age.is_some_and(|value| value < 0) {
        return audit_admin_oidc_rejection(
            &state,
            &tenant_id,
            json_error(StatusCode::BAD_REQUEST, "max_age must be non-negative"),
        )
        .await;
    }
    let required_class = match requested_class(query.acr_values.as_deref()) {
        Ok(class) => class,
        Err(_) => {
            return audit_admin_oidc_rejection(
                &state,
                &tenant_id,
                json_error(
                    StatusCode::BAD_REQUEST,
                    "requested authentication assurance is unsupported",
                ),
            )
            .await
        }
    };
    if required_class == Some(AssuranceClass::Strong) && config.strong_acr_values.is_empty() {
        return audit_admin_oidc_rejection(
            &state,
            &tenant_id,
            json_error(StatusCode::FORBIDDEN, "unmet_authentication_requirements"),
        )
        .await;
    }
    let required_max_age_secs = if required_class == Some(AssuranceClass::Strong) {
        Some(
            query
                .max_age
                .unwrap_or(state.assurance_policy.strong_max_age_secs())
                .min(state.assurance_policy.strong_max_age_secs()),
        )
    } else {
        query.max_age
    };

    let state_value = state.region.issue_id(random_b64(32));
    let browser_nonce = random_b64(32);
    let nonce = random_b64(32);
    let code_verifier = random_b64(48);
    let challenge = agent_auth_client::s256_challenge(&code_verifier);
    let flow = AdminOidcFlow {
        state_hash: admin_flow_hash(&state, &state_value, &browser_nonce),
        nonce: nonce.clone(),
        code_verifier,
        tenant_id,
        config_revision: config.revision,
        config_binding_id: config.binding_id.clone(),
        required_acr: required_class.map(|class| class.acr().to_string()),
        required_max_age_secs,
        expires_at: now_secs() + FLOW_TTL_SECS,
    };
    if state.admin_auth.put_flow(flow).await.is_err() {
        return audit_admin_oidc_rejection(
            &state,
            &config.tenant_id,
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Admin auth store unavailable",
            ),
        )
        .await;
    }
    let separator = if config
        .authorization_endpoint
        .parse::<Uri>()
        .ok()
        .and_then(|uri| uri.query().map(str::to_string))
        .is_some()
    {
        '&'
    } else {
        '?'
    };
    let mut location = format!(
        "{endpoint}{separator}response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&state={state_value}&nonce={nonce}&code_challenge={challenge}&code_challenge_method=S256&prompt=login",
        endpoint = config.authorization_endpoint,
        client_id = url_encode(&config.client_id),
        redirect_uri = url_encode(&config.redirect_uri),
        scope = url_encode(&config.scopes.join(" ")),
        state_value = url_encode(&state_value),
        nonce = url_encode(&nonce),
        challenge = url_encode(&challenge),
    );
    if required_class == Some(AssuranceClass::Strong) {
        location.push_str("&acr_values=");
        location.push_str(&url_encode(&config.strong_acr_values.join(" ")));
    }
    if let Some(max_age) = required_max_age_secs {
        location.push_str("&max_age=");
        location.push_str(&max_age.to_string());
    }
    let mut response_headers = HeaderMap::new();
    response_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response_headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&set_flow_cookie(&browser_nonce, FLOW_TTL_SECS))
            .expect("opaque flow cookie is a valid header"),
    );
    (response_headers, Redirect::to(&location)).into_response()
}

#[utoipa::path(
    get,
    path = "/admin/sso/callback",
    tag = "admin",
    responses(
        (status = 303, description = "Admin session created; redirect to /admin"),
        (status = 400, description = "Invalid, stale, or rejected upstream response"),
        (status = 403, description = "Identity has no active tenant role"),
        (status = 503, description = "Upstream or local store unavailable")
    )
)]
pub async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let Some(state_value) = query.state.as_deref().filter(|value| !value.is_empty()) else {
        return json_error(StatusCode::BAD_REQUEST, "missing state");
    };
    if !state.region.owns_id(state_value) {
        return json_error(StatusCode::BAD_REQUEST, "invalid or expired state");
    }
    let Some(browser_nonce) = admin_flow_cookie(&headers) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "missing Admin OIDC browser binding",
        );
    };
    let now = now_secs();
    let flow_hash = admin_flow_hash(&state, state_value, &browser_nonce);
    let flow = match state.admin_auth.consume_flow(&flow_hash, now).await {
        Ok(Some(flow)) => flow,
        Ok(None) => return json_error(StatusCode::BAD_REQUEST, "invalid or expired state"),
        Err(_) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Admin auth store unavailable",
            )
        }
    };
    let Some((tenant_id, storage_tenant)) = tenant_context(&state, &headers) else {
        return json_error(StatusCode::BAD_REQUEST, "invalid tenant origin");
    };
    if flow.tenant_id != tenant_id {
        state
            .record_security_event(
                crate::security_event::SecurityEventDraft::tenant_boundary_denial(
                    &tenant_id,
                    crate::security_event::SecurityActor::system("admin-oidc"),
                    &flow.tenant_id,
                ),
            )
            .await;
        return audit_admin_oidc_rejection(
            &state,
            &tenant_id,
            json_error(StatusCode::BAD_REQUEST, "tenant mismatch"),
        )
        .await;
    }
    if query
        .error
        .as_deref()
        .is_some_and(|error| !error.is_empty())
    {
        return audit_admin_oidc_rejection(
            &state,
            &tenant_id,
            json_error(StatusCode::BAD_REQUEST, "upstream authentication failed"),
        )
        .await;
    }
    let config = match state.admin_auth.get_config(&tenant_id).await {
        Ok(Some(config))
            if config.tenant_id == tenant_id
                && config.revision == flow.config_revision
                && config.binding_id == flow.config_binding_id =>
        {
            config
        }
        Ok(_) => {
            return audit_admin_oidc_rejection(
                &state,
                &tenant_id,
                json_error(StatusCode::BAD_REQUEST, "Admin OIDC configuration changed"),
            )
            .await
        }
        Err(_) => {
            return audit_admin_oidc_rejection(
                &state,
                &tenant_id,
                json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Admin auth store unavailable",
                ),
            )
            .await
        }
    };
    let Some(redirect_uri) = callback_uri(&state, &headers) else {
        return audit_admin_oidc_rejection(
            &state,
            &tenant_id,
            json_error(StatusCode::BAD_REQUEST, "invalid tenant origin"),
        )
        .await;
    };
    if config.redirect_uri != redirect_uri {
        return audit_admin_oidc_rejection(
            &state,
            &tenant_id,
            json_error(StatusCode::BAD_REQUEST, "Admin OIDC redirect mismatch"),
        )
        .await;
    }
    let Some(code) = query.code.as_deref().filter(|value| !value.is_empty()) else {
        return audit_admin_oidc_rejection(
            &state,
            &tenant_id,
            json_error(StatusCode::BAD_REQUEST, "missing code"),
        )
        .await;
    };
    let secret = match state
        .secret_resolver
        .resolve(&config.client_secret_ref)
        .await
    {
        Ok(Some(secret)) => secret,
        Ok(None) => {
            return audit_admin_oidc_rejection(
                &state,
                &tenant_id,
                json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "client secret is unavailable",
                ),
            )
            .await
        }
        Err(_) => {
            return audit_admin_oidc_rejection(
                &state,
                &tenant_id,
                json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "client secret store unavailable",
                ),
            )
            .await
        }
    };
    let tokens = match state
        .upstream_token_exchanger
        .exchange_code(&UpstreamTokenExchangeRequest {
            token_endpoint: &config.token_endpoint,
            client_id: &config.client_id,
            client_secret: &secret,
            code,
            code_verifier: &flow.code_verifier,
            redirect_uri: &config.redirect_uri,
        })
        .await
    {
        Ok(Some(tokens)) => tokens,
        Ok(None) => {
            return audit_admin_oidc_rejection(
                &state,
                &tenant_id,
                json_error(StatusCode::BAD_REQUEST, "upstream rejected code"),
            )
            .await
        }
        Err(_) => {
            return audit_admin_oidc_rejection(
                &state,
                &tenant_id,
                json_error(StatusCode::SERVICE_UNAVAILABLE, "upstream unavailable"),
            )
            .await
        }
    };
    let kid = peek_kid(&tokens.id_token);
    let mut keys = match state.jwks_fetcher.fetch(&config.jwks_uri).await {
        Ok(keys) => keys,
        Err(_) => {
            return audit_admin_oidc_rejection(
                &state,
                &tenant_id,
                json_error(StatusCode::SERVICE_UNAVAILABLE, "upstream JWKS unavailable"),
            )
            .await
        }
    };
    let key = match select_key(&keys, kid.as_deref()) {
        Some(key) => key,
        None => {
            keys = match state.jwks_fetcher.fetch_fresh(&config.jwks_uri).await {
                Ok(keys) => keys,
                Err(_) => {
                    return audit_admin_oidc_rejection(
                        &state,
                        &tenant_id,
                        json_error(StatusCode::SERVICE_UNAVAILABLE, "upstream JWKS unavailable"),
                    )
                    .await
                }
            };
            let Some(key) = select_key(&keys, kid.as_deref()) else {
                return audit_admin_oidc_rejection(
                    &state,
                    &tenant_id,
                    json_error(StatusCode::BAD_REQUEST, "no matching upstream key"),
                )
                .await;
            };
            key
        }
    };
    let verified = match agent_auth_workload::verify_rs256(
        &tokens.id_token,
        &key.n,
        &key.e,
        key.kid.as_deref(),
    ) {
        Ok(verified) => verified,
        Err(_) => {
            return audit_admin_oidc_rejection(
                &state,
                &tenant_id,
                json_error(StatusCode::BAD_REQUEST, "id_token signature invalid"),
            )
            .await
        }
    };
    let upstream_subject = match verify_upstream_id_token_claims(
        &verified.claims,
        &IdTokenExpectations {
            upstream_issuer: &config.issuer,
            client_id: &config.client_id,
            nonce: &flow.nonce,
            now,
            clock_skew_secs: CLOCK_SKEW_SECS,
        },
    ) {
        Ok(subject) => subject.to_string(),
        Err(_) => {
            return audit_admin_oidc_rejection(
                &state,
                &tenant_id,
                json_error(StatusCode::BAD_REQUEST, "id_token claims invalid"),
            )
            .await
        }
    };
    let upstream_acr = verified.claims.get("acr").and_then(|value| value.as_str());
    let upstream_amr = verified
        .claims
        .get("amr")
        .and_then(|value| value.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let assurance = classify_upstream(upstream_acr, &upstream_amr, &config.strong_acr_values);
    let upstream_auth_time = match verified
        .claims
        .get("auth_time")
        .and_then(|value| value.as_i64())
    {
        Some(auth_time) => match normalize_auth_time(auth_time, now, CLOCK_SKEW_SECS) {
            Some(auth_time) => Some(auth_time),
            None => {
                return audit_admin_oidc_rejection(
                    &state,
                    &tenant_id,
                    unmet_authentication_requirements(),
                )
                .await
            }
        },
        None => None,
    };
    let required_class = match flow.required_acr.as_deref() {
        Some(acr) => match AssuranceClass::from_internal_acr(acr) {
            Some(class) => Some(class),
            None => {
                return audit_admin_oidc_rejection(
                    &state,
                    &tenant_id,
                    json_error(StatusCode::BAD_REQUEST, "invalid assurance requirement"),
                )
                .await
            }
        },
        None => None,
    };
    let step_up_requested = required_class.is_some() || flow.required_max_age_secs.is_some();
    let assurance_satisfied = required_class.is_none_or(|required| assurance >= required);
    let freshness_satisfied = flow.required_max_age_secs.is_none_or(|max_age| {
        upstream_auth_time.is_some_and(|auth_time| authentication_is_fresh(auth_time, now, max_age))
    });
    if !assurance_satisfied || !freshness_satisfied {
        if step_up_requested {
            state
                .record_security_event(crate::security_event::SecurityEventDraft::new(
                    &tenant_id,
                    crate::security_event::SecurityActor::system("admin-oidc"),
                    Some(crate::security_event::SecuritySubject::user(
                        &upstream_subject,
                    )),
                    crate::security_event::SecurityEventCategory::StepUp,
                    "admin.step_up",
                    crate::security_event::SecurityEventOutcome::Denied,
                ))
                .await;
        }
        return audit_admin_oidc_rejection(&state, &tenant_id, unmet_authentication_requirements())
            .await;
    }
    let auth_time = upstream_auth_time.unwrap_or(now);
    if config.identity_field == AdminIdentityField::UserName && config.identity_claim != "email" {
        return audit_admin_oidc_rejection(
            &state,
            &tenant_id,
            json_error(
                StatusCode::BAD_REQUEST,
                "Admin OIDC identity mapping is invalid",
            ),
        )
        .await;
    }
    let Some(identity) = verified
        .claims
        .get(&config.identity_claim)
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return audit_admin_oidc_rejection(
            &state,
            &tenant_id,
            json_error(
                StatusCode::BAD_REQUEST,
                "identity claim is missing or invalid",
            ),
        )
        .await;
    };
    if (config.identity_field == AdminIdentityField::UserName || config.identity_claim == "email")
        && verified
            .claims
            .get("email_verified")
            .and_then(|value| value.as_bool())
            != Some(true)
    {
        return audit_admin_oidc_rejection(
            &state,
            &tenant_id,
            json_error(StatusCode::BAD_REQUEST, "email identity is not verified"),
        )
        .await;
    }
    let user = match config.identity_field {
        AdminIdentityField::UserId => state.users.get_by_id(&storage_tenant, identity).await,
        AdminIdentityField::UserName => {
            state
                .users
                .get_by_email(&storage_tenant, &identity.to_ascii_lowercase())
                .await
        }
    };
    let user = match user {
        Ok(Some(user))
            if user.status == UserStatus::Active
                && user.scim_external_id.is_some()
                && !user.revocation_pending =>
        {
            user
        }
        Ok(_) => {
            return audit_admin_oidc_rejection(
                &state,
                &tenant_id,
                json_error(StatusCode::FORBIDDEN, "SCIM identity is not active"),
            )
            .await
        }
        Err(_) => {
            return audit_admin_oidc_rejection(
                &state,
                &tenant_id,
                json_error(StatusCode::SERVICE_UNAVAILABLE, "User store unavailable"),
            )
            .await
        }
    };
    let role = match state
        .scim_groups
        .mapped_role_for_member(&storage_tenant, &user.user_id)
        .await
    {
        Ok(mapped) => match mapped.role {
            Some(role) => role,
            None => {
                return audit_admin_oidc_rejection(
                    &state,
                    &tenant_id,
                    json_error(StatusCode::FORBIDDEN, "identity has no tenant role"),
                )
                .await
            }
        },
        Err(_) => {
            return audit_admin_oidc_rejection(
                &state,
                &tenant_id,
                json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Group mapping store unavailable",
                ),
            )
            .await
        }
    };
    let raw_session = state.region.issue_id(random_b64(32));
    let session_hash = admin_session_hash(&state, &raw_session);
    let session = AdminSessionRecord {
        session_hash,
        tenant_id: tenant_id.clone(),
        user_id: user.user_id.clone(),
        upstream_subject,
        role,
        credential_epoch: user.credential_epoch,
        config_revision: config.revision,
        config_binding_id: config.binding_id,
        acr: Some(assurance.acr().to_string()),
        auth_time,
        created_at: now,
        expires_at: now + SESSION_TTL_SECS,
    };
    if state.admin_auth.create_session(session).await.is_err() {
        return audit_admin_oidc_rejection(
            &state,
            &tenant_id,
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Admin auth store unavailable",
            ),
        )
        .await;
    }
    let authentication_event = crate::security_event::SecurityEventDraft::authentication(
        &tenant_id,
        Some(&user.user_id),
        crate::security_event::AuthenticationMethod::AdminOidc,
        crate::security_event::SecurityEventOutcome::Success,
    );
    let authorization_event = crate::credential::CredentialAuditEvent::AdminAuthorization {
        tenant: &tenant_id,
        actor: &user.user_id,
        role: role_name(role),
        action: "session.create",
        result: "allowed",
    };
    if step_up_requested {
        tokio::join!(
            state.record_security_event(authentication_event),
            state.record_security_event(crate::security_event::SecurityEventDraft::new(
                &tenant_id,
                crate::security_event::SecurityActor::user(&user.user_id),
                Some(crate::security_event::SecuritySubject::user(&user.user_id)),
                crate::security_event::SecurityEventCategory::StepUp,
                "admin.step_up",
                crate::security_event::SecurityEventOutcome::Success,
            )),
            state.audit_credential_event(authorization_event),
        );
    } else {
        tokio::join!(
            state.record_security_event(authentication_event),
            state.audit_credential_event(authorization_event),
        );
    }
    let origin = crate::hostutil::browser_origin(&state, &headers)
        .expect("callback_uri already validated browser origin");
    let mut response_headers = HeaderMap::new();
    response_headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&set_session_cookie(&raw_session, SESSION_TTL_SECS))
            .expect("opaque Admin session cookie is a valid header"),
    );
    response_headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&set_flow_cookie("", 0))
            .expect("empty Admin flow cookie is a valid header"),
    );
    (response_headers, Redirect::to(&format!("{origin}/admin"))).into_response()
}

fn unmet_authentication_requirements() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "unmet_authentication_requirements",
            "error_description": "upstream authentication did not satisfy the requested assurance"
        })),
    )
        .into_response()
}

#[utoipa::path(
    get,
    path = "/admin/session",
    tag = "admin",
    responses(
        (status = 200, description = "Current attributable Admin identity", body = AdminSessionView),
        (status = 401, description = "No valid Admin session or break-glass credential"),
        (status = 503, description = "Admin auth store unavailable")
    )
)]
pub async fn session(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin =
        match TenantAdminContext::authenticate(&state, &headers, AdminAction::SessionRead).await {
            Ok(admin) => admin,
            Err(response) => return response,
        };
    Json(AdminSessionView {
        tenant_id: admin.tenant_id().to_string(),
        actor: admin.audit_identity(),
        auth_type: if admin.is_break_glass() {
            "break_glass".to_string()
        } else {
            "oidc_session".to_string()
        },
        role: admin.role().map(role_name).map(str::to_string),
        expires_at: admin.expires_at(),
    })
    .into_response()
}

#[utoipa::path(
    post,
    path = "/admin/logout",
    tag = "admin",
    responses(
        (status = 204, description = "Admin session deleted and cookie cleared"),
        (status = 503, description = "Admin session could not be destroyed")
    )
)]
pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(raw_session) = admin_session_cookie(&headers) {
        let Some((tenant_id, _)) = tenant_context(&state, &headers) else {
            return json_error(StatusCode::BAD_REQUEST, "invalid tenant origin");
        };
        let session_hash = admin_session_hash(&state, &raw_session);
        if state
            .admin_auth
            .delete_session(&tenant_id, &session_hash)
            .await
            .is_err()
        {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Admin session could not be destroyed",
            );
        }
    }
    (
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, set_session_cookie("", 0))],
    )
        .into_response()
}

fn set_session_cookie(value: &str, max_age: i64) -> String {
    format!(
        "{}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}",
        admin_session_cookie_name()
    )
}

fn set_flow_cookie(value: &str, max_age: i64) -> String {
    format!(
        "{}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}",
        admin_flow_cookie_name()
    )
}

fn peek_kid(jwt: &str) -> Option<String> {
    let header = jwt.split('.').next()?;
    let value: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).ok()?).ok()?;
    value
        .get("kid")
        .and_then(|kid| kid.as_str())
        .map(String::from)
}

fn select_key(
    keys: &[crate::ports::PlatformJwk],
    kid: Option<&str>,
) -> Option<crate::ports::PlatformJwk> {
    match kid {
        Some(kid) => keys
            .iter()
            .find(|key| key.kid.as_deref() == Some(kid))
            .cloned(),
        None if keys.len() == 1 => keys.first().cloned(),
        None => None,
    }
}

fn url_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char)
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_config, put_config, delete_config))
        .routes(routes!(start))
        .routes(routes!(callback))
        .routes(routes!(session))
        .routes(routes!(logout))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_identity_claim_shape() {
        assert!(valid_identity_claim("email"));
        assert!(valid_identity_claim("custom.user-id"));
        assert!(!valid_identity_claim(""));
        assert!(!valid_identity_claim(".email"));
        assert!(!valid_identity_claim("email[0]"));
    }

    #[test]
    fn validates_https_uri_shape() {
        assert!(valid_https_uri("https://idp.example.com/tenant", true));
        assert!(valid_https_uri(
            "https://idp.example.com/authorize?policy=mfa",
            false
        ));
        assert!(!valid_https_uri("http://idp.example.com", false));
        assert!(!valid_https_uri("https://user@idp.example.com", false));
        assert!(!valid_https_uri(
            "https://idp.example.com/tenant?unexpected=1",
            true
        ));
    }
}
