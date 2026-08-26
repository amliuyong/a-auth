//! 租户管理面认证上下文。
//!
//! 凭据校验、请求 Host 的租户解析和存储分区键在此一次完成。调用方只能取得已认证的
//! 租户事实，不能在认证后重新从路径或请求体选择其他租户。

use agent_auth_discovery::Form;
use axum::{
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::admin_credentials::{
    AdminCredentialError, AdminCredentialMatch, AdminCredentialOwner, AdminCredentialSlot,
};
use crate::ports::{AdminAuthStore, ScimGroupsStore, TenantRole, UserStatus, UsersStore};
use crate::state::AppState;

const ADMIN_SESSION_COOKIE: &str = "__Host-agent_auth_admin_session";
const ADMIN_FLOW_COOKIE: &str = "__Host-agent_auth_admin_oidc_flow";
const GOVERNANCE_PURPOSE_HEADER: &str = "x-agent-auth-purpose";
const GOVERNANCE_CONFIRM_HEADER: &str = "x-agent-auth-confirm";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdminAction {
    SessionRead,
    Read,
    Write,
    ManageAccess,
    DataExportUser,
    DataExportTenant,
    DataErase,
    LegalHoldManage,
    TenantOffboard,
}

impl AdminAction {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::SessionRead => "session.read",
            Self::Read => "tenant.read",
            Self::Write => "tenant.write",
            Self::ManageAccess => "access.manage",
            Self::DataExportUser => "data.export.user",
            Self::DataExportTenant => "data.export.tenant",
            Self::DataErase => "data.erase",
            Self::LegalHoldManage => "legal_hold.manage",
            Self::TenantOffboard => "tenant.offboard",
        }
    }

    fn allowed_for(self, role: TenantRole) -> bool {
        match self {
            Self::SessionRead => true,
            Self::Read => role >= TenantRole::Auditor,
            Self::Write => role >= TenantRole::Admin,
            Self::ManageAccess => role == TenantRole::Owner,
            Self::DataExportUser => role >= TenantRole::Admin,
            Self::DataExportTenant
            | Self::DataErase
            | Self::LegalHoldManage
            | Self::TenantOffboard => role == TenantRole::Owner,
        }
    }

    const fn is_governance(self) -> bool {
        matches!(
            self,
            Self::DataExportUser
                | Self::DataExportTenant
                | Self::DataErase
                | Self::LegalHoldManage
                | Self::TenantOffboard
        )
    }

    const fn requires_strong(self) -> bool {
        self.is_governance()
    }
}

#[derive(Debug, Clone)]
enum AdminPrincipal {
    BreakGlass {
        credential_id: String,
    },
    Session {
        user_id: String,
        role: TenantRole,
        expires_at: i64,
    },
}

pub(crate) struct TenantAdminContext {
    tenant_id: String,
    storage_tenant: String,
    principal: AdminPrincipal,
}

impl TenantAdminContext {
    #[allow(clippy::result_large_err)]
    pub(crate) async fn authenticate(
        state: &AppState,
        headers: &HeaderMap,
        action: AdminAction,
    ) -> Result<Self, axum::response::Response> {
        let (tenant_id, storage_tenant, owner) = match &state.form {
            Form::SelfHosted { .. } => {
                let storage_tenant = crate::tenant::tenant_or_400(state, headers)?;
                (
                    "default".to_string(),
                    storage_tenant,
                    AdminCredentialOwner::platform(),
                )
            }
            Form::Saas { .. } => {
                // Preserve the tenant-admin auth domain: an invalid/control Host is not a
                // tenant credential context and is therefore rejected as unauthorized.
                let storage_tenant =
                    crate::tenant::tenant_or_400(state, headers).map_err(|_| unauthorized())?;
                let owner = AdminCredentialOwner::tenant(&storage_tenant);
                (storage_tenant.clone(), storage_tenant, owner)
            }
        };

        // An explicit Authorization header selects the break-glass domain. An
        // invalid bearer never falls through to a browser session.
        if headers.contains_key(header::AUTHORIZATION) {
            let token = match bearer(headers) {
                Some(token) => token,
                None => {
                    audit_admin_authentication(
                        state,
                        &tenant_id,
                        crate::security_event::SecurityEventOutcome::Denied,
                    )
                    .await;
                    return Err(unauthorized());
                }
            };
            let matched = match verify(state, &owner, &token).await {
                Ok(matched) => matched,
                Err(response) => {
                    let outcome = if response.status() == StatusCode::UNAUTHORIZED {
                        crate::security_event::SecurityEventOutcome::Denied
                    } else {
                        crate::security_event::SecurityEventOutcome::Failure
                    };
                    audit_admin_authentication(state, &tenant_id, outcome).await;
                    return Err(response);
                }
            };
            if action.is_governance() && !valid_governance_break_glass_confirmation(headers) {
                audit_governance_authorization(
                    state,
                    &tenant_id,
                    &format!("break-glass:{}", matched.credential_id),
                    action,
                    crate::security_event::SecurityEventOutcome::Denied,
                )
                .await;
                return Err(governance_confirmation_required());
            }
            audit_break_glass(state, &matched, &tenant_id).await;
            if action.is_governance() {
                audit_governance_authorization(
                    state,
                    &tenant_id,
                    &format!("break-glass:{}", matched.credential_id),
                    action,
                    crate::security_event::SecurityEventOutcome::Success,
                )
                .await;
            }
            return Ok(Self {
                tenant_id,
                storage_tenant,
                principal: AdminPrincipal::BreakGlass {
                    credential_id: matched.credential_id,
                },
            });
        }

        let raw_session = match cookie(headers, ADMIN_SESSION_COOKIE) {
            Some(session) => session,
            None => {
                return Err(audited_admin_authentication_error(
                    state,
                    &tenant_id,
                    crate::security_event::SecurityEventOutcome::Denied,
                    unauthorized(),
                )
                .await)
            }
        };
        if !state.region.owns_id(&raw_session) {
            return Err(audited_admin_authentication_error(
                state,
                &tenant_id,
                crate::security_event::SecurityEventOutcome::Denied,
                unauthorized(),
            )
            .await);
        }
        let session_hash = opaque_hash(&state.server_secret, b"admin-session:", &raw_session);
        let now = crate::token::current_unix_secs_pub();
        let session = match state.admin_auth.get_session(&session_hash, now).await {
            Ok(Some(session)) => session,
            Ok(None) => {
                return Err(audited_admin_authentication_error(
                    state,
                    &tenant_id,
                    crate::security_event::SecurityEventOutcome::Denied,
                    unauthorized(),
                )
                .await)
            }
            Err(_) => {
                return Err(audited_admin_authentication_error(
                    state,
                    &tenant_id,
                    crate::security_event::SecurityEventOutcome::Failure,
                    unavailable(),
                )
                .await)
            }
        };
        if session.tenant_id != tenant_id {
            state
                .record_security_event(
                    crate::security_event::SecurityEventDraft::tenant_boundary_denial(
                        &tenant_id,
                        crate::security_event::SecurityActor::user(&session.user_id),
                        &session.tenant_id,
                    ),
                )
                .await;
            return Err(audited_admin_authentication_error(
                state,
                &tenant_id,
                crate::security_event::SecurityEventOutcome::Denied,
                unauthorized(),
            )
            .await);
        }
        let config = match state.admin_auth.get_config(&tenant_id).await {
            Ok(Some(config))
                if config.revision == session.config_revision
                    && config.binding_id == session.config_binding_id =>
            {
                config
            }
            Ok(_) => {
                return Err(audited_admin_authentication_error(
                    state,
                    &tenant_id,
                    crate::security_event::SecurityEventOutcome::Denied,
                    unauthorized(),
                )
                .await)
            }
            Err(_) => {
                return Err(audited_admin_authentication_error(
                    state,
                    &tenant_id,
                    crate::security_event::SecurityEventOutcome::Failure,
                    unavailable(),
                )
                .await)
            }
        };
        if config.tenant_id != tenant_id {
            return Err(audited_admin_authentication_error(
                state,
                &tenant_id,
                crate::security_event::SecurityEventOutcome::Failure,
                unauthorized(),
            )
            .await);
        }
        let user = match state
            .users
            .get_by_id(&storage_tenant, &session.user_id)
            .await
        {
            Ok(Some(user))
                if user.status == UserStatus::Active
                    && user.scim_external_id.is_some()
                    && !user.revocation_pending
                    && user.credential_epoch == session.credential_epoch =>
            {
                user
            }
            Ok(_) => {
                return Err(audited_admin_authentication_error(
                    state,
                    &tenant_id,
                    crate::security_event::SecurityEventOutcome::Denied,
                    unauthorized(),
                )
                .await)
            }
            Err(_) => {
                return Err(audited_admin_authentication_error(
                    state,
                    &tenant_id,
                    crate::security_event::SecurityEventOutcome::Failure,
                    unavailable(),
                )
                .await)
            }
        };
        if user.user_id != session.user_id {
            return Err(audited_admin_authentication_error(
                state,
                &tenant_id,
                crate::security_event::SecurityEventOutcome::Failure,
                unauthorized(),
            )
            .await);
        }
        let current_role = match state
            .scim_groups
            .mapped_role_for_member(&storage_tenant, &session.user_id)
            .await
        {
            Ok(mapping) => match mapping.role.filter(|role| *role == session.role) {
                Some(role) => role,
                None => {
                    return Err(audited_admin_authentication_error(
                        state,
                        &tenant_id,
                        crate::security_event::SecurityEventOutcome::Denied,
                        unauthorized(),
                    )
                    .await)
                }
            },
            Err(_) => {
                return Err(audited_admin_authentication_error(
                    state,
                    &tenant_id,
                    crate::security_event::SecurityEventOutcome::Failure,
                    unavailable(),
                )
                .await)
            }
        };
        let latest_user = match state
            .users
            .get_by_id(&storage_tenant, &session.user_id)
            .await
        {
            Ok(Some(latest))
                if latest.status == UserStatus::Active
                    && latest.scim_external_id.is_some()
                    && !latest.revocation_pending
                    && latest.credential_epoch == session.credential_epoch =>
            {
                latest
            }
            Ok(_) => {
                return Err(audited_admin_authentication_error(
                    state,
                    &tenant_id,
                    crate::security_event::SecurityEventOutcome::Denied,
                    unauthorized(),
                )
                .await)
            }
            Err(_) => {
                return Err(audited_admin_authentication_error(
                    state,
                    &tenant_id,
                    crate::security_event::SecurityEventOutcome::Failure,
                    unavailable(),
                )
                .await)
            }
        };
        if latest_user.user_id != session.user_id {
            return Err(audited_admin_authentication_error(
                state,
                &tenant_id,
                crate::security_event::SecurityEventOutcome::Failure,
                unauthorized(),
            )
            .await);
        }
        if !action.allowed_for(current_role) {
            audit_authorization(
                state,
                &tenant_id,
                &session.user_id,
                current_role,
                action,
                "denied",
            )
            .await;
            if action.is_governance() {
                audit_governance_authorization(
                    state,
                    &tenant_id,
                    &session.user_id,
                    action,
                    crate::security_event::SecurityEventOutcome::Denied,
                )
                .await;
            }
            return Err(forbidden());
        }
        if (action.requires_strong() || state.assurance_policy.admin_requires_strong(action.name()))
            && (session.acr.as_deref() != Some(agent_auth_authn::assurance::STRONG_ACR)
                || !agent_auth_authn::assurance::authentication_is_fresh(
                    session.auth_time,
                    now,
                    state.assurance_policy.strong_max_age_secs(),
                ))
        {
            audit_authorization(
                state,
                &tenant_id,
                &session.user_id,
                current_role,
                action,
                "step_up_required",
            )
            .await;
            if action.is_governance() {
                audit_governance_authorization(
                    state,
                    &tenant_id,
                    &session.user_id,
                    action,
                    crate::security_event::SecurityEventOutcome::Denied,
                )
                .await;
            }
            return Err(assurance_challenge(
                state.assurance_policy.strong_max_age_secs(),
            ));
        }
        audit_authorization(
            state,
            &tenant_id,
            &session.user_id,
            current_role,
            action,
            "allowed",
        )
        .await;
        if action.is_governance() {
            audit_governance_authorization(
                state,
                &tenant_id,
                &session.user_id,
                action,
                crate::security_event::SecurityEventOutcome::Success,
            )
            .await;
        }
        Ok(Self {
            tenant_id,
            storage_tenant,
            principal: AdminPrincipal::Session {
                user_id: session.user_id,
                role: current_role,
                expires_at: session.expires_at,
            },
        })
    }

    pub(crate) fn storage_tenant(&self) -> &str {
        &self.storage_tenant
    }

    pub(crate) fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub(crate) fn audit_identity(&self) -> String {
        match &self.principal {
            AdminPrincipal::BreakGlass { credential_id } => {
                format!("break-glass:{credential_id}")
            }
            AdminPrincipal::Session { user_id, .. } => format!("admin-user:{user_id}"),
        }
    }

    pub(crate) fn role(&self) -> Option<TenantRole> {
        match &self.principal {
            AdminPrincipal::BreakGlass { .. } => None,
            AdminPrincipal::Session { role, .. } => Some(*role),
        }
    }

    pub(crate) fn is_break_glass(&self) -> bool {
        matches!(&self.principal, AdminPrincipal::BreakGlass { .. })
    }

    pub(crate) fn expires_at(&self) -> Option<i64> {
        match &self.principal {
            AdminPrincipal::BreakGlass { .. } => None,
            AdminPrincipal::Session { expires_at, .. } => Some(*expires_at),
        }
    }

    #[allow(clippy::result_large_err)]
    pub(crate) async fn require_tenant(
        &self,
        state: &AppState,
        requested: &str,
    ) -> Result<(), axum::response::Response> {
        if requested == self.tenant_id {
            Ok(())
        } else {
            state
                .record_security_event(
                    crate::security_event::SecurityEventDraft::tenant_boundary_denial(
                        &self.tenant_id,
                        crate::security_event::SecurityActor::admin(self.audit_identity()),
                        requested,
                    ),
                )
                .await;
            Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "status": StatusCode::FORBIDDEN.as_u16(),
                    "message": "tenant is outside authenticated admin context"
                })),
            )
                .into_response())
        }
    }
}

pub(crate) fn admin_session_cookie(headers: &HeaderMap) -> Option<String> {
    cookie(headers, ADMIN_SESSION_COOKIE)
}

pub(crate) fn admin_flow_cookie(headers: &HeaderMap) -> Option<String> {
    cookie(headers, ADMIN_FLOW_COOKIE)
}

pub(crate) fn admin_session_hash(state: &AppState, value: &str) -> String {
    opaque_hash(&state.server_secret, b"admin-session:", value)
}

pub(crate) fn admin_flow_hash(state: &AppState, state_value: &str, browser_nonce: &str) -> String {
    let framed = format!("{state_value}.{browser_nonce}");
    opaque_hash(&state.server_secret, b"admin-oidc-flow:", &framed)
}

pub(crate) const fn admin_session_cookie_name() -> &'static str {
    ADMIN_SESSION_COOKIE
}

pub(crate) const fn admin_flow_cookie_name() -> &'static str {
    ADMIN_FLOW_COOKIE
}

pub(crate) async fn authenticate_platform(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), axum::response::Response> {
    let token = match bearer(headers) {
        Some(token) => token,
        None => {
            if headers.contains_key(header::AUTHORIZATION) {
                audit_admin_authentication(
                    state,
                    "platform",
                    crate::security_event::SecurityEventOutcome::Denied,
                )
                .await;
            }
            return Err(unauthorized());
        }
    };
    let matched = match verify(state, &AdminCredentialOwner::platform(), &token).await {
        Ok(matched) => matched,
        Err(response) => {
            let outcome = if response.status() == StatusCode::UNAUTHORIZED {
                crate::security_event::SecurityEventOutcome::Denied
            } else {
                crate::security_event::SecurityEventOutcome::Failure
            };
            audit_admin_authentication(state, "platform", outcome).await;
            return Err(response);
        }
    };
    audit_break_glass(state, &matched, "platform").await;
    Ok(())
}

pub(crate) async fn authenticate_platform_governance(
    state: &AppState,
    headers: &HeaderMap,
    tenant_id: &str,
    action: &str,
) -> Result<(), axum::response::Response> {
    authenticate_platform(state, headers).await?;
    let outcome = if valid_governance_break_glass_confirmation(headers) {
        crate::security_event::SecurityEventOutcome::Success
    } else {
        crate::security_event::SecurityEventOutcome::Denied
    };
    state
        .record_security_event(crate::security_event::SecurityEventDraft::new(
            tenant_id,
            crate::security_event::SecurityActor::admin("platform"),
            Some(crate::security_event::SecuritySubject::tenant(tenant_id)),
            crate::security_event::SecurityEventCategory::Administration,
            format!("admin.authorization.{action}"),
            outcome,
        ))
        .await;
    if outcome == crate::security_event::SecurityEventOutcome::Denied {
        return Err(governance_confirmation_required());
    }
    Ok(())
}

async fn audit_admin_authentication(
    state: &AppState,
    tenant: &str,
    outcome: crate::security_event::SecurityEventOutcome,
) {
    state
        .record_security_event(crate::security_event::SecurityEventDraft::new(
            tenant,
            crate::security_event::SecurityActor::system("anonymous"),
            Some(crate::security_event::SecuritySubject::tenant(tenant)),
            crate::security_event::SecurityEventCategory::Authentication,
            "authentication.admin",
            outcome,
        ))
        .await;
}

async fn audited_admin_authentication_error(
    state: &AppState,
    tenant: &str,
    outcome: crate::security_event::SecurityEventOutcome,
    response: axum::response::Response,
) -> axum::response::Response {
    audit_admin_authentication(state, tenant, outcome).await;
    response
}

pub(crate) fn bearer(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = raw.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| rest.trim().to_string())
}

async fn verify(
    state: &AppState,
    owner: &AdminCredentialOwner,
    token: &str,
) -> Result<AdminCredentialMatch, axum::response::Response> {
    match state
        .admin_credentials
        .verify(owner, token, crate::token::current_unix_secs_pub())
        .await
    {
        Ok(Some(matched)) => Ok(matched),
        Ok(None) => Err(unauthorized()),
        Err(
            AdminCredentialError::InvalidConfiguration
            | AdminCredentialError::Unavailable
            | AdminCredentialError::Removed,
        ) => Err(unavailable()),
    }
}

async fn audit_break_glass(state: &AppState, matched: &AdminCredentialMatch, tenant: &str) {
    let owner = match &matched.owner {
        AdminCredentialOwner::Platform => "platform",
        AdminCredentialOwner::Tenant { .. } => "tenant",
        AdminCredentialOwner::ScimTenant { .. } => "scim",
    };
    let slot = match matched.slot {
        AdminCredentialSlot::Current => "current",
        AdminCredentialSlot::Next => "next",
    };
    state
        .audit_credential_event(
            crate::credential::CredentialAuditEvent::AdminBreakGlassUse {
                tenant,
                owner,
                credential_id: &matched.credential_id,
                slot,
                revision: matched.revision,
            },
        )
        .await;
}

async fn audit_authorization(
    state: &AppState,
    tenant: &str,
    actor: &str,
    role: TenantRole,
    action: AdminAction,
    result: &str,
) {
    state
        .audit_credential_event(
            crate::credential::CredentialAuditEvent::AdminAuthorization {
                tenant,
                actor,
                role: role_name(role),
                action: action.name(),
                result,
            },
        )
        .await;
}

async fn audit_governance_authorization(
    state: &AppState,
    tenant: &str,
    actor: &str,
    action: AdminAction,
    outcome: crate::security_event::SecurityEventOutcome,
) {
    state
        .record_security_event(crate::security_event::SecurityEventDraft::new(
            tenant,
            crate::security_event::SecurityActor::admin(actor),
            Some(crate::security_event::SecuritySubject::tenant(tenant)),
            crate::security_event::SecurityEventCategory::Administration,
            format!("admin.authorization.{}", action.name()),
            outcome,
        ))
        .await;
}

fn valid_governance_break_glass_confirmation(headers: &HeaderMap) -> bool {
    let purpose = headers
        .get(GOVERNANCE_PURPOSE_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| crate::governance::validate_purpose(value).ok());
    let confirmed = headers
        .get(GOVERNANCE_CONFIRM_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("true"));
    purpose.is_some() && confirmed
}

pub(crate) const fn role_name(role: TenantRole) -> &'static str {
    match role {
        TenantRole::Owner => "owner",
        TenantRole::Admin => "admin",
        TenantRole::Auditor => "auditor",
        TenantRole::Member => "member",
    }
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(key, value)| (key == name && !value.is_empty()).then(|| value.to_string()))
}

fn opaque_hash(secret: &[u8], domain: &[u8], value: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(domain);
    mac.update(value.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn unauthorized() -> axum::response::Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({
            "status": StatusCode::UNAUTHORIZED.as_u16(),
            "message": "admin auth required"
        })),
    )
        .into_response()
}

fn forbidden() -> axum::response::Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "status": StatusCode::FORBIDDEN.as_u16(),
            "message": "admin role does not permit this action"
        })),
    )
        .into_response()
}

fn governance_confirmation_required() -> axum::response::Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "status": StatusCode::FORBIDDEN.as_u16(),
            "message": "governance break-glass requires explicit purpose and confirmation"
        })),
    )
        .into_response()
}

fn assurance_challenge(max_age_secs: i64) -> axum::response::Response {
    let challenge = format!(
        "Bearer error=\"insufficient_user_authentication\", \
         error_description=\"A different and recent authentication level is required\", \
         acr_values=\"{}\", max_age=\"{max_age_secs}\"",
        agent_auth_authn::assurance::STRONG_ACR
    );
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({
            "status": StatusCode::UNAUTHORIZED.as_u16(),
            "message": "strong recent authentication required",
            "error": "insufficient_user_authentication"
        })),
    )
        .into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_str(&challenge).expect("fixed assurance challenge is a valid header"),
    );
    response
}

fn unavailable() -> axum::response::Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "status": StatusCode::SERVICE_UNAVAILABLE.as_u16(),
            "message": "admin authentication unavailable"
        })),
    )
        .into_response()
}
