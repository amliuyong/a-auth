//! Bounded presentation settings. Authorization facts never come from branding.

use agent_auth_discovery::Form;
use axum::{
    extract::{rejection::JsonRejection, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::branding_store::StoredBranding;
use crate::ports::{StoreError, TenantRole};
use crate::state::AppState;
use crate::tenant_admin::{AdminAction, TenantAdminContext};

const MAX_REVISION: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BrandingLogo {
    #[default]
    None,
    Shield,
    Key,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BrandingPrimary {
    #[default]
    Blue,
    Teal,
    Violet,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BrandingSettings {
    /// None keeps the existing localized product name.
    pub name: Option<String>,
    pub logo: BrandingLogo,
    pub primary: BrandingPrimary,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BrandingView {
    pub status: String,
    pub version: u32,
    pub revision: u64,
    pub settings: BrandingSettings,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BrandingUpdate {
    pub expected_revision: u64,
    pub settings: BrandingSettings,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BrandingReset {
    pub expected_revision: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AdminBrandingView {
    #[serde(flatten)]
    pub branding: BrandingView,
    pub can_manage: bool,
}

fn valid_settings(settings: &BrandingSettings) -> bool {
    settings.name.as_ref().is_none_or(|name| {
        !name.is_empty()
            && name.trim() == name
            && name.chars().count() <= 64
            && !name.chars().any(|c| {
                c.is_control()
                    || matches!(
                        c,
                        '\u{061c}' | '\u{200e}' | '\u{200f}'
                            | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
                    )
            })
    })
}

async fn load(state: &AppState) -> Result<BrandingView, StoreError> {
    let mut view = BrandingView {
        status: "ready".into(),
        version: 1,
        revision: 0,
        settings: BrandingSettings::default(),
    };
    let Form::SelfHosted { configured_host } = &state.form else {
        view.status = "unsupported_deployment".into();
        return Ok(view);
    };
    if let Some(record) = state.branding.get(configured_host).await? {
        if record.revision == 0 || record.revision > MAX_REVISION {
            return Err(StoreError::Permanent("invalid branding revision".into()));
        }
        view.version = record.version;
        view.revision = record.revision;
        if record.version != 1 {
            view.status = "unsupported_version".into();
            return Ok(view);
        }
        let settings: BrandingSettings = serde_json::from_value(record.settings)
            .map_err(|_| StoreError::Permanent("invalid branding settings".into()))?;
        if !valid_settings(&settings) {
            return Err(StoreError::Permanent("invalid branding settings".into()));
        }
        view.settings = settings;
    }
    Ok(view)
}

fn error(status: StatusCode, code: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({"error": code})),
    )
        .into_response()
}

#[utoipa::path(
    get,
    path = "/ui/branding",
    tag = "login",
    responses(
        (status = 200, description = "Public deployment presentation settings", body = BrandingView),
        (status = 503, description = "Branding store unavailable")
    )
)]
pub async fn public_settings(State(state): State<AppState>) -> Response {
    match load(&state).await {
        Ok(view) => ([(header::CACHE_CONTROL, "no-store")], Json(view)).into_response(),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "branding_unavailable"),
    }
}

#[utoipa::path(
    get, path = "/admin/branding", tag = "admin",
    responses(
        (status = 200, description = "Deployment branding and current management permission", body = AdminBrandingView),
        (status = 401, description = "Admin authentication required"),
        (status = 403, description = "Admin read permission required"),
        (status = 503, description = "Branding store unavailable")
    )
)]
pub async fn admin_settings(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Read).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    match load(&state).await {
        Ok(branding) => {
            let can_manage = branding.status == "ready"
                && (admin.is_break_glass() || admin.role() == Some(TenantRole::Owner));
            (
                [(header::CACHE_CONTROL, "no-store")],
                Json(AdminBrandingView {
                    branding,
                    can_manage,
                }),
            )
                .into_response()
        }
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "branding_unavailable"),
    }
}

#[utoipa::path(
    put, path = "/admin/branding", tag = "admin", request_body = BrandingUpdate,
    responses(
        (status = 200, description = "Version-1 deployment branding saved", body = BrandingView),
        (status = 400, description = "Invalid bounded settings or revision"),
        (status = 401, description = "Admin authentication required"),
        (status = 403, description = "Owner or break-glass required"),
        (status = 409, description = "Revision conflict or unsupported stored version"),
        (status = 501, description = "SaaS deployment branding unsupported"),
        (status = 503, description = "Branding store unavailable")
    )
)]
pub async fn put_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Result<Json<BrandingUpdate>, JsonRejection>,
) -> Response {
    if let Err(response) =
        TenantAdminContext::authenticate(&state, &headers, AdminAction::ManageAccess).await
    {
        return response;
    }
    let Ok(Json(request)) = request else {
        return error(StatusCode::BAD_REQUEST, "invalid_branding");
    };
    save(&state, request).await
}

#[utoipa::path(
    post, path = "/admin/branding/reset", tag = "admin", request_body = BrandingReset,
    responses(
        (status = 200, description = "Defaults persisted with an advanced revision", body = BrandingView),
        (status = 400, description = "Invalid revision"),
        (status = 401, description = "Admin authentication required"),
        (status = 403, description = "Owner or break-glass required"),
        (status = 409, description = "Revision conflict or unsupported stored version"),
        (status = 501, description = "SaaS deployment branding unsupported"),
        (status = 503, description = "Branding store unavailable")
    )
)]
pub async fn reset_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Result<Json<BrandingReset>, JsonRejection>,
) -> Response {
    if let Err(response) =
        TenantAdminContext::authenticate(&state, &headers, AdminAction::ManageAccess).await
    {
        return response;
    }
    let Ok(Json(request)) = request else {
        return error(StatusCode::BAD_REQUEST, "invalid_branding");
    };
    save(
        &state,
        BrandingUpdate {
            expected_revision: request.expected_revision,
            settings: BrandingSettings::default(),
        },
    )
    .await
}

async fn save(state: &AppState, request: BrandingUpdate) -> Response {
    let Form::SelfHosted { configured_host } = &state.form else {
        return error(StatusCode::NOT_IMPLEMENTED, "unsupported_deployment");
    };
    if request.expected_revision >= MAX_REVISION || !valid_settings(&request.settings) {
        return error(StatusCode::BAD_REQUEST, "invalid_branding");
    }
    let current = match load(state).await {
        Ok(view) => view,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "branding_unavailable"),
    };
    if current.status != "ready" || current.revision != request.expected_revision {
        return error(StatusCode::CONFLICT, "branding_conflict");
    }
    let revision = request.expected_revision + 1;
    let record = StoredBranding {
        version: 1,
        revision,
        settings: serde_json::to_value(&request.settings).expect("typed branding settings"),
    };
    match state
        .branding
        .put(configured_host, record, request.expected_revision)
        .await
    {
        Ok(true) => (
            [(header::CACHE_CONTROL, "no-store")],
            Json(BrandingView {
                status: "ready".into(),
                version: 1,
                revision,
                settings: request.settings,
            }),
        )
            .into_response(),
        Ok(false) => error(StatusCode::CONFLICT, "branding_conflict"),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "branding_unavailable"),
    }
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(public_settings))
        .routes(routes!(admin_settings, put_settings))
        .routes(routes!(reset_settings))
}
