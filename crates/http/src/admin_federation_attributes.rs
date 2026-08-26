use agent_auth_discovery::Form;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::attribute_namespace::{AttributeNamespaceStore, RegistrationState};
use crate::federation_attributes::{
    AttributeMapping, FederationAttributeMappingsStore, MappingChange, MappingChangeOutcome,
    MappingMode, MappingRegistry, MappingSpec,
};
use crate::ports::FederationConfigStore;
use crate::security_event::{
    SecurityEventCategory, SecurityEventCorrelation, SecurityEventDraft, SecurityEventOutcome,
    SecuritySubject,
};
use crate::state::AppState;
use crate::tenant_admin::{AdminAction, TenantAdminContext};

#[derive(Debug, Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MappingModeInput {
    CopyString,
    ExactMembership,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateFederationAttributeMapping {
    pub expected_registry_revision: u64,
    pub mode: MappingModeInput,
    pub source_claim: String,
    #[schema(required = true)]
    pub source_value: Option<String>,
    #[schema(max_length = 1024)]
    pub target_namespace: String,
    pub target_key: String,
    #[schema(required = true)]
    pub target_value: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateFederationAttributeMapping {
    pub expected_registry_revision: u64,
    pub expected_mapping_revision: u64,
    pub enabled: bool,
    pub mode: MappingModeInput,
    pub source_claim: String,
    #[schema(required = true)]
    pub source_value: Option<String>,
    #[schema(max_length = 1024)]
    pub target_namespace: String,
    pub target_key: String,
    #[schema(required = true)]
    pub target_value: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub struct DeleteFederationAttributeMapping {
    pub expected_registry_revision: u64,
    pub expected_mapping_revision: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FederationAttributeMappingView {
    pub mapping_id: String,
    pub revision: u64,
    pub enabled: bool,
    pub mode: String,
    pub source_claim: String,
    #[schema(required = true)]
    pub source_value: Option<String>,
    #[schema(max_length = 1024)]
    pub target_namespace: String,
    pub target_key: String,
    #[schema(required = true)]
    pub target_value: Option<String>,
}

impl From<&AttributeMapping> for FederationAttributeMappingView {
    fn from(mapping: &AttributeMapping) -> Self {
        let (mode, source_value, target_value) = match &mapping.mode {
            MappingMode::CopyString => ("copy_string", None, None),
            MappingMode::ExactMembership {
                source_value,
                target_value,
            } => (
                "exact_membership",
                Some(source_value.clone()),
                Some(target_value.clone()),
            ),
        };
        Self {
            mapping_id: mapping.mapping_id.clone(),
            revision: mapping.revision,
            enabled: mapping.enabled,
            mode: mode.to_string(),
            source_claim: mapping.source_claim.clone(),
            source_value,
            target_namespace: mapping.target_namespace.clone(),
            target_key: mapping.target_key.clone(),
            target_value,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FederationAttributeMappingList {
    pub tenant_id: String,
    pub upstream_idp_id: String,
    pub upstream_issuer: String,
    pub registry_revision: u64,
    pub mappings: Vec<FederationAttributeMappingView>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FederationAttributeMappingCreated {
    pub registry_revision: u64,
    pub mapping: FederationAttributeMappingView,
}

fn error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "status": status.as_u16(),
            "message": message,
        })),
    )
        .into_response()
}

struct MappingAuditTarget<'a> {
    mapping_id: &'a str,
    mapping_revision: u64,
    target_namespace: &'a str,
    target_key: &'a str,
}

async fn audit_mapping_change(
    state: &AppState,
    admin: &TenantAdminContext,
    tenant_id: &str,
    upstream_idp_id: &str,
    action: &'static str,
    outcome: SecurityEventOutcome,
    target: MappingAuditTarget<'_>,
) {
    state
        .record_security_event(
            SecurityEventDraft::new(
                tenant_id,
                crate::security_event::SecurityActor::admin(admin.audit_identity()),
                Some(SecuritySubject::unknown(target.mapping_id)),
                SecurityEventCategory::Administration,
                action,
                outcome,
            )
            .correlated(SecurityEventCorrelation {
                upstream_idp_id: Some(upstream_idp_id.to_string()),
                mapping_id: Some(target.mapping_id.to_string()),
                mapping_revision: Some(target.mapping_revision),
                target_namespace: Some(target.target_namespace.to_string()),
                target_key: Some(target.target_key.to_string()),
                ..Default::default()
            }),
        )
        .await;
}

fn mapping_spec(
    request: CreateFederationAttributeMapping,
) -> Result<(u64, MappingSpec), &'static str> {
    let mode = match request.mode {
        MappingModeInput::CopyString => {
            if request.source_value.is_some() || request.target_value.is_some() {
                return Err("copy_string does not accept source_value or target_value");
            }
            MappingMode::CopyString
        }
        MappingModeInput::ExactMembership => {
            let Some(source_value) = request.source_value else {
                return Err("exact_membership requires source_value");
            };
            let Some(target_value) = request.target_value else {
                return Err("exact_membership requires target_value");
            };
            MappingMode::ExactMembership {
                source_value,
                target_value,
            }
        }
    };
    Ok((
        request.expected_registry_revision,
        MappingSpec {
            source_claim: request.source_claim,
            target_namespace: request.target_namespace,
            target_key: request.target_key,
            mode,
        },
    ))
}

fn updated_mapping_spec(
    request: UpdateFederationAttributeMapping,
) -> Result<(u64, u64, bool, MappingSpec), &'static str> {
    let create = CreateFederationAttributeMapping {
        expected_registry_revision: request.expected_registry_revision,
        mode: request.mode,
        source_claim: request.source_claim,
        source_value: request.source_value,
        target_namespace: request.target_namespace,
        target_key: request.target_key,
        target_value: request.target_value,
    };
    let (expected_registry_revision, spec) = mapping_spec(create)?;
    Ok((
        expected_registry_revision,
        request.expected_mapping_revision,
        request.enabled,
        spec,
    ))
}

async fn idp_config(
    state: &AppState,
    tenant_id: &str,
    upstream_idp_id: &str,
) -> Result<agent_auth_authn::federation::FederationConfig, Response> {
    match state
        .federation_config
        .get(tenant_id, upstream_idp_id)
        .await
    {
        Ok(Some(config)) => Ok(config),
        Ok(None) => Err(error(StatusCode::NOT_FOUND, "federation IdP not found")),
        Err(_) => Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "federation config store unavailable",
        )),
    }
}

fn list_view(
    tenant_id: &str,
    upstream_idp_id: &str,
    upstream_issuer: &str,
    registry: Option<&MappingRegistry>,
) -> FederationAttributeMappingList {
    FederationAttributeMappingList {
        tenant_id: tenant_id.to_string(),
        upstream_idp_id: upstream_idp_id.to_string(),
        upstream_issuer: upstream_issuer.to_string(),
        registry_revision: registry.map_or(0, |registry| registry.revision),
        mappings: registry
            .map(|registry| {
                registry
                    .mappings
                    .iter()
                    .map(FederationAttributeMappingView::from)
                    .collect()
            })
            .unwrap_or_default(),
    }
}

async fn require_active_namespace(
    state: &AppState,
    storage_tenant: &str,
    target_namespace: &str,
) -> Result<(), Response> {
    match state
        .attribute_namespaces
        .get(storage_tenant, target_namespace)
        .await
    {
        Ok(Some(registration))
            if registration.state == RegistrationState::Active
                && registration.operation.is_none() =>
        {
            Ok(())
        }
        Ok(_) => Err(error(
            StatusCode::BAD_REQUEST,
            "target_namespace must be an active canonical namespace",
        )),
        Err(_) => Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "attribute namespace store unavailable",
        )),
    }
}

#[utoipa::path(
    get,
    path = "/admin/federation/{tenant_id}/{upstream_idp_id}/attribute-mappings",
    tag = "admin",
    params(
        ("tenant_id" = String, Path),
        ("upstream_idp_id" = String, Path)
    ),
    responses(
        (status = 200, body = FederationAttributeMappingList),
        (status = 401),
        (status = 403),
        (status = 404),
        (status = 503)
    )
)]
pub async fn list_federation_attribute_mappings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((tenant_id, upstream_idp_id)): Path<(String, String)>,
) -> Response {
    if !matches!(state.form, Form::SelfHosted { .. }) {
        return error(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Read).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    if let Err(response) = admin.require_tenant(&state, &tenant_id).await {
        return response;
    }
    let config = match idp_config(&state, &tenant_id, &upstream_idp_id).await {
        Ok(config) => config,
        Err(response) => return response,
    };
    match state
        .federation_attribute_mappings
        .get_registry(&tenant_id, &upstream_idp_id)
        .await
    {
        Ok(registry) => Json(list_view(
            &tenant_id,
            &upstream_idp_id,
            &config.upstream_issuer,
            registry.as_ref(),
        ))
        .into_response(),
        Err(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "federation attribute mapping store unavailable",
        ),
    }
}

#[utoipa::path(
    post,
    path = "/admin/federation/{tenant_id}/{upstream_idp_id}/attribute-mappings",
    tag = "admin",
    params(
        ("tenant_id" = String, Path),
        ("upstream_idp_id" = String, Path)
    ),
    request_body = CreateFederationAttributeMapping,
    responses(
        (status = 201, body = FederationAttributeMappingCreated),
        (status = 400),
        (status = 401),
        (status = 403),
        (status = 404),
        (status = 409),
        (status = 503)
    )
)]
pub async fn create_federation_attribute_mapping(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((tenant_id, upstream_idp_id)): Path<(String, String)>,
    Json(request): Json<CreateFederationAttributeMapping>,
) -> Response {
    if !matches!(state.form, Form::SelfHosted { .. }) {
        return error(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    if let Err(response) = admin.require_tenant(&state, &tenant_id).await {
        return response;
    }
    let config = match idp_config(&state, &tenant_id, &upstream_idp_id).await {
        Ok(config) => config,
        Err(response) => return response,
    };
    let (expected_registry_revision, spec) = match mapping_spec(request) {
        Ok(spec) => spec,
        Err(message) => return error(StatusCode::BAD_REQUEST, message),
    };
    let mapping_id = format!("fm_{}", state.region.issue_id(crate::login::rand_id(18)));
    let target_namespace = spec.target_namespace.clone();
    let target_key = spec.target_key.clone();
    let outcome = {
        let _guard = state.attribute_namespace_write_lock.lock().await;
        if let Err(response) =
            require_active_namespace(&state, admin.storage_tenant(), &spec.target_namespace).await
        {
            return response;
        }
        state
            .change_federation_attribute_mapping(
                &config,
                MappingChange::Create {
                    mapping_id: mapping_id.clone(),
                    expected_registry_revision,
                    spec,
                },
            )
            .await
    };
    match outcome {
        Ok(MappingChangeOutcome::Applied(registry)) => {
            let mapping = registry
                .mappings
                .iter()
                .find(|mapping| mapping.mapping_id == mapping_id)
                .expect("applied create must return the created mapping");
            audit_mapping_change(
                &state,
                &admin,
                &tenant_id,
                &upstream_idp_id,
                "federation.attribute_mapping.create",
                SecurityEventOutcome::Success,
                MappingAuditTarget {
                    mapping_id: &mapping_id,
                    mapping_revision: mapping.revision,
                    target_namespace: &mapping.target_namespace,
                    target_key: &mapping.target_key,
                },
            )
            .await;
            (
                StatusCode::CREATED,
                Json(FederationAttributeMappingCreated {
                    registry_revision: registry.revision,
                    mapping: FederationAttributeMappingView::from(mapping),
                }),
            )
                .into_response()
        }
        Ok(MappingChangeOutcome::Conflict | MappingChangeOutcome::TargetConflict) => {
            audit_mapping_change(
                &state,
                &admin,
                &tenant_id,
                &upstream_idp_id,
                "federation.attribute_mapping.create",
                SecurityEventOutcome::Denied,
                MappingAuditTarget {
                    mapping_id: &mapping_id,
                    mapping_revision: 1,
                    target_namespace: &target_namespace,
                    target_key: &target_key,
                },
            )
            .await;
            error(StatusCode::CONFLICT, "mapping authority conflict")
        }
        Ok(MappingChangeOutcome::Invalid(_) | MappingChangeOutcome::LimitExceeded) => {
            audit_mapping_change(
                &state,
                &admin,
                &tenant_id,
                &upstream_idp_id,
                "federation.attribute_mapping.create",
                SecurityEventOutcome::Denied,
                MappingAuditTarget {
                    mapping_id: &mapping_id,
                    mapping_revision: 1,
                    target_namespace: &target_namespace,
                    target_key: &target_key,
                },
            )
            .await;
            error(StatusCode::BAD_REQUEST, "invalid mapping")
        }
        Ok(MappingChangeOutcome::MappingIdRetired | MappingChangeOutcome::NotFound) => {
            audit_mapping_change(
                &state,
                &admin,
                &tenant_id,
                &upstream_idp_id,
                "federation.attribute_mapping.create",
                SecurityEventOutcome::Denied,
                MappingAuditTarget {
                    mapping_id: &mapping_id,
                    mapping_revision: 1,
                    target_namespace: &target_namespace,
                    target_key: &target_key,
                },
            )
            .await;
            error(StatusCode::CONFLICT, "mapping state conflict")
        }
        Err(_) => {
            audit_mapping_change(
                &state,
                &admin,
                &tenant_id,
                &upstream_idp_id,
                "federation.attribute_mapping.create",
                SecurityEventOutcome::Failure,
                MappingAuditTarget {
                    mapping_id: &mapping_id,
                    mapping_revision: 1,
                    target_namespace: &target_namespace,
                    target_key: &target_key,
                },
            )
            .await;
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "federation attribute mapping store unavailable",
            )
        }
    }
}

#[utoipa::path(
    put,
    path = "/admin/federation/{tenant_id}/{upstream_idp_id}/attribute-mappings/{mapping_id}",
    tag = "admin",
    params(
        ("tenant_id" = String, Path),
        ("upstream_idp_id" = String, Path),
        ("mapping_id" = String, Path)
    ),
    request_body = UpdateFederationAttributeMapping,
    responses(
        (status = 200, body = FederationAttributeMappingCreated),
        (status = 400),
        (status = 401),
        (status = 403),
        (status = 404),
        (status = 409),
        (status = 503)
    )
)]
pub async fn update_federation_attribute_mapping(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((tenant_id, upstream_idp_id, mapping_id)): Path<(String, String, String)>,
    Json(request): Json<UpdateFederationAttributeMapping>,
) -> Response {
    if !matches!(state.form, Form::SelfHosted { .. }) {
        return error(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    if let Err(response) = admin.require_tenant(&state, &tenant_id).await {
        return response;
    }
    let config = match idp_config(&state, &tenant_id, &upstream_idp_id).await {
        Ok(config) => config,
        Err(response) => return response,
    };
    let (expected_registry_revision, expected_mapping_revision, enabled, spec) =
        match updated_mapping_spec(request) {
            Ok(spec) => spec,
            Err(message) => return error(StatusCode::BAD_REQUEST, message),
        };
    let target_namespace = spec.target_namespace.clone();
    let target_key = spec.target_key.clone();
    let outcome = {
        let _guard = state.attribute_namespace_write_lock.lock().await;
        if let Err(response) =
            require_active_namespace(&state, admin.storage_tenant(), &spec.target_namespace).await
        {
            return response;
        }
        state
            .change_federation_attribute_mapping(
                &config,
                MappingChange::Update {
                    mapping_id: mapping_id.clone(),
                    expected_registry_revision,
                    expected_mapping_revision,
                    enabled,
                    spec,
                },
            )
            .await
    };
    match outcome {
        Ok(MappingChangeOutcome::Applied(registry)) => {
            let mapping = registry
                .mappings
                .iter()
                .find(|mapping| mapping.mapping_id == mapping_id)
                .expect("applied update must return the updated mapping");
            audit_mapping_change(
                &state,
                &admin,
                &tenant_id,
                &upstream_idp_id,
                "federation.attribute_mapping.update",
                SecurityEventOutcome::Success,
                MappingAuditTarget {
                    mapping_id: &mapping_id,
                    mapping_revision: mapping.revision,
                    target_namespace: &mapping.target_namespace,
                    target_key: &mapping.target_key,
                },
            )
            .await;
            Json(FederationAttributeMappingCreated {
                registry_revision: registry.revision,
                mapping: FederationAttributeMappingView::from(mapping),
            })
            .into_response()
        }
        Ok(MappingChangeOutcome::Conflict | MappingChangeOutcome::TargetConflict) => {
            audit_mapping_change(
                &state,
                &admin,
                &tenant_id,
                &upstream_idp_id,
                "federation.attribute_mapping.update",
                SecurityEventOutcome::Denied,
                MappingAuditTarget {
                    mapping_id: &mapping_id,
                    mapping_revision: expected_mapping_revision,
                    target_namespace: &target_namespace,
                    target_key: &target_key,
                },
            )
            .await;
            error(StatusCode::CONFLICT, "mapping authority conflict")
        }
        Ok(MappingChangeOutcome::Invalid(_) | MappingChangeOutcome::LimitExceeded) => {
            audit_mapping_change(
                &state,
                &admin,
                &tenant_id,
                &upstream_idp_id,
                "federation.attribute_mapping.update",
                SecurityEventOutcome::Denied,
                MappingAuditTarget {
                    mapping_id: &mapping_id,
                    mapping_revision: expected_mapping_revision,
                    target_namespace: &target_namespace,
                    target_key: &target_key,
                },
            )
            .await;
            error(StatusCode::BAD_REQUEST, "invalid mapping")
        }
        Ok(MappingChangeOutcome::NotFound) => {
            audit_mapping_change(
                &state,
                &admin,
                &tenant_id,
                &upstream_idp_id,
                "federation.attribute_mapping.update",
                SecurityEventOutcome::Denied,
                MappingAuditTarget {
                    mapping_id: &mapping_id,
                    mapping_revision: expected_mapping_revision,
                    target_namespace: &target_namespace,
                    target_key: &target_key,
                },
            )
            .await;
            error(StatusCode::NOT_FOUND, "mapping not found")
        }
        Ok(MappingChangeOutcome::MappingIdRetired) => {
            audit_mapping_change(
                &state,
                &admin,
                &tenant_id,
                &upstream_idp_id,
                "federation.attribute_mapping.update",
                SecurityEventOutcome::Denied,
                MappingAuditTarget {
                    mapping_id: &mapping_id,
                    mapping_revision: expected_mapping_revision,
                    target_namespace: &target_namespace,
                    target_key: &target_key,
                },
            )
            .await;
            error(StatusCode::CONFLICT, "mapping state conflict")
        }
        Err(_) => {
            audit_mapping_change(
                &state,
                &admin,
                &tenant_id,
                &upstream_idp_id,
                "federation.attribute_mapping.update",
                SecurityEventOutcome::Failure,
                MappingAuditTarget {
                    mapping_id: &mapping_id,
                    mapping_revision: expected_mapping_revision,
                    target_namespace: &target_namespace,
                    target_key: &target_key,
                },
            )
            .await;
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "federation attribute mapping store unavailable",
            )
        }
    }
}

#[utoipa::path(
    delete,
    path = "/admin/federation/{tenant_id}/{upstream_idp_id}/attribute-mappings/{mapping_id}",
    tag = "admin",
    params(
        ("tenant_id" = String, Path),
        ("upstream_idp_id" = String, Path),
        ("mapping_id" = String, Path),
        DeleteFederationAttributeMapping
    ),
    responses(
        (status = 200, body = FederationAttributeMappingList),
        (status = 400),
        (status = 401),
        (status = 403),
        (status = 404),
        (status = 409),
        (status = 503)
    )
)]
pub async fn delete_federation_attribute_mapping(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((tenant_id, upstream_idp_id, mapping_id)): Path<(String, String, String)>,
    Query(request): Query<DeleteFederationAttributeMapping>,
) -> Response {
    if !matches!(state.form, Form::SelfHosted { .. }) {
        return error(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    if let Err(response) = admin.require_tenant(&state, &tenant_id).await {
        return response;
    }
    let config = match idp_config(&state, &tenant_id, &upstream_idp_id).await {
        Ok(config) => config,
        Err(response) => return response,
    };
    let (target_namespace, target_key, outcome) = {
        let _guard = state.attribute_namespace_write_lock.lock().await;
        let current_mapping = match state
            .federation_attribute_mappings
            .get_registry(&tenant_id, &upstream_idp_id)
            .await
        {
            Ok(Some(registry)) => match registry
                .mappings
                .into_iter()
                .find(|mapping| mapping.mapping_id == mapping_id)
            {
                Some(mapping) => mapping,
                None => return error(StatusCode::NOT_FOUND, "mapping not found"),
            },
            Ok(None) => return error(StatusCode::NOT_FOUND, "mapping not found"),
            Err(_) => {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "federation attribute mapping store unavailable",
                )
            }
        };
        let target_namespace = current_mapping.target_namespace;
        let target_key = current_mapping.target_key;
        let outcome = state
            .change_federation_attribute_mapping(
                &config,
                MappingChange::Delete {
                    mapping_id: mapping_id.clone(),
                    expected_registry_revision: request.expected_registry_revision,
                    expected_mapping_revision: request.expected_mapping_revision,
                },
            )
            .await;
        (target_namespace, target_key, outcome)
    };
    match outcome {
        Ok(MappingChangeOutcome::Applied(registry)) => {
            audit_mapping_change(
                &state,
                &admin,
                &tenant_id,
                &upstream_idp_id,
                "federation.attribute_mapping.delete",
                SecurityEventOutcome::Success,
                MappingAuditTarget {
                    mapping_id: &mapping_id,
                    mapping_revision: request.expected_mapping_revision,
                    target_namespace: &target_namespace,
                    target_key: &target_key,
                },
            )
            .await;
            Json(list_view(
                &tenant_id,
                &upstream_idp_id,
                &config.upstream_issuer,
                Some(&registry),
            ))
            .into_response()
        }
        Ok(MappingChangeOutcome::Conflict | MappingChangeOutcome::TargetConflict) => {
            audit_mapping_change(
                &state,
                &admin,
                &tenant_id,
                &upstream_idp_id,
                "federation.attribute_mapping.delete",
                SecurityEventOutcome::Denied,
                MappingAuditTarget {
                    mapping_id: &mapping_id,
                    mapping_revision: request.expected_mapping_revision,
                    target_namespace: &target_namespace,
                    target_key: &target_key,
                },
            )
            .await;
            error(StatusCode::CONFLICT, "mapping authority conflict")
        }
        Ok(MappingChangeOutcome::NotFound) => {
            audit_mapping_change(
                &state,
                &admin,
                &tenant_id,
                &upstream_idp_id,
                "federation.attribute_mapping.delete",
                SecurityEventOutcome::Denied,
                MappingAuditTarget {
                    mapping_id: &mapping_id,
                    mapping_revision: request.expected_mapping_revision,
                    target_namespace: &target_namespace,
                    target_key: &target_key,
                },
            )
            .await;
            error(StatusCode::NOT_FOUND, "mapping not found")
        }
        Ok(
            MappingChangeOutcome::Invalid(_)
            | MappingChangeOutcome::LimitExceeded
            | MappingChangeOutcome::MappingIdRetired,
        ) => {
            audit_mapping_change(
                &state,
                &admin,
                &tenant_id,
                &upstream_idp_id,
                "federation.attribute_mapping.delete",
                SecurityEventOutcome::Denied,
                MappingAuditTarget {
                    mapping_id: &mapping_id,
                    mapping_revision: request.expected_mapping_revision,
                    target_namespace: &target_namespace,
                    target_key: &target_key,
                },
            )
            .await;
            error(StatusCode::CONFLICT, "mapping state conflict")
        }
        Err(_) => {
            audit_mapping_change(
                &state,
                &admin,
                &tenant_id,
                &upstream_idp_id,
                "federation.attribute_mapping.delete",
                SecurityEventOutcome::Failure,
                MappingAuditTarget {
                    mapping_id: &mapping_id,
                    mapping_revision: request.expected_mapping_revision,
                    target_namespace: &target_namespace,
                    target_key: &target_key,
                },
            )
            .await;
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "federation attribute mapping store unavailable",
            )
        }
    }
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(
            list_federation_attribute_mappings,
            create_federation_attribute_mapping
        ))
        .routes(routes!(
            update_federation_attribute_mapping,
            delete_federation_attribute_mapping
        ))
}
