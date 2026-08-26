use std::collections::BTreeSet;

use agent_auth_discovery::Form;
use axum::{
    extract::{Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::attribute_namespace::{
    plan_attribute_migration, AttributeNamespaceStore, BeginNamespaceChange,
    BeginNamespaceChangeOutcome, MigrationDecision, NamespaceChangeKind, NamespaceChangeOutcome,
    NamespaceMigrationOperation, NamespaceMigrationPhase, NamespaceOperationCheckpoint,
    NamespaceRegistration, RegistrationState,
};
use crate::ports::{AttributeMigrationOutcome, UsersStore};
use crate::state::AppState;
use crate::tenant_admin::{AdminAction, TenantAdminContext};

const MIGRATION_PAGE_SIZE: usize = 50;
const MAX_CONFLICT_SAMPLE: usize = 20;

#[derive(Debug, Deserialize, ToSchema)]
pub struct PutNamespaceRegistration {
    #[schema(max_length = 1024)]
    pub canonical_namespace: String,
    #[schema(min_items = 1, max_items = 32)]
    pub exact_audiences: Vec<String>,
    pub expected_revision: u64,
    pub operation_id: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DeleteNamespaceRegistration {
    #[schema(max_length = 1024)]
    pub canonical_namespace: String,
    pub expected_revision: u64,
    pub operation_id: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NamespaceOperationRequest {
    #[schema(max_length = 1024)]
    pub canonical_namespace: String,
    pub operation_id: String,
    pub expected_operation_revision: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct NamespaceOperationView {
    pub operation_id: String,
    pub expected_registration_revision: u64,
    pub revision: u64,
    pub kind: String,
    #[schema(max_items = 32)]
    pub desired_exact_audiences: Vec<String>,
    pub phase: String,
    #[schema(required = true)]
    pub cursor: Option<String>,
    pub scan_complete: bool,
    pub started_mutation: bool,
    #[schema(required = true)]
    pub inflight_user_id: Option<String>,
    pub users_scanned: u64,
    pub users_completed: u64,
    pub conflict_count: u64,
    pub conflict_user_ids: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct NamespaceRegistrationView {
    #[schema(max_length = 1024)]
    pub canonical_namespace: String,
    pub revision: u64,
    #[schema(max_items = 32)]
    pub exact_audiences: Vec<String>,
    pub state: String,
    #[schema(required = true)]
    pub operation: Option<NamespaceOperationView>,
}

impl From<&NamespaceRegistration> for NamespaceRegistrationView {
    fn from(registration: &NamespaceRegistration) -> Self {
        Self {
            canonical_namespace: registration.canonical_namespace.clone(),
            revision: registration.revision,
            exact_audiences: registration.exact_audiences.iter().cloned().collect(),
            state: match registration.state {
                RegistrationState::Pending => "pending",
                RegistrationState::Active => "active",
                RegistrationState::Retired => "retired",
            }
            .into(),
            operation: registration
                .operation
                .as_ref()
                .map(|operation| NamespaceOperationView {
                    operation_id: operation.operation_id.clone(),
                    expected_registration_revision: operation.expected_registration_revision,
                    revision: operation.revision,
                    kind: match operation.kind {
                        NamespaceChangeKind::Upsert => "upsert",
                        NamespaceChangeKind::Delete => "delete",
                    }
                    .into(),
                    desired_exact_audiences: operation
                        .desired_exact_audiences
                        .iter()
                        .cloned()
                        .collect(),
                    phase: match operation.phase {
                        NamespaceMigrationPhase::Validating => "validating",
                        NamespaceMigrationPhase::Migrating => "migrating",
                    }
                    .into(),
                    cursor: operation.cursor.clone(),
                    scan_complete: operation.scan_complete,
                    started_mutation: operation.started_mutation,
                    inflight_user_id: operation.inflight_user_id.clone(),
                    users_scanned: operation.users_scanned,
                    users_completed: operation.users_completed,
                    conflict_count: operation.conflict_count,
                    conflict_user_ids: operation.conflict_user_ids.clone(),
                }),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct NamespaceRegistrationList {
    pub registrations: Vec<NamespaceRegistrationView>,
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

fn self_hosted(state: &AppState) -> bool {
    matches!(state.form, Form::SelfHosted { .. })
}

pub async fn self_hosted_attribute_surface_layer(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let admin_user_attributes = path
        .strip_prefix("/admin/users/")
        .and_then(|rest| rest.split_once("/attributes"))
        .is_some_and(|(user_id, suffix)| {
            !user_id.is_empty() && (suffix.is_empty() || suffix.starts_with('/'))
        });
    if !self_hosted(&state)
        && (path == "/rs/attributes"
            || path.starts_with("/admin/attribute-namespaces")
            || (path.starts_with("/admin/federation/") && path.contains("/attribute-mappings"))
            || admin_user_attributes)
    {
        return error(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    next.run(request).await
}

fn updated_response(outcome: NamespaceChangeOutcome) -> Response {
    match outcome {
        NamespaceChangeOutcome::Updated(registration) => {
            Json(NamespaceRegistrationView::from(&registration)).into_response()
        }
        NamespaceChangeOutcome::Cancelled(registration) => Json(serde_json::json!({
            "cancelled": true,
            "registration": registration.as_ref().map(NamespaceRegistrationView::from),
        }))
        .into_response(),
        NamespaceChangeOutcome::OperationConflict {
            operation_id,
            revision,
        } => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "operation_conflict",
                "operation_id": operation_id,
                "operation_revision": revision,
            })),
        )
            .into_response(),
        NamespaceChangeOutcome::InvalidState => error(
            StatusCode::CONFLICT,
            "namespace operation state is not ready",
        ),
        NamespaceChangeOutcome::CannotCancel => {
            error(StatusCode::CONFLICT, "namespace migration already started")
        }
        NamespaceChangeOutcome::NotFound => error(StatusCode::NOT_FOUND, "not found"),
    }
}

async fn audit(
    state: &AppState,
    tenant: &str,
    actor: &str,
    canonical_namespace: &str,
    action: &str,
    outcome: crate::security_event::SecurityEventOutcome,
) {
    state
        .record_security_event(crate::security_event::SecurityEventDraft::new(
            tenant,
            crate::security_event::SecurityActor::admin(actor),
            Some(crate::security_event::SecuritySubject::unknown(
                canonical_namespace,
            )),
            crate::security_event::SecurityEventCategory::Administration,
            action,
            outcome,
        ))
        .await;
}

#[utoipa::path(
    get,
    path = "/admin/attribute-namespaces",
    tag = "admin",
    responses(
        (status = 200, body = NamespaceRegistrationList),
        (status = 401),
        (status = 403),
        (status = 404, description = "SaaS form"),
        (status = 503)
    )
)]
pub async fn list_namespace_registrations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if !self_hosted(&state) {
        return error(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Read).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    match state
        .attribute_namespaces
        .list(admin.storage_tenant())
        .await
    {
        Ok(registrations) => Json(NamespaceRegistrationList {
            registrations: registrations
                .iter()
                .map(NamespaceRegistrationView::from)
                .collect(),
        })
        .into_response(),
        Err(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "namespace store unavailable",
        ),
    }
}

#[utoipa::path(
    put,
    path = "/admin/attribute-namespaces",
    tag = "admin",
    request_body = PutNamespaceRegistration,
    responses(
        (status = 202, body = NamespaceRegistrationView),
        (status = 400),
        (status = 401),
        (status = 403),
        (status = 404, description = "SaaS form"),
        (status = 409),
        (status = 503)
    )
)]
pub async fn put_namespace_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PutNamespaceRegistration>,
) -> Response {
    if !self_hosted(&state) {
        return error(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let tenant = admin.storage_tenant();
    let exact_audiences: BTreeSet<String> = request.exact_audiences.iter().cloned().collect();
    if exact_audiences.len() != request.exact_audiences.len() {
        return error(StatusCode::BAD_REQUEST, "duplicate exact audience");
    }
    let canonical_namespace = request.canonical_namespace.clone();
    let outcome = {
        let _guard = state.attribute_namespace_write_lock.lock().await;
        state
            .attribute_namespaces
            .begin_change(
                tenant,
                BeginNamespaceChange {
                    canonical_namespace: request.canonical_namespace,
                    exact_audiences,
                    expected_revision: request.expected_revision,
                    operation_id: request.operation_id,
                    kind: NamespaceChangeKind::Upsert,
                },
            )
            .await
    };
    let (audit_outcome, response) = match outcome {
        Ok(BeginNamespaceChangeOutcome::Started(registration)) => (
            crate::security_event::SecurityEventOutcome::Success,
            (
                StatusCode::ACCEPTED,
                Json(NamespaceRegistrationView::from(registration.as_ref())),
            )
                .into_response(),
        ),
        Ok(BeginNamespaceChangeOutcome::RevisionConflict { current }) => (
            crate::security_event::SecurityEventOutcome::Denied,
            (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "revision_conflict",
                    "current_revision": current,
                })),
            )
                .into_response(),
        ),
        Ok(BeginNamespaceChangeOutcome::Busy { operation_id }) => (
            crate::security_event::SecurityEventOutcome::Denied,
            (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "operation_in_progress",
                    "operation_id": operation_id,
                })),
            )
                .into_response(),
        ),
        Ok(BeginNamespaceChangeOutcome::AudienceConflict {
            audience,
            canonical_namespace: conflicting_canonical,
        }) => (
            crate::security_event::SecurityEventOutcome::Denied,
            (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "audience_conflict",
                    "audience": audience,
                    "canonical_namespace": conflicting_canonical,
                })),
            )
                .into_response(),
        ),
        Ok(BeginNamespaceChangeOutcome::NotFound) => (
            crate::security_event::SecurityEventOutcome::Denied,
            error(StatusCode::NOT_FOUND, "not found"),
        ),
        Err(crate::ports::StoreError::Permanent(message)) => (
            crate::security_event::SecurityEventOutcome::Denied,
            error(StatusCode::BAD_REQUEST, &message),
        ),
        Err(_) => (
            crate::security_event::SecurityEventOutcome::Failure,
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "namespace store unavailable",
            ),
        ),
    };
    audit(
        &state,
        tenant,
        &admin.audit_identity(),
        &canonical_namespace,
        "attribute_namespace.change.begin",
        audit_outcome,
    )
    .await;
    response
}

#[utoipa::path(
    delete,
    path = "/admin/attribute-namespaces",
    tag = "admin",
    params(
        ("canonical_namespace" = String, Query),
        ("expected_revision" = u64, Query),
        ("operation_id" = String, Query)
    ),
    responses((status = 200), (status = 400), (status = 401), (status = 403), (status = 404), (status = 409), (status = 503))
)]
pub async fn delete_namespace_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(request): Query<DeleteNamespaceRegistration>,
) -> Response {
    if !self_hosted(&state) {
        return error(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let tenant = admin.storage_tenant();
    let canonical_namespace = request.canonical_namespace.clone();
    let operation_id = request.operation_id.clone();
    let begin_outcome = {
        let _guard = state.attribute_namespace_write_lock.lock().await;
        state
            .attribute_namespaces
            .begin_change(
                tenant,
                BeginNamespaceChange {
                    canonical_namespace: request.canonical_namespace,
                    exact_audiences: BTreeSet::new(),
                    expected_revision: request.expected_revision,
                    operation_id: operation_id.clone(),
                    kind: NamespaceChangeKind::Delete,
                },
            )
            .await
    };
    let registration = match begin_outcome {
        Ok(BeginNamespaceChangeOutcome::Started(registration)) => *registration,
        Ok(BeginNamespaceChangeOutcome::RevisionConflict { current }) => {
            audit(
                &state,
                tenant,
                &admin.audit_identity(),
                &canonical_namespace,
                "attribute_namespace.delete",
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "revision_conflict",
                    "current_revision": current,
                })),
            )
                .into_response();
        }
        Ok(BeginNamespaceChangeOutcome::Busy { operation_id }) => {
            audit(
                &state,
                tenant,
                &admin.audit_identity(),
                &canonical_namespace,
                "attribute_namespace.delete",
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "operation_in_progress",
                    "operation_id": operation_id,
                })),
            )
                .into_response();
        }
        Ok(BeginNamespaceChangeOutcome::AudienceConflict { .. }) => {
            audit(
                &state,
                tenant,
                &admin.audit_identity(),
                &canonical_namespace,
                "attribute_namespace.delete",
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return error(StatusCode::CONFLICT, "audience conflict");
        }
        Ok(BeginNamespaceChangeOutcome::NotFound) => {
            audit(
                &state,
                tenant,
                &admin.audit_identity(),
                &canonical_namespace,
                "attribute_namespace.delete",
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return error(StatusCode::NOT_FOUND, "not found");
        }
        Err(crate::ports::StoreError::Permanent(message)) => {
            audit(
                &state,
                tenant,
                &admin.audit_identity(),
                &canonical_namespace,
                "attribute_namespace.delete",
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return error(StatusCode::BAD_REQUEST, &message);
        }
        Err(_) => {
            audit(
                &state,
                tenant,
                &admin.audit_identity(),
                &canonical_namespace,
                "attribute_namespace.delete",
                crate::security_event::SecurityEventOutcome::Failure,
            )
            .await;
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "namespace store unavailable",
            );
        }
    };
    let Some(operation) = registration.operation else {
        return error(StatusCode::CONFLICT, "namespace operation missing");
    };
    let checkpoint = NamespaceOperationCheckpoint {
        expected_revision: operation.revision,
        phase: NamespaceMigrationPhase::Migrating,
        cursor: None,
        scan_complete: true,
        started_mutation: false,
        inflight_user_id: None,
        users_scanned: 0,
        users_completed: 0,
        conflict_count: 0,
        conflict_user_ids: vec![],
    };
    let registration = match state
        .attribute_namespaces
        .checkpoint(tenant, &canonical_namespace, &operation_id, checkpoint)
        .await
    {
        Ok(NamespaceChangeOutcome::Updated(registration)) => registration,
        Ok(outcome) => {
            audit(
                &state,
                tenant,
                &admin.audit_identity(),
                &canonical_namespace,
                "attribute_namespace.delete",
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return updated_response(outcome);
        }
        Err(_) => {
            audit(
                &state,
                tenant,
                &admin.audit_identity(),
                &canonical_namespace,
                "attribute_namespace.delete",
                crate::security_event::SecurityEventOutcome::Failure,
            )
            .await;
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "namespace store unavailable",
            );
        }
    };
    let operation_revision = registration
        .operation
        .as_ref()
        .map(|operation| operation.revision)
        .unwrap_or(0);
    activate_ready(
        &state,
        tenant,
        &canonical_namespace,
        &operation_id,
        operation_revision,
        &admin.audit_identity(),
        "attribute_namespace.delete",
    )
    .await
}

fn add_conflict(operation: &NamespaceMigrationOperation, user_id: &str) -> (u64, Vec<String>) {
    let mut sample = operation.conflict_user_ids.clone();
    if sample.len() < MAX_CONFLICT_SAMPLE && !sample.iter().any(|value| value == user_id) {
        sample.push(user_id.to_string());
    }
    (operation.conflict_count.saturating_add(1), sample)
}

struct MigrationProgress {
    inflight_user_id: Option<String>,
    users_completed: u64,
    conflict_count: u64,
    conflict_user_ids: Vec<String>,
}

async fn checkpoint_current_migration(
    state: &AppState,
    tenant: &str,
    canonical_namespace: &str,
    operation: &NamespaceMigrationOperation,
    progress: MigrationProgress,
) -> Result<NamespaceMigrationOperation, Response> {
    match state
        .attribute_namespaces
        .checkpoint(
            tenant,
            canonical_namespace,
            &operation.operation_id,
            NamespaceOperationCheckpoint {
                expected_revision: operation.revision,
                phase: NamespaceMigrationPhase::Migrating,
                cursor: operation.cursor.clone(),
                scan_complete: operation.scan_complete,
                started_mutation: true,
                inflight_user_id: progress.inflight_user_id,
                users_scanned: operation.users_scanned,
                users_completed: progress.users_completed,
                conflict_count: progress.conflict_count,
                conflict_user_ids: progress.conflict_user_ids,
            },
        )
        .await
    {
        Ok(NamespaceChangeOutcome::Updated(registration)) => registration
            .operation
            .ok_or_else(|| error(StatusCode::CONFLICT, "namespace operation missing")),
        Ok(outcome) => Err(updated_response(outcome)),
        Err(_) => Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "namespace store unavailable",
        )),
    }
}

async fn resume_inflight_migration(
    state: &AppState,
    tenant: &str,
    canonical_namespace: &str,
    source_namespaces: &BTreeSet<String>,
    operation: &NamespaceMigrationOperation,
) -> Result<(NamespaceMigrationOperation, bool), Response> {
    let Some(user_id) = operation.inflight_user_id.as_deref() else {
        return Ok((operation.clone(), false));
    };
    let outcome = state
        .users
        .migrate_attributes(tenant, user_id, canonical_namespace, source_namespaces)
        .await
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "user store unavailable"))?;
    let (users_completed, conflict_count, conflict_user_ids, conflict) = match outcome {
        AttributeMigrationOutcome::Migrated { .. }
        | AttributeMigrationOutcome::Noop
        | AttributeMigrationOutcome::NotFound
        | AttributeMigrationOutcome::Tombstoned => (
            operation.users_completed.saturating_add(1),
            operation.conflict_count,
            operation.conflict_user_ids.clone(),
            false,
        ),
        AttributeMigrationOutcome::Conflict { .. }
        | AttributeMigrationOutcome::TooLarge
        | AttributeMigrationOutcome::RevisionExhausted => {
            let (count, sample) = add_conflict(operation, user_id);
            (operation.users_completed, count, sample, true)
        }
    };
    let operation = checkpoint_current_migration(
        state,
        tenant,
        canonical_namespace,
        operation,
        MigrationProgress {
            inflight_user_id: None,
            users_completed,
            conflict_count,
            conflict_user_ids,
        },
    )
    .await?;
    Ok((operation, conflict))
}

async fn activate_ready(
    state: &AppState,
    tenant: &str,
    canonical_namespace: &str,
    operation_id: &str,
    operation_revision: u64,
    actor: &str,
    audit_action: &str,
) -> Response {
    match state
        .attribute_namespaces
        .activate(
            tenant,
            canonical_namespace,
            operation_id,
            operation_revision,
        )
        .await
    {
        Ok(outcome) => {
            let success = matches!(
                outcome,
                NamespaceChangeOutcome::Updated(ref registration)
                    if registration.operation.is_none()
            );
            audit(
                state,
                tenant,
                actor,
                canonical_namespace,
                audit_action,
                if success {
                    crate::security_event::SecurityEventOutcome::Success
                } else {
                    crate::security_event::SecurityEventOutcome::Denied
                },
            )
            .await;
            updated_response(outcome)
        }
        Err(_) => {
            audit(
                state,
                tenant,
                actor,
                canonical_namespace,
                audit_action,
                crate::security_event::SecurityEventOutcome::Failure,
            )
            .await;
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "namespace store unavailable",
            )
        }
    }
}

#[utoipa::path(
    post,
    path = "/admin/attribute-namespaces/advance",
    tag = "admin",
    request_body = NamespaceOperationRequest,
    responses((status = 200, body = NamespaceRegistrationView), (status = 400), (status = 401), (status = 403), (status = 404), (status = 409), (status = 503))
)]
pub async fn advance_namespace_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<NamespaceOperationRequest>,
) -> Response {
    if !self_hosted(&state) {
        return error(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let tenant = admin.storage_tenant();
    let registration = match state
        .attribute_namespaces
        .get(tenant, &request.canonical_namespace)
        .await
    {
        Ok(Some(registration)) => registration,
        Ok(None) => return error(StatusCode::NOT_FOUND, "not found"),
        Err(_) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "namespace store unavailable",
            )
        }
    };
    let Some(mut operation) = registration.operation.clone() else {
        if registration.last_operation_id.as_deref() == Some(&request.operation_id) {
            return Json(NamespaceRegistrationView::from(&registration)).into_response();
        }
        return error(StatusCode::CONFLICT, "namespace operation missing");
    };
    if operation.operation_id != request.operation_id
        || operation.revision != request.expected_operation_revision
    {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "operation_conflict",
                "operation_id": operation.operation_id,
                "operation_revision": operation.revision,
            })),
        )
            .into_response();
    }
    if operation.kind == NamespaceChangeKind::Delete {
        if operation.phase == NamespaceMigrationPhase::Validating {
            let outcome = state
                .attribute_namespaces
                .checkpoint(
                    tenant,
                    &request.canonical_namespace,
                    &request.operation_id,
                    NamespaceOperationCheckpoint {
                        expected_revision: operation.revision,
                        phase: NamespaceMigrationPhase::Migrating,
                        cursor: None,
                        scan_complete: true,
                        started_mutation: false,
                        inflight_user_id: None,
                        users_scanned: 0,
                        users_completed: 0,
                        conflict_count: 0,
                        conflict_user_ids: vec![],
                    },
                )
                .await;
            operation = match outcome {
                Ok(NamespaceChangeOutcome::Updated(registration)) => {
                    registration.operation.unwrap()
                }
                Ok(outcome) => return updated_response(outcome),
                Err(_) => {
                    return error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "namespace store unavailable",
                    )
                }
            };
        }
        return activate_ready(
            &state,
            tenant,
            &request.canonical_namespace,
            &operation.operation_id,
            operation.revision,
            &admin.audit_identity(),
            "attribute_namespace.delete",
        )
        .await;
    }

    if operation.phase == NamespaceMigrationPhase::Validating {
        if operation.scan_complete {
            return error(StatusCode::CONFLICT, "namespace validation has conflicts");
        }
        let (users, next_cursor) = match state
            .users
            .list(
                tenant,
                MIGRATION_PAGE_SIZE,
                operation.cursor.as_deref(),
                None,
                crate::ports::UserListStatusFilter::All,
            )
            .await
        {
            Ok(page) => page,
            Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "user store unavailable"),
        };
        let mut conflict_count = operation.conflict_count;
        let mut conflict_user_ids = operation.conflict_user_ids.clone();
        for user in &users {
            let conflict = match plan_attribute_migration(
                &user.attributes,
                &registration.canonical_namespace,
                &operation.source_namespaces,
            ) {
                MigrationDecision::Conflict { .. } | MigrationDecision::RevisionExhausted => true,
                MigrationDecision::Replace { attributes } => {
                    crate::adapters::memory::attributes_serialized_len(&attributes)
                        > crate::ports::ATTRIBUTES_MAX_BYTES
                }
                MigrationDecision::Noop => false,
            };
            if conflict {
                conflict_count = conflict_count.saturating_add(1);
                if conflict_user_ids.len() < MAX_CONFLICT_SAMPLE {
                    conflict_user_ids.push(user.user_id.clone());
                }
            }
        }
        let users_scanned = operation.users_scanned.saturating_add(users.len() as u64);
        let (phase, scan_complete, cursor) = match next_cursor {
            Some(cursor) => (NamespaceMigrationPhase::Validating, false, Some(cursor)),
            None if conflict_count == 0 => (NamespaceMigrationPhase::Migrating, false, None),
            None => (NamespaceMigrationPhase::Validating, true, None),
        };
        let outcome = state
            .attribute_namespaces
            .checkpoint(
                tenant,
                &registration.canonical_namespace,
                &operation.operation_id,
                NamespaceOperationCheckpoint {
                    expected_revision: operation.revision,
                    phase,
                    cursor,
                    scan_complete,
                    started_mutation: false,
                    inflight_user_id: None,
                    users_scanned,
                    users_completed: operation.users_completed,
                    conflict_count,
                    conflict_user_ids,
                },
            )
            .await;
        return match outcome {
            Ok(NamespaceChangeOutcome::Updated(registration))
                if registration.operation.as_ref().is_some_and(|operation| {
                    operation.scan_complete && operation.conflict_count > 0
                }) =>
            {
                audit(
                    &state,
                    tenant,
                    &admin.audit_identity(),
                    &registration.canonical_namespace,
                    "attribute_namespace.validation.conflict",
                    crate::security_event::SecurityEventOutcome::Denied,
                )
                .await;
                (
                    StatusCode::CONFLICT,
                    Json(NamespaceRegistrationView::from(&registration)),
                )
                    .into_response()
            }
            Ok(outcome) => updated_response(outcome),
            Err(_) => error(
                StatusCode::SERVICE_UNAVAILABLE,
                "namespace store unavailable",
            ),
        };
    }

    if operation.inflight_user_id.is_some() {
        let (resumed, conflict) = match resume_inflight_migration(
            &state,
            tenant,
            &registration.canonical_namespace,
            &operation.source_namespaces,
            &operation,
        )
        .await
        {
            Ok(result) => result,
            Err(response) => return response,
        };
        operation = resumed;
        if conflict {
            audit(
                &state,
                tenant,
                &admin.audit_identity(),
                &registration.canonical_namespace,
                "attribute_namespace.migration.conflict",
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return error(StatusCode::CONFLICT, "attribute migration conflict");
        }
    }
    if operation.scan_complete {
        return activate_ready(
            &state,
            tenant,
            &registration.canonical_namespace,
            &operation.operation_id,
            operation.revision,
            &admin.audit_identity(),
            "attribute_namespace.migration.complete",
        )
        .await;
    }
    let (users, next_cursor) = match state
        .users
        .list(
            tenant,
            MIGRATION_PAGE_SIZE,
            operation.cursor.as_deref(),
            None,
            crate::ports::UserListStatusFilter::All,
        )
        .await
    {
        Ok(page) => page,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "user store unavailable"),
    };
    if !operation.started_mutation {
        operation = match state
            .attribute_namespaces
            .checkpoint(
                tenant,
                &registration.canonical_namespace,
                &operation.operation_id,
                NamespaceOperationCheckpoint {
                    expected_revision: operation.revision,
                    phase: NamespaceMigrationPhase::Migrating,
                    cursor: operation.cursor.clone(),
                    scan_complete: false,
                    started_mutation: true,
                    inflight_user_id: operation.inflight_user_id.clone(),
                    users_scanned: operation.users_scanned,
                    users_completed: operation.users_completed,
                    conflict_count: operation.conflict_count,
                    conflict_user_ids: operation.conflict_user_ids.clone(),
                },
            )
            .await
        {
            Ok(NamespaceChangeOutcome::Updated(registration)) => registration.operation.unwrap(),
            Ok(outcome) => return updated_response(outcome),
            Err(_) => {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "namespace store unavailable",
                )
            }
        };
    }
    for user in &users {
        let needs_migration = match plan_attribute_migration(
            &user.attributes,
            &registration.canonical_namespace,
            &operation.source_namespaces,
        ) {
            MigrationDecision::Noop => false,
            MigrationDecision::Replace { attributes } => {
                if crate::adapters::memory::attributes_serialized_len(&attributes)
                    > crate::ports::ATTRIBUTES_MAX_BYTES
                {
                    let (conflict_count, conflict_user_ids) =
                        add_conflict(&operation, &user.user_id);
                    operation = match checkpoint_current_migration(
                        &state,
                        tenant,
                        &registration.canonical_namespace,
                        &operation,
                        MigrationProgress {
                            inflight_user_id: None,
                            users_completed: operation.users_completed,
                            conflict_count,
                            conflict_user_ids,
                        },
                    )
                    .await
                    {
                        Ok(operation) => operation,
                        Err(response) => return response,
                    };
                    false
                } else {
                    true
                }
            }
            MigrationDecision::Conflict { .. } | MigrationDecision::RevisionExhausted => {
                let (conflict_count, conflict_user_ids) = add_conflict(&operation, &user.user_id);
                operation = match checkpoint_current_migration(
                    &state,
                    tenant,
                    &registration.canonical_namespace,
                    &operation,
                    MigrationProgress {
                        inflight_user_id: None,
                        users_completed: operation.users_completed,
                        conflict_count,
                        conflict_user_ids,
                    },
                )
                .await
                {
                    Ok(operation) => operation,
                    Err(response) => return response,
                };
                false
            }
        };
        if operation.conflict_count != 0 {
            audit(
                &state,
                tenant,
                &admin.audit_identity(),
                &registration.canonical_namespace,
                "attribute_namespace.migration.conflict",
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return error(StatusCode::CONFLICT, "attribute migration conflict");
        }
        if !needs_migration {
            continue;
        }
        operation = match checkpoint_current_migration(
            &state,
            tenant,
            &registration.canonical_namespace,
            &operation,
            MigrationProgress {
                inflight_user_id: Some(user.user_id.clone()),
                users_completed: operation.users_completed,
                conflict_count: operation.conflict_count,
                conflict_user_ids: operation.conflict_user_ids.clone(),
            },
        )
        .await
        {
            Ok(operation) => operation,
            Err(response) => return response,
        };
        let (resumed, conflict) = match resume_inflight_migration(
            &state,
            tenant,
            &registration.canonical_namespace,
            &operation.source_namespaces,
            &operation,
        )
        .await
        {
            Ok(result) => result,
            Err(response) => return response,
        };
        operation = resumed;
        if conflict {
            audit(
                &state,
                tenant,
                &admin.audit_identity(),
                &registration.canonical_namespace,
                "attribute_namespace.migration.conflict",
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return error(StatusCode::CONFLICT, "attribute migration conflict");
        }
    }
    let users_scanned = operation.users_scanned.saturating_add(users.len() as u64);
    let scan_complete = next_cursor.is_none();
    let outcome = state
        .attribute_namespaces
        .checkpoint(
            tenant,
            &registration.canonical_namespace,
            &operation.operation_id,
            NamespaceOperationCheckpoint {
                expected_revision: operation.revision,
                phase: NamespaceMigrationPhase::Migrating,
                cursor: next_cursor,
                scan_complete,
                started_mutation: true,
                inflight_user_id: None,
                users_scanned,
                users_completed: operation.users_completed,
                conflict_count: operation.conflict_count,
                conflict_user_ids: operation.conflict_user_ids.clone(),
            },
        )
        .await;
    match outcome {
        Ok(NamespaceChangeOutcome::Updated(registration)) => {
            let operation = registration.operation.as_ref().unwrap();
            if operation.scan_complete {
                activate_ready(
                    &state,
                    tenant,
                    &registration.canonical_namespace,
                    &operation.operation_id,
                    operation.revision,
                    &admin.audit_identity(),
                    "attribute_namespace.migration.complete",
                )
                .await
            } else {
                Json(NamespaceRegistrationView::from(&registration)).into_response()
            }
        }
        Ok(outcome) => updated_response(outcome),
        Err(_) => {
            audit(
                &state,
                tenant,
                &admin.audit_identity(),
                &request.canonical_namespace,
                "attribute_namespace.migration.advance",
                crate::security_event::SecurityEventOutcome::Failure,
            )
            .await;
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "namespace store unavailable",
            )
        }
    }
}

#[utoipa::path(
    post,
    path = "/admin/attribute-namespaces/cancel",
    tag = "admin",
    request_body = NamespaceOperationRequest,
    responses((status = 200), (status = 400), (status = 401), (status = 403), (status = 404), (status = 409), (status = 503))
)]
pub async fn cancel_namespace_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<NamespaceOperationRequest>,
) -> Response {
    if !self_hosted(&state) {
        return error(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let tenant = admin.storage_tenant();
    match state
        .attribute_namespaces
        .cancel(
            tenant,
            &request.canonical_namespace,
            &request.operation_id,
            request.expected_operation_revision,
        )
        .await
    {
        Ok(outcome) => {
            let success = matches!(outcome, NamespaceChangeOutcome::Cancelled(_));
            audit(
                &state,
                tenant,
                &admin.audit_identity(),
                &request.canonical_namespace,
                "attribute_namespace.migration.cancel",
                if success {
                    crate::security_event::SecurityEventOutcome::Success
                } else {
                    crate::security_event::SecurityEventOutcome::Denied
                },
            )
            .await;
            updated_response(outcome)
        }
        Err(_) => {
            audit(
                &state,
                tenant,
                &admin.audit_identity(),
                &request.canonical_namespace,
                "attribute_namespace.migration.cancel",
                crate::security_event::SecurityEventOutcome::Failure,
            )
            .await;
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "namespace store unavailable",
            )
        }
    }
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(
            list_namespace_registrations,
            put_namespace_registration,
            delete_namespace_registration
        ))
        .routes(routes!(advance_namespace_registration))
        .routes(routes!(cancel_namespace_registration))
}
