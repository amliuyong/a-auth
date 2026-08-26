//! Tenant-scoped privacy export and durable governance job APIs.

use std::collections::{BTreeMap, BTreeSet};

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    federation_attributes::{FederationAttributeMappingsStore, MappingRegistry},
    governance::{
        ExportSection, GovernanceContinuationAction, GovernanceContinuationRecord,
        GovernanceContinuationUpdateOutcome, GovernanceEvidenceRecord, GovernanceExportManifest,
        GovernanceJobCommand, GovernanceJobKind, GovernanceJobPhase, GovernanceJobRecord,
        GovernanceJobStartOutcome, GovernanceJobState, GovernancePolicyPutOutcome,
        GovernancePolicyRecord, GovernanceRetentionExceptionCapability, LegalHoldState,
        TenantResidency, EXPORT_MANIFEST_TTL_SECS, GOVERNANCE_SCHEMA_VERSION,
    },
    ports::{
        AdminAuthStore, ClientStore, DomainMapStore, FederationConfigStore, GovernanceJobQueue,
        GovernanceStore, GrantStore, InitialAccessTokenStore, PasskeyStore, PasswordStore,
        RecoveryStore, ScimGroupsStore, SessionStore, StoreError, UserRecord, UserStatus,
        UsersStore, WorkloadTrustStore,
    },
    security_event::{
        SecurityEventCursor, SecurityEventStore, SecuritySubjectKind, StoredSecurityEvent,
    },
    ssf::SsfStore,
    state::AppState,
    tenant_admin::{authenticate_platform_governance, AdminAction, TenantAdminContext},
    tenant_keys::TenantKeyRegistry,
};

const DEFAULT_PAGE_SIZE: usize = 100;
const MAX_PAGE_SIZE: usize = 500;
const USER_EVENT_SCAN_SIZE: usize = 500;
const EXPORT_CURSOR_VERSION: u8 = 1;
const CONTINUATION_TOKEN_VERSION: u8 = 1;
const CONTINUATION_TOKEN_TTL_SECS: i64 = 15 * 60;
const CONTINUATION_TOKEN_ISSUER: &str = "agent-auth:platform-control";
const CONTINUATION_TOKEN_AUDIENCE: &str = "urn:agent-auth:governance-control";

struct GovernanceRequestContext {
    admin: TenantAdminContext,
    residency: TenantResidency,
    region: String,
    region_revision: u64,
}

async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    action: AdminAction,
) -> Result<GovernanceRequestContext, Response> {
    if matches!(state.form, agent_auth_discovery::Form::Saas { .. }) && !state.tenant_partitioning {
        return Err(error(
            StatusCode::NOT_FOUND,
            "not_available",
            "Data governance requires tenant-partitioned storage",
        ));
    }
    let admin = TenantAdminContext::authenticate(state, headers, action).await?;
    let tenant_id = admin.tenant_id();
    let Some(residency) = state.governance_config.residency(tenant_id).cloned() else {
        return Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "residency_unavailable",
            "Tenant residency is not configured",
        ));
    };
    let region = state.region.local_region().to_string();
    if !state.governance_config.admits(tenant_id, &region) {
        return Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "residency_rejected",
            "The local Region is outside the tenant residency set",
        ));
    }
    let region_revision = state.region.active_revision();
    if state.region.is_multi_region() && region_revision == 0 {
        return Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "inactive_writer",
            "No active Region revision has been admitted",
        ));
    }
    Ok(GovernanceRequestContext {
        admin,
        residency,
        region,
        region_revision,
    })
}

fn error(status: StatusCode, code: &str, description: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": code,
            "error_description": description
        })),
    )
        .into_response()
}

fn store_error(error_value: StoreError) -> Response {
    match error_value {
        StoreError::Transient(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Governance storage is unavailable",
        ),
        StoreError::Permanent(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "governance_store_error",
            "Governance storage rejected the operation",
        ),
    }
}

async fn policy(state: &AppState, tenant_id: &str) -> Result<GovernancePolicyRecord, Response> {
    state
        .governance
        .get_policy(tenant_id)
        .await
        .map(|record| record.unwrap_or_else(|| GovernancePolicyRecord::default_for(tenant_id)))
        .map_err(store_error)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GovernancePolicyView {
    pub schema_version: String,
    pub tenant_id: String,
    pub residency_jurisdiction: String,
    pub allowed_regions: Vec<String>,
    pub governance_region: String,
    pub active_writer_region: String,
    pub region_control_revision: u64,
    pub legal_hold: LegalHoldState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legal_hold_reason: Option<String>,
    pub retention_exception_capability: GovernanceRetentionExceptionCapability,
    pub updated_at: i64,
    pub revision: u64,
}

fn policy_view(
    context: &GovernanceRequestContext,
    record: GovernancePolicyRecord,
) -> GovernancePolicyView {
    GovernancePolicyView {
        schema_version: GOVERNANCE_SCHEMA_VERSION.into(),
        tenant_id: context.admin.tenant_id().to_string(),
        residency_jurisdiction: context.residency.jurisdiction.clone(),
        allowed_regions: context.residency.allowed_regions.clone(),
        governance_region: context.residency.governance_region.clone(),
        active_writer_region: context.region.clone(),
        region_control_revision: context.region_revision,
        legal_hold: record.legal_hold,
        legal_hold_reason: record.legal_hold_reason,
        retention_exception_capability: record.retention_exception_capability,
        updated_at: record.updated_at,
        revision: record.revision,
    }
}

#[utoipa::path(
    get,
    path = "/admin/data-governance/policy",
    tag = "data_governance",
    responses(
        (status = 200, description = "Tenant data-governance policy", body = GovernancePolicyView),
        (status = 401, description = "Admin authentication failed"),
        (status = 403, description = "Owner permission required"),
        (status = 503, description = "Governance or residency state unavailable")
    )
)]
pub async fn get_policy(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let context = match authorize(&state, &headers, AdminAction::LegalHoldManage).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    match policy(&state, context.admin.tenant_id()).await {
        Ok(record) => Json(policy_view(&context, record)).into_response(),
        Err(response) => response,
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PutGovernancePolicy {
    pub expected_revision: u64,
    pub legal_hold: bool,
    /// Opaque operator reason code. Free-form case details and PII are rejected.
    pub reason: Option<String>,
}

fn reconciles_committed_policy_update(
    current: &GovernancePolicyRecord,
    request: &PutGovernancePolicy,
    reason: &Option<String>,
    actor: &str,
) -> bool {
    let first_revision = request.expected_revision.checked_add(1);
    let settled_revision = first_revision.and_then(|revision| revision.checked_add(1));
    let exact_state = match (request.legal_hold, current.legal_hold) {
        (true, LegalHoldState::Enabling) => first_revision == Some(current.revision),
        (true, LegalHoldState::Enabled) => settled_revision == Some(current.revision),
        (false, LegalHoldState::Disabled) => first_revision == Some(current.revision),
        _ => false,
    };
    exact_state && current.actor == actor && current.legal_hold_reason == *reason
}

async fn settle_enabling_policy(
    state: &AppState,
    mut record: GovernancePolicyRecord,
    now: i64,
) -> Result<GovernancePolicyRecord, StoreError> {
    if record.legal_hold != LegalHoldState::Enabling {
        return Ok(record);
    }
    if state
        .governance
        .tenant_has_active_job_leases(&record.tenant_id, now)
        .await?
    {
        return Ok(record);
    }
    let actions = state
        .governance
        .list_tenant_external_actions(&record.tenant_id)
        .await?;
    let job_ids = actions
        .iter()
        .filter(|action| action.state.requires_hold_drain())
        .map(|action| action.job_id.clone())
        .collect::<BTreeSet<_>>();
    if !job_ids.is_empty() {
        for job_id in job_ids {
            let job = state
                .governance
                .get_job(&record.tenant_id, &job_id)
                .await?
                .ok_or_else(|| {
                    StoreError::Permanent("legal-hold drain action references a missing job".into())
                })?;
            state
                .governance_jobs
                .enqueue(GovernanceJobCommand {
                    tenant_id: job.tenant_id,
                    job_id: job.job_id,
                    expected_revision: job.revision,
                    failure_attempt: 0,
                })
                .await?;
        }
        return Ok(record);
    }

    let expected_revision = record.revision;
    record.legal_hold = LegalHoldState::Enabled;
    record.updated_at = now;
    match state
        .governance
        .put_policy(record, expected_revision)
        .await?
    {
        GovernancePolicyPutOutcome::Stored(record)
        | GovernancePolicyPutOutcome::Conflict(record) => Ok(record),
    }
}

#[utoipa::path(
    put,
    path = "/admin/data-governance/policy",
    tag = "data_governance",
    request_body = PutGovernancePolicy,
    responses(
        (status = 200, description = "Policy updated by exact revision", body = GovernancePolicyView),
        (status = 400, description = "Invalid legal-hold reason"),
        (status = 401, description = "Admin authentication failed"),
        (status = 403, description = "Owner and strong authentication required"),
        (status = 409, description = "Policy revision conflict", body = GovernancePolicyView),
        (status = 503, description = "Governance or residency state unavailable")
    )
)]
pub async fn put_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PutGovernancePolicy>,
) -> Response {
    let context = match authorize(&state, &headers, AdminAction::LegalHoldManage).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !state
        .governance_config
        .admits_destructive_governance(context.admin.tenant_id(), &context.region)
    {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "governance_region_inactive",
            "Destructive governance is paused outside the designated governance Region",
        );
    }
    let reason =
        match crate::governance::validate_reason(request.reason.as_deref(), request.legal_hold) {
            Ok(reason) => reason,
            Err(message) => return error(StatusCode::BAD_REQUEST, "invalid_request", message),
        };
    let now = crate::current_unix_secs();
    let actor = context.admin.audit_identity();
    let current = match policy(&state, context.admin.tenant_id()).await {
        Ok(record) => record,
        Err(response) => return response,
    };
    let (mut record, status, event_outcome) = if current.revision != request.expected_revision {
        if reconciles_committed_policy_update(&current, &request, &reason, &actor) {
            (
                current,
                StatusCode::OK,
                crate::security_event::SecurityEventOutcome::Success,
            )
        } else {
            (
                current,
                StatusCode::CONFLICT,
                crate::security_event::SecurityEventOutcome::Denied,
            )
        }
    } else if (request.legal_hold && current.legal_hold == LegalHoldState::Enabled)
        || (!request.legal_hold && current.legal_hold == LegalHoldState::Disabled)
    {
        (
            current,
            StatusCode::OK,
            crate::security_event::SecurityEventOutcome::Success,
        )
    } else if request.legal_hold && current.legal_hold == LegalHoldState::Enabling {
        if current.legal_hold_reason != reason {
            (
                current,
                StatusCode::CONFLICT,
                crate::security_event::SecurityEventOutcome::Denied,
            )
        } else {
            (
                current,
                StatusCode::OK,
                crate::security_event::SecurityEventOutcome::Success,
            )
        }
    } else {
        let next = GovernancePolicyRecord {
            tenant_id: context.admin.tenant_id().to_string(),
            legal_hold: if request.legal_hold {
                LegalHoldState::Enabling
            } else {
                LegalHoldState::Disabled
            },
            legal_hold_reason: reason,
            retention_exception_capability: current.retention_exception_capability,
            actor,
            updated_at: now,
            revision: request.expected_revision.saturating_add(1),
        };
        match state
            .governance
            .put_policy(next, request.expected_revision)
            .await
        {
            Ok(GovernancePolicyPutOutcome::Stored(record)) => (
                record,
                StatusCode::OK,
                crate::security_event::SecurityEventOutcome::Success,
            ),
            Ok(GovernancePolicyPutOutcome::Conflict(record)) => (
                record,
                StatusCode::CONFLICT,
                crate::security_event::SecurityEventOutcome::Denied,
            ),
            Err(store_error_value) => return store_error(store_error_value),
        }
    };
    if status == StatusCode::OK && record.legal_hold == LegalHoldState::Enabling {
        record = match settle_enabling_policy(&state, record, now).await {
            Ok(record) => record,
            Err(store_error_value) => return store_error(store_error_value),
        };
    };
    let affected_jobs = match state.governance.list_jobs(context.admin.tenant_id()).await {
        Ok(jobs) => jobs,
        Err(store_error_value) => return store_error(store_error_value),
    };
    for job in affected_jobs {
        if let Err(response) = audit_job_operation(
            &state,
            &job,
            if request.legal_hold {
                "governance.job.legal_hold.enable"
            } else {
                "governance.job.legal_hold.disable"
            },
            event_outcome,
        )
        .await
        {
            return response;
        }
    }
    state
        .record_security_event(crate::security_event::SecurityEventDraft::new(
            context.admin.tenant_id(),
            crate::security_event::SecurityActor::admin(context.admin.audit_identity()),
            Some(crate::security_event::SecuritySubject::tenant(
                context.admin.tenant_id(),
            )),
            crate::security_event::SecurityEventCategory::Administration,
            if request.legal_hold {
                "governance.legal_hold.enable"
            } else {
                "governance.legal_hold.disable"
            },
            event_outcome,
        ))
        .await;
    (status, Json(policy_view(&context, record))).into_response()
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct UserExportQuery {
    pub event_limit: Option<usize>,
    pub event_cursor: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct NamespaceExport {
    pub revision: u64,
    pub values: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserIdentityExport {
    pub user_id: String,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scim_external_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scim_user_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub status: String,
    pub credential_epoch: u64,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_login_at: Option<i64>,
    pub attributes: BTreeMap<String, NamespaceExport>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PasskeySummary {
    pub name: String,
    pub created_at: i64,
    pub sign_count: u32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LoginSessionSummary {
    pub device: String,
    pub created_at: i64,
    pub last_used_at: i64,
    pub expires_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assurance: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CredentialStatusExport {
    pub password_configured: bool,
    pub recovery_codes_configured: bool,
    pub passkey_count: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GroupMembershipExport {
    pub group_id: String,
    pub external_id: String,
    pub display_name: String,
    pub revision: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserExportResponse {
    pub schema_version: String,
    pub tenant_id: String,
    pub residency_jurisdiction: String,
    pub active_writer_region: String,
    pub region_control_revision: u64,
    pub generated_at: i64,
    pub identity: UserIdentityExport,
    pub credentials: CredentialStatusExport,
    pub passkeys: Vec<PasskeySummary>,
    pub login_sessions: Vec<LoginSessionSummary>,
    pub grants: Vec<serde_json::Value>,
    pub group_memberships: Vec<GroupMembershipExport>,
    pub security_events: Vec<StoredSecurityEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_event_cursor: Option<String>,
}

fn identity_export(user: UserRecord) -> UserIdentityExport {
    UserIdentityExport {
        user_id: user.user_id,
        email: user.email,
        scim_external_id: user.scim_external_id,
        scim_user_name: user.scim_user_name,
        display_name: user.scim_display_name,
        status: user_status(user.status).into(),
        credential_epoch: user.credential_epoch,
        created_at: user.created_at,
        updated_at: user.updated_at,
        last_login_at: user.last_login_at,
        attributes: user
            .attributes
            .into_iter()
            .map(|(namespace, attributes)| {
                (
                    namespace,
                    NamespaceExport {
                        revision: attributes.revision,
                        values: attributes.kv,
                    },
                )
            })
            .collect(),
    }
}

fn user_status(status: UserStatus) -> &'static str {
    match status {
        UserStatus::Active => "active",
        UserStatus::Disabled => "disabled",
        UserStatus::Tombstoned => "tombstoned",
    }
}

async fn user_groups(
    state: &AppState,
    tenant: &str,
    user_id: &str,
) -> Result<Vec<GroupMembershipExport>, StoreError> {
    let mut offset = 0;
    let mut memberships = Vec::new();
    loop {
        let (groups, total) = state.scim_groups.list(tenant, offset, 100).await?;
        let count = groups.len();
        memberships.extend(
            groups
                .into_iter()
                .filter(|group| group.members.iter().any(|member| member == user_id))
                .map(|group| GroupMembershipExport {
                    group_id: group.group_id,
                    external_id: group.external_id,
                    display_name: group.display_name,
                    revision: group.version,
                }),
        );
        offset += count;
        if count == 0 || offset >= total {
            break;
        }
    }
    memberships.sort_by(|left, right| left.group_id.cmp(&right.group_id));
    Ok(memberships)
}

async fn list_user_security_event_page(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
    through: i64,
    limit: usize,
    mut cursor: Option<SecurityEventCursor>,
) -> Result<(Vec<StoredSecurityEvent>, Option<String>), StoreError> {
    let mut events = Vec::with_capacity(limit);
    loop {
        let page = state
            .security_events
            .list_by_tenant_page(tenant_id, 0, through, USER_EVENT_SCAN_SIZE, cursor.as_ref())
            .await?;
        let page_len = page.events.len();
        let has_more_store_events = page.next_cursor.is_some();

        for (index, stored) in page.events.into_iter().enumerate() {
            if stored.event.subject.kind() != SecuritySubjectKind::User
                || stored.event.subject.id() != user_id
            {
                continue;
            }
            events.push(stored);
            if events.len() == limit {
                let exhausted = index + 1 == page_len && !has_more_store_events;
                let next_cursor = if exhausted {
                    None
                } else {
                    events
                        .last()
                        .map(|stored| SecurityEventCursor::new(&stored.event).encode())
                        .transpose()?
                };
                return Ok((events, next_cursor));
            }
        }

        let Some(next_cursor) = page.next_cursor else {
            return Ok((events, None));
        };
        cursor = Some(SecurityEventCursor::decode_for_query(
            &next_cursor,
            tenant_id,
            0,
            through,
        )?);
    }
}

#[utoipa::path(
    get,
    path = "/admin/data-governance/users/{user_id}/export",
    tag = "data_governance",
    params(("user_id" = String, Path), UserExportQuery),
    responses(
        (status = 200, description = "Tenant-scoped redacted user export", body = UserExportResponse),
        (status = 400, description = "Malformed event cursor"),
        (status = 401, description = "Admin authentication failed"),
        (status = 403, description = "Admin or owner strong authentication required"),
        (status = 404, description = "User is absent in this tenant"),
        (status = 503, description = "Governance or source storage unavailable")
    )
)]
pub async fn export_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Query(query): Query<UserExportQuery>,
) -> Response {
    let context = match authorize(&state, &headers, AdminAction::DataExportUser).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let tenant = context.admin.storage_tenant();
    let user = match state.users.get_by_id(tenant, &user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return error(StatusCode::NOT_FOUND, "not_found", "User was not found"),
        Err(store_error_value) => return store_error(store_error_value),
    };
    let limit = query.event_limit.unwrap_or(DEFAULT_PAGE_SIZE);
    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "event_limit must be between 1 and 500",
        );
    }
    let now = crate::current_unix_secs();
    let cursor = match query.event_cursor.as_deref() {
        Some(encoded) => {
            let payload = match decode_cursor(
                &state.governance_hmac_key,
                encoded,
                context.admin.tenant_id(),
                &format!("user:{user_id}"),
                "security_events",
                context.region_revision,
                now,
            ) {
                Ok(payload) => payload,
                Err(()) => {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "invalid_cursor",
                        "Event cursor is invalid or expired",
                    )
                }
            };
            match payload.inner {
                Some(inner) => match SecurityEventCursor::decode_for_query(
                    &inner,
                    context.admin.tenant_id(),
                    0,
                    payload.through,
                ) {
                    Ok(cursor) => Some((cursor, payload.through)),
                    Err(_) => {
                        return error(
                            StatusCode::BAD_REQUEST,
                            "invalid_cursor",
                            "Event cursor is invalid or expired",
                        )
                    }
                },
                None => None,
            }
        }
        None => None,
    };
    let through = cursor.as_ref().map_or(now, |(_, through)| *through);
    let (events, next_inner_cursor) = match list_user_security_event_page(
        &state,
        context.admin.tenant_id(),
        &user_id,
        through,
        limit,
        cursor.map(|(cursor, _)| cursor),
    )
    .await
    {
        Ok(page) => page,
        Err(store_error_value) => return store_error(store_error_value),
    };
    let next_event_cursor = next_inner_cursor.map(|inner| {
        encode_cursor(
            &state.governance_hmac_key,
            CursorPayload {
                version: EXPORT_CURSOR_VERSION,
                tenant_id: context.admin.tenant_id().to_string(),
                resource: format!("user:{user_id}"),
                section: "security_events".into(),
                region_revision: context.region_revision,
                expires_at: now + EXPORT_MANIFEST_TTL_SECS,
                through,
                inner: Some(inner),
            },
        )
    });

    let passkeys = match state.passkeys.list_by_user(tenant, &user_id).await {
        Ok(passkeys) => passkeys,
        Err(store_error_value) => return store_error(store_error_value),
    };
    let passkey_summaries = passkeys
        .iter()
        .map(|passkey| PasskeySummary {
            name: passkey.name.clone(),
            created_at: passkey.created_at,
            sign_count: passkey.sign_count,
        })
        .collect::<Vec<_>>();
    let login_sessions = match state.sessions.list_by_user(tenant, &user_id, now).await {
        Ok(sessions) => sessions
            .into_iter()
            .map(|session| LoginSessionSummary {
                device: session.device,
                created_at: session.created_at,
                last_used_at: session.last_used_at,
                expires_at: session.expires_at,
                assurance: session.acr,
            })
            .collect(),
        Err(store_error_value) => return store_error(store_error_value),
    };
    let grants = match state.grants.list_by_user(tenant, &user_id).await {
        Ok(grants) => grants
            .into_iter()
            .filter_map(|grant| serde_json::to_value(grant).ok())
            .collect(),
        Err(store_error_value) => return store_error(store_error_value),
    };
    let group_memberships = match user_groups(&state, tenant, &user_id).await {
        Ok(groups) => groups,
        Err(store_error_value) => return store_error(store_error_value),
    };
    let password_configured = match state.passwords.get(tenant, &user_id).await {
        Ok(value) => value.is_some(),
        Err(store_error_value) => return store_error(store_error_value),
    };
    let recovery_codes_configured = match state
        .recovery
        .get(tenant, &crate::recover::user_lookup(&user_id))
        .await
    {
        Ok(value) => value.is_some(),
        Err(store_error_value) => return store_error(store_error_value),
    };

    Json(UserExportResponse {
        schema_version: GOVERNANCE_SCHEMA_VERSION.into(),
        tenant_id: context.admin.tenant_id().to_string(),
        residency_jurisdiction: context.residency.jurisdiction,
        active_writer_region: context.region,
        region_control_revision: context.region_revision,
        generated_at: now,
        identity: identity_export(user),
        credentials: CredentialStatusExport {
            password_configured,
            recovery_codes_configured,
            passkey_count: passkey_summaries.len(),
        },
        passkeys: passkey_summaries,
        login_sessions,
        grants,
        group_memberships,
        security_events: events,
        next_event_cursor,
    })
    .into_response()
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTenantExport {
    pub purpose: String,
    pub sections: BTreeSet<ExportSection>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ExportManifestView {
    pub schema_version: String,
    pub export_id: String,
    pub tenant_id: String,
    pub purpose: String,
    pub policy_revision: u64,
    pub residency_jurisdiction: String,
    pub active_writer_region: String,
    pub region_control_revision: u64,
    pub sections: BTreeSet<ExportSection>,
    pub created_at: i64,
    pub expires_at: i64,
}

fn manifest_view(
    context: &GovernanceRequestContext,
    manifest: GovernanceExportManifest,
) -> ExportManifestView {
    ExportManifestView {
        schema_version: GOVERNANCE_SCHEMA_VERSION.into(),
        export_id: manifest.export_id,
        tenant_id: manifest.tenant_id,
        purpose: manifest.purpose,
        policy_revision: manifest.policy_revision,
        residency_jurisdiction: context.residency.jurisdiction.clone(),
        active_writer_region: manifest.region,
        region_control_revision: manifest.region_revision,
        sections: manifest.sections,
        created_at: manifest.created_at,
        expires_at: manifest.expires_at,
    }
}

fn random_export_id(state: &AppState) -> String {
    let mut random = [0u8; 18];
    rand::thread_rng().fill_bytes(&mut random);
    state.region.issue_base64_id(URL_SAFE_NO_PAD.encode(random))
}

#[utoipa::path(
    post,
    path = "/admin/data-governance/exports",
    tag = "data_governance",
    request_body = CreateTenantExport,
    responses(
        (status = 201, description = "Short-lived tenant export manifest", body = ExportManifestView),
        (status = 400, description = "Invalid purpose or section set"),
        (status = 401, description = "Admin authentication failed"),
        (status = 403, description = "Owner and strong authentication required"),
        (status = 503, description = "Governance or residency state unavailable")
    )
)]
pub async fn create_tenant_export(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateTenantExport>,
) -> Response {
    let context = match authorize(&state, &headers, AdminAction::DataExportTenant).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let purpose = match crate::governance::validate_purpose(&request.purpose) {
        Ok(purpose) => purpose,
        Err(message) => return error(StatusCode::BAD_REQUEST, "invalid_request", message),
    };
    if request.sections.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "At least one export section is required",
        );
    }
    let policy = match policy(&state, context.admin.tenant_id()).await {
        Ok(policy) => policy,
        Err(response) => return response,
    };
    let now = crate::current_unix_secs();
    let manifest = GovernanceExportManifest {
        export_id: random_export_id(&state),
        tenant_id: context.admin.tenant_id().to_string(),
        actor: context.admin.audit_identity(),
        purpose,
        policy_revision: policy.revision,
        region: context.region.clone(),
        region_revision: context.region_revision,
        sections: request.sections,
        created_at: now,
        expires_at: now + EXPORT_MANIFEST_TTL_SECS,
    };
    match state.governance.put_export_manifest(manifest.clone()).await {
        Ok(true) => (StatusCode::CREATED, Json(manifest_view(&context, manifest))).into_response(),
        Ok(false) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "identifier_collision",
            "Could not allocate an export manifest",
        ),
        Err(store_error_value) => store_error(store_error_value),
    }
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct TenantExportQuery {
    pub section: String,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TenantExportPage {
    pub schema_version: String,
    pub export_id: String,
    pub tenant_id: String,
    pub residency_jurisdiction: String,
    pub active_writer_region: String,
    pub region_control_revision: u64,
    pub section: String,
    pub view_consistency: String,
    pub generated_at: i64,
    pub records: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct TenantUserView {
    user_id: String,
    email: String,
    scim_external_id: Option<String>,
    scim_user_name: Option<String>,
    display_name: Option<String>,
    status: String,
    credential_epoch: u64,
    created_at: i64,
    updated_at: i64,
    attributes: BTreeMap<String, NamespaceExport>,
}

fn tenant_user_view(user: UserRecord) -> TenantUserView {
    let identity = identity_export(user);
    TenantUserView {
        user_id: identity.user_id,
        email: identity.email,
        scim_external_id: identity.scim_external_id,
        scim_user_name: identity.scim_user_name,
        display_name: identity.display_name,
        status: identity.status,
        credential_epoch: identity.credential_epoch,
        created_at: identity.created_at,
        updated_at: identity.updated_at,
        attributes: identity.attributes,
    }
}

#[derive(Debug, Serialize)]
struct CredentialSetSummary {
    version: u64,
    current_status: Option<String>,
    next_status: Option<String>,
    overlap_expires_at: Option<i64>,
}

fn credential_set_summary(set: &crate::credential::CredentialSet) -> CredentialSetSummary {
    let status = |record: &crate::credential::CredentialRecord| {
        format!("{:?}", record.status).to_ascii_lowercase()
    };
    CredentialSetSummary {
        version: set.version,
        current_status: set.current.as_ref().map(status),
        next_status: set.next.as_ref().map(status),
        overlap_expires_at: set.overlap_expires_at,
    }
}

fn export_source_revision<T: Serialize + ?Sized>(source: &T) -> String {
    let bytes = serde_json::to_vec(source).expect("tenant export revision source serializes");
    URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
}

#[derive(Debug, Serialize)]
struct TenantClientView {
    record_type: &'static str,
    record_id: String,
    source_revision: String,
    client_id: String,
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: String,
    client_type: String,
    id_token_signed_response_alg: String,
    introspect_enabled: bool,
    resource_ids: Vec<String>,
    allowed_resources: Vec<String>,
    allowed_scopes: Vec<String>,
    credential: CredentialSetSummary,
    registration_credential: CredentialSetSummary,
    created_at: i64,
    last_used_day: Option<i64>,
    tombstoned_at: Option<i64>,
}

fn tenant_client_view(client: crate::ports::ClientRecord) -> TenantClientView {
    let client_type = format!("{:?}", client.client_type()).to_ascii_lowercase();
    let id_token_signed_response_alg = client.id_token_alg().to_string();
    let credential = credential_set_summary(&client.client_secret_credentials);
    let registration_credential = credential_set_summary(&client.registration_token_credentials);
    let source = serde_json::json!({
        "client_id": &client.client_id,
        "redirect_uris": &client.redirect_uris,
        "token_endpoint_auth_method": &client.token_endpoint_auth_method,
        "jwks": &client.jwks,
        "jwks_uri": &client.jwks_uri,
        "token_endpoint_auth_signing_alg": &client.token_endpoint_auth_signing_alg,
        "default_resource": &client.default_resource,
        "introspect_enabled": client.introspect_enabled,
        "resource_ids": &client.resource_ids,
        "post_logout_redirect_uris": &client.post_logout_redirect_uris,
        "client_type": &client.client_type,
        "id_token_signed_response_alg": &client.id_token_signed_response_alg,
        "oidc_sector_identifier": &client.oidc_sector_identifier,
        "allowed_resources": &client.allowed_resources,
        "allowed_scopes": &client.allowed_scopes,
        "redirect_mode": &client.redirect_mode,
        "created_at": client.created_at,
        "last_used_day": client.last_used_day,
        "tombstoned_at": client.tombstoned_at,
        "backchannel_token_delivery_mode": &client.backchannel_token_delivery_mode,
        "backchannel_client_notification_endpoint":
            &client.backchannel_client_notification_endpoint,
        "require_dpop": client.require_dpop,
        "prm_domains": &client.prm_domains,
        "credential": &credential,
        "registration_credential": &registration_credential,
    });
    TenantClientView {
        record_type: "client",
        record_id: client.client_id.clone(),
        source_revision: export_source_revision(&source),
        client_id: client.client_id,
        redirect_uris: client.redirect_uris,
        token_endpoint_auth_method: client.token_endpoint_auth_method,
        client_type,
        id_token_signed_response_alg,
        introspect_enabled: client.introspect_enabled,
        resource_ids: client.resource_ids,
        allowed_resources: client.allowed_resources,
        allowed_scopes: client.allowed_scopes,
        credential,
        registration_credential,
        created_at: client.created_at,
        last_used_day: client.last_used_day,
        tombstoned_at: client.tombstoned_at,
    }
}

#[derive(Debug, Serialize)]
struct InitialAccessTokenView {
    record_type: &'static str,
    record_id: String,
    token_id: String,
    status: String,
    scopes: Vec<String>,
    one_time: bool,
    used_at: Option<i64>,
    expires_at: i64,
    version: u64,
}

fn section(value: &str) -> Option<ExportSection> {
    match value {
        "users" => Some(ExportSection::Users),
        "clients" => Some(ExportSection::Clients),
        "groups" => Some(ExportSection::Groups),
        "role_mappings" => Some(ExportSection::RoleMappings),
        "security_events" => Some(ExportSection::SecurityEvents),
        "tenant_configuration" => Some(ExportSection::TenantConfiguration),
        "secret_metadata" => Some(ExportSection::SecretMetadata),
        "signing_keys" => Some(ExportSection::SigningKeys),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct ExportRecordKey {
    record_type: String,
    record_id: String,
}

fn export_record_key(record: &serde_json::Value) -> Result<ExportRecordKey, Response> {
    let required = |name| {
        record
            .get(name)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                store_error(StoreError::Permanent(format!(
                    "tenant export record is missing {name}"
                )))
            })
    };
    Ok(ExportRecordKey {
        record_type: required("record_type")?,
        record_id: required("record_id")?,
    })
}

fn keyset_values(
    values: Vec<serde_json::Value>,
    after: Option<&str>,
    limit: usize,
) -> Result<(Vec<serde_json::Value>, Option<String>), Response> {
    let after = after
        .map(serde_json::from_str::<ExportRecordKey>)
        .transpose()
        .map_err(|_| {
            error(
                StatusCode::BAD_REQUEST,
                "invalid_cursor",
                "Export cursor is invalid",
            )
        })?;
    let mut keyed = values
        .into_iter()
        .map(|record| export_record_key(&record).map(|key| (key, record)))
        .collect::<Result<Vec<_>, _>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    if keyed.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(store_error(StoreError::Permanent(
            "tenant export record identity is not unique".into(),
        )));
    }
    let start = after
        .as_ref()
        .map_or(0, |key| keyed.partition_point(|entry| &entry.0 <= key));
    let has_more = keyed.len().saturating_sub(start) > limit;
    let page = keyed
        .into_iter()
        .skip(start)
        .take(limit)
        .collect::<Vec<_>>();
    let next = if has_more {
        page.last()
            .map(|(key, _)| serde_json::to_string(key))
            .transpose()
            .map_err(|error| {
                store_error(StoreError::Permanent(format!(
                    "serialize tenant export keyset cursor: {error}"
                )))
            })?
    } else {
        None
    };
    Ok((page.into_iter().map(|(_, record)| record).collect(), next))
}

fn federation_configuration_value(
    config: agent_auth_authn::federation::FederationConfig,
) -> serde_json::Value {
    let protocol = format!("{:?}", config.protocol).to_ascii_lowercase();
    let oidc = config.oidc.map(|oidc| {
        serde_json::json!({
            "client_id": oidc.client_id,
            "client_secret_configured": !oidc.client_secret_ref.is_empty(),
            "authorization_endpoint": oidc.authorization_endpoint,
            "token_endpoint": oidc.token_endpoint,
            "jwks_uri": oidc.jwks_uri,
            "scopes": oidc.scopes
        })
    });
    let source_revision = export_source_revision(&serde_json::json!({
        "tenant_id": &config.tenant_id,
        "upstream_idp_id": &config.upstream_idp_id,
        "protocol": &protocol,
        "upstream_issuer": &config.upstream_issuer,
        "strong_acr_values": &config.strong_acr_values,
        "oidc": &oidc,
    }));
    serde_json::json!({
        "record_type": "federation",
        "record_id": config.upstream_idp_id,
        "source_revision": source_revision,
        "protocol": protocol,
        "upstream_issuer": config.upstream_issuer,
        "strong_acr_values": config.strong_acr_values,
        "oidc": oidc
    })
}

fn federation_attribute_mapping_configuration_value(
    registry: MappingRegistry,
) -> serde_json::Value {
    let source_revision = export_source_revision(
        &serde_json::to_value(&registry)
            .expect("serializable federation attribute mapping registry"),
    );
    serde_json::json!({
        "record_type": "federation_attribute_mappings",
        "record_id": registry.upstream_idp_id,
        "source_revision": source_revision,
        "upstream_issuer": registry.upstream_issuer,
        "registry_revision": registry.revision,
        "mappings": registry.mappings
    })
}

fn workload_trust_configuration_value(
    entry: crate::ports::WorkloadTrustEntry,
) -> serde_json::Value {
    let source_revision = export_source_revision(&serde_json::json!({
        "binding_id": &entry.binding_id,
        "binding": &entry.binding,
    }));
    serde_json::json!({
        "record_type": "workload_trust",
        "record_id": entry.binding_id,
        "source_revision": source_revision,
        "mapped_client_id": entry.binding.mapped_client_id,
        "mechanism": entry.binding.mechanism
    })
}

fn domain_binding_configuration_value(binding: crate::ports::DomainBinding) -> serde_json::Value {
    let source_revision = export_source_revision(&serde_json::json!({
        "domain": &binding.domain,
        "resource_id": &binding.resource_id,
        "tenant_id": &binding.tenant_id,
        "client_id": &binding.client_id,
    }));
    serde_json::json!({
        "record_type": "domain_binding",
        "record_id": binding.domain,
        "source_revision": source_revision,
        "resource_id": binding.resource_id,
        "client_id": binding.client_id
    })
}

async fn tenant_configuration_values(
    state: &AppState,
    context: &GovernanceRequestContext,
) -> Result<Vec<serde_json::Value>, Response> {
    let logical_tenant = context.admin.tenant_id();
    let storage_tenant = context.admin.storage_tenant();
    let mut values = vec![serde_json::json!({
        "record_type": "residency",
        "record_id": "residency",
        "jurisdiction": context.residency.jurisdiction,
        "allowed_regions": context.residency.allowed_regions,
        "governance_region": context.residency.governance_region,
        "region_control_revision": context.region_revision
    })];
    let policy = policy(state, logical_tenant).await?;
    values.push(serde_json::json!({
        "record_type": "governance_policy",
        "record_id": "governance_policy",
        "legal_hold": policy.legal_hold,
        "revision": policy.revision,
        "updated_at": policy.updated_at
    }));

    let federation = state
        .federation_config
        .list_by_tenant(logical_tenant)
        .await
        .map_err(store_error)?;
    values.extend(federation.into_iter().map(federation_configuration_value));

    let federation_attribute_mappings = state
        .federation_attribute_mappings
        .list_by_tenant(logical_tenant)
        .await
        .map_err(store_error)?;
    values.extend(
        federation_attribute_mappings
            .into_iter()
            .map(federation_attribute_mapping_configuration_value),
    );

    let workload = state
        .workload_trust
        .list_by_tenant(logical_tenant)
        .await
        .map_err(store_error)?;
    values.extend(workload.into_iter().map(workload_trust_configuration_value));

    if let Some(config) = state
        .admin_auth
        .get_config(logical_tenant)
        .await
        .map_err(store_error)?
    {
        values.push(serde_json::json!({
            "record_type": "admin_oidc",
            "record_id": "admin_oidc",
            "issuer": config.issuer,
            "client_id": config.client_id,
            "client_secret_configured": !config.client_secret_ref.is_empty(),
            "authorization_endpoint": config.authorization_endpoint,
            "token_endpoint": config.token_endpoint,
            "jwks_uri": config.jwks_uri,
            "redirect_uri": config.redirect_uri,
            "scopes": config.scopes,
            "strong_acr_values": config.strong_acr_values,
            "identity_claim": config.identity_claim,
            "identity_field": config.identity_field,
            "revision": config.revision,
            "updated_at": config.updated_at
        }));
    }

    let clients = state
        .clients
        .list(storage_tenant)
        .await
        .map_err(store_error)?;
    for client in clients {
        let bindings = state
            .domain_map
            .list_by_client(&client.client_id)
            .await
            .map_err(store_error)?;
        values.extend(
            bindings
                .into_iter()
                .filter(|binding| binding.tenant_id == logical_tenant)
                .map(domain_binding_configuration_value),
        );
    }

    let streams = state
        .ssf
        .list_streams(logical_tenant)
        .await
        .map_err(store_error)?;
    values.extend(streams.into_iter().map(|stream| {
        serde_json::json!({
            "record_type": "ssf_stream",
            "record_id": stream.stream_id,
            "revision": stream.revision,
            "endpoint": stream.endpoint,
            "audience": stream.audience,
            "requested_events": stream.requested_events,
            "delivered_events": stream.delivered_events,
            "status": stream.status,
            "activation_at": stream.activation_at,
            "created_at": stream.created_at,
            "updated_at": stream.updated_at
        })
    }));
    Ok(values)
}

fn tenant_secret_metadata_values(state: &AppState, tenant_id: &str) -> Vec<serde_json::Value> {
    state
        .tenant_secret_references
        .get(tenant_id)
        .into_iter()
        .flatten()
        .map(|reference| {
            serde_json::json!({
                "record_type": "tenant_secret",
                "record_id": reference.purpose,
                "purpose": reference.purpose,
                "ownership": reference.ownership,
                "resource_region": reference.resource_region,
                "ownership_revision": reference.ownership_revision,
                "status": "configured"
            })
        })
        .collect()
}

fn signing_key_record_id(algorithm: &str, kid: &str) -> String {
    format!("{algorithm}:{kid}")
}

async fn tenant_signing_key_values(
    state: &AppState,
    tenant_id: &str,
) -> Result<Vec<serde_json::Value>, Response> {
    let mut values = vec![serde_json::json!({
        "record_type": "governance_suppression_key",
        "record_id": format!("v{}", crate::governance::SUPPRESSION_KEY_VERSION),
        "key_version": crate::governance::SUPPRESSION_KEY_VERSION,
        "status": "active"
    })];
    let Some(record) = state
        .tenant_keys
        .registry()
        .get(tenant_id)
        .await
        .map_err(store_error)?
    else {
        values.push(serde_json::json!({
            "record_type": "tenant_key_registry",
            "record_id": "registry",
            "lifecycle": "not_configured",
            "pending_deletion_count": 0,
            "scheduled_deletion_count": 0
        }));
        return Ok(values);
    };
    values.push(serde_json::json!({
        "record_type": "tenant_key_registry",
        "record_id": "registry",
        "lifecycle": record.lifecycle,
        "revision": record.revision,
        "updated_at": record.updated_at,
        "pending_deletion_count": record.pending_deletion_arns.len(),
        "scheduled_deletion_count": record.scheduled_deletion_arns.len()
    }));
    if let Some(snapshot) = record.served_snapshot {
        values.extend(snapshot.ec.published.into_iter().map(|key| {
            serde_json::json!({
                "record_type": "tenant_signing_key",
                "record_id": signing_key_record_id("es256", &key.public_jwk.kid),
                "algorithm": "es256",
                "kid": key.public_jwk.kid,
                "generation": key.generation,
                "active": key.key_arn == snapshot.ec.active.key_arn,
                "created_at": key.created_at,
                "verified_at": key.verified_at
            })
        }));
        values.extend(snapshot.rsa.published.into_iter().map(|key| {
            serde_json::json!({
                "record_type": "tenant_signing_key",
                "record_id": signing_key_record_id("rs256", &key.public_jwk.kid),
                "algorithm": "rs256",
                "kid": key.public_jwk.kid,
                "generation": key.generation,
                "active": key.key_arn == snapshot.rsa.active.key_arn,
                "created_at": key.created_at,
                "verified_at": key.verified_at
            })
        }));
    }
    Ok(values)
}

async fn tenant_export_records(
    state: &AppState,
    context: &GovernanceRequestContext,
    manifest: &GovernanceExportManifest,
    section: ExportSection,
    limit: usize,
    cursor: Option<CursorPayload>,
    now: i64,
) -> Result<(Vec<serde_json::Value>, Option<String>), Response> {
    let tenant = context.admin.storage_tenant();
    let inner = cursor.as_ref().and_then(|cursor| cursor.inner.as_deref());
    let encode_next = |inner: String, through: i64| {
        encode_cursor(
            &state.governance_hmac_key,
            CursorPayload {
                version: EXPORT_CURSOR_VERSION,
                tenant_id: manifest.tenant_id.clone(),
                resource: manifest.export_id.clone(),
                section: section.as_str().into(),
                region_revision: manifest.region_revision,
                expires_at: manifest.expires_at,
                through,
                inner: Some(inner),
            },
        )
    };

    match section {
        ExportSection::Users => {
            let (users, next) = state
                .users
                .list(
                    tenant,
                    limit,
                    inner,
                    None,
                    crate::ports::UserListStatusFilter::All,
                )
                .await
                .map_err(|store_error_value| match store_error_value {
                    StoreError::Permanent(_) => error(
                        StatusCode::BAD_REQUEST,
                        "invalid_cursor",
                        "Export cursor is invalid",
                    ),
                    other => store_error(other),
                })?;
            Ok((
                users
                    .into_iter()
                    .filter_map(|user| serde_json::to_value(tenant_user_view(user)).ok())
                    .collect(),
                next.map(|next| encode_next(next, 0)),
            ))
        }
        ExportSection::Clients => {
            let mut records = state.clients.list(tenant).await.map_err(store_error)?;
            records.sort_by(|left, right| left.client_id.cmp(&right.client_id));
            let iats = state
                .initial_access_tokens
                .list(tenant)
                .await
                .map_err(store_error)?;
            let mut values = records
                .into_iter()
                .filter_map(|client| serde_json::to_value(tenant_client_view(client)).ok())
                .collect::<Vec<_>>();
            values.extend(iats.into_iter().filter_map(|iat| {
                let record_id = iat.token_id.clone();
                serde_json::to_value(InitialAccessTokenView {
                    record_type: "initial_access_token",
                    record_id,
                    token_id: iat.token_id,
                    status: format!("{:?}", iat.credential.status).to_ascii_lowercase(),
                    scopes: iat.scopes,
                    one_time: iat.one_time,
                    used_at: iat.used_at,
                    expires_at: iat.credential.expires_at,
                    version: iat.version,
                })
                .ok()
            }));
            let (page, next) = keyset_values(values, inner, limit)?;
            Ok((page, next.map(|next| encode_next(next, 0))))
        }
        ExportSection::Groups => {
            let (groups, _) = state
                .scim_groups
                .list(tenant, 0, usize::MAX)
                .await
                .map_err(store_error)?;
            let values = groups
                .into_iter()
                .map(|group| {
                    serde_json::json!({
                        "record_type": "group",
                        "record_id": group.group_id.clone(),
                        "group_id": group.group_id,
                        "external_id": group.external_id,
                        "display_name": group.display_name,
                        "members": group.members,
                        "revision": group.version,
                        "created_at": group.created_at,
                        "updated_at": group.updated_at
                    })
                })
                .collect();
            let (page, next) = keyset_values(values, inner, limit)?;
            Ok((page, next.map(|next| encode_next(next, 0))))
        }
        ExportSection::RoleMappings => {
            let mut mappings = state
                .scim_groups
                .list_role_mappings(tenant)
                .await
                .map_err(store_error)?;
            mappings.sort_by(|left, right| left.external_id.cmp(&right.external_id));
            let values = mappings
                .into_iter()
                .map(|mapping| {
                    serde_json::json!({
                        "record_type": "role_mapping",
                        "record_id": mapping.external_id.clone(),
                        "group_id": mapping.group_id,
                        "external_id": mapping.external_id,
                        "role": mapping.role,
                        "updated_at": mapping.updated_at
                    })
                })
                .collect::<Vec<_>>();
            let (page, next) = keyset_values(values, inner, limit)?;
            Ok((page, next.map(|next| encode_next(next, 0))))
        }
        ExportSection::SecurityEvents => {
            let through = cursor.as_ref().map_or(now, |cursor| cursor.through);
            let decoded = match inner {
                Some(inner) => Some(
                    SecurityEventCursor::decode_for_query(
                        inner,
                        context.admin.tenant_id(),
                        0,
                        through,
                    )
                    .map_err(|_| {
                        error(
                            StatusCode::BAD_REQUEST,
                            "invalid_cursor",
                            "Export cursor is invalid",
                        )
                    })?,
                ),
                None => None,
            };
            let page = state
                .security_events
                .list_by_tenant_page(
                    context.admin.tenant_id(),
                    0,
                    through,
                    limit,
                    decoded.as_ref(),
                )
                .await
                .map_err(store_error)?;
            Ok((
                page.events
                    .into_iter()
                    .filter_map(|event| serde_json::to_value(event).ok())
                    .collect(),
                page.next_cursor.map(|next| encode_next(next, through)),
            ))
        }
        ExportSection::TenantConfiguration => {
            let values = tenant_configuration_values(state, context).await?;
            let (page, next) = keyset_values(values, inner, limit)?;
            Ok((page, next.map(|next| encode_next(next, 0))))
        }
        ExportSection::SecretMetadata => {
            let values = tenant_secret_metadata_values(state, context.admin.tenant_id());
            let (page, next) = keyset_values(values, inner, limit)?;
            Ok((page, next.map(|next| encode_next(next, 0))))
        }
        ExportSection::SigningKeys => {
            let values = tenant_signing_key_values(state, context.admin.tenant_id()).await?;
            let (page, next) = keyset_values(values, inner, limit)?;
            Ok((page, next.map(|next| encode_next(next, 0))))
        }
    }
}

#[utoipa::path(
    get,
    path = "/admin/data-governance/exports/{export_id}",
    tag = "data_governance",
    params(("export_id" = String, Path), TenantExportQuery),
    responses(
        (status = 200, description = "One independently paginated export section", body = TenantExportPage),
        (status = 400, description = "Malformed or mismatched cursor"),
        (status = 401, description = "Admin authentication failed"),
        (status = 403, description = "Manifest actor or permission mismatch"),
        (status = 404, description = "Manifest absent or expired"),
        (status = 409, description = "Manifest Region revision is stale"),
        (status = 503, description = "Governance or source storage unavailable")
    )
)]
pub async fn get_tenant_export(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(export_id): Path<String>,
    Query(query): Query<TenantExportQuery>,
) -> Response {
    let context = match authorize(&state, &headers, AdminAction::DataExportTenant).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Some(section) = section(&query.section) else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Unknown export section",
        );
    };
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE);
    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "limit must be between 1 and 500",
        );
    }
    let now = crate::current_unix_secs();
    let manifest = match state
        .governance
        .get_export_manifest(context.admin.tenant_id(), &export_id, now)
        .await
    {
        Ok(Some(manifest)) => manifest,
        Ok(None) => {
            return error(
                StatusCode::NOT_FOUND,
                "not_found",
                "Export manifest was not found or has expired",
            )
        }
        Err(store_error_value) => return store_error(store_error_value),
    };
    if manifest.actor != context.admin.audit_identity() {
        return error(
            StatusCode::FORBIDDEN,
            "manifest_actor_mismatch",
            "Export manifest belongs to a different Admin actor",
        );
    }
    if manifest.region != context.region || manifest.region_revision != context.region_revision {
        return error(
            StatusCode::CONFLICT,
            "region_revision_changed",
            "Export manifest cannot continue after an active Region change",
        );
    }
    if !manifest.sections.contains(&section) {
        return error(
            StatusCode::FORBIDDEN,
            "section_not_authorized",
            "The manifest does not authorize this export section",
        );
    }
    let cursor = match query.cursor.as_deref() {
        Some(encoded) => match decode_cursor(
            &state.governance_hmac_key,
            encoded,
            context.admin.tenant_id(),
            &export_id,
            section.as_str(),
            context.region_revision,
            now,
        ) {
            Ok(payload) => Some(payload),
            Err(()) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "invalid_cursor",
                    "Export cursor is invalid or expired",
                )
            }
        },
        None => None,
    };
    let (records, next_cursor) =
        match tenant_export_records(&state, &context, &manifest, section, limit, cursor, now).await
        {
            Ok(page) => page,
            Err(response) => return response,
        };
    Json(TenantExportPage {
        schema_version: GOVERNANCE_SCHEMA_VERSION.into(),
        export_id,
        tenant_id: context.admin.tenant_id().to_string(),
        residency_jurisdiction: context.residency.jurisdiction,
        active_writer_region: context.region,
        region_control_revision: context.region_revision,
        section: section.as_str().into(),
        view_consistency: "live_keyset".into(),
        generated_at: now,
        records,
        next_cursor,
    })
    .into_response()
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GovernanceJobView {
    pub schema_version: String,
    pub tenant_id: String,
    pub job_id: String,
    pub kind: GovernanceJobKind,
    pub state: GovernanceJobState,
    pub phase: GovernanceJobPhase,
    pub policy_revision: u64,
    pub tenant_lifecycle_revision: u64,
    pub revision: u64,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_erasure_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_until: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
}

impl From<GovernanceJobRecord> for GovernanceJobView {
    fn from(job: GovernanceJobRecord) -> Self {
        Self {
            schema_version: GOVERNANCE_SCHEMA_VERSION.into(),
            tenant_id: job.tenant_id,
            job_id: job.job_id,
            kind: job.kind,
            state: job.state,
            phase: job.phase,
            policy_revision: job.policy_revision,
            tenant_lifecycle_revision: job.tenant_revision,
            revision: job.revision,
            created_at: job.created_at,
            updated_at: job.updated_at,
            primary_erasure_at: job.primary_erasure_at,
            retention_until: job.retention_until,
            error_class: job.error_class,
        }
    }
}

async fn record_job_audit(
    state: &AppState,
    job: &GovernanceJobRecord,
    action: &str,
    outcome: crate::security_event::SecurityEventOutcome,
    extend_retention: bool,
) -> Result<(), Response> {
    let event = AppState::prepare_security_event(
        crate::security_event::SecurityEventDraft::new(
            &job.tenant_id,
            crate::security_event::SecurityActor::admin("governance-control"),
            Some(crate::security_event::SecuritySubject::tenant(
                &job.tenant_id,
            )),
            crate::security_event::SecurityEventCategory::Administration,
            action,
            outcome,
        )
        .correlated(crate::security_event::SecurityEventCorrelation {
            operation_id: Some(job.job_id.clone()),
            ..Default::default()
        }),
    )
    .ok_or_else(|| {
        error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "governance_audit_invalid",
            "Governance audit event was invalid",
        )
    })?;
    if extend_retention {
        crate::governance_worker::extend_retention_for_audit(
            state,
            &job.tenant_id,
            &job.job_id,
            event.occurred_at,
        )
        .await
        .map_err(store_error)?;
    }
    state.record_prepared_security_event(event).await;
    Ok(())
}

async fn audit_job_operation(
    state: &AppState,
    job: &GovernanceJobRecord,
    action: &str,
    outcome: crate::security_event::SecurityEventOutcome,
) -> Result<(), Response> {
    record_job_audit(state, job, action, outcome, true).await
}

async fn audit_job_status(state: &AppState, job: &GovernanceJobRecord) -> Result<(), Response> {
    // Status polling must not invalidate the exact-revision worker command it observes.
    record_job_audit(
        state,
        job,
        "governance.job.status",
        crate::security_event::SecurityEventOutcome::Success,
        false,
    )
    .await
}

async fn reload_and_enqueue_job(
    state: &AppState,
    tenant_id: &str,
    job_id: &str,
) -> Result<GovernanceJobRecord, Response> {
    let job = state
        .governance
        .get_job(tenant_id, job_id)
        .await
        .map_err(store_error)?
        .ok_or_else(|| {
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "governance_state_inconsistent",
                "Governance job disappeared before worker dispatch",
            )
        })?;
    if matches!(
        job.state,
        GovernanceJobState::Queued | GovernanceJobState::Running | GovernanceJobState::Retryable
    ) {
        state
            .governance_jobs
            .enqueue(GovernanceJobCommand {
                tenant_id: job.tenant_id.clone(),
                job_id: job.job_id.clone(),
                expected_revision: job.revision,
                failure_attempt: 0,
            })
            .await
            .map_err(store_error)?;
    }
    Ok(job)
}

async fn start_job(
    state: &AppState,
    context: &GovernanceRequestContext,
    kind: GovernanceJobKind,
    target_id: String,
    target_epoch: u64,
) -> Result<GovernanceJobRecord, Response> {
    if !state
        .governance_config
        .admits_destructive_governance(context.admin.tenant_id(), &context.region)
    {
        return Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "governance_region_inactive",
            "Destructive governance is paused outside the designated governance Region",
        ));
    }
    let policy = policy(state, context.admin.tenant_id()).await?;
    let now = crate::current_unix_secs();
    let job_id = crate::governance::stable_job_id(
        &state.governance_hmac_key,
        context.admin.tenant_id(),
        kind,
        &target_id,
        target_epoch,
    );
    let verification_target = if kind == GovernanceJobKind::UserErasure {
        match crate::governance::seal_verification_target(
            &state.governance_hmac_key,
            &job_id,
            &target_id,
        ) {
            Ok(target) => Some(target),
            Err(message) => {
                return Err(error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "governance_state_error",
                    &message,
                ))
            }
        }
    } else {
        None
    };
    let job = GovernanceJobRecord {
        job_id,
        tenant_id: context.admin.tenant_id().to_string(),
        kind,
        target_id: Some(target_id),
        target_aliases: vec![],
        verification_target,
        active_child_job_id: None,
        processed_records: 0,
        tenant_cleanup_stage: crate::governance::TenantCleanupStage::Users,
        target_epoch,
        state: GovernanceJobState::Queued,
        phase: GovernanceJobPhase::IntentRecorded,
        policy_revision: policy.revision,
        tenant_revision: 0,
        revision: 1,
        created_at: now,
        updated_at: now,
        primary_erasure_at: None,
        retention_anchor_at: None,
        retention_until: None,
        evidence_revision: 0,
        error_class: None,
    };
    match state
        .governance
        .start_or_resume_job(
            job,
            policy.revision,
            kind == GovernanceJobKind::TenantOffboarding,
        )
        .await
    {
        Ok(GovernanceJobStartOutcome::Stored(job))
        | Ok(GovernanceJobStartOutcome::Existing(job)) => {
            audit_job_operation(
                state,
                &job,
                "governance.job.start_or_resume",
                crate::security_event::SecurityEventOutcome::Success,
            )
            .await?;
            reload_and_enqueue_job(state, &job.tenant_id, &job.job_id).await
        }
        Ok(GovernanceJobStartOutcome::PolicyConflict(_)) => Err(error(
            StatusCode::CONFLICT,
            "policy_revision_changed",
            "Governance policy changed while the job was starting",
        )),
        Ok(GovernanceJobStartOutcome::MutationConflict { active_permits }) => Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "tenant_mutations_in_flight",
                "error_description": "Tenant offboarding is waiting for active mutations to drain",
                "active_permits": active_permits
            })),
        )
            .into_response()),
        Ok(GovernanceJobStartOutcome::TenantFrozen { lifecycle_revision }) => Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "tenant_offboarding",
                "error_description": "Tenant authority is frozen for offboarding",
                "lifecycle_revision": lifecycle_revision
            })),
        )
            .into_response()),
        Err(store_error_value) => Err(store_error(store_error_value)),
    }
}

fn job_response(job: GovernanceJobRecord) -> Response {
    let status = if job.state == GovernanceJobState::BlockedLegalHold {
        StatusCode::CONFLICT
    } else {
        StatusCode::ACCEPTED
    };
    (status, Json(GovernanceJobView::from(job))).into_response()
}

#[utoipa::path(
    post,
    path = "/admin/data-governance/users/{user_id}/erasure",
    tag = "data_governance",
    params(("user_id" = String, Path)),
    responses(
        (status = 202, description = "Durable user-erasure job queued or resumed", body = GovernanceJobView),
        (status = 401, description = "Admin authentication failed"),
        (status = 403, description = "Owner and strong authentication required"),
        (status = 404, description = "User is absent in this tenant"),
        (status = 409, description = "Durable job blocked by legal hold", body = GovernanceJobView),
        (status = 503, description = "Governance or residency state unavailable")
    )
)]
pub async fn start_user_erasure(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Response {
    let context = match authorize(&state, &headers, AdminAction::DataErase).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    match state
        .governance
        .get_tenant_lifecycle(context.admin.tenant_id())
        .await
    {
        Ok(Some(lifecycle))
            if lifecycle.state == crate::governance::TenantLifecycleState::Offboarding =>
        {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "tenant_offboarding",
                    "error_description": "Tenant authority is frozen for offboarding",
                    "lifecycle_revision": lifecycle.revision
                })),
            )
                .into_response()
        }
        Ok(_) => {}
        Err(store_error_value) => return store_error(store_error_value),
    }
    let canonical_digest = crate::governance::suppression_digest(
        &state.governance_hmac_key,
        context.admin.tenant_id(),
        "user",
        crate::governance::GovernanceAliasKind::CanonicalId.as_str(),
        crate::governance::SUPPRESSION_NORMALIZATION_VERSION,
        &user_id,
    );
    let suppressed_epoch = match state
        .governance
        .latest_suppression_epoch(context.admin.tenant_id(), "user", &canonical_digest)
        .await
    {
        Ok(epoch) => epoch,
        Err(store_error_value) => return store_error(store_error_value),
    };
    if let Some(target_epoch) = suppressed_epoch {
        let job_id = crate::governance::stable_job_id(
            &state.governance_hmac_key,
            context.admin.tenant_id(),
            GovernanceJobKind::UserErasure,
            &user_id,
            target_epoch,
        );
        return match state
            .governance
            .get_job(context.admin.tenant_id(), &job_id)
            .await
        {
            Ok(Some(job)) if job.state == GovernanceJobState::BlockedLegalHold => {
                match start_job(
                    &state,
                    &context,
                    GovernanceJobKind::UserErasure,
                    user_id,
                    target_epoch,
                )
                .await
                {
                    Ok(job) => job_response(job),
                    Err(response) => response,
                }
            }
            Ok(Some(_)) => {
                match reload_and_enqueue_job(&state, context.admin.tenant_id(), &job_id).await {
                    Ok(job) => job_response(job),
                    Err(response) => response,
                }
            }
            Ok(None) => error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "governance_state_inconsistent",
                "Suppression authority exists without its durable job",
            ),
            Err(store_error_value) => store_error(store_error_value),
        };
    }
    let user = match state
        .users
        .get_by_id(context.admin.storage_tenant(), &user_id)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return error(StatusCode::NOT_FOUND, "not_found", "User was not found"),
        Err(store_error_value) => return store_error(store_error_value),
    };
    let target_epoch = match user.status {
        UserStatus::Tombstoned if user.credential_epoch > 0 => user.credential_epoch,
        _ => match user.credential_epoch.checked_add(1) {
            Some(epoch) => epoch,
            None => {
                return error(
                    StatusCode::CONFLICT,
                    "epoch_exhausted",
                    "User lifecycle epoch is exhausted",
                )
            }
        },
    };
    match start_job(
        &state,
        &context,
        GovernanceJobKind::UserErasure,
        user_id,
        target_epoch,
    )
    .await
    {
        Ok(job) => job_response(job),
        Err(response) => response,
    }
}

#[utoipa::path(
    post,
    path = "/admin/data-governance/tenant/offboarding",
    tag = "data_governance",
    responses(
        (status = 202, description = "Tenant frozen and durable offboarding job queued", body = GovernanceJobView),
        (status = 401, description = "Admin authentication failed"),
        (status = 403, description = "Owner and strong authentication required"),
        (status = 409, description = "Durable job blocked by legal hold", body = GovernanceJobView),
        (status = 503, description = "Governance or residency state unavailable")
    )
)]
pub async fn start_tenant_offboarding(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let context = match authorize(&state, &headers, AdminAction::TenantOffboard).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    match start_job(
        &state,
        &context,
        GovernanceJobKind::TenantOffboarding,
        context.admin.tenant_id().to_string(),
        1,
    )
    .await
    {
        Ok(job) => job_response(job),
        Err(response) => response,
    }
}

#[utoipa::path(
    get,
    path = "/admin/data-governance/jobs/{job_id}",
    tag = "data_governance",
    params(("job_id" = String, Path)),
    responses(
        (status = 200, description = "Redacted durable governance job", body = GovernanceJobView),
        (status = 401, description = "Admin authentication failed"),
        (status = 403, description = "Owner and strong authentication required"),
        (status = 404, description = "Job absent in this tenant"),
        (status = 503, description = "Governance or residency state unavailable")
    )
)]
pub async fn get_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Response {
    let context = match authorize(&state, &headers, AdminAction::DataErase).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    match state
        .governance
        .get_job(context.admin.tenant_id(), &job_id)
        .await
    {
        Ok(Some(job)) => {
            if let Err(response) = audit_job_status(&state, &job).await {
                return response;
            }
            Json(GovernanceJobView::from(job)).into_response()
        }
        Ok(None) => error(StatusCode::NOT_FOUND, "not_found", "Job was not found"),
        Err(store_error_value) => store_error(store_error_value),
    }
}

#[utoipa::path(
    get,
    path = "/admin/data-governance/jobs/{job_id}/evidence",
    tag = "data_governance",
    params(("job_id" = String, Path)),
    responses(
        (status = 200, description = "Latest immutable completion evidence", body = GovernanceEvidenceRecord),
        (status = 401, description = "Admin authentication failed"),
        (status = 403, description = "Owner and strong authentication required"),
        (status = 404, description = "Completion evidence is not available"),
        (status = 503, description = "Governance or residency state unavailable")
    )
)]
pub async fn get_evidence(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Response {
    let context = match authorize(&state, &headers, AdminAction::DataErase).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let job = match state
        .governance
        .get_job(context.admin.tenant_id(), &job_id)
        .await
    {
        Ok(Some(job)) => job,
        Ok(None) => return error(StatusCode::NOT_FOUND, "not_found", "Job was not found"),
        Err(store_error_value) => return store_error(store_error_value),
    };
    if let Err(response) = audit_job_operation(
        &state,
        &job,
        "governance.job.evidence",
        crate::security_event::SecurityEventOutcome::Success,
    )
    .await
    {
        return response;
    }
    match state
        .governance
        .latest_evidence(context.admin.tenant_id(), &job_id)
        .await
    {
        Ok(Some(evidence)) if evidence.verify_hash() => Json(evidence).into_response(),
        Ok(Some(_)) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "governance_evidence_invalid",
            "Completion evidence failed integrity verification",
        ),
        Ok(None) => error(
            StatusCode::NOT_FOUND,
            "not_found",
            "Completion evidence is not available",
        ),
        Err(store_error_value) => store_error(store_error_value),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContinuationTokenPayload {
    version: u8,
    issuer: String,
    audience: String,
    tenant_id: String,
    job_id: String,
    action: GovernanceContinuationAction,
    capability_revision: u64,
    jti: String,
    issued_at: i64,
    expires_at: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct IssueContinuationTokenRequest {
    pub action: GovernanceContinuationAction,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct IssuedContinuationToken {
    pub token_type: String,
    pub continuation_token: String,
    pub action: GovernanceContinuationAction,
    pub expires_in: i64,
    pub expires_at: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateContinuationRequest {
    pub expected_revision: u64,
    #[serde(default)]
    pub rotate_resume: bool,
    #[serde(default)]
    pub rotate_read: bool,
    pub resume_enabled: Option<bool>,
    pub read_enabled: Option<bool>,
}

fn continuation_action_name(action: GovernanceContinuationAction) -> &'static str {
    match action {
        GovernanceContinuationAction::Status => "status",
        GovernanceContinuationAction::Resume => "resume",
        GovernanceContinuationAction::Evidence => "evidence",
    }
}

fn resume_state_allowed(job: &GovernanceJobRecord) -> bool {
    matches!(
        job.state,
        GovernanceJobState::Queued | GovernanceJobState::Running | GovernanceJobState::Retryable
    )
}

fn authorize_control_target(
    state: &AppState,
    headers: &HeaderMap,
    tenant_id: &str,
) -> Result<(), Response> {
    let agent_auth_discovery::Form::Saas { control_host, .. } = &state.form else {
        return Err(error(StatusCode::NOT_FOUND, "not_found", "Not found"));
    };
    if crate::hostutil::issuer_host(headers).as_deref() != Some(control_host.as_str())
        || !state
            .saas_tenants
            .iter()
            .any(|configured| configured == tenant_id)
    {
        return Err(error(StatusCode::NOT_FOUND, "not_found", "Not found"));
    }
    let local_region = state.region.local_region();
    if !state.governance_config.admits(tenant_id, local_region)
        || (state.region.is_multi_region() && state.region.active_revision() == 0)
    {
        return Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "governance_region_inactive",
            "The governance control plane is unavailable in this Region",
        ));
    }
    Ok(())
}

fn sign_continuation_token(
    key: &[u8],
    payload: &ContinuationTokenPayload,
) -> Result<String, Response> {
    let payload = serde_json::to_vec(payload).map_err(|_| {
        error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "governance_state_error",
            "Continuation token serialization failed",
        )
    })?;
    let body = URL_SAFE_NO_PAD.encode(payload);
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(b"governance-continuation:v1\0");
    mac.update(body.as_bytes());
    Ok(format!(
        "{body}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    ))
}

fn verify_continuation_token(
    key: &[u8],
    encoded: &str,
    tenant_id: &str,
    job_id: &str,
    action: GovernanceContinuationAction,
    now: i64,
) -> Result<ContinuationTokenPayload, ()> {
    if encoded.len() > 4_096 {
        return Err(());
    }
    let (body, signature) = encoded.split_once('.').ok_or(())?;
    if body.is_empty() || signature.is_empty() || signature.contains('.') {
        return Err(());
    }
    let signature = URL_SAFE_NO_PAD.decode(signature).map_err(|_| ())?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| ())?;
    mac.update(b"governance-continuation:v1\0");
    mac.update(body.as_bytes());
    mac.verify_slice(&signature).map_err(|_| ())?;
    let payload: ContinuationTokenPayload =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(body).map_err(|_| ())?).map_err(|_| ())?;
    let valid_jti = (20..=128).contains(&payload.jti.len())
        && payload
            .jti
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if payload.version != CONTINUATION_TOKEN_VERSION
        || payload.issuer != CONTINUATION_TOKEN_ISSUER
        || payload.audience != CONTINUATION_TOKEN_AUDIENCE
        || payload.tenant_id != tenant_id
        || payload.job_id != job_id
        || payload.action != action
        || payload.capability_revision == 0
        || !valid_jti
        || payload.issued_at > now.saturating_add(30)
        || payload.expires_at <= now
        || payload.expires_at <= payload.issued_at
        || payload.expires_at.saturating_sub(payload.issued_at) > CONTINUATION_TOKEN_TTL_SECS
    {
        return Err(());
    }
    Ok(payload)
}

fn continuation_jti_digest(key: &[u8], jti: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(b"governance-continuation-jti:v1\0");
    mac.update(jti.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn continuation_auth_error() -> Response {
    error(
        StatusCode::UNAUTHORIZED,
        "invalid_continuation_token",
        "A valid job-bound continuation token is required",
    )
}

async fn continuation_job(
    state: &AppState,
    headers: &HeaderMap,
    tenant_id: &str,
    job_id: &str,
    action: GovernanceContinuationAction,
) -> Result<
    (
        ContinuationTokenPayload,
        GovernanceContinuationRecord,
        GovernanceJobRecord,
    ),
    Response,
> {
    authorize_control_target(state, headers, tenant_id)?;
    let token = crate::tenant_admin::bearer(headers).ok_or_else(continuation_auth_error)?;
    let now = crate::current_unix_secs();
    let payload = verify_continuation_token(
        &state.governance_hmac_key,
        &token,
        tenant_id,
        job_id,
        action,
        now,
    )
    .map_err(|()| continuation_auth_error())?;
    let continuation = state
        .governance
        .get_continuation(tenant_id, job_id)
        .await
        .map_err(store_error)?
        .ok_or_else(continuation_auth_error)?;
    let job = state
        .governance
        .get_job(tenant_id, job_id)
        .await
        .map_err(store_error)?
        .ok_or_else(continuation_auth_error)?;
    if job.kind != GovernanceJobKind::TenantOffboarding
        || job.tenant_revision != continuation.tenant_revision
        || !continuation.action_enabled(action)
        || continuation.action_revision(action) != payload.capability_revision
        || (action == GovernanceContinuationAction::Resume && !resume_state_allowed(&job))
    {
        return Err(continuation_auth_error());
    }
    Ok((payload, continuation, job))
}

async fn audit_continuation_use(
    state: &AppState,
    tenant_id: &str,
    job_id: &str,
    action: GovernanceContinuationAction,
    outcome: crate::security_event::SecurityEventOutcome,
) -> Result<(), Response> {
    let event = AppState::prepare_security_event(
        crate::security_event::SecurityEventDraft::new(
            tenant_id,
            crate::security_event::SecurityActor::admin("platform-continuation"),
            Some(crate::security_event::SecuritySubject::tenant(tenant_id)),
            crate::security_event::SecurityEventCategory::Administration,
            format!(
                "governance.continuation.{}",
                continuation_action_name(action)
            ),
            outcome,
        )
        .correlated(crate::security_event::SecurityEventCorrelation {
            operation_id: Some(job_id.to_string()),
            ..Default::default()
        }),
    )
    .ok_or_else(|| {
        error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "governance_audit_invalid",
            "Governance audit event was invalid",
        )
    })?;
    crate::governance_worker::extend_retention_for_audit(
        state,
        tenant_id,
        job_id,
        event.occurred_at,
    )
    .await
    .map_err(store_error)?;
    state.record_prepared_security_event(event).await;
    Ok(())
}

#[utoipa::path(
    post,
    path = "/admin/control/data-governance/tenants/{tenant_id}/jobs/{job_id}/continuation-tokens",
    tag = "data_governance",
    params(("tenant_id" = String, Path), ("job_id" = String, Path)),
    request_body = IssueContinuationTokenRequest,
    responses(
        (status = 201, description = "Short-lived job-bound continuation token", body = IssuedContinuationToken),
        (status = 401, description = "Platform authentication failed"),
        (status = 403, description = "Explicit governance confirmation required"),
        (status = 404, description = "Unknown tenant, job, or non-control host"),
        (status = 409, description = "Requested continuation action is disabled")
    )
)]
pub async fn issue_continuation_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((tenant_id, job_id)): Path<(String, String)>,
    Json(request): Json<IssueContinuationTokenRequest>,
) -> Response {
    if let Err(response) = authorize_control_target(&state, &headers, &tenant_id) {
        return response;
    }
    if let Err(response) = authenticate_platform_governance(
        &state,
        &headers,
        &tenant_id,
        "governance.continuation.issue",
    )
    .await
    {
        if let Ok(Some(job)) = state.governance.get_job(&tenant_id, &job_id).await {
            if let Err(audit_error) = audit_job_operation(
                &state,
                &job,
                "governance.continuation.issue",
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await
            {
                return audit_error;
            }
        }
        return response;
    }
    let continuation = match state.governance.get_continuation(&tenant_id, &job_id).await {
        Ok(Some(record)) => record,
        Ok(None) => {
            return error(
                StatusCode::NOT_FOUND,
                "not_found",
                "Continuation authority was not found",
            )
        }
        Err(store_error_value) => return store_error(store_error_value),
    };
    let job = match state.governance.get_job(&tenant_id, &job_id).await {
        Ok(Some(job))
            if job.kind == GovernanceJobKind::TenantOffboarding
                && job.tenant_revision == continuation.tenant_revision =>
        {
            job
        }
        Ok(_) => return error(StatusCode::NOT_FOUND, "not_found", "Job was not found"),
        Err(store_error_value) => return store_error(store_error_value),
    };
    if let Err(response) = audit_job_operation(
        &state,
        &job,
        "governance.continuation.issue",
        crate::security_event::SecurityEventOutcome::Success,
    )
    .await
    {
        return response;
    }
    if !continuation.action_enabled(request.action)
        || (request.action == GovernanceContinuationAction::Resume
            && (!resume_state_allowed(&job)
                || !state
                    .governance_config
                    .admits_destructive_governance(&tenant_id, state.region.local_region())))
    {
        return error(
            StatusCode::CONFLICT,
            "continuation_action_disabled",
            "The requested continuation action is not currently available",
        );
    }
    let now = crate::current_unix_secs();
    let expires_at = now.saturating_add(CONTINUATION_TOKEN_TTL_SECS);
    let mut jti = [0_u8; 24];
    rand::thread_rng().fill_bytes(&mut jti);
    let payload = ContinuationTokenPayload {
        version: CONTINUATION_TOKEN_VERSION,
        issuer: CONTINUATION_TOKEN_ISSUER.into(),
        audience: CONTINUATION_TOKEN_AUDIENCE.into(),
        tenant_id,
        job_id,
        action: request.action,
        capability_revision: continuation.action_revision(request.action),
        jti: URL_SAFE_NO_PAD.encode(jti),
        issued_at: now,
        expires_at,
    };
    let token = match sign_continuation_token(&state.governance_hmac_key, &payload) {
        Ok(token) => token,
        Err(response) => return response,
    };
    let mut response = (
        StatusCode::CREATED,
        Json(IssuedContinuationToken {
            token_type: "Bearer".into(),
            continuation_token: token,
            action: request.action,
            expires_in: CONTINUATION_TOKEN_TTL_SECS,
            expires_at,
        }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[utoipa::path(
    put,
    path = "/admin/control/data-governance/tenants/{tenant_id}/jobs/{job_id}/continuation",
    tag = "data_governance",
    params(("tenant_id" = String, Path), ("job_id" = String, Path)),
    request_body = UpdateContinuationRequest,
    responses(
        (status = 200, description = "Continuation revisions and enablement", body = GovernanceContinuationRecord),
        (status = 401, description = "Platform authentication failed"),
        (status = 403, description = "Explicit governance confirmation required"),
        (status = 404, description = "Unknown tenant, job, or non-control host"),
        (status = 409, description = "Continuation revision conflict", body = GovernanceContinuationRecord)
    )
)]
pub async fn update_continuation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((tenant_id, job_id)): Path<(String, String)>,
    Json(request): Json<UpdateContinuationRequest>,
) -> Response {
    if let Err(response) = authorize_control_target(&state, &headers, &tenant_id) {
        return response;
    }
    if let Err(response) = authenticate_platform_governance(
        &state,
        &headers,
        &tenant_id,
        "governance.continuation.rotate",
    )
    .await
    {
        if let Ok(Some(job)) = state.governance.get_job(&tenant_id, &job_id).await {
            if let Err(audit_error) = audit_job_operation(
                &state,
                &job,
                "governance.continuation.rotate",
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await
            {
                return audit_error;
            }
        }
        return response;
    }
    let mut record = match state.governance.get_continuation(&tenant_id, &job_id).await {
        Ok(Some(record)) => record,
        Ok(None) => {
            return error(
                StatusCode::NOT_FOUND,
                "not_found",
                "Continuation authority was not found",
            )
        }
        Err(store_error_value) => return store_error(store_error_value),
    };
    if record.revision != request.expected_revision {
        return (StatusCode::CONFLICT, Json(record)).into_response();
    }
    let job = match state.governance.get_job(&tenant_id, &job_id).await {
        Ok(Some(job)) => job,
        Ok(None) => return error(StatusCode::NOT_FOUND, "not_found", "Job was not found"),
        Err(store_error_value) => return store_error(store_error_value),
    };
    if let Err(response) = audit_job_operation(
        &state,
        &job,
        "governance.continuation.rotate",
        crate::security_event::SecurityEventOutcome::Success,
    )
    .await
    {
        return response;
    }
    if request.resume_enabled == Some(true) && !resume_state_allowed(&job) {
        return error(
            StatusCode::CONFLICT,
            "continuation_action_disabled",
            "Destructive resume cannot be enabled for this job state",
        );
    }
    let resume_enabled = request.resume_enabled.unwrap_or(record.resume_enabled);
    let read_enabled = request.read_enabled.unwrap_or(record.read_enabled);
    let resume_changed = request.rotate_resume || resume_enabled != record.resume_enabled;
    let read_changed = request.rotate_read || read_enabled != record.read_enabled;
    if !resume_changed && !read_changed {
        return Json(record).into_response();
    }
    if resume_changed {
        record.resume_revision = match record.resume_revision.checked_add(1) {
            Some(revision) => revision,
            None => {
                return error(
                    StatusCode::CONFLICT,
                    "continuation_revision_exhausted",
                    "Resume continuation revision is exhausted",
                )
            }
        };
    }
    if read_changed {
        record.read_revision = match record.read_revision.checked_add(1) {
            Some(revision) => revision,
            None => {
                return error(
                    StatusCode::CONFLICT,
                    "continuation_revision_exhausted",
                    "Read continuation revision is exhausted",
                )
            }
        };
    }
    record.resume_enabled = resume_enabled;
    record.read_enabled = read_enabled;
    record.updated_at = crate::current_unix_secs();
    match state
        .governance
        .update_continuation(record, request.expected_revision)
        .await
    {
        Ok(GovernanceContinuationUpdateOutcome::Stored(record)) => Json(record).into_response(),
        Ok(GovernanceContinuationUpdateOutcome::Conflict(record)) => {
            (StatusCode::CONFLICT, Json(record)).into_response()
        }
        Err(store_error_value) => store_error(store_error_value),
    }
}

#[utoipa::path(
    get,
    path = "/admin/control/data-governance/tenants/{tenant_id}/jobs/{job_id}",
    tag = "data_governance",
    params(("tenant_id" = String, Path), ("job_id" = String, Path)),
    responses(
        (status = 200, description = "Redacted offboarding job", body = GovernanceJobView),
        (status = 401, description = "Job-bound status token rejected"),
        (status = 404, description = "Unknown tenant, job, or non-control host")
    )
)]
pub async fn control_get_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((tenant_id, job_id)): Path<(String, String)>,
) -> Response {
    match continuation_job(
        &state,
        &headers,
        &tenant_id,
        &job_id,
        GovernanceContinuationAction::Status,
    )
    .await
    {
        Ok((_, _, _)) => {
            if let Err(response) = audit_continuation_use(
                &state,
                &tenant_id,
                &job_id,
                GovernanceContinuationAction::Status,
                crate::security_event::SecurityEventOutcome::Success,
            )
            .await
            {
                return response;
            }
            match state.governance.get_job(&tenant_id, &job_id).await {
                Ok(Some(job)) => Json(GovernanceJobView::from(job)).into_response(),
                Ok(None) => error(StatusCode::NOT_FOUND, "not_found", "Job was not found"),
                Err(store_error_value) => store_error(store_error_value),
            }
        }
        Err(response) => {
            if let Err(audit_error) = audit_continuation_use(
                &state,
                &tenant_id,
                &job_id,
                GovernanceContinuationAction::Status,
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await
            {
                audit_error
            } else {
                response
            }
        }
    }
}

#[utoipa::path(
    post,
    path = "/admin/control/data-governance/tenants/{tenant_id}/jobs/{job_id}/resume",
    tag = "data_governance",
    params(("tenant_id" = String, Path), ("job_id" = String, Path)),
    responses(
        (status = 202, description = "Current job revision queued", body = GovernanceJobView),
        (status = 401, description = "Job-bound resume token rejected"),
        (status = 409, description = "Resume token replayed or job no longer resumable"),
        (status = 503, description = "Governance queue unavailable")
    )
)]
pub async fn control_resume_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((tenant_id, job_id)): Path<(String, String)>,
) -> Response {
    let (payload, _, _) = match continuation_job(
        &state,
        &headers,
        &tenant_id,
        &job_id,
        GovernanceContinuationAction::Resume,
    )
    .await
    {
        Ok(result) => result,
        Err(response) => {
            if let Err(audit_error) = audit_continuation_use(
                &state,
                &tenant_id,
                &job_id,
                GovernanceContinuationAction::Resume,
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await
            {
                return audit_error;
            }
            return response;
        }
    };
    if !state
        .governance_config
        .admits_destructive_governance(&tenant_id, state.region.local_region())
    {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "governance_region_inactive",
            "Destructive governance is paused outside the designated governance Region",
        );
    }
    let digest = continuation_jti_digest(&state.governance_hmac_key, &payload.jti);
    match state
        .governance
        .consume_continuation_resume(
            &tenant_id,
            &job_id,
            &digest,
            payload.capability_revision,
            payload.expires_at,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            if let Err(response) = audit_continuation_use(
                &state,
                &tenant_id,
                &job_id,
                GovernanceContinuationAction::Resume,
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await
            {
                return response;
            }
            return error(
                StatusCode::CONFLICT,
                "continuation_replayed_or_revoked",
                "The resume token was already used or has been revoked",
            );
        }
        Err(store_error_value) => return store_error(store_error_value),
    }
    let job = match state.governance.get_job(&tenant_id, &job_id).await {
        Ok(Some(job)) if resume_state_allowed(&job) => job,
        Ok(_) => {
            return error(
                StatusCode::CONFLICT,
                "job_not_resumable",
                "The governance job no longer accepts destructive resume",
            )
        }
        Err(store_error_value) => return store_error(store_error_value),
    };
    if let Err(store_error_value) = state
        .governance_jobs
        .enqueue(GovernanceJobCommand {
            tenant_id: tenant_id.clone(),
            job_id: job_id.clone(),
            expected_revision: job.revision,
            failure_attempt: 0,
        })
        .await
    {
        return store_error(store_error_value);
    }
    if let Err(response) = audit_continuation_use(
        &state,
        &tenant_id,
        &job_id,
        GovernanceContinuationAction::Resume,
        crate::security_event::SecurityEventOutcome::Success,
    )
    .await
    {
        return response;
    }
    job_response(job)
}

#[utoipa::path(
    get,
    path = "/admin/control/data-governance/tenants/{tenant_id}/jobs/{job_id}/evidence",
    tag = "data_governance",
    params(("tenant_id" = String, Path), ("job_id" = String, Path)),
    responses(
        (status = 200, description = "Latest immutable completion evidence", body = GovernanceEvidenceRecord),
        (status = 401, description = "Job-bound evidence token rejected"),
        (status = 404, description = "Completion evidence is not available")
    )
)]
pub async fn control_get_evidence(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((tenant_id, job_id)): Path<(String, String)>,
) -> Response {
    if let Err(response) = continuation_job(
        &state,
        &headers,
        &tenant_id,
        &job_id,
        GovernanceContinuationAction::Evidence,
    )
    .await
    {
        if let Err(audit_error) = audit_continuation_use(
            &state,
            &tenant_id,
            &job_id,
            GovernanceContinuationAction::Evidence,
            crate::security_event::SecurityEventOutcome::Denied,
        )
        .await
        {
            return audit_error;
        }
        return response;
    }
    let response = match state.governance.latest_evidence(&tenant_id, &job_id).await {
        Ok(Some(evidence)) if evidence.verify_hash() => Json(evidence).into_response(),
        Ok(Some(_)) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "governance_evidence_invalid",
            "Completion evidence failed integrity verification",
        ),
        Ok(None) => error(
            StatusCode::NOT_FOUND,
            "not_found",
            "Completion evidence is not available",
        ),
        Err(store_error_value) => store_error(store_error_value),
    };
    if let Err(audit_error) = audit_continuation_use(
        &state,
        &tenant_id,
        &job_id,
        GovernanceContinuationAction::Evidence,
        if response.status().is_success() {
            crate::security_event::SecurityEventOutcome::Success
        } else {
            crate::security_event::SecurityEventOutcome::Denied
        },
    )
    .await
    {
        audit_error
    } else {
        response
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CursorPayload {
    version: u8,
    tenant_id: String,
    resource: String,
    section: String,
    region_revision: u64,
    expires_at: i64,
    through: i64,
    inner: Option<String>,
}

fn encode_cursor(key: &[u8], payload: CursorPayload) -> String {
    let body = serde_json::to_vec(&payload).expect("cursor payload is serializable");
    let body = URL_SAFE_NO_PAD.encode(body);
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(b"governance-cursor:v1\0");
    mac.update(body.as_bytes());
    format!(
        "{body}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

#[allow(clippy::too_many_arguments)]
fn decode_cursor(
    key: &[u8],
    encoded: &str,
    tenant_id: &str,
    resource: &str,
    section: &str,
    region_revision: u64,
    now: i64,
) -> Result<CursorPayload, ()> {
    if encoded.len() > 8_192 {
        return Err(());
    }
    let (body, signature) = encoded.split_once('.').ok_or(())?;
    let signature = URL_SAFE_NO_PAD.decode(signature).map_err(|_| ())?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| ())?;
    mac.update(b"governance-cursor:v1\0");
    mac.update(body.as_bytes());
    mac.verify_slice(&signature).map_err(|_| ())?;
    let payload: CursorPayload =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(body).map_err(|_| ())?).map_err(|_| ())?;
    if payload.version != EXPORT_CURSOR_VERSION
        || payload.tenant_id != tenant_id
        || payload.resource != resource
        || payload.section != section
        || payload.region_revision != region_revision
        || payload.expires_at <= now
    {
        return Err(());
    }
    Ok(payload)
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_policy, put_policy))
        .routes(routes!(export_user))
        .routes(routes!(create_tenant_export))
        .routes(routes!(get_tenant_export))
        .routes(routes!(start_user_erasure))
        .routes(routes!(start_tenant_offboarding))
        .routes(routes!(get_job))
        .routes(routes!(get_evidence))
        .routes(routes!(issue_continuation_token))
        .routes(routes!(update_continuation))
        .routes(routes!(control_get_job))
        .routes(routes!(control_resume_job))
        .routes(routes!(control_get_evidence))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::to_bytes,
        extract::{Path, Query, State},
        http::{header, HeaderMap, HeaderValue, StatusCode},
        response::Response,
    };
    use serde_json::Value;

    use crate::{
        ports::UsersStore,
        security_event::{
            SecurityActor, SecurityEvent, SecurityEventCategory, SecurityEventCorrelation,
            SecurityEventOutcome, SecuritySubject, SECURITY_EVENT_SCHEMA_VERSION,
        },
    };

    fn test_event(event_id: String, occurred_at: i64, user_id: Option<&str>) -> SecurityEvent {
        SecurityEvent {
            schema_version: SECURITY_EVENT_SCHEMA_VERSION.into(),
            event_id,
            occurred_at,
            tenant_id: "default".into(),
            actor: SecurityActor::system("data-governance-pagination-test"),
            subject: user_id
                .map_or_else(|| SecuritySubject::tenant("default"), SecuritySubject::user),
            category: SecurityEventCategory::Administration,
            action: "data.export.pagination.test".into(),
            outcome: SecurityEventOutcome::Success,
            correlation: SecurityEventCorrelation::default(),
        }
    }

    async fn call_user_export(
        state: &AppState,
        user_id: &str,
        event_limit: usize,
        event_cursor: Option<String>,
    ) -> (StatusCode, Value) {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("localhost"));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer dev-admin-token-not-for-prod"),
        );
        headers.insert(
            "x-agent-auth-purpose",
            HeaderValue::from_static("privacy-request:pagination-test"),
        );
        headers.insert("x-agent-auth-confirm", HeaderValue::from_static("true"));

        let response: Response = export_user(
            State(state.clone()),
            headers,
            Path(user_id.to_string()),
            Query(UserExportQuery {
                event_limit: Some(event_limit),
                event_cursor,
            }),
        )
        .await;
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value = serde_json::from_slice(&body).unwrap();
        (status, value)
    }

    fn event_ids(response: &Value) -> Vec<String> {
        response["security_events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|stored| stored["event"]["event_id"].as_str().unwrap().to_string())
            .collect()
    }

    fn replica_verification_job(job_id: &str, now: i64) -> GovernanceJobRecord {
        GovernanceJobRecord {
            job_id: job_id.into(),
            tenant_id: "default".into(),
            kind: GovernanceJobKind::UserErasure,
            target_id: Some(format!("user:{job_id}@example.com")),
            target_aliases: Vec::new(),
            verification_target: None,
            active_child_job_id: None,
            processed_records: 0,
            tenant_cleanup_stage: crate::governance::TenantCleanupStage::Users,
            target_epoch: 1,
            state: GovernanceJobState::Running,
            phase: GovernanceJobPhase::ReplicaVerification,
            policy_revision: 0,
            tenant_revision: 0,
            revision: 1,
            created_at: now.saturating_sub(20),
            updated_at: now.saturating_sub(10),
            primary_erasure_at: Some(now.saturating_sub(10)),
            retention_anchor_at: Some(now.saturating_sub(10)),
            retention_until: None,
            evidence_revision: 0,
            error_class: None,
        }
    }

    #[tokio::test]
    async fn http_hold_settlement_waits_until_internal_lease_is_released() {
        let state = AppState::dev("localhost");
        let candidate = GovernanceJobRecord {
            job_id: "job-http-hold-drain".into(),
            tenant_id: "default".into(),
            kind: GovernanceJobKind::UserErasure,
            target_id: Some("user:http-hold-drain".into()),
            target_aliases: Vec::new(),
            verification_target: None,
            active_child_job_id: None,
            processed_records: 0,
            tenant_cleanup_stage: crate::governance::TenantCleanupStage::Users,
            target_epoch: 1,
            state: GovernanceJobState::Queued,
            phase: GovernanceJobPhase::IntentRecorded,
            policy_revision: 0,
            tenant_revision: 0,
            revision: 1,
            created_at: 100,
            updated_at: 100,
            primary_erasure_at: None,
            retention_anchor_at: None,
            retention_until: None,
            evidence_revision: 0,
            error_class: None,
        };
        let job = match state
            .governance
            .start_or_resume_job(candidate, 0, false)
            .await
            .unwrap()
        {
            GovernanceJobStartOutcome::Stored(job) => job,
            outcome => panic!("unexpected job start: {outcome:?}"),
        };
        let lease = match state
            .governance
            .claim_job_lease(
                &job.tenant_id,
                &job.job_id,
                job.revision,
                "http-hold-drain-lease",
                100,
                200,
            )
            .await
            .unwrap()
        {
            crate::governance::GovernanceJobLeaseOutcome::Acquired(lease) => lease,
            outcome => panic!("unexpected lease outcome: {outcome:?}"),
        };
        let mut enabling = GovernancePolicyRecord::default_for(&job.tenant_id);
        enabling.legal_hold = LegalHoldState::Enabling;
        enabling.legal_hold_reason = Some("case-http-hold-drain".into());
        let enabling = match state.governance.put_policy(enabling, 0).await.unwrap() {
            GovernancePolicyPutOutcome::Stored(policy) => policy,
            outcome => panic!("unexpected policy outcome: {outcome:?}"),
        };

        let still_enabling = settle_enabling_policy(&state, enabling.clone(), 101)
            .await
            .unwrap();
        assert_eq!(still_enabling.legal_hold, LegalHoldState::Enabling);
        assert_eq!(still_enabling.revision, enabling.revision);

        assert!(matches!(
            state
                .governance
                .release_job_lease(&job.tenant_id, lease.destructive_fence(None))
                .await
                .unwrap(),
            crate::governance::GovernanceJobLeaseOutcome::Released
        ));
        let enabled = settle_enabling_policy(&state, enabling, 102).await.unwrap();
        assert_eq!(enabled.legal_hold, LegalHoldState::Enabled);
        assert_eq!(enabled.revision, 2);
    }

    #[tokio::test]
    async fn suppressed_blocked_erasure_rebinds_to_the_current_policy() {
        let state = AppState::dev("localhost");
        let now = crate::current_unix_secs();
        let user_id = "user:suppressed-resume@example.com";
        state
            .users
            .create_or_get_by_email("", "suppressed-resume@example.com", user_id, now)
            .await
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("localhost"));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer dev-admin-token-not-for-prod"),
        );
        headers.insert(
            "x-agent-auth-purpose",
            HeaderValue::from_static("privacy-request:suppressed-resume-test"),
        );
        headers.insert("x-agent-auth-confirm", HeaderValue::from_static("true"));

        let started = start_user_erasure(
            State(state.clone()),
            headers.clone(),
            Path(user_id.to_string()),
        )
        .await;
        assert_eq!(started.status(), StatusCode::ACCEPTED);
        let body = to_bytes(started.into_body(), usize::MAX).await.unwrap();
        let started: Value = serde_json::from_slice(&body).unwrap();
        let job_id = started["job_id"].as_str().unwrap();
        for _ in 0..4 {
            crate::governance_worker::advance_user_erasure_once(&state, "default", job_id, now)
                .await
                .unwrap();
        }

        let mut held = GovernancePolicyRecord::default_for("default");
        held.legal_hold = LegalHoldState::Enabled;
        held.legal_hold_reason = Some("suppressed-resume-test".into());
        held.updated_at = now;
        let held = match state.governance.put_policy(held, 0).await.unwrap() {
            GovernancePolicyPutOutcome::Stored(policy) => policy,
            outcome => panic!("unexpected policy outcome: {outcome:?}"),
        };
        let blocked =
            crate::governance_worker::advance_user_erasure_once(&state, "default", job_id, now)
                .await
                .unwrap();
        assert_eq!(blocked.state, GovernanceJobState::BlockedLegalHold);
        assert_eq!(blocked.policy_revision, held.revision);

        let mut released = held;
        released.legal_hold = LegalHoldState::Disabled;
        released.legal_hold_reason = None;
        let released = match state
            .governance
            .put_policy(released.clone(), released.revision)
            .await
            .unwrap()
        {
            GovernancePolicyPutOutcome::Stored(policy) => policy,
            outcome => panic!("unexpected policy outcome: {outcome:?}"),
        };
        let resumed =
            start_user_erasure(State(state.clone()), headers, Path(user_id.to_string())).await;
        assert_eq!(resumed.status(), StatusCode::ACCEPTED);

        let current = state
            .governance
            .get_job("default", job_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.job_id, job_id);
        assert_eq!(current.state, GovernanceJobState::Queued);
        assert_eq!(current.phase, GovernanceJobPhase::ReplicaVerification);
        assert_eq!(current.policy_revision, released.revision);
    }

    #[tokio::test]
    async fn job_audit_extends_to_the_exact_persisted_event_timestamp() {
        let state = AppState::dev("localhost");
        let now = crate::current_unix_secs();
        let candidate = GovernanceJobRecord {
            job_id: "job-audit-anchor".into(),
            tenant_id: "default".into(),
            kind: GovernanceJobKind::UserErasure,
            target_id: Some("user:audit-anchor@example.com".into()),
            target_aliases: Vec::new(),
            verification_target: None,
            active_child_job_id: None,
            processed_records: 0,
            tenant_cleanup_stage: crate::governance::TenantCleanupStage::Users,
            target_epoch: 1,
            state: GovernanceJobState::RetentionPending,
            phase: GovernanceJobPhase::RetentionVerification,
            policy_revision: 0,
            tenant_revision: 0,
            revision: 1,
            created_at: now.saturating_sub(20),
            updated_at: now.saturating_sub(10),
            primary_erasure_at: Some(now.saturating_sub(10)),
            retention_anchor_at: Some(now.saturating_sub(10)),
            retention_until: None,
            evidence_revision: 0,
            error_class: None,
        };
        let job = match state
            .governance
            .start_or_resume_job(candidate, 0, false)
            .await
            .unwrap()
        {
            GovernanceJobStartOutcome::Stored(job) => job,
            outcome => panic!("unexpected job start: {outcome:?}"),
        };

        audit_job_operation(
            &state,
            &job,
            "governance.job.audit_anchor_test",
            SecurityEventOutcome::Success,
        )
        .await
        .unwrap();

        let event = state
            .security_events
            .list_by_tenant(
                "default",
                now.saturating_sub(1),
                crate::current_unix_secs().saturating_add(1),
                10,
            )
            .await
            .unwrap()
            .into_iter()
            .find(|stored| stored.event.action == "governance.job.audit_anchor_test")
            .expect("job audit event persisted")
            .event;
        let updated = state
            .governance
            .get_job("default", "job-audit-anchor")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.retention_anchor_at, Some(event.occurred_at));
        assert_eq!(
            event.correlation.operation_id.as_deref(),
            Some("job-audit-anchor")
        );
    }

    #[tokio::test]
    async fn job_status_audit_does_not_advance_the_worker_revision() {
        let state = AppState::dev("localhost");
        let now = crate::current_unix_secs();
        let candidate = replica_verification_job("job-status-read", now);
        let stored = match state
            .governance
            .start_or_resume_job(candidate, 0, false)
            .await
            .unwrap()
        {
            GovernanceJobStartOutcome::Stored(job) => job,
            outcome => panic!("unexpected job start: {outcome:?}"),
        };
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("localhost"));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer dev-admin-token-not-for-prod"),
        );
        headers.insert(
            "x-agent-auth-purpose",
            HeaderValue::from_static("privacy-request:status-test"),
        );
        headers.insert("x-agent-auth-confirm", HeaderValue::from_static("true"));

        let response = get_job(State(state.clone()), headers, Path(stored.job_id.clone())).await;
        assert_eq!(response.status(), StatusCode::OK);
        let current = state
            .governance
            .get_job("default", &stored.job_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.revision, stored.revision);
        assert_eq!(current.retention_anchor_at, stored.retention_anchor_at);
        assert!(state
            .security_events
            .list_by_tenant(
                "default",
                now.saturating_sub(1),
                crate::current_unix_secs().saturating_add(1),
                10,
            )
            .await
            .unwrap()
            .iter()
            .any(|event| event.event.action == "governance.job.status"));
    }

    #[tokio::test]
    async fn worker_dispatch_reloads_revision_after_retention_audit() {
        let state = AppState::dev("localhost");
        let now = crate::current_unix_secs();
        let candidate = replica_verification_job("job-dispatch-reload", now);
        let stored = match state
            .governance
            .start_or_resume_job(candidate, 0, false)
            .await
            .unwrap()
        {
            GovernanceJobStartOutcome::Stored(job) => job,
            outcome => panic!("unexpected job start: {outcome:?}"),
        };

        audit_job_operation(
            &state,
            &stored,
            "governance.job.dispatch_reload_test",
            SecurityEventOutcome::Success,
        )
        .await
        .unwrap();
        let latest = reload_and_enqueue_job(&state, "default", &stored.job_id)
            .await
            .unwrap();
        assert!(latest.revision > stored.revision);
        let commands = match state.governance_jobs.as_ref() {
            crate::governance::GovernanceJobQueueImpl::Memory(queue) => queue.commands().await,
            _ => panic!("dev state must use the in-memory governance queue"),
        };
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].job_id, stored.job_id);
        assert_eq!(commands[0].expected_revision, latest.revision);
    }

    #[tokio::test]
    async fn user_event_cursor_resumes_within_a_scanned_page_without_skips() {
        let state = AppState::dev("localhost");
        let now = crate::current_unix_secs();
        let user_id = "pagination-user";
        state
            .users
            .create_or_get_by_email("", "pagination@example.com", user_id, now)
            .await
            .unwrap();

        let expected = (0..6)
            .map(|index| format!("evt_matching_{index:04}"))
            .collect::<Vec<_>>();
        for (index, event_id) in expected.iter().enumerate() {
            state
                .security_events
                .put(&test_event(
                    event_id.clone(),
                    now - 10 - index as i64,
                    Some(user_id),
                ))
                .await
                .unwrap();
        }
        state
            .security_events
            .put(&test_event(
                "evt_after_snapshot".into(),
                now + 60,
                Some(user_id),
            ))
            .await
            .unwrap();

        let mut cursor = None;
        let mut actual = Vec::new();
        for page_index in 0..3 {
            let (status, response) = call_user_export(&state, user_id, 2, cursor.take()).await;
            assert_eq!(status, StatusCode::OK);
            actual.extend(event_ids(&response));
            cursor = response["next_event_cursor"]
                .as_str()
                .map(ToString::to_string);
            assert_eq!(cursor.is_some(), page_index < 2);
        }

        assert_eq!(actual, expected);
        assert_eq!(
            actual.iter().collect::<BTreeSet<_>>().len(),
            actual.len(),
            "filtered pagination must not repeat events"
        );
        assert!(!actual
            .iter()
            .any(|event_id| event_id == "evt_after_snapshot"));
    }

    #[tokio::test]
    async fn user_event_export_fills_a_page_across_sparse_store_pages() {
        let state = AppState::dev("localhost");
        let now = crate::current_unix_secs();
        let user_id = "sparse-pagination-user";
        state
            .users
            .create_or_get_by_email("", "sparse-pagination@example.com", user_id, now)
            .await
            .unwrap();

        let target_indexes = BTreeSet::from([10usize, 510, 1000]);
        for index in 0..1005 {
            let target = target_indexes.contains(&index);
            state
                .security_events
                .put(&test_event(
                    format!("evt_sparse_{index:04}"),
                    now - 10 - index as i64,
                    target.then_some(user_id),
                ))
                .await
                .unwrap();
        }

        let (status, first) = call_user_export(&state, user_id, 2, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            event_ids(&first),
            vec!["evt_sparse_0010", "evt_sparse_0510"]
        );
        let cursor = first["next_event_cursor"]
            .as_str()
            .expect("a later matching event remains")
            .to_string();

        let (status, second) = call_user_export(&state, user_id, 2, Some(cursor)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(event_ids(&second), vec!["evt_sparse_1000"]);
        assert!(second.get("next_event_cursor").is_none());
    }

    #[test]
    fn cursor_is_bound_to_tenant_resource_section_and_revision() {
        let key = b"governance-cursor-test-key";
        let encoded = encode_cursor(
            key,
            CursorPayload {
                version: EXPORT_CURSOR_VERSION,
                tenant_id: "t1".into(),
                resource: "export-1".into(),
                section: "users".into(),
                region_revision: 7,
                expires_at: 200,
                through: 0,
                inner: Some("next".into()),
            },
        );
        assert!(decode_cursor(key, &encoded, "t1", "export-1", "users", 7, 100).is_ok());
        assert!(decode_cursor(key, &encoded, "t2", "export-1", "users", 7, 100).is_err());
        assert!(decode_cursor(key, &encoded, "t1", "export-1", "clients", 7, 100).is_err());
        assert!(decode_cursor(key, &encoded, "t1", "export-1", "users", 8, 100).is_err());
        assert!(decode_cursor(key, &encoded, "t1", "export-1", "users", 7, 200).is_err());
    }

    #[test]
    fn cursor_tampering_is_rejected() {
        let key = b"governance-cursor-test-key";
        let mut encoded = encode_cursor(
            key,
            CursorPayload {
                version: EXPORT_CURSOR_VERSION,
                tenant_id: "t1".into(),
                resource: "export-1".into(),
                section: "users".into(),
                region_revision: 0,
                expires_at: 200,
                through: 0,
                inner: None,
            },
        );
        encoded.replace_range(0..1, "A");
        assert!(decode_cursor(key, &encoded, "t1", "export-1", "users", 0, 100).is_err());
    }

    #[test]
    fn materialized_export_sections_resume_by_key_not_offset() {
        let record = |id: &str| {
            serde_json::json!({
                "record_type": "test",
                "record_id": id
            })
        };
        let (first, cursor) = keyset_values(vec![record("b"), record("d")], None, 1).unwrap();
        assert_eq!(first[0]["record_id"], "b");

        let (second, next) = keyset_values(
            vec![record("a"), record("c"), record("d")],
            cursor.as_deref(),
            10,
        )
        .unwrap();
        assert_eq!(
            second
                .iter()
                .map(|value| value["record_id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["c", "d"]
        );
        assert!(next.is_none());
    }

    #[test]
    fn client_export_source_revision_tracks_mutable_content() {
        let mut client = crate::ports::ClientRecord {
            client_id: "client-export-revision".into(),
            redirect_uris: vec!["https://client.example/callback".into()],
            token_endpoint_auth_method: "none".into(),
            created_at: 100,
            ..Default::default()
        };
        let first = tenant_client_view(client.clone());
        assert_eq!(first.source_revision.len(), 43);

        client.default_resource = Some("https://resource.example".into());
        let updated = tenant_client_view(client);
        assert_ne!(first.source_revision, updated.source_revision);
    }

    #[test]
    fn configuration_export_source_revisions_track_only_redacted_projection_changes() {
        let mut federation = agent_auth_authn::federation::FederationConfig {
            tenant_id: "default".into(),
            upstream_idp_id: "idp-1".into(),
            protocol: agent_auth_authn::federation::UpstreamProtocol::Oidc,
            upstream_issuer: "https://idp.example.com".into(),
            strong_acr_values: vec![],
            oidc: Some(agent_auth_authn::federation::OidcRpParams {
                client_id: "client-1".into(),
                client_secret_ref: "secret-ref-one".into(),
                authorization_endpoint: "https://idp.example.com/authorize".into(),
                token_endpoint: "https://idp.example.com/token".into(),
                jwks_uri: "https://idp.example.com/jwks".into(),
                scopes: vec!["openid".into()],
            }),
        };
        let first_federation = federation_configuration_value(federation.clone());
        federation.oidc.as_mut().unwrap().client_secret_ref = "secret-ref-two".into();
        let hidden_only_update = federation_configuration_value(federation.clone());
        assert_eq!(
            first_federation["source_revision"].as_str().unwrap().len(),
            43
        );
        assert_eq!(
            first_federation["source_revision"], hidden_only_update["source_revision"],
            "a low-entropy secret reference must not become a public digest oracle"
        );
        assert!(!first_federation.to_string().contains("secret-ref-one"));
        federation.oidc.as_mut().unwrap().client_id = "client-2".into();
        let visible_update = federation_configuration_value(federation.clone());
        assert_ne!(
            first_federation["source_revision"],
            visible_update["source_revision"]
        );
        federation.oidc.as_mut().unwrap().client_secret_ref.clear();
        let secret_removed = federation_configuration_value(federation);
        assert_ne!(
            visible_update["source_revision"], secret_removed["source_revision"],
            "the redacted configured/not-configured state remains part of the projection"
        );

        let workload = crate::ports::WorkloadTrustEntry {
            binding_id: "binding-1".into(),
            binding: agent_auth_workload::TrustBinding {
                tenant_id: "default".into(),
                mechanism: agent_auth_workload::TrustMechanism::Sigv4 {
                    aws_account_id: "123456789012".into(),
                    role_arn_pattern: "arn:aws:iam::123456789012:role/agent-*".into(),
                },
                mapped_client_id: "workload-client-1".into(),
            },
        };
        let first_workload = workload_trust_configuration_value(workload.clone());
        let mut updated_workload = workload;
        updated_workload.binding.mapped_client_id = "workload-client-2".into();
        let updated_workload = workload_trust_configuration_value(updated_workload);
        assert_eq!(
            first_workload["source_revision"].as_str().unwrap().len(),
            43
        );
        assert_ne!(
            first_workload["source_revision"],
            updated_workload["source_revision"]
        );

        let domain = crate::ports::DomainBinding {
            domain: "api.example.com".into(),
            resource_id: "https://api.example.com/v1".into(),
            tenant_id: "default".into(),
            client_id: "resource-client".into(),
        };
        let first_domain = domain_binding_configuration_value(domain.clone());
        let mut updated_domain = domain;
        updated_domain.resource_id = "https://api.example.com/v2".into();
        let updated_domain = domain_binding_configuration_value(updated_domain);
        assert_eq!(first_domain["source_revision"].as_str().unwrap().len(), 43);
        assert_ne!(
            first_domain["source_revision"],
            updated_domain["source_revision"]
        );
    }

    #[test]
    fn federation_attribute_mapping_export_is_portable_and_revisioned() {
        let mut registry = crate::federation_attributes::MappingRegistry {
            tenant_id: "default".into(),
            upstream_idp_id: "idp-1".into(),
            upstream_issuer: "https://idp.example.com".into(),
            revision: 1,
            mappings: vec![crate::federation_attributes::AttributeMapping {
                mapping_id: "fm_finance".into(),
                revision: 1,
                enabled: true,
                source_claim: "groups".into(),
                target_namespace: "https://resource.example.com".into(),
                target_key: "role".into(),
                mode: crate::federation_attributes::MappingMode::ExactMembership {
                    source_value: "finance-admin".into(),
                    target_value: "admin".into(),
                },
            }],
        };
        let first = federation_attribute_mapping_configuration_value(registry.clone());
        assert_eq!(first["record_type"], "federation_attribute_mappings");
        assert_eq!(first["record_id"], "idp-1");
        assert_eq!(first["mappings"][0]["mapping_id"], "fm_finance");
        assert_eq!(
            first["mappings"][0]["mode"]["exact_membership"]["source_value"],
            "finance-admin"
        );
        assert_eq!(first["source_revision"].as_str().unwrap().len(), 43);
        assert!(first.get("tenant_id").is_none());

        registry.revision = 2;
        registry.mappings[0].revision = 2;
        registry.mappings[0].enabled = false;
        let updated = federation_attribute_mapping_configuration_value(registry);
        assert_ne!(first["source_revision"], updated["source_revision"]);
    }

    #[test]
    fn policy_reconciliation_accepts_only_the_exact_committed_update() {
        let release_request = PutGovernancePolicy {
            expected_revision: 4,
            legal_hold: false,
            reason: None,
        };
        let mut current = GovernancePolicyRecord {
            tenant_id: "default".into(),
            legal_hold: LegalHoldState::Disabled,
            legal_hold_reason: None,
            retention_exception_capability:
                GovernanceRetentionExceptionCapability::ExternalOperatorManaged,
            actor: "break-glass:credential-1".into(),
            updated_at: 100,
            revision: 5,
        };
        assert!(reconciles_committed_policy_update(
            &current,
            &release_request,
            &None,
            "break-glass:credential-1"
        ));

        current.revision = 6;
        assert!(!reconciles_committed_policy_update(
            &current,
            &release_request,
            &None,
            "break-glass:credential-1"
        ));
        current.revision = 5;
        assert!(!reconciles_committed_policy_update(
            &current,
            &release_request,
            &None,
            "break-glass:credential-2"
        ));
        current.legal_hold = LegalHoldState::Enabled;
        assert!(!reconciles_committed_policy_update(
            &current,
            &release_request,
            &None,
            "break-glass:credential-1"
        ));

        let enable_request = PutGovernancePolicy {
            expected_revision: 0,
            legal_hold: true,
            reason: Some("case-1".into()),
        };
        current.revision = 1;
        current.legal_hold = LegalHoldState::Enabling;
        current.legal_hold_reason = Some("case-1".into());
        assert!(reconciles_committed_policy_update(
            &current,
            &enable_request,
            &Some("case-1".into()),
            "break-glass:credential-1"
        ));
        current.revision = 2;
        current.legal_hold = LegalHoldState::Enabled;
        assert!(reconciles_committed_policy_update(
            &current,
            &enable_request,
            &Some("case-1".into()),
            "break-glass:credential-1"
        ));
        current.revision = 3;
        assert!(!reconciles_committed_policy_update(
            &current,
            &enable_request,
            &Some("case-1".into()),
            "break-glass:credential-1"
        ));
    }

    #[test]
    fn signing_key_export_identity_includes_algorithm() {
        assert_eq!(
            signing_key_record_id("es256", "shared-kid"),
            "es256:shared-kid"
        );
        assert_eq!(
            signing_key_record_id("rs256", "shared-kid"),
            "rs256:shared-kid"
        );
        assert_ne!(
            signing_key_record_id("es256", "shared-kid"),
            signing_key_record_id("rs256", "shared-kid")
        );
    }

    #[test]
    fn continuation_token_is_bound_to_action_tenant_job_and_expiry() {
        let key = b"governance-continuation-test-key";
        let payload = ContinuationTokenPayload {
            version: CONTINUATION_TOKEN_VERSION,
            issuer: CONTINUATION_TOKEN_ISSUER.into(),
            audience: CONTINUATION_TOKEN_AUDIENCE.into(),
            tenant_id: "t1".into(),
            job_id: "job-1".into(),
            action: GovernanceContinuationAction::Status,
            capability_revision: 3,
            jti: "abcdefghijklmnopqrstuvwx".into(),
            issued_at: 100,
            expires_at: 200,
        };
        let encoded = sign_continuation_token(key, &payload).unwrap();
        assert!(verify_continuation_token(
            key,
            &encoded,
            "t1",
            "job-1",
            GovernanceContinuationAction::Status,
            150,
        )
        .is_ok());
        assert!(verify_continuation_token(
            key,
            &encoded,
            "t2",
            "job-1",
            GovernanceContinuationAction::Status,
            150,
        )
        .is_err());
        assert!(verify_continuation_token(
            key,
            &encoded,
            "t1",
            "job-2",
            GovernanceContinuationAction::Status,
            150,
        )
        .is_err());
        assert!(verify_continuation_token(
            key,
            &encoded,
            "t1",
            "job-1",
            GovernanceContinuationAction::Evidence,
            150,
        )
        .is_err());
        assert!(verify_continuation_token(
            key,
            &encoded,
            "t1",
            "job-1",
            GovernanceContinuationAction::Status,
            200,
        )
        .is_err());

        let mut tampered = encoded;
        tampered.replace_range(0..1, "A");
        assert!(verify_continuation_token(
            key,
            &tampered,
            "t1",
            "job-1",
            GovernanceContinuationAction::Status,
            150,
        )
        .is_err());
    }
}
