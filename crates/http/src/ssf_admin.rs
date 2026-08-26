//! Tenant Admin API for Shared Signals stream lifecycle and delivery history.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    ports::{Signer, StoreError},
    security_event::{
        SecurityActor, SecurityEventCategory, SecurityEventCorrelation, SecurityEventDraft,
        SecurityEventOutcome, SecuritySubject,
    },
    ssf::{
        validate_stream_configuration, validate_verification_request, SsfDelivery,
        SsfDeliveryCursor, SsfDeliveryPage, SsfRedriveOutcome, SsfStore, SsfStream,
        SsfStreamCreateOutcome, SsfStreamMutation, SsfStreamMutationOutcome,
        SsfVerificationOutcome, SSF_MAX_DELIVERY_PAGE_SIZE, SUPPORTED_EVENT_TYPES,
    },
    state::AppState,
    tenant_admin::{AdminAction, TenantAdminContext},
};

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateStreamRequest {
    pub endpoint: String,
    pub audience: String,
    pub event_types: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ReplaceStreamRequest {
    pub expected_revision: u64,
    pub endpoint: String,
    pub audience: String,
    pub event_types: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct StreamRevisionRequest {
    pub expected_revision: u64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyStreamRequest {
    pub expected_revision: u64,
    pub state: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SigningKeyRotationPhase {
    PublishAhead,
    Activate,
    Retire,
    EmergencyRevoke,
    Rollback,
}

impl SigningKeyRotationPhase {
    const fn action(self) -> &'static str {
        match self {
            Self::PublishAhead => "key.signing.rotate.publish_ahead",
            Self::Activate => "key.signing.rotate.activate",
            Self::Retire => "key.signing.rotate.retire",
            Self::EmergencyRevoke => "key.signing.rotate.emergency_revoke",
            Self::Rollback => "key.signing.rotate.rollback",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SigningKeyRotationResult {
    Success,
    Failure,
}

impl SigningKeyRotationResult {
    const fn outcome(self) -> SecurityEventOutcome {
        match self {
            Self::Success => SecurityEventOutcome::Success,
            Self::Failure => SecurityEventOutcome::Failure,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RecordSigningKeyRotationRequest {
    pub phase: SigningKeyRotationPhase,
    pub old_kid: String,
    pub new_kid: String,
    pub result: SigningKeyRotationResult,
    pub operation_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct StreamListResponse {
    pub streams: Vec<SsfStream>,
}

#[derive(Debug, Deserialize)]
pub struct DeliveryListQuery {
    limit: Option<usize>,
    cursor: Option<String>,
}

fn json_error(status: StatusCode, error: &str) -> Response {
    (status, Json(serde_json::json!({ "error": error }))).into_response()
}

fn ssf_management_unavailable(state: &AppState) -> Option<Response> {
    (!state.ssf_management_enabled).then(|| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "SSF management unavailable in standby Region",
        )
    })
}

fn new_stream_id() -> String {
    let mut random = [0u8; 18];
    rand::thread_rng().fill_bytes(&mut random);
    format!("strm_{}", URL_SAFE_NO_PAD.encode(random))
}

fn valid_rotation_identifier(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn request_issuer(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let host = crate::hostutil::issuer_host(headers)?;
    agent_auth_discovery::derive_issuer(&host, &state.form)
        .ok()
        .map(|issuer| issuer.as_str().to_string())
}

async fn audit_stream(
    state: &AppState,
    admin: &TenantAdminContext,
    action: &'static str,
    stream_id: &str,
    revision: u64,
    outcome: SecurityEventOutcome,
) {
    state
        .record_security_event(
            SecurityEventDraft::new(
                admin.tenant_id(),
                SecurityActor::admin(admin.audit_identity()),
                Some(SecuritySubject::tenant(admin.tenant_id())),
                SecurityEventCategory::Delivery,
                action,
                outcome,
            )
            .correlated(SecurityEventCorrelation {
                operation_id: Some(format!("{stream_id}:revision:{revision}")),
                ..Default::default()
            }),
        )
        .await;
}

fn rotation_state_matches(
    phase: SigningKeyRotationPhase,
    result: SigningKeyRotationResult,
    old_kid: &str,
    new_kid: &str,
    active_kid: &str,
    published_kids: &[String],
) -> bool {
    let old_published = published_kids.iter().any(|kid| kid == old_kid);
    let new_published = published_kids.iter().any(|kid| kid == new_kid);
    let success_state = match phase {
        SigningKeyRotationPhase::PublishAhead => {
            active_kid == old_kid && old_published && new_published
        }
        SigningKeyRotationPhase::Activate => {
            active_kid == new_kid && old_published && new_published
        }
        SigningKeyRotationPhase::Retire
        | SigningKeyRotationPhase::EmergencyRevoke
        | SigningKeyRotationPhase::Rollback => {
            active_kid == new_kid && !old_published && new_published
        }
    };
    match result {
        SigningKeyRotationResult::Success => success_state,
        SigningKeyRotationResult::Failure => {
            !success_state && (active_kid == old_kid || active_kid == new_kid)
        }
    }
}

#[cfg(test)]
mod rotation_state_tests {
    use super::{
        rotation_state_matches, SigningKeyRotationPhase as Phase,
        SigningKeyRotationResult as Result,
    };

    fn kids(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn success_requires_the_exact_deployed_rotation_state() {
        assert!(rotation_state_matches(
            Phase::PublishAhead,
            Result::Success,
            "old",
            "new",
            "old",
            &kids(&["old", "new"]),
        ));
        assert!(rotation_state_matches(
            Phase::Activate,
            Result::Success,
            "old",
            "new",
            "new",
            &kids(&["old", "new"]),
        ));
        for phase in [Phase::Retire, Phase::EmergencyRevoke, Phase::Rollback] {
            assert!(rotation_state_matches(
                phase,
                Result::Success,
                "old",
                "new",
                "new",
                &kids(&["new"]),
            ));
        }
        assert!(!rotation_state_matches(
            Phase::Activate,
            Result::Success,
            "invented-old",
            "invented-new",
            "actual",
            &kids(&["actual"]),
        ));
    }

    #[test]
    fn failure_still_requires_one_reported_key_to_be_active() {
        assert!(rotation_state_matches(
            Phase::Activate,
            Result::Failure,
            "old",
            "new",
            "old",
            &kids(&["old"]),
        ));
        assert!(!rotation_state_matches(
            Phase::Activate,
            Result::Failure,
            "invented-old",
            "invented-new",
            "actual",
            &kids(&["actual"]),
        ));
    }
}

#[utoipa::path(
    post,
    path = "/admin/ssf/signing-key-rotations",
    tag = "admin",
    request_body = RecordSigningKeyRotationRequest,
    responses(
        (status = 201, description = "Signing-key rotation phase recorded", body = crate::security_event::SecurityEvent),
        (status = 400, description = "Invalid phase audit identifiers"),
        (status = 401, description = "Admin authentication required"),
        (status = 403, description = "access.manage permission required"),
        (status = 409, description = "Observed signing-key state does not match the reported phase result"),
        (status = 503, description = "Signing-key state or canonical security-event ledger unavailable")
    )
)]
pub async fn record_signing_key_rotation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RecordSigningKeyRotationRequest>,
) -> Response {
    let admin =
        match TenantAdminContext::authenticate(&state, &headers, AdminAction::ManageAccess).await {
            Ok(admin) => admin,
            Err(response) => return response,
        };
    if request.old_kid == request.new_kid
        || !valid_rotation_identifier(&request.old_kid, 128)
        || !valid_rotation_identifier(&request.new_kid, 128)
        || !valid_rotation_identifier(&request.operation_id, 128)
    {
        return json_error(
            StatusCode::BAD_REQUEST,
            "rotation audit accepts opaque kid and operation identifiers only",
        );
    }
    let signer = match crate::tenant_keys::signer_or_503(&state, admin.storage_tenant()).await {
        Ok(signer) => signer,
        Err(response) => return response,
    };
    let active_kid = match signer.active_kid().await {
        Ok(kid) => kid,
        Err(_) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "signing-key state unavailable",
            )
        }
    };
    let published_kids = match signer.public_jwks().await {
        Ok(keys) => keys.into_iter().map(|key| key.kid).collect::<Vec<_>>(),
        Err(_) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "signing-key state unavailable",
            )
        }
    };
    if !rotation_state_matches(
        request.phase,
        request.result,
        &request.old_kid,
        &request.new_kid,
        &active_kid,
        &published_kids,
    ) {
        return json_error(
            StatusCode::CONFLICT,
            "reported rotation phase does not match deployed signing-key state",
        );
    }
    let draft = SecurityEventDraft::new(
        admin.tenant_id(),
        SecurityActor::admin(admin.audit_identity()),
        Some(SecuritySubject::credential(&request.new_kid)),
        SecurityEventCategory::KeySecret,
        request.phase.action(),
        request.result.outcome(),
    )
    .correlated(SecurityEventCorrelation {
        credential_id: Some(request.old_kid),
        operation_id: Some(request.operation_id),
        ..Default::default()
    });
    match state.record_security_event(draft).await {
        Some(event) => (StatusCode::CREATED, Json(event)).into_response(),
        None => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "signing-key rotation audit unavailable",
        ),
    }
}

fn store_error(error: StoreError) -> Response {
    match error {
        StoreError::Transient(_) => {
            json_error(StatusCode::SERVICE_UNAVAILABLE, "SSF store unavailable")
        }
        StoreError::Permanent(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SSF store rejected operation",
        ),
    }
}

#[utoipa::path(
    post,
    path = "/admin/ssf/streams",
    tag = "admin",
    request_body = CreateStreamRequest,
    responses(
        (status = 201, description = "SSF stream created", body = SsfStream),
        (status = 400, description = "Invalid endpoint, audience, or event set"),
        (status = 401, description = "Admin authentication required"),
        (status = 403, description = "access.manage permission required"),
        (status = 409, description = "Tenant stream registration quota exhausted"),
        (status = 503, description = "SSF management or store unavailable")
    )
)]
pub async fn create_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateStreamRequest>,
) -> Response {
    let admin =
        match TenantAdminContext::authenticate(&state, &headers, AdminAction::ManageAccess).await {
            Ok(admin) => admin,
            Err(response) => return response,
        };
    if let Some(response) = ssf_management_unavailable(&state) {
        return response;
    }
    let now = crate::current_unix_secs();
    let stream_id = new_stream_id();
    let stream = match SsfStream::new(
        admin.tenant_id(),
        &stream_id,
        request.endpoint,
        request.audience,
        request.event_types,
        now,
    ) {
        Ok(stream) => stream,
        Err(error) => {
            audit_stream(
                &state,
                &admin,
                "ssf.stream.create",
                &stream_id,
                0,
                SecurityEventOutcome::Denied,
            )
            .await;
            return json_error(StatusCode::BAD_REQUEST, error);
        }
    };
    match state.ssf.create_stream(stream).await {
        Ok(SsfStreamCreateOutcome::Created(stream)) => {
            audit_stream(
                &state,
                &admin,
                "ssf.stream.create",
                &stream.stream_id,
                stream.revision,
                SecurityEventOutcome::Success,
            )
            .await;
            (StatusCode::CREATED, Json(stream)).into_response()
        }
        Ok(SsfStreamCreateOutcome::AlreadyExists) => {
            audit_stream(
                &state,
                &admin,
                "ssf.stream.create",
                &stream_id,
                0,
                SecurityEventOutcome::Failure,
            )
            .await;
            json_error(StatusCode::SERVICE_UNAVAILABLE, "stream id collision")
        }
        Ok(SsfStreamCreateOutcome::QuotaExceeded { .. }) => {
            audit_stream(
                &state,
                &admin,
                "ssf.stream.create",
                &stream_id,
                0,
                SecurityEventOutcome::Denied,
            )
            .await;
            json_error(StatusCode::CONFLICT, "SSF stream quota exceeded")
        }
        Err(error) => {
            audit_stream(
                &state,
                &admin,
                "ssf.stream.create",
                &stream_id,
                0,
                SecurityEventOutcome::Failure,
            )
            .await;
            store_error(error)
        }
    }
}

#[utoipa::path(
    get,
    path = "/admin/ssf/streams",
    tag = "admin",
    responses(
        (status = 200, description = "Tenant SSF streams", body = StreamListResponse),
        (status = 401, description = "Admin authentication required"),
        (status = 403, description = "tenant.read permission required"),
        (status = 503, description = "SSF store unavailable")
    )
)]
pub async fn list_streams(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Read).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    match state.ssf.list_streams(admin.tenant_id()).await {
        Ok(mut streams) => {
            streams.sort_by(|left, right| left.stream_id.cmp(&right.stream_id));
            Json(StreamListResponse { streams }).into_response()
        }
        Err(error) => store_error(error),
    }
}

#[utoipa::path(
    get,
    path = "/admin/ssf/streams/{stream_id}",
    tag = "admin",
    params(("stream_id" = String, Path, description = "Tenant-scoped SSF stream ID")),
    responses(
        (status = 200, description = "Tenant SSF stream", body = SsfStream),
        (status = 401, description = "Admin authentication required"),
        (status = 403, description = "tenant.read permission required"),
        (status = 404, description = "Stream not found")
    )
)]
pub async fn get_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(stream_id): Path<String>,
) -> Response {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Read).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    match state.ssf.get_stream(admin.tenant_id(), &stream_id).await {
        Ok(Some(stream)) => Json(stream).into_response(),
        Ok(None) => json_error(StatusCode::NOT_FOUND, "SSF stream not found"),
        Err(error) => store_error(error),
    }
}

async fn mutate(
    state: &AppState,
    admin: &TenantAdminContext,
    stream_id: &str,
    expected_revision: u64,
    mutation: SsfStreamMutation,
    action: &'static str,
) -> Response {
    match state
        .ssf
        .mutate_stream(
            admin.tenant_id(),
            stream_id,
            expected_revision,
            mutation,
            crate::current_unix_secs(),
        )
        .await
    {
        Ok(SsfStreamMutationOutcome::Updated(stream)) => {
            audit_stream(
                state,
                admin,
                action,
                stream_id,
                stream.revision,
                SecurityEventOutcome::Success,
            )
            .await;
            Json(stream).into_response()
        }
        Ok(SsfStreamMutationOutcome::RevisionConflict { current_revision }) => {
            audit_stream(
                state,
                admin,
                action,
                stream_id,
                expected_revision,
                SecurityEventOutcome::Denied,
            )
            .await;
            (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "stream revision conflict",
                    "current_revision": current_revision
                })),
            )
                .into_response()
        }
        Ok(SsfStreamMutationOutcome::NotFound) => {
            audit_stream(
                state,
                admin,
                action,
                stream_id,
                expected_revision,
                SecurityEventOutcome::Denied,
            )
            .await;
            json_error(StatusCode::NOT_FOUND, "SSF stream not found")
        }
        Ok(SsfStreamMutationOutcome::Revoked) => {
            audit_stream(
                state,
                admin,
                action,
                stream_id,
                expected_revision,
                SecurityEventOutcome::Denied,
            )
            .await;
            json_error(StatusCode::GONE, "SSF stream is permanently revoked")
        }
        Err(error) => {
            audit_stream(
                state,
                admin,
                action,
                stream_id,
                expected_revision,
                SecurityEventOutcome::Failure,
            )
            .await;
            store_error(error)
        }
    }
}

#[utoipa::path(
    put,
    path = "/admin/ssf/streams/{stream_id}",
    tag = "admin",
    params(("stream_id" = String, Path, description = "Tenant-scoped SSF stream ID")),
    request_body = ReplaceStreamRequest,
    responses(
        (status = 200, description = "Stream revision replaced", body = SsfStream),
        (status = 400, description = "Invalid stream configuration"),
        (status = 409, description = "Stream revision conflict"),
        (status = 410, description = "Stream permanently revoked"),
        (status = 503, description = "SSF management unavailable")
    )
)]
pub async fn replace_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(stream_id): Path<String>,
    Json(request): Json<ReplaceStreamRequest>,
) -> Response {
    let admin =
        match TenantAdminContext::authenticate(&state, &headers, AdminAction::ManageAccess).await {
            Ok(admin) => admin,
            Err(response) => return response,
        };
    if let Some(response) = ssf_management_unavailable(&state) {
        return response;
    }
    let invalid =
        validate_stream_configuration(&request.endpoint, &request.audience, &request.event_types)
            .err()
            .or_else(|| {
                (!request
                    .event_types
                    .iter()
                    .any(|event| SUPPORTED_EVENT_TYPES.contains(&event.as_str())))
                .then_some("stream must request at least one supported event")
            });
    if let Some(error) = invalid {
        audit_stream(
            &state,
            &admin,
            "ssf.stream.replace",
            &stream_id,
            request.expected_revision,
            SecurityEventOutcome::Denied,
        )
        .await;
        return json_error(StatusCode::BAD_REQUEST, error);
    }
    mutate(
        &state,
        &admin,
        &stream_id,
        request.expected_revision,
        SsfStreamMutation::Replace {
            endpoint: request.endpoint,
            audience: request.audience,
            requested_events: request.event_types,
        },
        "ssf.stream.replace",
    )
    .await
}

async fn mutate_status(
    state: AppState,
    headers: HeaderMap,
    stream_id: String,
    request: StreamRevisionRequest,
    mutation: SsfStreamMutation,
    action: &'static str,
) -> Response {
    let admin =
        match TenantAdminContext::authenticate(&state, &headers, AdminAction::ManageAccess).await {
            Ok(admin) => admin,
            Err(response) => return response,
        };
    if let Some(response) = ssf_management_unavailable(&state) {
        return response;
    }
    mutate(
        &state,
        &admin,
        &stream_id,
        request.expected_revision,
        mutation,
        action,
    )
    .await
}

#[utoipa::path(
    post,
    path = "/admin/ssf/streams/{stream_id}/pause",
    tag = "admin",
    params(("stream_id" = String, Path)),
    request_body = StreamRevisionRequest,
    responses(
        (status = 200, body = SsfStream),
        (status = 409),
        (status = 410),
        (status = 503, description = "SSF management unavailable")
    )
)]
pub async fn pause_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(stream_id): Path<String>,
    Json(request): Json<StreamRevisionRequest>,
) -> Response {
    mutate_status(
        state,
        headers,
        stream_id,
        request,
        SsfStreamMutation::Pause,
        "ssf.stream.pause",
    )
    .await
}

#[utoipa::path(
    post,
    path = "/admin/ssf/streams/{stream_id}/resume",
    tag = "admin",
    params(("stream_id" = String, Path)),
    request_body = StreamRevisionRequest,
    responses(
        (status = 200, body = SsfStream),
        (status = 409),
        (status = 410),
        (status = 503, description = "SSF management unavailable")
    )
)]
pub async fn resume_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(stream_id): Path<String>,
    Json(request): Json<StreamRevisionRequest>,
) -> Response {
    mutate_status(
        state,
        headers,
        stream_id,
        request,
        SsfStreamMutation::Resume,
        "ssf.stream.resume",
    )
    .await
}

#[utoipa::path(
    post,
    path = "/admin/ssf/streams/{stream_id}/revoke",
    tag = "admin",
    params(("stream_id" = String, Path)),
    request_body = StreamRevisionRequest,
    responses(
        (status = 200, body = SsfStream),
        (status = 409),
        (status = 410),
        (status = 503, description = "SSF management unavailable")
    )
)]
pub async fn revoke_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(stream_id): Path<String>,
    Json(request): Json<StreamRevisionRequest>,
) -> Response {
    mutate_status(
        state,
        headers,
        stream_id,
        request,
        SsfStreamMutation::Revoke,
        "ssf.stream.revoke",
    )
    .await
}

#[utoipa::path(
    post,
    path = "/admin/ssf/streams/{stream_id}/verify",
    tag = "admin",
    params(("stream_id" = String, Path)),
    request_body = VerifyStreamRequest,
    responses(
        (status = 202, description = "Verification delivery queued", body = SsfDelivery),
        (status = 400, description = "Invalid verification state"),
        (status = 404, description = "Stream not found"),
        (status = 409, description = "Revision conflict or stream not enabled"),
        (status = 503, description = "SSF management unavailable")
    )
)]
pub async fn verify_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(stream_id): Path<String>,
    Json(request): Json<VerifyStreamRequest>,
) -> Response {
    let admin =
        match TenantAdminContext::authenticate(&state, &headers, AdminAction::ManageAccess).await {
            Ok(admin) => admin,
            Err(response) => return response,
        };
    if let Some(response) = ssf_management_unavailable(&state) {
        return response;
    }
    let Some(issuer) = request_issuer(&state, &headers) else {
        return json_error(StatusCode::BAD_REQUEST, "invalid tenant issuer");
    };
    let event_id = crate::security_event::new_event_id();
    let now = crate::current_unix_secs();
    if validate_verification_request(&event_id, request.state.as_deref(), now).is_err() {
        audit_stream(
            &state,
            &admin,
            "ssf.stream.verify",
            &stream_id,
            request.expected_revision,
            SecurityEventOutcome::Denied,
        )
        .await;
        return json_error(StatusCode::BAD_REQUEST, "invalid verification state");
    }
    match state
        .ssf
        .enqueue_verification(
            admin.tenant_id(),
            &stream_id,
            request.expected_revision,
            &event_id,
            &issuer,
            request.state.as_deref(),
            now,
        )
        .await
    {
        Ok(SsfVerificationOutcome::Enqueued(delivery)) => {
            audit_stream(
                &state,
                &admin,
                "ssf.stream.verify",
                &stream_id,
                delivery.stream_revision,
                SecurityEventOutcome::Success,
            )
            .await;
            (StatusCode::ACCEPTED, Json(delivery)).into_response()
        }
        Ok(SsfVerificationOutcome::NotFound) => {
            audit_stream(
                &state,
                &admin,
                "ssf.stream.verify",
                &stream_id,
                request.expected_revision,
                SecurityEventOutcome::Denied,
            )
            .await;
            json_error(StatusCode::NOT_FOUND, "SSF stream not found")
        }
        Ok(SsfVerificationOutcome::RevisionConflict { current_revision }) => {
            audit_stream(
                &state,
                &admin,
                "ssf.stream.verify",
                &stream_id,
                request.expected_revision,
                SecurityEventOutcome::Denied,
            )
            .await;
            (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "stream revision conflict",
                    "current_revision": current_revision
                })),
            )
                .into_response()
        }
        Ok(SsfVerificationOutcome::NotEnabled) => {
            audit_stream(
                &state,
                &admin,
                "ssf.stream.verify",
                &stream_id,
                request.expected_revision,
                SecurityEventOutcome::Denied,
            )
            .await;
            json_error(StatusCode::CONFLICT, "SSF stream is not enabled")
        }
        Err(error) => {
            audit_stream(
                &state,
                &admin,
                "ssf.stream.verify",
                &stream_id,
                request.expected_revision,
                SecurityEventOutcome::Failure,
            )
            .await;
            store_error(error)
        }
    }
}

#[utoipa::path(
    get,
    path = "/admin/ssf/streams/{stream_id}/deliveries",
    tag = "admin",
    params(
        ("stream_id" = String, Path),
        ("limit" = Option<usize>, Query, description = "Page size, 1 through 100"),
        ("cursor" = Option<String>, Query, description = "Opaque tenant and stream-bound cursor")
    ),
    responses(
        (status = 200, description = "Stream delivery history", body = SsfDeliveryPage),
        (status = 400, description = "Invalid limit or cursor"),
        (status = 404, description = "Stream not found")
    )
)]
pub async fn list_deliveries(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(stream_id): Path<String>,
    Query(query): Query<DeliveryListQuery>,
) -> Response {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Read).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    match state.ssf.get_stream(admin.tenant_id(), &stream_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return json_error(StatusCode::NOT_FOUND, "SSF stream not found"),
        Err(error) => return store_error(error),
    }
    let limit = query.limit.unwrap_or(50);
    if !(1..=SSF_MAX_DELIVERY_PAGE_SIZE).contains(&limit) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "delivery limit must be 1 through 100",
        );
    }
    let cursor = match query.cursor.as_deref() {
        Some(encoded) => {
            match SsfDeliveryCursor::decode_for_stream(encoded, admin.tenant_id(), &stream_id) {
                Ok(cursor) => Some(cursor),
                Err(_) => return json_error(StatusCode::BAD_REQUEST, "invalid delivery cursor"),
            }
        }
        None => None,
    };
    match state
        .ssf
        .list_deliveries(admin.tenant_id(), &stream_id, limit, cursor.as_ref())
        .await
    {
        Ok(page) => Json(page).into_response(),
        Err(error) => store_error(error),
    }
}

#[utoipa::path(
    get,
    path = "/admin/ssf/streams/{stream_id}/deliveries/{stream_revision}/{event_id}",
    tag = "admin",
    params(
        ("stream_id" = String, Path),
        ("stream_revision" = u64, Path),
        ("event_id" = String, Path)
    ),
    responses(
        (status = 200, description = "Tenant-scoped delivery", body = SsfDelivery),
        (status = 404, description = "Delivery not found")
    )
)]
pub async fn get_delivery(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((stream_id, stream_revision, event_id)): Path<(String, u64, String)>,
) -> Response {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Read).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    match state
        .ssf
        .get_delivery(admin.tenant_id(), &stream_id, stream_revision, &event_id)
        .await
    {
        Ok(Some(delivery)) => Json(delivery).into_response(),
        Ok(None) => json_error(StatusCode::NOT_FOUND, "SSF delivery not found"),
        Err(error) => store_error(error),
    }
}

#[utoipa::path(
    post,
    path = "/admin/ssf/streams/{stream_id}/deliveries/{stream_revision}/{event_id}/redrive",
    tag = "admin",
    params(
        ("stream_id" = String, Path),
        ("stream_revision" = u64, Path),
        ("event_id" = String, Path)
    ),
    responses(
        (status = 202, description = "Terminal delivery reopened", body = SsfDelivery),
        (status = 404, description = "Delivery not found"),
        (status = 409, description = "Delivery is not terminal or stream revision is stale"),
        (status = 410, description = "Delivery retention expired"),
        (status = 503, description = "SSF management unavailable")
    )
)]
pub async fn redrive_delivery(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((stream_id, stream_revision, event_id)): Path<(String, u64, String)>,
) -> Response {
    let admin =
        match TenantAdminContext::authenticate(&state, &headers, AdminAction::ManageAccess).await {
            Ok(admin) => admin,
            Err(response) => return response,
        };
    if let Some(response) = ssf_management_unavailable(&state) {
        return response;
    }
    match state
        .ssf
        .redrive_delivery(
            admin.tenant_id(),
            &stream_id,
            stream_revision,
            &event_id,
            crate::current_unix_secs(),
        )
        .await
    {
        Ok(SsfRedriveOutcome::Redriven(delivery)) => {
            audit_stream(
                &state,
                &admin,
                "ssf.delivery.redrive",
                &stream_id,
                stream_revision,
                SecurityEventOutcome::Success,
            )
            .await;
            (StatusCode::ACCEPTED, Json(delivery)).into_response()
        }
        Ok(outcome) => {
            audit_stream(
                &state,
                &admin,
                "ssf.delivery.redrive",
                &stream_id,
                stream_revision,
                SecurityEventOutcome::Denied,
            )
            .await;
            match outcome {
                SsfRedriveOutcome::NotFound => {
                    json_error(StatusCode::NOT_FOUND, "SSF delivery not found")
                }
                SsfRedriveOutcome::Expired => {
                    json_error(StatusCode::GONE, "SSF delivery retry window expired")
                }
                SsfRedriveOutcome::NotTerminal => {
                    json_error(StatusCode::CONFLICT, "SSF delivery is not terminal")
                }
                SsfRedriveOutcome::StreamNotCurrent => {
                    json_error(StatusCode::CONFLICT, "SSF stream revision is not current")
                }
                SsfRedriveOutcome::Redriven(_) => unreachable!(),
            }
        }
        Err(error) => {
            audit_stream(
                &state,
                &admin,
                "ssf.delivery.redrive",
                &stream_id,
                stream_revision,
                SecurityEventOutcome::Failure,
            )
            .await;
            store_error(error)
        }
    }
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(record_signing_key_rotation))
        .routes(routes!(create_stream, list_streams))
        .routes(routes!(get_stream, replace_stream))
        .routes(routes!(pause_stream))
        .routes(routes!(resume_stream))
        .routes(routes!(revoke_stream))
        .routes(routes!(verify_stream))
        .routes(routes!(list_deliveries))
        .routes(routes!(get_delivery))
        .routes(routes!(redrive_delivery))
}
