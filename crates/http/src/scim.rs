use agent_auth_discovery::Form;
use axum::{
    body::Bytes,
    extract::{
        rejection::{BytesRejection, PathRejection},
        FromRequestParts, Path, RawQuery, State,
    },
    http::{header, request::Parts, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde::Deserialize;
use serde_json::{json, Value};
use std::future::Future;
use utoipa_axum::{
    router::{OpenApiRouter, UtoipaMethodRouterExt},
    routes,
};

use crate::admin_credentials::{AdminCredentialError, AdminCredentialOwner, AdminCredentialSlot};
use crate::ports::{
    ScimCreateOutcome, ScimReplaceOutcome, StoreError, UserRecord, UserStatus, UsersStore,
};
use crate::state::AppState;

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const CONFIG_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
const SCIM_CONTENT_TYPE: &str = "application/scim+json";
const SCIM_PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'#')
    .add(b'?')
    .add(b'[')
    .add(b']')
    .add(b'^')
    .add(b'{')
    .add(b'|')
    .add(b'}')
    .add(b'/')
    .add(b'%')
    .add(b'\\');

pub(crate) struct ScimContext {
    pub(crate) storage_tenant: String,
    pub(crate) audit_tenant: String,
    pub(crate) base_url: String,
}

impl ScimContext {
    async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<Self, Response> {
        let token = crate::tenant_admin::bearer(headers).ok_or_else(scim_unauthorized)?;
        let host = crate::hostutil::issuer_host(headers).ok_or_else(scim_unauthorized)?;
        let storage_tenant =
            crate::tenant::tenant_or_400(state, headers).map_err(|_| scim_unauthorized())?;
        let tenant_id = match &state.form {
            Form::SelfHosted { .. } => "default".to_string(),
            Form::Saas { .. } => storage_tenant.clone(),
        };
        let owner = AdminCredentialOwner::scim_tenant(&tenant_id);
        let matched = match state
            .admin_credentials
            .verify(&owner, &token, crate::token::current_unix_secs_pub())
            .await
        {
            Ok(Some(matched)) => matched,
            Ok(None) => return Err(scim_unauthorized()),
            Err(
                AdminCredentialError::InvalidConfiguration
                | AdminCredentialError::Unavailable
                | AdminCredentialError::Removed,
            ) => {
                return Err(scim_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    None,
                    "SCIM credential verification unavailable",
                ))
            }
        };
        let slot = match matched.slot {
            AdminCredentialSlot::Current => "current",
            AdminCredentialSlot::Next => "next",
        };
        state
            .audit_credential_event(crate::credential::CredentialAuditEvent::ScimCredentialUse {
                tenant: &tenant_id,
                credential_id: &matched.credential_id,
                slot,
                revision: matched.revision,
            })
            .await;
        let issuer = agent_auth_discovery::derive_issuer(&host, &state.form)
            .map_err(|_| scim_unauthorized())?;
        Ok(Self {
            storage_tenant,
            audit_tenant: tenant_id,
            base_url: format!("{}/scim/v2", issuer.as_str()),
        })
    }
}

impl FromRequestParts<AppState> for ScimContext {
    type Rejection = Response;

    fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let headers = parts.headers.clone();
        async move { Self::authenticate(state, &headers).await }
    }
}

pub(crate) fn scim_json(status: StatusCode, body: Value) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static(SCIM_CONTENT_TYPE),
        )],
        body.to_string(),
    )
        .into_response()
}

pub(crate) fn scim_json_with_headers(
    status: StatusCode,
    body: Value,
    headers: impl IntoIterator<Item = (HeaderName, HeaderValue)>,
) -> Response {
    let mut response = scim_json(status, body);
    for (name, value) in headers {
        response.headers_mut().insert(name, value);
    }
    response
}

pub(crate) fn scim_error(status: StatusCode, scim_type: Option<&str>, detail: &str) -> Response {
    let mut body = json!({
        "schemas": [ERROR_SCHEMA],
        "status": status.as_u16().to_string(),
        "detail": detail,
    });
    if let Some(scim_type) = scim_type {
        body["scimType"] = Value::String(scim_type.to_string());
    }
    scim_json(status, body)
}

fn scim_unauthorized() -> Response {
    scim_json_with_headers(
        StatusCode::UNAUTHORIZED,
        json!({
            "schemas": [ERROR_SCHEMA],
            "status": StatusCode::UNAUTHORIZED.as_u16().to_string(),
            "detail": "SCIM bearer credential required",
        }),
        [(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"))],
    )
}

fn scim_user_id(path: Result<Path<String>, PathRejection>) -> Result<String, Box<Response>> {
    path.map(|Path(id)| id).map_err(|_| {
        Box::new(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "invalid SCIM User id",
        ))
    })
}

pub(crate) fn scim_request_body(
    body: Result<Bytes, BytesRejection>,
) -> Result<Bytes, Box<Response>> {
    body.map_err(|rejection| {
        let status = rejection.status();
        let detail = if status == StatusCode::PAYLOAD_TOO_LARGE {
            "SCIM request body exceeds the configured size limit"
        } else {
            "invalid SCIM request body"
        };
        Box::new(scim_error(status, None, detail))
    })
}

pub(crate) fn store_error(error: StoreError) -> Response {
    match error {
        StoreError::Transient(_) | StoreError::Permanent(_) => scim_error(
            StatusCode::SERVICE_UNAVAILABLE,
            None,
            "SCIM persistence unavailable",
        ),
    }
}

fn has_schema(schemas: &[String], required: &str) -> bool {
    schemas.iter().any(|schema| schema == required)
}

fn normalize_user_name(value: &str) -> Option<String> {
    let value = value.trim().to_lowercase();
    if value.is_empty()
        || value
            .chars()
            .any(|c| c.is_ascii_control() || c.is_whitespace())
        || value.matches('@').count() != 1
    {
        return None;
    }
    let (local, domain) = value.split_once('@')?;
    (!local.is_empty() && !domain.is_empty() && domain.contains('.')).then_some(value)
}

pub(crate) fn unix_rfc3339(timestamp: i64) -> String {
    let days = timestamp.div_euclid(86_400);
    let seconds = timestamp.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

pub(crate) fn resource_location(base_url: &str, resource: &str, id: &str) -> String {
    format!(
        "{base_url}/{resource}/{}",
        utf8_percent_encode(id, SCIM_PATH_SEGMENT)
    )
}

fn user_location(base_url: &str, user_id: &str) -> String {
    resource_location(base_url, "Users", user_id)
}

fn user_json(record: &UserRecord, base_url: &str) -> Value {
    json!({
        "schemas": [USER_SCHEMA],
        "id": record.user_id,
        "externalId": record.scim_external_id,
        "userName": record.scim_user_name,
        "displayName": record.scim_display_name,
        "active": record.status == UserStatus::Active && !record.revocation_pending,
        "meta": {
            "resourceType": "User",
            "created": unix_rfc3339(record.created_at),
            "lastModified": unix_rfc3339(record.updated_at),
            "location": user_location(base_url, &record.user_id),
        }
    })
}

#[derive(Deserialize)]
struct ScimUserRequest {
    #[serde(default)]
    schemas: Vec<String>,
    #[serde(rename = "externalId")]
    external_id: String,
    #[serde(rename = "userName")]
    user_name: String,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    active: Option<bool>,
}

fn parse_user_request(body: &[u8]) -> Result<ScimUserRequest, Box<Response>> {
    let request: ScimUserRequest = serde_json::from_slice(body).map_err(|_| {
        Box::new(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidSyntax"),
            "malformed SCIM User",
        ))
    })?;
    if !has_schema(&request.schemas, USER_SCHEMA) {
        return Err(Box::new(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidSyntax"),
            "core User schema is required",
        )));
    }
    if request.external_id.is_empty() || normalize_user_name(&request.user_name).is_none() {
        return Err(Box::new(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "externalId and an email-shaped userName are required",
        )));
    }
    Ok(request)
}

async fn suppressed_scim_alias_response(
    state: &AppState,
    tenant_id: &str,
    external_id: &str,
    user_name: &str,
) -> Option<Response> {
    for (kind, value) in [
        (
            crate::governance::GovernanceAliasKind::ScimExternalId,
            external_id,
        ),
        (
            crate::governance::GovernanceAliasKind::ScimUserName,
            user_name,
        ),
        (crate::governance::GovernanceAliasKind::Email, user_name),
    ] {
        match crate::governance::user_alias_is_suppressed(state, tenant_id, kind, value).await {
            Ok(true) => {
                return Some(scim_error(
                    StatusCode::CONFLICT,
                    Some("uniqueness"),
                    "identity alias is permanently suppressed",
                ))
            }
            Ok(false) => {}
            Err(_) => {
                return Some(scim_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    None,
                    "suppression authority unavailable",
                ))
            }
        }
    }
    None
}

struct ActiveResult {
    record: UserRecord,
    counts: Option<crate::user_lifecycle::CascadeCounts>,
}

async fn apply_active(
    state: &AppState,
    tenant: &str,
    record: UserRecord,
    active: bool,
    now: i64,
) -> Result<ActiveResult, Response> {
    if active {
        match crate::user_lifecycle::enable(state, tenant, &record.user_id, now).await {
            Ok(crate::user_lifecycle::LifecycleEnableOutcome::Enabled(record)) => {
                Ok(ActiveResult {
                    record,
                    counts: None,
                })
            }
            Ok(crate::user_lifecycle::LifecycleEnableOutcome::NotFound) => Err(scim_error(
                StatusCode::NOT_FOUND,
                None,
                "SCIM User not found",
            )),
            Ok(crate::user_lifecycle::LifecycleEnableOutcome::Tombstoned) => Err(scim_error(
                StatusCode::CONFLICT,
                Some("uniqueness"),
                "tombstoned identity cannot be rebound",
            )),
            Err(_) => Err(scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                None,
                "user lifecycle unavailable",
            )),
        }
    } else {
        match crate::user_lifecycle::disable(state, tenant, &record.user_id, now).await {
            Ok(crate::user_lifecycle::DisableOutcome::Disabled { record, counts }) => {
                Ok(ActiveResult {
                    record: *record,
                    counts: Some(counts),
                })
            }
            Ok(crate::user_lifecycle::DisableOutcome::NotFound) => Err(scim_error(
                StatusCode::NOT_FOUND,
                None,
                "SCIM User not found",
            )),
            Ok(crate::user_lifecycle::DisableOutcome::Tombstoned) => Err(scim_error(
                StatusCode::CONFLICT,
                Some("uniqueness"),
                "tombstoned identity cannot be rebound",
            )),
            Err(_) => Err(scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                None,
                "user lifecycle unavailable",
            )),
        }
    }
}

async fn resume_initial_create_lifecycle(
    state: &AppState,
    tenant: &str,
    external_id: &str,
    user_name: &str,
    user_id: &str,
    now: i64,
) -> Result<ActiveResult, Response> {
    use crate::ports::ScimCreateLifecycleStart;

    let counts = match state
        .users
        .begin_scim_create_lifecycle(tenant, external_id, user_name, user_id, now)
        .await
    {
        Ok(ScimCreateLifecycleStart::Ready { epoch, .. }) => {
            let counts =
                crate::user_lifecycle::cascade_revoke_before_epoch(state, tenant, user_id, epoch)
                    .await
                    .map_err(|_| {
                        scim_error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            None,
                            "user lifecycle unavailable",
                        )
                    })?;
            let completed = state
                .users
                .complete_disable(tenant, user_id, epoch, now)
                .await
                .map_err(store_error)?;
            if !completed {
                return Err(scim_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    None,
                    "user lifecycle changed concurrently",
                ));
            }
            Some(counts)
        }
        Ok(ScimCreateLifecycleStart::Complete) => None,
        Ok(ScimCreateLifecycleStart::Tombstoned) => {
            return Err(scim_error(
                StatusCode::CONFLICT,
                Some("uniqueness"),
                "tombstoned identity cannot be rebound",
            ))
        }
        Err(error) => return Err(store_error(error)),
    };
    state
        .users
        .complete_scim_create_lifecycle(tenant, external_id, user_name, user_id)
        .await
        .map_err(store_error)?;
    let record = state
        .users
        .get_by_id(tenant, user_id)
        .await
        .map_err(store_error)?
        .ok_or_else(|| scim_error(StatusCode::NOT_FOUND, None, "SCIM User not found"))?;
    Ok(ActiveResult { record, counts })
}

async fn load_scim_user_after_initial_lifecycle(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    now: i64,
) -> Result<ActiveResult, Response> {
    let record = match state.users.get_by_id(tenant, user_id).await {
        Ok(Some(record))
            if record.scim_external_id.is_some() && record.scim_user_name.is_some() =>
        {
            record
        }
        Ok(_) => {
            return Err(scim_error(
                StatusCode::NOT_FOUND,
                None,
                "SCIM User not found",
            ))
        }
        Err(error) => return Err(store_error(error)),
    };
    resume_initial_create_lifecycle(
        state,
        tenant,
        record
            .scim_external_id
            .as_deref()
            .expect("checked SCIM externalId"),
        record
            .scim_user_name
            .as_deref()
            .expect("checked SCIM userName"),
        user_id,
        now,
    )
    .await
}

async fn audit_mutation(
    state: &AppState,
    action: &'static str,
    tenant: &str,
    user_id: &str,
    credential_epoch: u64,
    counts: Option<&crate::user_lifecycle::CascadeCounts>,
) {
    let event = crate::credential::CredentialAuditEvent::ScimMutation {
        action,
        tenant,
        user_id,
        credential_epoch,
        sessions: counts.map_or(0, |counts| counts.sessions),
        families: counts.map_or(0, |counts| counts.families),
        grants: counts.map_or(0, |counts| counts.grants),
    };
    if action == "disable" {
        let event_id = crate::security_event::scim_lifecycle_event_id(
            tenant,
            user_id,
            action,
            credential_epoch,
        );
        state.audit_credential_event_with_id(event_id, event).await;
    } else {
        state.audit_credential_event(event).await;
    }
}

#[utoipa::path(
    get,
    path = "/scim/v2/ServiceProviderConfig",
    tag = "scim",
    responses(
        (status = 200, description = "SCIM service capabilities", content_type = "application/scim+json"),
        (status = 401, description = "Missing or invalid tenant SCIM bearer", content_type = "application/scim+json"),
        (status = 503, description = "SCIM credential verification unavailable", content_type = "application/scim+json")
    )
)]
async fn service_provider_config(_context: ScimContext) -> Response {
    scim_json(
        StatusCode::OK,
        json!({
            "schemas": [CONFIG_SCHEMA],
            "patch": {"supported": true},
            "bulk": {"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": true, "maxResults": 100},
            "changePassword": {"supported": false},
            "sort": {"supported": false},
            "etag": {"supported": false},
            "authenticationSchemes": [{
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "Tenant-scoped SCIM bearer credential",
                "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
                "primary": true
            }]
        }),
    )
}

#[utoipa::path(
    post,
    path = "/scim/v2/Users",
    tag = "scim",
    request_body(content = Value, content_type = "application/scim+json"),
    responses(
        (status = 200, description = "Exact retry returned the existing User", content_type = "application/scim+json"),
        (status = 201, description = "User provisioned", content_type = "application/scim+json"),
        (status = 400, description = "Invalid SCIM User", content_type = "application/scim+json"),
        (status = 401, description = "Missing or invalid tenant SCIM bearer", content_type = "application/scim+json"),
        (status = 409, description = "Identity alias conflict", content_type = "application/scim+json"),
        (status = 503, description = "SCIM persistence or lifecycle unavailable", content_type = "application/scim+json")
    )
)]
async fn create_user(
    context: ScimContext,
    State(state): State<AppState>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match scim_request_body(body) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let request = match parse_user_request(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    let user_name = normalize_user_name(&request.user_name).expect("validated userName");
    if let Some(response) = suppressed_scim_alias_response(
        &state,
        &context.audit_tenant,
        &request.external_id,
        &user_name,
    )
    .await
    {
        return response;
    }
    let now = crate::token::current_unix_secs_pub();
    let target_active = request.active.unwrap_or(true);
    let create_external_id = request.external_id.clone();
    let input = crate::ports::ScimUserInput {
        user_id: format!("user:scim:{}", crate::login::rand_id(24)),
        external_id: request.external_id,
        user_name: user_name.clone(),
        display_name: request.display_name,
        active: target_active,
        now,
    };
    let (status, mut record, created, resume_initial_lifecycle) = match state
        .users
        .create_scim(&context.storage_tenant, input)
        .await
    {
        Ok(ScimCreateOutcome::Created(record)) => {
            (StatusCode::CREATED, record, true, !target_active)
        }
        Ok(ScimCreateOutcome::Existing {
            record,
            pending_initial_epoch,
        }) => (
            StatusCode::OK,
            record,
            false,
            pending_initial_epoch.is_some(),
        ),
        Ok(ScimCreateOutcome::Conflict) => {
            return scim_error(
                StatusCode::CONFLICT,
                Some("uniqueness"),
                "externalId or userName is already bound",
            )
        }
        Ok(ScimCreateOutcome::Tombstoned) => {
            return scim_error(
                StatusCode::CONFLICT,
                Some("uniqueness"),
                "tombstoned identity cannot be rebound",
            )
        }
        Err(error) => return store_error(error),
    };
    let mut counts = None;
    if resume_initial_lifecycle {
        let result = match resume_initial_create_lifecycle(
            &state,
            &context.storage_tenant,
            &create_external_id,
            &user_name,
            &record.user_id,
            now,
        )
        .await
        {
            Ok(result) => result,
            Err(response) => return response,
        };
        record = result.record;
        counts = result.counts;
        if created {
            audit_mutation(
                &state,
                "create",
                &context.audit_tenant,
                &record.user_id,
                record.credential_epoch,
                counts.as_ref(),
            )
            .await;
        } else if counts.is_some() {
            audit_mutation(
                &state,
                "disable",
                &context.audit_tenant,
                &record.user_id,
                record.credential_epoch,
                counts.as_ref(),
            )
            .await;
        }
    } else if created {
        let currently_active = record.status == UserStatus::Active && !record.revocation_pending;
        if target_active != currently_active || record.revocation_pending {
            let result =
                match apply_active(&state, &context.storage_tenant, record, target_active, now)
                    .await
                {
                    Ok(result) => result,
                    Err(response) => return response,
                };
            record = result.record;
            counts = result.counts;
        }
        audit_mutation(
            &state,
            "create",
            &context.audit_tenant,
            &record.user_id,
            record.credential_epoch,
            counts.as_ref(),
        )
        .await;
    } else if record.revocation_pending {
        let result = match apply_active(&state, &context.storage_tenant, record, false, now).await {
            Ok(result) => result,
            Err(response) => return response,
        };
        record = result.record;
        counts = result.counts;
        audit_mutation(
            &state,
            "disable",
            &context.audit_tenant,
            &record.user_id,
            record.credential_epoch,
            counts.as_ref(),
        )
        .await;
    }
    let location = user_location(&context.base_url, &record.user_id);
    let location_header = match HeaderValue::from_str(&location) {
        Ok(value) => value,
        Err(_) => {
            return scim_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                None,
                "invalid resource location",
            )
        }
    };
    scim_json_with_headers(
        status,
        user_json(&record, &context.base_url),
        [(header::LOCATION, location_header)],
    )
}

#[utoipa::path(
    get,
    path = "/scim/v2/Users/{id}",
    tag = "scim",
    params(("id" = String, Path)),
    responses(
        (status = 200, description = "Tenant-local SCIM User", content_type = "application/scim+json"),
        (status = 401, description = "Missing or invalid tenant SCIM bearer", content_type = "application/scim+json"),
        (status = 404, description = "SCIM User not found in this tenant", content_type = "application/scim+json"),
        (status = 503, description = "SCIM persistence unavailable", content_type = "application/scim+json")
    )
)]
async fn get_user(
    context: ScimContext,
    State(state): State<AppState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let id = match scim_user_id(path) {
        Ok(id) => id,
        Err(response) => return *response,
    };
    match state.users.get_by_id(&context.storage_tenant, &id).await {
        Ok(Some(record))
            if record.scim_external_id.is_some() && record.status != UserStatus::Tombstoned =>
        {
            scim_json(StatusCode::OK, user_json(&record, &context.base_url))
        }
        Ok(_) => scim_error(StatusCode::NOT_FOUND, None, "SCIM User not found"),
        Err(error) => store_error(error),
    }
}

#[derive(Default, Deserialize)]
struct ListQuery {
    filter: Option<String>,
    #[serde(rename = "startIndex")]
    start_index: Option<i64>,
    count: Option<i64>,
}

enum Filter {
    ExternalId(String),
    UserName(String),
}

pub(crate) fn parse_eq_filter(filter: &str) -> Option<(String, String)> {
    let mut parts = filter.trim().splitn(2, char::is_whitespace);
    let attribute = parts.next()?.to_ascii_lowercase();
    let remainder = parts.next()?.trim_start();
    let mut parts = remainder.splitn(2, char::is_whitespace);
    if !parts.next()?.eq_ignore_ascii_case("eq") {
        return None;
    }
    let literal = parts.next()?.trim();
    let value: String = serde_json::from_str(literal).ok()?;
    Some((attribute, value))
}

fn parse_filter(filter: &str) -> Option<Filter> {
    let (attribute, value) = parse_eq_filter(filter)?;
    match attribute.as_str() {
        "externalid" => Some(Filter::ExternalId(value)),
        "username" => Some(Filter::UserName(value)),
        _ => None,
    }
}

#[utoipa::path(
    get,
    path = "/scim/v2/Users",
    tag = "scim",
    params(
        ("filter" = Option<String>, Query, description = "externalId eq or userName eq"),
        ("startIndex" = Option<i64>, Query, description = "One-based result offset"),
        ("count" = Option<i64>, Query, description = "Requested page size, capped at 100")
    ),
    responses(
        (status = 200, description = "SCIM ListResponse", content_type = "application/scim+json"),
        (status = 400, description = "Invalid filter or pagination", content_type = "application/scim+json"),
        (status = 401, description = "Missing or invalid tenant SCIM bearer", content_type = "application/scim+json"),
        (status = 503, description = "SCIM persistence unavailable", content_type = "application/scim+json")
    )
)]
async fn list_users(
    context: ScimContext,
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let query: ListQuery = match raw_query {
        Some(raw) => match serde_urlencoded::from_str(&raw) {
            Ok(query) => query,
            Err(_) => {
                return scim_error(
                    StatusCode::BAD_REQUEST,
                    Some("invalidSyntax"),
                    "malformed query",
                )
            }
        },
        None => ListQuery::default(),
    };
    // RFC 7644 section 3.4.2.4 normalizes values below the lower bound.
    let start_index = query.start_index.unwrap_or(1).max(1);
    let count = query.count.unwrap_or(100).max(0);
    let offset = usize::try_from(start_index.saturating_sub(1)).unwrap_or(usize::MAX);
    let limit = usize::try_from(count.min(100)).unwrap_or(0);
    let page = match query.filter.as_deref() {
        Some(filter) => match parse_filter(filter) {
            Some(Filter::ExternalId(value)) => state
                .users
                .get_scim_by_external_id(&context.storage_tenant, &value)
                .await
                .map(|record| {
                    let records: Vec<_> = record
                        .into_iter()
                        .filter(|record| record.status != UserStatus::Tombstoned)
                        .collect();
                    let total_results = records.len();
                    (
                        records.into_iter().skip(offset).take(limit).collect(),
                        total_results,
                    )
                }),
            Some(Filter::UserName(value)) => state
                .users
                .get_scim_by_user_name(&context.storage_tenant, &value)
                .await
                .map(|record| {
                    let records: Vec<_> = record
                        .into_iter()
                        .filter(|record| record.status != UserStatus::Tombstoned)
                        .collect();
                    let total_results = records.len();
                    (
                        records.into_iter().skip(offset).take(limit).collect(),
                        total_results,
                    )
                }),
            None => {
                return scim_error(
                    StatusCode::BAD_REQUEST,
                    Some("invalidFilter"),
                    "unsupported SCIM filter",
                )
            }
        },
        None => {
            state
                .users
                .list_scim(&context.storage_tenant, offset, limit)
                .await
        }
    };
    let (records, total_results) = match page {
        Ok(page) => page,
        Err(error) => return store_error(error),
    };
    let resources: Vec<_> = records
        .iter()
        .map(|record| user_json(record, &context.base_url))
        .collect();
    scim_json(
        StatusCode::OK,
        json!({
            "schemas": [LIST_SCHEMA],
            "totalResults": total_results,
            "startIndex": start_index,
            "itemsPerPage": resources.len(),
            "Resources": resources,
        }),
    )
}

#[utoipa::path(
    put,
    path = "/scim/v2/Users/{id}",
    tag = "scim",
    params(("id" = String, Path)),
    request_body(content = Value, content_type = "application/scim+json"),
    responses(
        (status = 200, description = "SCIM User replaced", content_type = "application/scim+json"),
        (status = 400, description = "Invalid SCIM User", content_type = "application/scim+json"),
        (status = 401, description = "Missing or invalid tenant SCIM bearer", content_type = "application/scim+json"),
        (status = 404, description = "SCIM User not found in this tenant", content_type = "application/scim+json"),
        (status = 409, description = "Identity alias conflict", content_type = "application/scim+json"),
        (status = 503, description = "SCIM persistence or lifecycle unavailable", content_type = "application/scim+json")
    )
)]
async fn replace_user(
    context: ScimContext,
    State(state): State<AppState>,
    path: Result<Path<String>, PathRejection>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let id = match scim_user_id(path) {
        Ok(id) => id,
        Err(response) => return *response,
    };
    let body = match scim_request_body(body) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let request = match parse_user_request(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    let user_name = normalize_user_name(&request.user_name).expect("validated userName");
    if let Some(response) = suppressed_scim_alias_response(
        &state,
        &context.audit_tenant,
        &request.external_id,
        &user_name,
    )
    .await
    {
        return response;
    }
    let now = crate::token::current_unix_secs_pub();
    let initial =
        match load_scim_user_after_initial_lifecycle(&state, &context.storage_tenant, &id, now)
            .await
        {
            Ok(result) => result,
            Err(response) => return response,
        };
    if let Some(counts) = initial.counts.as_ref() {
        audit_mutation(
            &state,
            "disable",
            &context.audit_tenant,
            &initial.record.user_id,
            initial.record.credential_epoch,
            Some(counts),
        )
        .await;
    }
    let mut counts = None;
    let target_active = request.active.unwrap_or(true);
    let mut record = match state
        .users
        .replace_scim(
            &context.storage_tenant,
            &id,
            crate::ports::ScimReplaceInput {
                external_id: request.external_id,
                user_name,
                display_name: request.display_name,
                active: target_active,
                now,
            },
        )
        .await
    {
        Ok(ScimReplaceOutcome::Updated(record)) => record,
        Ok(ScimReplaceOutcome::NotFound) => {
            return scim_error(StatusCode::NOT_FOUND, None, "SCIM User not found")
        }
        Ok(ScimReplaceOutcome::Conflict) => {
            return scim_error(
                StatusCode::CONFLICT,
                Some("uniqueness"),
                "externalId or userName is already bound",
            )
        }
        Ok(ScimReplaceOutcome::Tombstoned) => {
            return scim_error(
                StatusCode::CONFLICT,
                Some("uniqueness"),
                "tombstoned identity cannot be rebound",
            )
        }
        Err(error) => return store_error(error),
    };
    let currently_active = record.status == UserStatus::Active && !record.revocation_pending;
    // A repeated explicit deprovision is also a cleanup retry. DynamoDB user
    // indexes are eventually consistent, so a later pass may discover
    // old-epoch artifacts that were not visible to the first pass.
    if !target_active || target_active != currently_active || record.revocation_pending {
        let result =
            match apply_active(&state, &context.storage_tenant, record, target_active, now).await {
                Ok(result) => result,
                Err(response) => return response,
            };
        record = result.record;
        if result.counts.is_some() {
            counts = result.counts;
        }
    }
    audit_mutation(
        &state,
        "replace",
        &context.audit_tenant,
        &record.user_id,
        record.credential_epoch,
        counts.as_ref(),
    )
    .await;
    if !target_active {
        audit_mutation(
            &state,
            "disable",
            &context.audit_tenant,
            &record.user_id,
            record.credential_epoch,
            counts.as_ref(),
        )
        .await;
    }
    scim_json(StatusCode::OK, user_json(&record, &context.base_url))
}

#[derive(Deserialize)]
struct PatchRequest {
    #[serde(default)]
    schemas: Vec<String>,
    #[serde(rename = "Operations")]
    operations: Vec<PatchOperation>,
}

#[derive(Deserialize)]
struct PatchOperation {
    op: String,
    path: Option<String>,
    value: Value,
}

fn parse_patch(body: &[u8]) -> Result<bool, Box<Response>> {
    let patch: PatchRequest = serde_json::from_slice(body).map_err(|_| {
        Box::new(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidSyntax"),
            "malformed PatchOp",
        ))
    })?;
    if !has_schema(&patch.schemas, PATCH_SCHEMA) || patch.operations.is_empty() {
        return Err(Box::new(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidSyntax"),
            "PatchOp schema and Operations are required",
        )));
    }
    let mut active = None;
    for operation in patch.operations {
        if !operation.op.eq_ignore_ascii_case("replace")
            && !operation.op.eq_ignore_ascii_case("add")
        {
            return Err(Box::new(scim_error(
                StatusCode::BAD_REQUEST,
                Some("invalidSyntax"),
                "only add and replace are supported",
            )));
        }
        let value = match operation.path.as_deref() {
            Some(path) if path.eq_ignore_ascii_case("active") => operation.value.as_bool(),
            Some(_) => {
                return Err(Box::new(scim_error(
                    StatusCode::BAD_REQUEST,
                    Some("invalidPath"),
                    "only the active path is supported",
                )))
            }
            None => {
                let object = operation.value.as_object().ok_or_else(|| {
                    Box::new(scim_error(
                        StatusCode::BAD_REQUEST,
                        Some("invalidValue"),
                        "pathless active value must be an object",
                    ))
                })?;
                if object.len() != 1 {
                    return Err(Box::new(scim_error(
                        StatusCode::BAD_REQUEST,
                        Some("invalidPath"),
                        "only the active path is supported",
                    )));
                }
                let (attribute, value) = object.iter().next().expect("one PatchOp attribute");
                if !attribute.eq_ignore_ascii_case("active") {
                    return Err(Box::new(scim_error(
                        StatusCode::BAD_REQUEST,
                        Some("invalidPath"),
                        "only the active path is supported",
                    )));
                }
                value.as_bool()
            }
        }
        .ok_or_else(|| {
            Box::new(scim_error(
                StatusCode::BAD_REQUEST,
                Some("invalidValue"),
                "active must be Boolean",
            ))
        })?;
        active = Some(value);
    }
    active.ok_or_else(|| {
        Box::new(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidPath"),
            "active operation is required",
        ))
    })
}

#[utoipa::path(
    patch,
    path = "/scim/v2/Users/{id}",
    tag = "scim",
    params(("id" = String, Path)),
    request_body(content = Value, content_type = "application/scim+json"),
    responses(
        (status = 200, description = "SCIM User lifecycle updated", content_type = "application/scim+json"),
        (status = 400, description = "Invalid or unsupported PatchOp", content_type = "application/scim+json"),
        (status = 401, description = "Missing or invalid tenant SCIM bearer", content_type = "application/scim+json"),
        (status = 404, description = "SCIM User not found in this tenant", content_type = "application/scim+json"),
        (status = 409, description = "Tombstoned identity cannot be rebound", content_type = "application/scim+json"),
        (status = 503, description = "SCIM persistence or lifecycle unavailable", content_type = "application/scim+json")
    )
)]
async fn patch_user(
    context: ScimContext,
    State(state): State<AppState>,
    path: Result<Path<String>, PathRejection>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let id = match scim_user_id(path) {
        Ok(id) => id,
        Err(response) => return *response,
    };
    let body = match scim_request_body(body) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let active = match parse_patch(&body) {
        Ok(active) => active,
        Err(response) => return *response,
    };
    let now = crate::token::current_unix_secs_pub();
    let mut result =
        match load_scim_user_after_initial_lifecycle(&state, &context.storage_tenant, &id, now)
            .await
        {
            Ok(result) => result,
            Err(response) => return response,
        };
    if let Some(counts) = result.counts.take() {
        audit_mutation(
            &state,
            "disable",
            &context.audit_tenant,
            &result.record.user_id,
            result.record.credential_epoch,
            Some(&counts),
        )
        .await;
    }
    let currently_active =
        result.record.status == UserStatus::Active && !result.record.revocation_pending;
    // Re-run the same disable generation for an explicit active=false retry.
    // begin_disable preserves the epoch for an already Disabled user.
    if !active || active != currently_active || result.record.revocation_pending {
        let applied =
            match apply_active(&state, &context.storage_tenant, result.record, active, now).await {
                Ok(applied) => applied,
                Err(response) => return response,
            };
        result.record = applied.record;
        if applied.counts.is_some() {
            result.counts = applied.counts;
        }
    }
    audit_mutation(
        &state,
        if active { "enable" } else { "disable" },
        &context.audit_tenant,
        &result.record.user_id,
        result.record.credential_epoch,
        result.counts.as_ref(),
    )
    .await;
    scim_json(StatusCode::OK, user_json(&result.record, &context.base_url))
}

async fn scim_method_not_allowed(_context: ScimContext) -> Response {
    scim_error(
        StatusCode::METHOD_NOT_ALLOWED,
        None,
        "SCIM method not supported",
    )
}

async fn scim_not_found(_context: ScimContext) -> Response {
    scim_error(StatusCode::NOT_FOUND, None, "SCIM resource not found")
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(
            routes!(service_provider_config).map(|router| router.fallback(scim_method_not_allowed)),
        )
        .routes(
            routes!(list_users, create_user).map(|router| router.fallback(scim_method_not_allowed)),
        )
        .routes(
            routes!(get_user, replace_user, patch_user)
                .map(|router| router.fallback(scim_method_not_allowed)),
        )
        .merge(crate::scim_groups::scim_router())
        .route("/scim/v2", axum::routing::any(scim_not_found))
        .route("/scim/v2/{*path}", axum::routing::any(scim_not_found))
}

#[cfg(test)]
mod tests {
    use super::{normalize_user_name, parse_filter, parse_patch, Filter, PATCH_SCHEMA};
    use serde_json::json;

    #[test]
    fn user_name_normalization_rejects_ambiguous_values() {
        assert_eq!(
            normalize_user_name(" Alice@Example.COM "),
            Some("alice@example.com".to_string())
        );
        for value in ["", "alice", "a@@example.com", "a @example.com", "a@example"] {
            assert_eq!(normalize_user_name(value), None, "{value}");
        }
    }

    #[test]
    fn filter_parser_accepts_only_supported_eq_grammar() {
        match parse_filter(r#"EXTERNALID  EQ  "directory\u002d001""#) {
            Some(Filter::ExternalId(value)) => assert_eq!(value, "directory-001"),
            _ => panic!("supported externalId filter was rejected"),
        }
        match parse_filter(r#"username eq "Alice@Example.com""#) {
            Some(Filter::UserName(value)) => assert_eq!(value, "Alice@Example.com"),
            _ => panic!("supported userName filter was rejected"),
        }
        for filter in [
            r#"userName sw "alice""#,
            r#"displayName eq "Alice""#,
            r#"userName eq "alice" trailing"#,
        ] {
            assert!(parse_filter(filter).is_none(), "{filter}");
        }
    }

    #[test]
    fn patch_validation_happens_before_reducing_operations() {
        let valid = json!({
            "schemas": [PATCH_SCHEMA],
            "Operations": [
                {"op": "replace", "path": "active", "value": false},
                {"op": "add", "value": {"active": true}}
            ]
        });
        assert!(parse_patch(valid.to_string().as_bytes()).unwrap());

        let invalid = json!({
            "schemas": [PATCH_SCHEMA],
            "Operations": [
                {"op": "replace", "path": "active", "value": false},
                {"op": "replace", "path": "displayName", "value": "Alice"}
            ]
        });
        assert!(parse_patch(invalid.to_string().as_bytes()).is_err());
    }
}
