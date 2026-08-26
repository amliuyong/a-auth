use axum::{
    body::Bytes,
    extract::{
        rejection::{BytesRejection, JsonRejection, PathRejection},
        Path, RawQuery, State,
    },
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use utoipa::ToSchema;
use utoipa_axum::{
    router::{OpenApiRouter, UtoipaMethodRouterExt},
    routes,
};

use crate::ports::{
    ScimGroupChange, ScimGroupCreateInput, ScimGroupCreateOutcome, ScimGroupDeleteOutcome,
    ScimGroupMutation, ScimGroupMutationOutcome, ScimGroupRecord, ScimGroupsStore,
    ScimRoleMappingOutcome, TenantRole, UserStatus, UsersStore, SCIM_GROUP_MAX_MEMBERS,
};
use crate::scim::{
    parse_eq_filter, resource_location, scim_error, scim_json, scim_json_with_headers,
    scim_request_body, store_error, unix_rfc3339, ScimContext,
};
use crate::state::AppState;
use crate::tenant_admin::{AdminAction, TenantAdminContext};

const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

fn group_json(record: &ScimGroupRecord, base_url: &str) -> Value {
    let members: Vec<_> = record
        .members
        .iter()
        .map(|user_id| {
            json!({
                "value": user_id,
                "$ref": resource_location(base_url, "Users", user_id),
                "type": "User"
            })
        })
        .collect();
    json!({
        "schemas": [GROUP_SCHEMA],
        "id": record.group_id,
        "externalId": record.external_id,
        "displayName": record.display_name,
        "members": members,
        "meta": {
            "resourceType": "Group",
            "created": unix_rfc3339(record.created_at),
            "lastModified": unix_rfc3339(record.updated_at),
            "location": resource_location(base_url, "Groups", &record.group_id)
        }
    })
}

fn group_id(path: Result<Path<String>, PathRejection>) -> Result<String, Box<Response>> {
    path.map(|Path(id)| id).map_err(|_| {
        Box::new(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "invalid SCIM Group id",
        ))
    })
}

fn valid_text(value: &str, max_len: usize) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= max_len
        && !value.chars().any(|character| character.is_control()))
    .then(|| value.to_string())
}

fn valid_identifier(value: &str, max_len: usize) -> Option<String> {
    (!value.trim().is_empty()
        && value.len() <= max_len
        && !value.chars().any(|character| character.is_control()))
    .then(|| value.to_string())
}

#[derive(Clone, Deserialize)]
struct GroupMemberInput {
    value: String,
    #[serde(rename = "type")]
    member_type: Option<String>,
}

#[derive(Deserialize)]
struct GroupRequest {
    #[serde(default)]
    schemas: Vec<String>,
    #[serde(rename = "externalId")]
    external_id: String,
    #[serde(rename = "displayName")]
    display_name: String,
    #[serde(default)]
    members: Vec<GroupMemberInput>,
}

struct ValidGroupRequest {
    external_id: String,
    display_name: String,
    members: Vec<String>,
}

fn parse_members(members: Vec<GroupMemberInput>) -> Result<Vec<String>, Box<Response>> {
    let mut values = Vec::with_capacity(members.len());
    for member in members {
        if member
            .member_type
            .as_deref()
            .is_some_and(|kind| !kind.eq_ignore_ascii_case("User"))
        {
            return Err(Box::new(scim_error(
                StatusCode::BAD_REQUEST,
                Some("invalidValue"),
                "only User Group members are supported",
            )));
        }
        let value = valid_identifier(&member.value, 512).ok_or_else(|| {
            Box::new(scim_error(
                StatusCode::BAD_REQUEST,
                Some("invalidValue"),
                "Group member value must be a non-empty User id",
            ))
        })?;
        values.push(value);
    }
    values.sort();
    values.dedup();
    if values.len() > SCIM_GROUP_MAX_MEMBERS {
        return Err(Box::new(scim_error(
            StatusCode::BAD_REQUEST,
            Some("tooMany"),
            "Group exceeds the supported member limit",
        )));
    }
    Ok(values)
}

fn parse_group_request(body: &[u8]) -> Result<ValidGroupRequest, Box<Response>> {
    let value: Value = serde_json::from_slice(body).map_err(|_| {
        Box::new(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidSyntax"),
            "malformed SCIM Group",
        ))
    })?;
    if value.as_object().is_some_and(|object| {
        object.keys().any(|attribute| {
            attribute.eq_ignore_ascii_case("role")
                || attribute.eq_ignore_ascii_case("roles")
                || attribute.eq_ignore_ascii_case("tenantRole")
        })
    }) {
        return Err(Box::new(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidPath"),
            "tenant roles cannot be supplied through SCIM",
        )));
    }
    let request: GroupRequest = serde_json::from_value(value).map_err(|_| {
        Box::new(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidSyntax"),
            "malformed SCIM Group",
        ))
    })?;
    if !request.schemas.iter().any(|schema| schema == GROUP_SCHEMA) {
        return Err(Box::new(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidSyntax"),
            "SCIM Group schema is required",
        )));
    }
    let external_id = valid_identifier(&request.external_id, 256).ok_or_else(|| {
        Box::new(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "externalId must be a non-empty stable identifier",
        ))
    })?;
    let display_name = valid_text(&request.display_name, 256).ok_or_else(|| {
        Box::new(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "displayName must be non-empty",
        ))
    })?;
    Ok(ValidGroupRequest {
        external_id,
        display_name,
        members: parse_members(request.members)?,
    })
}

async fn validate_member_users(
    state: &AppState,
    tenant: &str,
    members: &[String],
) -> Result<(), Response> {
    for user_id in members {
        match state.users.get_by_id(tenant, user_id).await {
            Ok(Some(user))
                if user.scim_external_id.is_some() && user.status != UserStatus::Tombstoned => {}
            Ok(_) => {
                return Err(scim_error(
                    StatusCode::BAD_REQUEST,
                    Some("invalidValue"),
                    "Group member must reference a tenant-local SCIM User",
                ))
            }
            Err(error) => return Err(store_error(error)),
        }
    }
    Ok(())
}

fn group_response(status: StatusCode, record: &ScimGroupRecord, base_url: &str) -> Response {
    let location = resource_location(base_url, "Groups", &record.group_id);
    match HeaderValue::from_str(&location) {
        Ok(value) => scim_json_with_headers(
            status,
            group_json(record, base_url),
            [(header::LOCATION, value)],
        ),
        Err(_) => scim_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            None,
            "invalid resource location",
        ),
    }
}

#[utoipa::path(
    post,
    path = "/scim/v2/Groups",
    tag = "scim",
    request_body(content = Value, content_type = "application/scim+json"),
    responses(
        (status = 200, description = "Idempotent retry returned the existing Group", content_type = "application/scim+json"),
        (status = 201, description = "Group provisioned", content_type = "application/scim+json"),
        (status = 400, description = "Invalid Group or member reference", content_type = "application/scim+json"),
        (status = 401, description = "Missing or invalid tenant SCIM bearer", content_type = "application/scim+json"),
        (status = 409, description = "externalId is already bound to a different Group representation", content_type = "application/scim+json"),
        (status = 503, description = "SCIM persistence unavailable", content_type = "application/scim+json")
    )
)]
async fn create_group(
    context: ScimContext,
    State(state): State<AppState>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match scim_request_body(body) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let request = match parse_group_request(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    if let Err(response) =
        validate_member_users(&state, &context.storage_tenant, &request.members).await
    {
        return response;
    }
    let input = ScimGroupCreateInput {
        group_id: format!("group:scim:{}", crate::login::rand_id(24)),
        external_id: request.external_id,
        display_name: request.display_name,
        members: request.members,
        now: crate::token::current_unix_secs_pub(),
    };
    let expected_display_name = input.display_name.clone();
    let expected_members = input.members.clone();
    match state
        .scim_groups
        .create(&context.storage_tenant, input)
        .await
    {
        Ok(ScimGroupCreateOutcome::Created(record)) => {
            group_response(StatusCode::CREATED, &record, &context.base_url)
        }
        Ok(ScimGroupCreateOutcome::Existing(record))
            if record.display_name == expected_display_name
                && record.members == expected_members =>
        {
            group_response(StatusCode::OK, &record, &context.base_url)
        }
        Ok(ScimGroupCreateOutcome::Existing(_)) => scim_error(
            StatusCode::CONFLICT,
            Some("uniqueness"),
            "externalId is already bound to a different Group representation",
        ),
        Err(error) => store_error(error),
    }
}

#[utoipa::path(
    get,
    path = "/scim/v2/Groups/{id}",
    tag = "scim",
    params(("id" = String, Path)),
    responses(
        (status = 200, description = "Tenant-local SCIM Group", content_type = "application/scim+json"),
        (status = 401, description = "Missing or invalid tenant SCIM bearer", content_type = "application/scim+json"),
        (status = 404, description = "SCIM Group not found", content_type = "application/scim+json"),
        (status = 503, description = "SCIM persistence unavailable", content_type = "application/scim+json")
    )
)]
async fn get_group(
    context: ScimContext,
    State(state): State<AppState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let id = match group_id(path) {
        Ok(id) => id,
        Err(response) => return *response,
    };
    match state.scim_groups.get(&context.storage_tenant, &id).await {
        Ok(Some(record)) => scim_json(StatusCode::OK, group_json(&record, &context.base_url)),
        Ok(None) => scim_error(StatusCode::NOT_FOUND, None, "SCIM Group not found"),
        Err(error) => store_error(error),
    }
}

#[derive(Default, Deserialize)]
struct GroupListQuery {
    filter: Option<String>,
    #[serde(rename = "startIndex")]
    start_index: Option<i64>,
    count: Option<i64>,
}

fn parse_external_id_filter(filter: &str) -> Option<String> {
    let (attribute, value) = parse_eq_filter(filter)?;
    (attribute == "externalid").then_some(value)
}

#[utoipa::path(
    get,
    path = "/scim/v2/Groups",
    tag = "scim",
    params(
        ("filter" = Option<String>, Query, description = "externalId eq"),
        ("startIndex" = Option<i64>, Query, description = "One-based result offset"),
        ("count" = Option<i64>, Query, description = "Requested page size, capped at 100")
    ),
    responses(
        (status = 200, description = "SCIM Group ListResponse", content_type = "application/scim+json"),
        (status = 400, description = "Invalid filter or pagination", content_type = "application/scim+json"),
        (status = 401, description = "Missing or invalid tenant SCIM bearer", content_type = "application/scim+json"),
        (status = 503, description = "SCIM persistence unavailable", content_type = "application/scim+json")
    )
)]
async fn list_groups(
    context: ScimContext,
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let query: GroupListQuery = match raw_query {
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
        None => GroupListQuery::default(),
    };
    let start_index = query.start_index.unwrap_or(1).max(1);
    let count = query.count.unwrap_or(100).max(0);
    let offset = usize::try_from(start_index.saturating_sub(1)).unwrap_or(usize::MAX);
    let limit = usize::try_from(count.min(100)).unwrap_or(0);
    let result = match query.filter.as_deref() {
        Some(filter) => {
            let Some(external_id) = parse_external_id_filter(filter) else {
                return scim_error(
                    StatusCode::BAD_REQUEST,
                    Some("invalidFilter"),
                    "unsupported SCIM Group filter",
                );
            };
            state
                .scim_groups
                .get_by_external_id(&context.storage_tenant, &external_id)
                .await
                .map(|record| {
                    let records: Vec<_> = record.into_iter().collect();
                    let total = records.len();
                    (
                        records.into_iter().skip(offset).take(limit).collect(),
                        total,
                    )
                })
        }
        None => {
            state
                .scim_groups
                .list(&context.storage_tenant, offset, limit)
                .await
        }
    };
    let (records, total_results) = match result {
        Ok(result) => result,
        Err(error) => return store_error(error),
    };
    let resources: Vec<_> = records
        .iter()
        .map(|record| group_json(record, &context.base_url))
        .collect();
    scim_json(
        StatusCode::OK,
        json!({
            "schemas": [LIST_SCHEMA],
            "totalResults": total_results,
            "startIndex": start_index,
            "itemsPerPage": resources.len(),
            "Resources": resources
        }),
    )
}

fn mutation_response(
    outcome: Result<ScimGroupMutationOutcome, crate::ports::StoreError>,
    base_url: &str,
) -> Response {
    match outcome {
        Ok(ScimGroupMutationOutcome::Updated(record)) => {
            scim_json(StatusCode::OK, group_json(&record, base_url))
        }
        Ok(ScimGroupMutationOutcome::NotFound) => {
            scim_error(StatusCode::NOT_FOUND, None, "SCIM Group not found")
        }
        Ok(ScimGroupMutationOutcome::TooManyMembers) => scim_error(
            StatusCode::BAD_REQUEST,
            Some("tooMany"),
            "Group exceeds the supported member limit",
        ),
        Err(error) => store_error(error),
    }
}

#[utoipa::path(
    put,
    path = "/scim/v2/Groups/{id}",
    tag = "scim",
    params(("id" = String, Path)),
    request_body(content = Value, content_type = "application/scim+json"),
    responses(
        (status = 200, description = "SCIM Group replaced", content_type = "application/scim+json"),
        (status = 400, description = "Invalid Group or member reference", content_type = "application/scim+json"),
        (status = 401, description = "Missing or invalid tenant SCIM bearer", content_type = "application/scim+json"),
        (status = 404, description = "SCIM Group not found", content_type = "application/scim+json"),
        (status = 503, description = "SCIM persistence unavailable", content_type = "application/scim+json")
    )
)]
async fn replace_group(
    context: ScimContext,
    State(state): State<AppState>,
    path: Result<Path<String>, PathRejection>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let id = match group_id(path) {
        Ok(id) => id,
        Err(response) => return *response,
    };
    let current = match state.scim_groups.get(&context.storage_tenant, &id).await {
        Ok(Some(current)) => current,
        Ok(None) => return scim_error(StatusCode::NOT_FOUND, None, "SCIM Group not found"),
        Err(error) => return store_error(error),
    };
    let body = match scim_request_body(body) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let request = match parse_group_request(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    if request.external_id != current.external_id {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("mutability"),
            "Group externalId is immutable",
        );
    }
    if let Err(response) =
        validate_member_users(&state, &context.storage_tenant, &request.members).await
    {
        return response;
    }
    mutation_response(
        state
            .scim_groups
            .mutate(
                &context.storage_tenant,
                &id,
                ScimGroupMutation::Replace {
                    display_name: request.display_name,
                    members: request.members,
                    now: crate::token::current_unix_secs_pub(),
                },
            )
            .await,
        &context.base_url,
    )
}

#[derive(Deserialize)]
struct GroupPatchRequest {
    #[serde(default)]
    schemas: Vec<String>,
    #[serde(rename = "Operations")]
    operations: Vec<GroupPatchOperation>,
}

#[derive(Deserialize)]
struct GroupPatchOperation {
    op: String,
    path: Option<String>,
    #[serde(default)]
    value: Value,
}

fn members_from_value(value: Value) -> Result<Vec<String>, Box<Response>> {
    let members: Vec<GroupMemberInput> = serde_json::from_value(value).map_err(|_| {
        Box::new(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "members must be an array of User references",
        ))
    })?;
    parse_members(members)
}

fn member_filter_value(path: &str) -> Option<String> {
    let path = path.trim();
    let open = path.find('[')?;
    if !path[..open].eq_ignore_ascii_case("members") || !path.ends_with(']') {
        return None;
    }
    let expression = path[open + 1..path.len() - 1].trim();
    let mut parts = expression.splitn(2, char::is_whitespace);
    if !parts.next()?.eq_ignore_ascii_case("value") {
        return None;
    }
    let remainder = parts.next()?.trim_start();
    let mut parts = remainder.splitn(2, char::is_whitespace);
    if !parts.next()?.eq_ignore_ascii_case("eq") {
        return None;
    }
    serde_json::from_str(parts.next()?.trim()).ok()
}

fn parse_group_patch(body: &[u8]) -> Result<Vec<ScimGroupChange>, Box<Response>> {
    let patch: GroupPatchRequest = serde_json::from_slice(body).map_err(|_| {
        Box::new(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidSyntax"),
            "malformed PatchOp",
        ))
    })?;
    if !patch.schemas.iter().any(|schema| schema == PATCH_SCHEMA) || patch.operations.is_empty() {
        return Err(Box::new(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidSyntax"),
            "PatchOp schema and Operations are required",
        )));
    }
    let mut changes = Vec::new();
    for operation in patch.operations {
        let op = operation.op.to_ascii_lowercase();
        if !matches!(op.as_str(), "add" | "replace" | "remove") {
            return Err(Box::new(scim_error(
                StatusCode::BAD_REQUEST,
                Some("invalidSyntax"),
                "only add, replace, and remove are supported",
            )));
        }
        match operation.path.as_deref().map(str::trim) {
            Some(path) if path.eq_ignore_ascii_case("displayName") => {
                if op == "remove" {
                    return Err(Box::new(scim_error(
                        StatusCode::BAD_REQUEST,
                        Some("mutability"),
                        "displayName cannot be removed",
                    )));
                }
                let display_name = operation
                    .value
                    .as_str()
                    .and_then(|value| valid_text(value, 256))
                    .ok_or_else(|| {
                        Box::new(scim_error(
                            StatusCode::BAD_REQUEST,
                            Some("invalidValue"),
                            "displayName must be non-empty",
                        ))
                    })?;
                changes.push(ScimGroupChange::SetDisplayName(display_name));
            }
            Some(path) if path.eq_ignore_ascii_case("members") => match op.as_str() {
                "add" => changes.push(ScimGroupChange::AddMembers(members_from_value(
                    operation.value,
                )?)),
                "replace" => changes.push(ScimGroupChange::ReplaceMembers(members_from_value(
                    operation.value,
                )?)),
                "remove" => changes.push(ScimGroupChange::ReplaceMembers(Vec::new())),
                _ => unreachable!(),
            },
            Some(path) => {
                if op == "remove" {
                    if let Some(member) = member_filter_value(path) {
                        changes.push(ScimGroupChange::RemoveMembers(vec![member]));
                        continue;
                    }
                }
                return Err(Box::new(scim_error(
                    StatusCode::BAD_REQUEST,
                    Some("invalidPath"),
                    "unsupported SCIM Group path",
                )));
            }
            None => {
                if op == "remove" {
                    return Err(Box::new(scim_error(
                        StatusCode::BAD_REQUEST,
                        Some("invalidPath"),
                        "remove requires a Group attribute path",
                    )));
                }
                let object = operation.value.as_object().ok_or_else(|| {
                    Box::new(scim_error(
                        StatusCode::BAD_REQUEST,
                        Some("invalidValue"),
                        "pathless Group value must be an object",
                    ))
                })?;
                if object.is_empty() {
                    return Err(Box::new(scim_error(
                        StatusCode::BAD_REQUEST,
                        Some("invalidValue"),
                        "pathless Group value must contain an attribute",
                    )));
                }
                for (attribute, value) in object {
                    if attribute.eq_ignore_ascii_case("displayName") {
                        let display_name = value
                            .as_str()
                            .and_then(|value| valid_text(value, 256))
                            .ok_or_else(|| {
                                Box::new(scim_error(
                                    StatusCode::BAD_REQUEST,
                                    Some("invalidValue"),
                                    "displayName must be non-empty",
                                ))
                            })?;
                        changes.push(ScimGroupChange::SetDisplayName(display_name));
                    } else if attribute.eq_ignore_ascii_case("members") {
                        let members = members_from_value(value.clone())?;
                        changes.push(if op == "add" {
                            ScimGroupChange::AddMembers(members)
                        } else {
                            ScimGroupChange::ReplaceMembers(members)
                        });
                    } else {
                        return Err(Box::new(scim_error(
                            StatusCode::BAD_REQUEST,
                            Some("invalidPath"),
                            "unsupported SCIM Group attribute",
                        )));
                    }
                }
            }
        }
    }
    Ok(changes)
}

async fn validate_patch_members(
    state: &AppState,
    tenant: &str,
    changes: &[ScimGroupChange],
) -> Result<(), Response> {
    for change in changes {
        match change {
            ScimGroupChange::AddMembers(members) | ScimGroupChange::ReplaceMembers(members) => {
                validate_member_users(state, tenant, members).await?
            }
            ScimGroupChange::SetDisplayName(_) | ScimGroupChange::RemoveMembers(_) => {}
        }
    }
    Ok(())
}

#[utoipa::path(
    patch,
    path = "/scim/v2/Groups/{id}",
    tag = "scim",
    params(("id" = String, Path)),
    request_body(content = Value, content_type = "application/scim+json"),
    responses(
        (status = 200, description = "SCIM Group patched", content_type = "application/scim+json"),
        (status = 400, description = "Invalid PatchOp or member reference", content_type = "application/scim+json"),
        (status = 401, description = "Missing or invalid tenant SCIM bearer", content_type = "application/scim+json"),
        (status = 404, description = "SCIM Group not found", content_type = "application/scim+json"),
        (status = 503, description = "SCIM persistence unavailable", content_type = "application/scim+json")
    )
)]
async fn patch_group(
    context: ScimContext,
    State(state): State<AppState>,
    path: Result<Path<String>, PathRejection>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let id = match group_id(path) {
        Ok(id) => id,
        Err(response) => return *response,
    };
    match state.scim_groups.get(&context.storage_tenant, &id).await {
        Ok(Some(_)) => {}
        Ok(None) => return scim_error(StatusCode::NOT_FOUND, None, "SCIM Group not found"),
        Err(error) => return store_error(error),
    }
    let body = match scim_request_body(body) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let changes = match parse_group_patch(&body) {
        Ok(changes) => changes,
        Err(response) => return *response,
    };
    if let Err(response) = validate_patch_members(&state, &context.storage_tenant, &changes).await {
        return response;
    }
    mutation_response(
        state
            .scim_groups
            .mutate(
                &context.storage_tenant,
                &id,
                ScimGroupMutation::Patch {
                    changes,
                    now: crate::token::current_unix_secs_pub(),
                },
            )
            .await,
        &context.base_url,
    )
}

#[utoipa::path(
    delete,
    path = "/scim/v2/Groups/{id}",
    tag = "scim",
    params(("id" = String, Path)),
    responses(
        (status = 204, description = "SCIM Group deleted"),
        (status = 401, description = "Missing or invalid tenant SCIM bearer", content_type = "application/scim+json"),
        (status = 404, description = "SCIM Group not found", content_type = "application/scim+json"),
        (status = 503, description = "SCIM persistence unavailable", content_type = "application/scim+json")
    )
)]
async fn delete_group(
    context: ScimContext,
    State(state): State<AppState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let id = match group_id(path) {
        Ok(id) => id,
        Err(response) => return *response,
    };
    match state
        .scim_groups
        .delete(
            &context.storage_tenant,
            &id,
            crate::token::current_unix_secs_pub(),
        )
        .await
    {
        Ok(ScimGroupDeleteOutcome::Deleted) => StatusCode::NO_CONTENT.into_response(),
        Ok(ScimGroupDeleteOutcome::NotFound) => {
            scim_error(StatusCode::NOT_FOUND, None, "SCIM Group not found")
        }
        Err(error) => store_error(error),
    }
}

async fn scim_method_not_allowed(_context: ScimContext) -> Response {
    scim_error(
        StatusCode::METHOD_NOT_ALLOWED,
        None,
        "SCIM method not supported",
    )
}

pub fn scim_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(
            routes!(list_groups, create_group)
                .map(|router| router.fallback(scim_method_not_allowed)),
        )
        .routes(
            routes!(get_group, replace_group, patch_group, delete_group)
                .map(|router| router.fallback(scim_method_not_allowed)),
        )
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct RoleMappingRequest {
    role: TenantRole,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct RoleMappingList {
    mappings: Vec<crate::ports::ScimGroupRoleMapping>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct EffectiveRoleView {
    user_id: String,
    active: bool,
    role: Option<TenantRole>,
    mappings: Vec<crate::ports::ScimGroupRoleMapping>,
}

fn active_scim_epoch(user: &crate::ports::UserRecord) -> Option<u64> {
    (user.scim_external_id.is_some()
        && user.status == UserStatus::Active
        && !user.revocation_pending)
        .then_some(user.credential_epoch)
}

fn has_active_scim_epoch(user: &crate::ports::UserRecord, expected: u64) -> bool {
    active_scim_epoch(user) == Some(expected)
}

fn admin_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(json!({
            "status": status.as_u16(),
            "message": message
        })),
    )
        .into_response()
}

#[utoipa::path(
    get,
    path = "/admin/scim/group-role-mappings",
    tag = "admin",
    responses(
        (status = 200, description = "Explicit SCIM Group to tenant-role mappings", body = RoleMappingList),
        (status = 401, description = "Tenant admin authentication failed"),
        (status = 503, description = "Group mapping store unavailable")
    )
)]
async fn list_role_mappings(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Read).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    match state
        .scim_groups
        .list_role_mappings(admin.storage_tenant())
        .await
    {
        Ok(mappings) => Json(RoleMappingList { mappings }).into_response(),
        Err(_) => admin_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Group mapping store unavailable",
        ),
    }
}

#[utoipa::path(
    put,
    path = "/admin/scim/group-role-mappings/{externalId}",
    tag = "admin",
    params(("externalId" = String, Path)),
    request_body = RoleMappingRequest,
    responses(
        (status = 200, description = "Role mapping created or replaced", body = crate::ports::ScimGroupRoleMapping),
        (status = 400, description = "Unknown or malformed fixed tenant role"),
        (status = 401, description = "Tenant admin authentication failed"),
        (status = 404, description = "Active tenant-local SCIM Group not found"),
        (status = 503, description = "Group mapping store unavailable")
    )
)]
async fn put_role_mapping(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(external_id): Path<String>,
    request: Result<Json<RoleMappingRequest>, JsonRejection>,
) -> Response {
    let admin =
        match TenantAdminContext::authenticate(&state, &headers, AdminAction::ManageAccess).await {
            Ok(admin) => admin,
            Err(response) => return response,
        };
    let Json(request) = match request {
        Ok(request) => request,
        Err(_) => {
            return admin_error(
                StatusCode::BAD_REQUEST,
                "role must be owner, admin, auditor, or member",
            )
        }
    };
    match state
        .scim_groups
        .set_role_mapping(
            admin.storage_tenant(),
            &external_id,
            Some(request.role),
            crate::token::current_unix_secs_pub(),
        )
        .await
    {
        Ok(ScimRoleMappingOutcome::Updated(mapping)) => Json(mapping).into_response(),
        Ok(ScimRoleMappingOutcome::GroupNotFound) => admin_error(
            StatusCode::NOT_FOUND,
            "active tenant-local SCIM Group not found",
        ),
        Ok(ScimRoleMappingOutcome::Removed) => admin_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "unexpected Group mapping result",
        ),
        Err(_) => admin_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Group mapping store unavailable",
        ),
    }
}

#[utoipa::path(
    delete,
    path = "/admin/scim/group-role-mappings/{externalId}",
    tag = "admin",
    params(("externalId" = String, Path)),
    responses(
        (status = 204, description = "Role mapping removed"),
        (status = 401, description = "Tenant admin authentication failed"),
        (status = 404, description = "Active tenant-local SCIM Group not found"),
        (status = 503, description = "Group mapping store unavailable")
    )
)]
async fn delete_role_mapping(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(external_id): Path<String>,
) -> Response {
    let admin =
        match TenantAdminContext::authenticate(&state, &headers, AdminAction::ManageAccess).await {
            Ok(admin) => admin,
            Err(response) => return response,
        };
    match state
        .scim_groups
        .set_role_mapping(
            admin.storage_tenant(),
            &external_id,
            None,
            crate::token::current_unix_secs_pub(),
        )
        .await
    {
        Ok(ScimRoleMappingOutcome::Removed) => StatusCode::NO_CONTENT.into_response(),
        Ok(ScimRoleMappingOutcome::GroupNotFound) => admin_error(
            StatusCode::NOT_FOUND,
            "active tenant-local SCIM Group not found",
        ),
        Ok(ScimRoleMappingOutcome::Updated(_)) => admin_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "unexpected Group mapping result",
        ),
        Err(_) => admin_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Group mapping store unavailable",
        ),
    }
}

#[utoipa::path(
    get,
    path = "/admin/scim/effective-role/{userId}",
    tag = "admin",
    params(("userId" = String, Path)),
    responses(
        (status = 200, description = "Effective role derived only from explicit active Group mappings", body = EffectiveRoleView),
        (status = 401, description = "Tenant admin authentication failed"),
        (status = 404, description = "Tenant-local SCIM User not found"),
        (status = 503, description = "User or Group mapping store unavailable")
    )
)]
async fn effective_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Response {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Read).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let tenant = admin.storage_tenant();
    for _ in 0..3 {
        let user = match state.users.get_by_id(tenant, &user_id).await {
            Ok(Some(user))
                if user.scim_external_id.is_some() && user.status != UserStatus::Tombstoned =>
            {
                user
            }
            Ok(_) => return admin_error(StatusCode::NOT_FOUND, "tenant-local SCIM User not found"),
            Err(_) => {
                return admin_error(StatusCode::SERVICE_UNAVAILABLE, "User store unavailable")
            }
        };
        let Some(epoch) = active_scim_epoch(&user) else {
            return Json(EffectiveRoleView {
                user_id,
                active: false,
                role: None,
                mappings: Vec::new(),
            })
            .into_response();
        };
        let mapped = match state
            .scim_groups
            .mapped_role_for_member(tenant, &user_id)
            .await
        {
            Ok(mapped) => mapped,
            Err(_) => {
                return admin_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Group mapping store unavailable",
                )
            }
        };
        let latest = match state.users.get_by_id(tenant, &user_id).await {
            Ok(Some(user))
                if user.scim_external_id.is_some() && user.status != UserStatus::Tombstoned =>
            {
                user
            }
            Ok(_) => return admin_error(StatusCode::NOT_FOUND, "tenant-local SCIM User not found"),
            Err(_) => {
                return admin_error(StatusCode::SERVICE_UNAVAILABLE, "User store unavailable")
            }
        };
        if has_active_scim_epoch(&latest, epoch) {
            return Json(EffectiveRoleView {
                user_id,
                active: true,
                role: mapped.role,
                mappings: mapped.mappings,
            })
            .into_response();
        }
        if active_scim_epoch(&latest).is_none() {
            return Json(EffectiveRoleView {
                user_id,
                active: false,
                role: None,
                mappings: Vec::new(),
            })
            .into_response();
        }
    }
    admin_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "User lifecycle changed during role resolution",
    )
}

pub fn admin_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_role_mappings))
        .routes(routes!(put_role_mapping, delete_role_mapping))
        .routes(routes!(effective_role))
}

#[cfg(test)]
mod tests {
    use super::{
        active_scim_epoch, has_active_scim_epoch, member_filter_value, parse_external_id_filter,
        parse_group_patch, parse_group_request,
    };
    use crate::ports::{ScimGroupChange, UserRecord, UserStatus};
    use serde_json::json;
    use std::collections::BTreeMap;

    fn scim_user(epoch: u64, status: UserStatus, revocation_pending: bool) -> UserRecord {
        UserRecord {
            user_id: "user-1".into(),
            email: "user-1@example.com".into(),
            created_at: 1,
            updated_at: 1,
            last_login_at: None,
            status,
            credential_epoch: epoch,
            revocation_pending,
            scim_external_id: Some("directory-user-1".into()),
            scim_user_name: Some("user-1@example.com".into()),
            scim_display_name: None,
            attributes_generation: 0,
            attributes: BTreeMap::new(),
        }
    }

    #[test]
    fn group_filter_and_member_path_are_narrow() {
        assert_eq!(
            parse_external_id_filter(r#"EXTERNALID eq "directory-admins""#).as_deref(),
            Some("directory-admins")
        );
        assert!(parse_external_id_filter(r#"displayName eq "Admins""#).is_none());
        assert_eq!(
            member_filter_value(r#"members[value eq "user-1"]"#).as_deref(),
            Some("user-1")
        );
        assert!(member_filter_value(r#"members[type eq "User"]"#).is_none());

        let request = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "externalId": " directory-admins ",
            "displayName": "Directory Admins",
            "members": [{"value": " user-1 "}]
        });
        let parsed = parse_group_request(request.to_string().as_bytes()).unwrap();
        assert_eq!(parsed.external_id, " directory-admins ");
        assert_eq!(parsed.members, vec![" user-1 "]);
    }

    #[test]
    fn group_patch_rejects_platform_role_attributes() {
        let role_patch = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "replace",
                "path": "role",
                "value": "owner"
            }]
        });
        assert!(parse_group_patch(role_patch.to_string().as_bytes()).is_err());

        let member_patch = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "remove",
                "path": "members[value eq \"user-1\"]"
            }]
        });
        assert_eq!(
            parse_group_patch(member_patch.to_string().as_bytes()).unwrap(),
            vec![ScimGroupChange::RemoveMembers(vec!["user-1".into()])]
        );

        let empty_pathless_patch = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "replace",
                "value": {}
            }]
        });
        assert!(parse_group_patch(empty_pathless_patch.to_string().as_bytes()).is_err());
    }

    #[test]
    fn effective_role_requires_a_stable_active_user_generation() {
        assert_eq!(
            active_scim_epoch(&scim_user(7, UserStatus::Active, false)),
            Some(7)
        );
        assert_eq!(
            active_scim_epoch(&scim_user(8, UserStatus::Disabled, false)),
            None
        );
        assert_eq!(
            active_scim_epoch(&scim_user(8, UserStatus::Active, true)),
            None
        );
        assert!(has_active_scim_epoch(
            &scim_user(7, UserStatus::Active, false),
            7
        ));
        assert!(!has_active_scim_epoch(
            &scim_user(8, UserStatus::Active, false),
            7
        ));
    }
}
