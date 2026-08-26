//! Self-service credential inventory and mutation.
//!
//! Credential material never crosses this API. Passkeys are represented by
//! user-bound encrypted management handles, passwords by status only, and
//! recovery codes by an unused count.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use agent_auth_authn::{
    assurance::authentication_is_fresh,
    password::{validate_password, PasswordValue},
};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    credential::CredentialAuditEvent,
    ports::{
        CredentialChangeStart, GraceStore, PasskeyStore, PasswordCredential, PasswordStore,
        RecoveryStore, RefreshStore, SessionRecord, SessionStore, StoreError, UserStatus,
        UsersStore,
    },
    state::AppState,
};

pub(crate) const REAUTH_MAX_AGE_SECS: i64 = 300;

pub(crate) struct CredentialMutation {
    pub(crate) epoch: u64,
    pub(crate) operation_id: String,
}

impl CredentialMutation {
    pub(crate) fn owner(&self) -> crate::ports::CredentialChangeOwner<'_> {
        crate::ports::CredentialChangeOwner {
            epoch: self.epoch,
            operation_id: &self.operation_id,
        }
    }
}

pub(crate) fn credential_operation_id() -> String {
    let mut bytes = [0u8; 27];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccountPasswordStatus {
    NotConfigured,
    ChangeRequired,
    Active,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AccountPasskeyView {
    /// User-bound encrypted management handle, not the WebAuthn credential ID.
    pub id: String,
    pub name: String,
    /// Unknown for records created before credential-management metadata.
    pub created_at: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AccountCredentialSummary {
    pub passkeys: Vec<AccountPasskeyView>,
    pub password_status: AccountPasswordStatus,
    pub password_supported: bool,
    pub recovery_configured: bool,
    pub recovery_codes_remaining: u32,
    pub reauthenticated: bool,
    pub reauthenticate_after: i64,
}

#[derive(Deserialize, ToSchema)]
pub struct RenamePasskeyRequest {
    pub name: String,
}

#[derive(Deserialize, ToSchema)]
pub struct SetPasswordRequest {
    #[schema(value_type = String, format = Password)]
    pub new_password: PasswordValue,
}

fn no_store_json<T: Serialize>(status: StatusCode, body: T) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
}

fn store_error(error: StoreError) -> Response {
    match error {
        StoreError::Transient(_) => no_store_json(
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({ "error": "credential_store_unavailable" }),
        ),
        StoreError::Permanent(_) => no_store_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({ "error": "credential_store_error" }),
        ),
    }
}

async fn audit(
    state: &AppState,
    action: &'static str,
    tenant: &str,
    actor: &str,
    kind: &'static str,
    target: &str,
    result: &'static str,
) {
    state
        .audit_credential_event(CredentialAuditEvent::UserCredentialOperation {
            action,
            tenant,
            actor,
            kind,
            target,
            result,
        })
        .await;
}

fn handle_cipher(state: &AppState) -> Aes256Gcm {
    let mut digest = Sha256::new();
    digest.update(b"passkey-management-key:v1\0");
    digest.update(state.server_secret.as_slice());
    Aes256Gcm::new_from_slice(&digest.finalize()).expect("SHA-256 produces an AES-256 key")
}

fn handle_aad(tenant: &str, user_id: &str) -> Vec<u8> {
    let mut aad = b"passkey-management:v1\0".to_vec();
    aad.extend_from_slice(tenant.as_bytes());
    aad.push(0);
    aad.extend_from_slice(user_id.as_bytes());
    aad
}

fn passkey_handle(state: &AppState, tenant: &str, user_id: &str, credential_id: &str) -> String {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = handle_cipher(state)
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: credential_id.as_bytes(),
                aad: &handle_aad(tenant, user_id),
            },
        )
        .expect("bounded passkey id can be encrypted");
    let mut value = Vec::with_capacity(nonce.len() + ciphertext.len());
    value.extend_from_slice(&nonce);
    value.extend_from_slice(&ciphertext);
    URL_SAFE_NO_PAD.encode(value)
}

fn passkey_id_from_handle(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    handle: &str,
) -> Option<String> {
    if handle.len() > 1024 {
        return None;
    }
    let value = URL_SAFE_NO_PAD.decode(handle).ok()?;
    if value.len() <= 28 {
        return None;
    }
    let (nonce, ciphertext) = value.split_at(12);
    let plaintext = handle_cipher(state)
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &handle_aad(tenant, user_id),
            },
        )
        .ok()?;
    let credential_id = String::from_utf8(plaintext).ok()?;
    (!credential_id.is_empty() && credential_id.len() <= 768).then_some(credential_id)
}

pub(crate) fn session_is_reauthenticated(session: &SessionRecord, now: i64) -> bool {
    authentication_is_fresh(session.auth_time, now, REAUTH_MAX_AGE_SECS)
}

pub(crate) async fn require_fresh_session(
    state: &AppState,
    headers: &HeaderMap,
    action: &'static str,
    kind: &'static str,
) -> Result<(String, SessionRecord), Response> {
    let tenant = crate::tenant::tenant_or_400(state, headers)?;
    let Some(session) = crate::login::current_session_full(state, headers).await else {
        audit(state, action, &tenant, "anonymous", kind, "self", "denied").await;
        return Err(no_store_json(
            StatusCode::UNAUTHORIZED,
            serde_json::json!({ "error": "login_required" }),
        ));
    };
    if !session_is_reauthenticated(&session, crate::current_unix_secs()) {
        audit(
            state,
            action,
            &tenant,
            &session.user_id,
            kind,
            "self",
            "reauthentication_required",
        )
        .await;
        return Err(no_store_json(
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "error": "reauthentication_required",
                "max_age": REAUTH_MAX_AGE_SECS,
                "reauthenticate_url": "/login?next=%2Faccount"
            }),
        ));
    }
    Ok((tenant, session))
}

pub(crate) async fn consume_credential_session(
    state: &AppState,
    tenant: &str,
    session: &SessionRecord,
) -> Result<(), Response> {
    match state
        .sessions
        .revoke_all_by_actor(tenant, &session.user_id, &session.session_id)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(no_store_json(
            StatusCode::CONFLICT,
            serde_json::json!({ "error": "credential_change_conflict" }),
        )),
        Err(error) => Err(store_error(error)),
    }
}

async fn invalidate_prior_authentication(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    epoch: u64,
) {
    if let Err(error) = state
        .sessions
        .delete_by_user_before_epoch(tenant, user_id, epoch)
        .await
    {
        eprintln!(
            "CREDENTIAL_SESSION_CLEANUP_DEFERRED tenant={tenant} user_id={user_id} err={error:?}"
        );
    }
    let family_ids = match state
        .refresh
        .revoke_by_user_before_epoch(tenant, user_id, epoch)
        .await
    {
        Ok(family_ids) => family_ids,
        Err(error) => {
            eprintln!(
                "CREDENTIAL_REFRESH_CLEANUP_DEFERRED tenant={tenant} user_id={user_id} err={error:?}"
            );
            return;
        }
    };
    if let Some(grace) = &state.grace {
        for family_id in &family_ids {
            if let Err(error) = grace.delete_family(family_id).await {
                eprintln!(
                    "CREDENTIAL_GRACE_CLEANUP_DEFERRED tenant={tenant} \
                     user_id={user_id} family_id={family_id} err={error:?}"
                );
            }
        }
    }
}

pub(crate) async fn begin_credential_mutation(
    state: &AppState,
    tenant: &str,
    session: &SessionRecord,
) -> Result<CredentialMutation, Response> {
    let now = crate::current_unix_secs();
    let operation_id = credential_operation_id();
    let epoch = match state
        .users
        .begin_credential_change(
            tenant,
            &session.user_id,
            session.credential_epoch,
            &operation_id,
            now,
        )
        .await
    {
        Ok(CredentialChangeStart::Started { epoch }) => epoch,
        Ok(CredentialChangeStart::NotFound | CredentialChangeStart::Ineligible) => {
            return Err(clear_session(no_store_json(
                StatusCode::FORBIDDEN,
                serde_json::json!({ "error": "credential_change_not_allowed" }),
            )))
        }
        Ok(CredentialChangeStart::ConcurrentChange) => {
            return Err(clear_session(no_store_json(
                StatusCode::CONFLICT,
                serde_json::json!({ "error": "credential_change_conflict" }),
            )))
        }
        Err(error) => return Err(clear_session(store_error(error))),
    };
    if let Err(response) = consume_credential_session(state, tenant, session).await {
        abort_credential_mutation(
            state,
            tenant,
            &session.user_id,
            &CredentialMutation {
                epoch,
                operation_id,
            },
        )
        .await;
        return Err(clear_session(response));
    }
    invalidate_prior_authentication(state, tenant, &session.user_id, epoch).await;
    Ok(CredentialMutation {
        epoch,
        operation_id,
    })
}

pub(crate) async fn abort_credential_mutation(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    mutation: &CredentialMutation,
) {
    if let Err(error) = state
        .users
        .complete_credential_change(
            tenant,
            user_id,
            mutation.owner(),
            crate::current_unix_secs(),
        )
        .await
    {
        eprintln!(
            "CREDENTIAL_FENCE_RELEASE_DEFERRED tenant={tenant} user_id={user_id} \
             epoch={} err={error:?}",
            mutation.epoch
        );
    }
}

pub(crate) fn clear_session(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        crate::login::set_cookie(crate::login::SESSION_COOKIE, "", 0)
            .parse()
            .expect("session cookie is a valid header value"),
    );
    response
}

fn validate_passkey_name(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()
        && value.chars().count() <= 64
        && value.len() <= 256
        && !value.chars().any(char::is_control))
    .then(|| value.to_string())
}

/// List the current user's credential-management summary.
#[utoipa::path(
    get,
    path = "/account/credentials",
    tag = "account",
    responses(
        (status = 200, body = AccountCredentialSummary),
        (status = 401, description = "Login required"),
        (status = 503, description = "Credential store unavailable")
    )
)]
pub async fn credential_summary(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let Some(session) = crate::login::current_session_full(&state, &headers).await else {
        return no_store_json(
            StatusCode::UNAUTHORIZED,
            serde_json::json!({ "error": "login_required" }),
        );
    };
    let lookup = crate::recover::user_lookup(&session.user_id);
    let (user, passkeys, password, recovery) = tokio::join!(
        state.users.get_by_id(&tenant, &session.user_id),
        state.passkeys.list_by_user(&tenant, &session.user_id),
        state.passwords.get(&tenant, &session.user_id),
        state.recovery.get(&tenant, &lookup),
    );
    let user = match user {
        Ok(Some(user)) if user.status == UserStatus::Active => user,
        Ok(_) => {
            return no_store_json(
                StatusCode::UNAUTHORIZED,
                serde_json::json!({ "error": "login_required" }),
            )
        }
        Err(error) => return store_error(error),
    };
    let mut passkeys = match passkeys {
        Ok(passkeys) => passkeys,
        Err(error) => return store_error(error),
    };
    let password = match password {
        Ok(password) => password,
        Err(error) => return store_error(error),
    };
    let recovery = match recovery {
        Ok(recovery) => recovery,
        Err(error) => return store_error(error),
    };
    passkeys.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| left.name.cmp(&right.name))
    });
    let passkeys = passkeys
        .into_iter()
        .map(|passkey| AccountPasskeyView {
            id: passkey_handle(&state, &tenant, &session.user_id, &passkey.credential_id),
            name: passkey.name,
            created_at: (passkey.created_at > 0).then_some(passkey.created_at),
        })
        .collect();
    let password_status = match password {
        None => AccountPasswordStatus::NotConfigured,
        Some(password) if password.must_change || password.revocation_pending => {
            AccountPasswordStatus::ChangeRequired
        }
        Some(_) => AccountPasswordStatus::Active,
    };
    let recovery_codes_remaining = recovery.map_or(0, |record| {
        record
            .code_hashes
            .iter()
            .filter(|code| !code.consumed)
            .count() as u32
    });
    let now = crate::current_unix_secs();
    audit(
        &state,
        "list",
        &tenant,
        &session.user_id,
        "credential",
        "self",
        "success",
    )
    .await;
    no_store_json(
        StatusCode::OK,
        AccountCredentialSummary {
            passkeys,
            password_status,
            password_supported: crate::local_identity::is_password_capable_user_id(&user.user_id)
                && crate::local_identity::is_valid_email(&crate::local_identity::normalize_email(
                    &user.email,
                )),
            recovery_configured: recovery_codes_remaining > 0,
            recovery_codes_remaining,
            reauthenticated: session_is_reauthenticated(&session, now),
            reauthenticate_after: session.auth_time.saturating_add(REAUTH_MAX_AGE_SECS),
        },
    )
}

/// Rename one passkey without exposing its WebAuthn credential ID.
#[utoipa::path(
    patch,
    path = "/account/passkeys/{passkey_id}",
    tag = "account",
    params(("passkey_id" = String, Path, description = "Encrypted passkey management handle")),
    request_body = RenamePasskeyRequest,
    responses(
        (status = 204, description = "Passkey renamed"),
        (status = 400, description = "Invalid name"),
        (status = 401, description = "Login required"),
        (status = 403, description = "Recent reauthentication required"),
        (status = 404, description = "Passkey not found"),
        (status = 409, description = "Concurrent update")
    )
)]
pub async fn rename_passkey(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
    Json(request): Json<RenamePasskeyRequest>,
) -> Response {
    let (tenant, session) = match require_fresh_session(&state, &headers, "rename", "passkey").await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Some(name) = validate_passkey_name(&request.name) else {
        audit(
            &state,
            "rename",
            &tenant,
            &session.user_id,
            "passkey",
            "invalid",
            "denied",
        )
        .await;
        return no_store_json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({ "error": "invalid_passkey_name" }),
        );
    };
    let Some(credential_id) = passkey_id_from_handle(&state, &tenant, &session.user_id, &handle)
    else {
        audit(
            &state,
            "rename",
            &tenant,
            &session.user_id,
            "passkey",
            "invalid",
            "not_found",
        )
        .await;
        return no_store_json(
            StatusCode::NOT_FOUND,
            serde_json::json!({ "error": "passkey_not_found" }),
        );
    };
    for attempt in 0..3 {
        match state
            .passkeys
            .rename_owned(&tenant, &session.user_id, &credential_id, &name)
            .await
        {
            Ok(true) => {
                audit(
                    &state,
                    "rename",
                    &tenant,
                    &session.user_id,
                    "passkey",
                    &handle,
                    "success",
                )
                .await;
                return StatusCode::NO_CONTENT.into_response();
            }
            Ok(false) if attempt < 2 => continue,
            Ok(false) => {
                let (result, response) = match state.passkeys.get(&tenant, &credential_id).await {
                    Ok(Some(passkey)) if passkey.user_id == session.user_id => (
                        "conflict",
                        no_store_json(
                            StatusCode::CONFLICT,
                            serde_json::json!({ "error": "passkey_update_conflict" }),
                        ),
                    ),
                    Ok(_) => (
                        "not_found",
                        no_store_json(
                            StatusCode::NOT_FOUND,
                            serde_json::json!({ "error": "passkey_not_found" }),
                        ),
                    ),
                    Err(error) => ("failed", store_error(error)),
                };
                audit(
                    &state,
                    "rename",
                    &tenant,
                    &session.user_id,
                    "passkey",
                    &handle,
                    result,
                )
                .await;
                return response;
            }
            Err(error) => {
                audit(
                    &state,
                    "rename",
                    &tenant,
                    &session.user_id,
                    "passkey",
                    &handle,
                    "failed",
                )
                .await;
                return store_error(error);
            }
        }
    }
    unreachable!("bounded passkey rename loop returns")
}

fn active_password(password: Option<&PasswordCredential>) -> bool {
    password.is_some_and(|password| !password.must_change && !password.revocation_pending)
}

async fn passkey_deletion_state(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    credential_id: &str,
    current_rp_id: &str,
) -> Result<(bool, bool), Response> {
    let lookup = crate::recover::user_lookup(user_id);
    let (target, passkeys, password, recovery) = tokio::join!(
        state.passkeys.get(tenant, credential_id),
        state.passkeys.list_by_user(tenant, user_id),
        state.passwords.get(tenant, user_id),
        state.recovery.get(tenant, &lookup),
    );
    let target_exists = match target {
        Ok(Some(target)) => target.user_id == user_id,
        Ok(None) => false,
        Err(error) => return Err(store_error(error)),
    };
    let another_passkey = match passkeys {
        Ok(passkeys) => passkeys.iter().any(|passkey| {
            passkey.credential_id != credential_id && passkey.rp_id == current_rp_id
        }),
        Err(error) => return Err(store_error(error)),
    };
    let password_available = match password {
        Ok(password) => active_password(password.as_ref()),
        Err(error) => return Err(store_error(error)),
    };
    let recovery_available = match recovery {
        Ok(Some(recovery)) => recovery.code_hashes.iter().any(|code| !code.consumed),
        Ok(None) => false,
        Err(error) => return Err(store_error(error)),
    };
    Ok((
        target_exists,
        another_passkey || password_available || recovery_available,
    ))
}

/// Remove one owned passkey while preserving at least one viable factor.
#[utoipa::path(
    delete,
    path = "/account/passkeys/{passkey_id}",
    tag = "account",
    params(("passkey_id" = String, Path, description = "Encrypted passkey management handle")),
    responses(
        (status = 204, description = "Passkey removed and prior sessions revoked"),
        (status = 401, description = "Login required"),
        (status = 403, description = "Recent reauthentication required"),
        (status = 404, description = "Passkey not found"),
        (status = 409, description = "Removal would lock the user out")
    )
)]
pub async fn delete_passkey(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
) -> Response {
    let (tenant, session) = match require_fresh_session(&state, &headers, "delete", "passkey").await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Some(credential_id) = passkey_id_from_handle(&state, &tenant, &session.user_id, &handle)
    else {
        audit(
            &state,
            "delete",
            &tenant,
            &session.user_id,
            "passkey",
            "invalid",
            "not_found",
        )
        .await;
        return no_store_json(
            StatusCode::NOT_FOUND,
            serde_json::json!({ "error": "passkey_not_found" }),
        );
    };
    let Some((current_rp_id, _)) = crate::passkey_flow::rp_id_and_origin(&state, &headers) else {
        audit(
            &state,
            "delete",
            &tenant,
            &session.user_id,
            "passkey",
            &handle,
            "invalid_origin",
        )
        .await;
        return no_store_json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({ "error": "invalid_browser_origin" }),
        );
    };
    let (target_exists, alternative_exists) = match passkey_deletion_state(
        &state,
        &tenant,
        &session.user_id,
        &credential_id,
        &current_rp_id,
    )
    .await
    {
        Ok(state) => state,
        Err(response) => {
            audit(
                &state,
                "delete",
                &tenant,
                &session.user_id,
                "passkey",
                &handle,
                "failed",
            )
            .await;
            return response;
        }
    };
    if !target_exists {
        audit(
            &state,
            "delete",
            &tenant,
            &session.user_id,
            "passkey",
            &handle,
            "not_found",
        )
        .await;
        return no_store_json(
            StatusCode::NOT_FOUND,
            serde_json::json!({ "error": "passkey_not_found" }),
        );
    }
    if !alternative_exists {
        audit(
            &state,
            "delete",
            &tenant,
            &session.user_id,
            "passkey",
            &handle,
            "lockout_prevented",
        )
        .await;
        return no_store_json(
            StatusCode::CONFLICT,
            serde_json::json!({ "error": "last_viable_factor" }),
        );
    }
    let mutation = match begin_credential_mutation(&state, &tenant, &session).await {
        Ok(mutation) => mutation,
        Err(response) => {
            audit(
                &state,
                "delete",
                &tenant,
                &session.user_id,
                "passkey",
                &handle,
                "failed",
            )
            .await;
            return response;
        }
    };
    let (target_exists, alternative_exists) = match passkey_deletion_state(
        &state,
        &tenant,
        &session.user_id,
        &credential_id,
        &current_rp_id,
    )
    .await
    {
        Ok(state) => state,
        Err(response) => {
            audit(
                &state,
                "delete",
                &tenant,
                &session.user_id,
                "passkey",
                &handle,
                "failed",
            )
            .await;
            abort_credential_mutation(&state, &tenant, &session.user_id, &mutation).await;
            return clear_session(response);
        }
    };
    if !target_exists || !alternative_exists {
        abort_credential_mutation(&state, &tenant, &session.user_id, &mutation).await;
        let (status, error) = if target_exists {
            (StatusCode::CONFLICT, "last_viable_factor")
        } else {
            (StatusCode::NOT_FOUND, "passkey_not_found")
        };
        audit(
            &state,
            "delete",
            &tenant,
            &session.user_id,
            "passkey",
            &handle,
            if target_exists {
                "lockout_prevented"
            } else {
                "not_found"
            },
        )
        .await;
        return clear_session(no_store_json(status, serde_json::json!({ "error": error })));
    }
    match state
        .passkeys
        .delete_owned_and_complete(
            &state.users,
            &tenant,
            &session.user_id,
            &credential_id,
            mutation.owner(),
            crate::current_unix_secs(),
        )
        .await
    {
        Ok(true) => {
            audit(
                &state,
                "delete",
                &tenant,
                &session.user_id,
                "passkey",
                &handle,
                "success",
            )
            .await;
            clear_session(StatusCode::NO_CONTENT)
        }
        Ok(false) => {
            audit(
                &state,
                "delete",
                &tenant,
                &session.user_id,
                "passkey",
                &handle,
                "conflict",
            )
            .await;
            abort_credential_mutation(&state, &tenant, &session.user_id, &mutation).await;
            clear_session(no_store_json(
                StatusCode::CONFLICT,
                serde_json::json!({ "error": "credential_change_conflict" }),
            ))
        }
        Err(error) => {
            audit(
                &state,
                "delete",
                &tenant,
                &session.user_id,
                "passkey",
                &handle,
                "failed",
            )
            .await;
            abort_credential_mutation(&state, &tenant, &session.user_id, &mutation).await;
            clear_session(store_error(error))
        }
    }
}

/// Enroll or rotate an active local password after recent reauthentication.
#[utoipa::path(
    put,
    path = "/account/password",
    tag = "account",
    request_body = SetPasswordRequest,
    responses(
        (status = 204, description = "Password enrolled or rotated; prior sessions revoked"),
        (status = 400, description = "Password policy violation or unchanged password"),
        (status = 401, description = "Login required"),
        (status = 403, description = "Recent reauthentication required or unsupported identity"),
        (status = 409, description = "Credential changed concurrently"),
        (status = 503, description = "Password service unavailable")
    )
)]
pub async fn set_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SetPasswordRequest>,
) -> Response {
    let (tenant, session) = match require_fresh_session(&state, &headers, "set", "password").await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let user = match state.users.get_by_id(&tenant, &session.user_id).await {
        Ok(Some(user)) if user.status == UserStatus::Active => user,
        Ok(_) => {
            audit(
                &state,
                "set",
                &tenant,
                &session.user_id,
                "password",
                "self",
                "unsupported_identity",
            )
            .await;
            return no_store_json(
                StatusCode::FORBIDDEN,
                serde_json::json!({ "error": "password_not_supported" }),
            );
        }
        Err(error) => {
            audit(
                &state,
                "set",
                &tenant,
                &session.user_id,
                "password",
                "self",
                "failed",
            )
            .await;
            return store_error(error);
        }
    };
    let email = crate::local_identity::normalize_email(&user.email);
    if !crate::local_identity::is_password_capable_user_id(&user.user_id)
        || !crate::local_identity::is_valid_email(&email)
    {
        audit(
            &state,
            "set",
            &tenant,
            &session.user_id,
            "password",
            "self",
            "unsupported_identity",
        )
        .await;
        return no_store_json(
            StatusCode::FORBIDDEN,
            serde_json::json!({ "error": "password_not_supported" }),
        );
    }
    if validate_password(request.new_password.expose()).is_err() {
        audit(
            &state,
            "set",
            &tenant,
            &session.user_id,
            "password",
            "self",
            "policy_rejected",
        )
        .await;
        return no_store_json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({ "error": "password_policy_violation" }),
        );
    }
    let raw_password = request.new_password.expose().to_string();
    let existing = match state.passwords.get(&tenant, &session.user_id).await {
        Ok(existing) => existing,
        Err(error) => {
            audit(
                &state,
                "set",
                &tenant,
                &session.user_id,
                "password",
                "self",
                "failed",
            )
            .await;
            return store_error(error);
        }
    };
    if let Some(existing) = existing.as_ref() {
        if existing.must_change || existing.revocation_pending {
            audit(
                &state,
                "set",
                &tenant,
                &session.user_id,
                "password",
                "self",
                "change_required",
            )
            .await;
            return no_store_json(
                StatusCode::CONFLICT,
                serde_json::json!({ "error": "password_change_required" }),
            );
        }
        match crate::password_login::verify_with_budget(
            &state,
            PasswordValue::new(raw_password.clone()),
            existing.password_hash.clone(),
        )
        .await
        {
            Ok(true) => {
                audit(
                    &state,
                    "set",
                    &tenant,
                    &session.user_id,
                    "password",
                    "self",
                    "unchanged",
                )
                .await;
                return no_store_json(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({ "error": "password_unchanged" }),
                );
            }
            Ok(false) => {}
            Err(_) => {
                audit(
                    &state,
                    "set",
                    &tenant,
                    &session.user_id,
                    "password",
                    "self",
                    "verification_unavailable",
                )
                .await;
                return no_store_json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({ "error": "password_service_unavailable" }),
                );
            }
        }
    }
    let new_hash = match crate::password_login::hash_with_budget(&state, request.new_password).await
    {
        Ok((_, hash)) => hash,
        Err(_) => {
            audit(
                &state,
                "set",
                &tenant,
                &session.user_id,
                "password",
                "self",
                "hash_unavailable",
            )
            .await;
            return no_store_json(
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({ "error": "password_service_unavailable" }),
            );
        }
    };
    let mutation = match begin_credential_mutation(&state, &tenant, &session).await {
        Ok(mutation) => mutation,
        Err(response) => {
            audit(
                &state,
                "set",
                &tenant,
                &session.user_id,
                "password",
                "self",
                "failed",
            )
            .await;
            return response;
        }
    };
    let now = crate::current_unix_secs();
    let expected_version = existing.as_ref().map(|credential| credential.version);
    let write = state
        .passwords
        .commit_credential_change(
            &state.users,
            crate::ports::FencedPasswordMutation {
                tenant: &tenant,
                user_id: &session.user_id,
                password_hash: new_hash,
                expected_version,
                credential_epoch: mutation.epoch,
                updated_at: now,
            },
            mutation.owner(),
        )
        .await;
    match write {
        Ok(true) => {
            audit(
                &state,
                "set",
                &tenant,
                &session.user_id,
                "password",
                "self",
                "success",
            )
            .await;
            clear_session(StatusCode::NO_CONTENT)
        }
        Ok(false) => {
            audit(
                &state,
                "set",
                &tenant,
                &session.user_id,
                "password",
                "self",
                "conflict",
            )
            .await;
            abort_credential_mutation(&state, &tenant, &session.user_id, &mutation).await;
            clear_session(no_store_json(
                StatusCode::CONFLICT,
                serde_json::json!({ "error": "credential_change_conflict" }),
            ))
        }
        Err(error) => {
            audit(
                &state,
                "set",
                &tenant,
                &session.user_id,
                "password",
                "self",
                "failed",
            )
            .await;
            abort_credential_mutation(&state, &tenant, &session.user_id, &mutation).await;
            clear_session(store_error(error))
        }
    }
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(credential_summary))
        .routes(routes!(rename_passkey))
        .routes(routes!(delete_passkey))
        .routes(routes!(set_password))
        .layer(DefaultBodyLimit::max(4096))
}
