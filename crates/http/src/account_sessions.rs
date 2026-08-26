//! Self-service login-session management.
//!
//! This resource is intentionally separate from OAuth authorization sessions under
//! `/sessions`. Cookie credentials never leave the server: responses use a
//! tenant-bound encrypted management handle instead of the raw session id.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    credential::CredentialAuditEvent,
    ports::{SessionRecord, SessionStore, StoreError},
    state::AppState,
};

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AccountSessionView {
    /// Opaque management handle. This is not the cookie credential.
    pub id: String,
    pub current: bool,
    pub device: String,
    pub created_at: i64,
    pub last_used_at: i64,
    pub expires_at: i64,
}

fn management_cipher(state: &AppState) -> Aes256Gcm {
    let mut digest = Sha256::new();
    digest.update(b"login-session-management-key:v1\0");
    digest.update(state.server_secret.as_slice());
    Aes256Gcm::new_from_slice(&digest.finalize()).expect("SHA-256 produces an AES-256 key")
}

fn management_aad(tenant: &str) -> Vec<u8> {
    let mut aad = b"login-session-management:v1\0".to_vec();
    aad.extend_from_slice(tenant.as_bytes());
    aad
}

fn management_handle(state: &AppState, tenant: &str, session_id: &str) -> String {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = management_cipher(state)
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: session_id.as_bytes(),
                aad: &management_aad(tenant),
            },
        )
        .expect("bounded session id can be encrypted");
    let mut encoded = Vec::with_capacity(nonce.len() + ciphertext.len());
    encoded.extend_from_slice(&nonce);
    encoded.extend_from_slice(&ciphertext);
    URL_SAFE_NO_PAD.encode(encoded)
}

fn session_id_from_handle(state: &AppState, tenant: &str, handle: &str) -> Option<String> {
    if handle.len() > 512 {
        return None;
    }
    let encoded = URL_SAFE_NO_PAD.decode(handle).ok()?;
    if encoded.len() <= 12 + 16 {
        return None;
    }
    let (nonce, ciphertext) = encoded.split_at(12);
    let plaintext = management_cipher(state)
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &management_aad(tenant),
            },
        )
        .ok()?;
    let session_id = String::from_utf8(plaintext).ok()?;
    (!session_id.is_empty() && session_id.len() <= 256).then_some(session_id)
}

fn session_subject_id(state: &AppState, tenant: &str, session_id: &str) -> String {
    let material = format!(
        "login-session-subject:v1\0{}\0{tenant}\0{session_id}",
        tenant.len()
    );
    agent_auth_authn::authz_session::session_token_hash(&state.server_secret, &material)
}

fn store_error(error: StoreError) -> Response {
    match error {
        StoreError::Transient(_) => {
            (StatusCode::SERVICE_UNAVAILABLE, "session store unavailable").into_response()
        }
        StoreError::Permanent(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "session store error").into_response()
        }
    }
}

async fn require_session(
    state: &AppState,
    headers: &HeaderMap,
    action: &'static str,
    target: &str,
) -> Result<(String, SessionRecord), Response> {
    let tenant = crate::tenant::tenant_or_400(state, headers)?;
    match crate::login::current_session_full(state, headers).await {
        Some(session) => Ok((tenant, session)),
        None => {
            audit(
                state,
                action,
                &tenant,
                "anonymous",
                target,
                "denied",
                Some(0),
            )
            .await;
            Err((StatusCode::UNAUTHORIZED, "login required").into_response())
        }
    }
}

async fn audit(
    state: &AppState,
    action: &'static str,
    tenant: &str,
    actor: &str,
    target: &str,
    result: &'static str,
    affected: Option<usize>,
) {
    state
        .audit_credential_event(CredentialAuditEvent::UserSessionOperation {
            action,
            tenant,
            actor,
            target,
            result,
            affected,
        })
        .await;
}

/// List the signed-in user's browser login sessions.
#[utoipa::path(
    get,
    path = "/account/sessions",
    tag = "account",
    responses(
        (status = 200, description = "Current user's login sessions", body = [AccountSessionView]),
        (status = 400, description = "Invalid tenant host"),
        (status = 401, description = "Login required"),
        (status = 500, description = "Session store error"),
        (status = 503, description = "Session store unavailable")
    )
)]
pub async fn list_sessions(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, current) = match require_session(&state, &headers, "list", "self").await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let now = crate::current_unix_secs();
    let mut sessions = match state
        .sessions
        .list_by_user(&tenant, &current.user_id, now)
        .await
    {
        Ok(sessions) => sessions,
        Err(error) => {
            audit(
                &state,
                "list",
                &tenant,
                &current.user_id,
                "self",
                "error",
                Some(0),
            )
            .await;
            return store_error(error);
        }
    };

    // A newly-created DynamoDB record can briefly lag its GSI. The current session
    // came from a strongly consistent primary-key read, so keep it visible.
    if !sessions
        .iter()
        .any(|session| session.session_id == current.session_id)
    {
        sessions.push(current.clone());
    }
    sessions.sort_by(|left, right| {
        let left_current = left.session_id == current.session_id;
        let right_current = right.session_id == current.session_id;
        right_current
            .cmp(&left_current)
            .then_with(|| right.last_used_at.cmp(&left.last_used_at))
            .then_with(|| right.created_at.cmp(&left.created_at))
    });
    let views = sessions
        .into_iter()
        .map(|session| AccountSessionView {
            id: management_handle(&state, &tenant, &session.session_id),
            current: session.session_id == current.session_id,
            device: session.device,
            created_at: session.created_at,
            last_used_at: session.last_used_at,
            expires_at: session.expires_at,
        })
        .collect::<Vec<_>>();
    audit(
        &state,
        "list",
        &tenant,
        &current.user_id,
        "self",
        "success",
        Some(views.len()),
    )
    .await;
    let mut response = Json(views).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

/// Revoke one selected login session. Missing and already-revoked handles are idempotent.
#[utoipa::path(
    delete,
    path = "/account/sessions/{session_id}",
    tag = "account",
    params(("session_id" = String, Path, description = "Opaque session management handle")),
    responses(
        (status = 204, description = "Session revoked or already absent"),
        (status = 400, description = "Invalid tenant host"),
        (status = 401, description = "Login required"),
        (status = 500, description = "Session store error"),
        (status = 503, description = "Session store unavailable")
    )
)]
pub async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(presented_handle): Path<String>,
) -> Response {
    let (tenant, current) = match require_session(&state, &headers, "revoke", "invalid").await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let target_session_id = session_id_from_handle(&state, &tenant, &presented_handle);
    let audit_target = target_session_id
        .as_deref()
        .map(|session_id| session_subject_id(&state, &tenant, session_id));
    let audit_target = audit_target.as_deref().unwrap_or("invalid");

    let is_current = target_session_id
        .as_deref()
        .is_some_and(|session_id| session_id == current.session_id);
    let affected = if let Some(session_id) = target_session_id {
        match state
            .sessions
            .delete_owned(&tenant, &current.user_id, &current.session_id, &session_id)
            .await
        {
            Ok(deleted) => usize::from(deleted),
            Err(error) => {
                audit(
                    &state,
                    "revoke",
                    &tenant,
                    &current.user_id,
                    audit_target,
                    "error",
                    Some(0),
                )
                .await;
                return store_error(error);
            }
        }
    } else {
        0
    };
    audit(
        &state,
        "revoke",
        &tenant,
        &current.user_id,
        audit_target,
        "success",
        Some(affected),
    )
    .await;

    if is_current {
        (
            [(
                axum::http::header::SET_COOKIE,
                crate::login::set_cookie(crate::login::SESSION_COOKIE, "", 0),
            )],
            StatusCode::NO_CONTENT,
        )
            .into_response()
    } else {
        StatusCode::NO_CONTENT.into_response()
    }
}

/// Revoke all of the user's login sessions except the current one.
#[utoipa::path(
    delete,
    path = "/account/sessions",
    tag = "account",
    responses(
        (status = 204, description = "Other sessions revoked; current session retained"),
        (status = 400, description = "Invalid tenant host"),
        (status = 401, description = "Login required"),
        (status = 500, description = "Session store error"),
        (status = 503, description = "Session store unavailable")
    )
)]
pub async fn revoke_other_sessions(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, current) =
        match require_session(&state, &headers, "revoke_others", "all_other").await {
            Ok(value) => value,
            Err(response) => return response,
        };
    let affected = match state
        .sessions
        .delete_others_by_user(&tenant, &current.user_id, &current.session_id)
        .await
    {
        Ok(affected) => affected,
        Err(error) => {
            audit(
                &state,
                "revoke_others",
                &tenant,
                &current.user_id,
                "all_other",
                "error",
                Some(0),
            )
            .await;
            return store_error(error);
        }
    };
    audit(
        &state,
        "revoke_others",
        &tenant,
        &current.user_id,
        "all_other",
        "success",
        affected,
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_sessions, revoke_other_sessions))
        .routes(routes!(revoke_session))
}
