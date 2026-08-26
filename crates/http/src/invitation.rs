//! Admin-issued one-time onboarding invitations(issue #34).
//!
//! This flow is intentionally independent from magic-link login: it has its
//! own credential format, store, endpoints, expiry, audit actions, and
//! atomic session-creation path.

use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::IntoResponse,
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    ports::{
        InvitationAcceptOutcome, InvitationAcceptRequest, InvitationIssueOutcome, InvitationRecord,
        InvitationStore, UserRecord, UserStatus, UsersStore,
    },
    security_event::{
        AuthenticationMethod, SecurityActor, SecurityEventCategory, SecurityEventDraft,
        SecurityEventOutcome, SecuritySubject,
    },
    state::AppState,
    tenant_admin::{AdminAction, TenantAdminContext},
};

type HmacSha256 = Hmac<Sha256>;

const TOKEN_COMPONENT_LEN: usize = 43;

/// Stable opaque lookup for the single active invitation row. It is not a
/// bearer credential and reveals neither tenant nor email.
pub(crate) fn invitation_locator(server_secret: &[u8], tenant: &str, user_id: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(server_secret).expect("HMAC accepts any key length");
    mac.update(b"agent-auth-invitation-locator:v1\0");
    mac.update((tenant.len() as u64).to_be_bytes().as_slice());
    mac.update(tenant.as_bytes());
    mac.update((user_id.len() as u64).to_be_bytes().as_slice());
    mac.update(user_id.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn verifier_hash(secret: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))
}

pub(crate) fn verifier_matches(expected: &str, candidate: &str) -> bool {
    expected.len() == candidate.len() && bool::from(expected.as_bytes().ct_eq(candidate.as_bytes()))
}

fn random_secret_from(rng: &mut (impl RngCore + CryptoRng)) -> String {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Serialize, ToSchema)]
pub struct InvitationSecretResponse {
    /// Show-once URL. The bearer remains in the fragment so it is not sent in
    /// HTTP request targets or CloudFront/API access logs.
    pub invitation_url: String,
    pub expires_at: i64,
}

pub(crate) enum IssueInvitationError {
    Ineligible,
    PasswordConfigured,
    Store,
}

pub(crate) async fn issue_for_user(
    state: &AppState,
    tenant: &str,
    user: &UserRecord,
    actor: &str,
    browser_origin: &str,
) -> Result<InvitationSecretResponse, IssueInvitationError> {
    let mut rng = rand::rngs::OsRng;
    issue_for_user_with_rng(state, tenant, user, actor, browser_origin, &mut rng).await
}

async fn issue_for_user_with_rng(
    state: &AppState,
    tenant: &str,
    user: &UserRecord,
    actor: &str,
    browser_origin: &str,
    rng: &mut (impl RngCore + CryptoRng + Send),
) -> Result<InvitationSecretResponse, IssueInvitationError> {
    if user.status != UserStatus::Active
        || user.revocation_pending
        || !crate::local_identity::is_valid_email(&user.email)
        || !crate::local_identity::is_password_capable_user_id(&user.user_id)
    {
        return Err(IssueInvitationError::Ineligible);
    }
    let now = crate::token::current_unix_secs_pub();
    let expires_at = now
        .checked_add(state.invitation_ttl_secs)
        .ok_or(IssueInvitationError::Store)?;
    let locator = invitation_locator(&state.server_secret, tenant, &user.user_id);
    let secret = random_secret_from(rng);
    let record = InvitationRecord {
        locator: locator.clone(),
        activation_id: state.region.issue_id("invitation"),
        user_id: user.user_id.clone(),
        email: user.email.clone(),
        verifier_hash: verifier_hash(&secret),
        credential_epoch: user.credential_epoch,
        issued_at: now,
        expires_at,
    };
    let outcome = state
        .invitations
        .issue(tenant, record)
        .await
        .map_err(|_| IssueInvitationError::Store)?;
    match outcome {
        InvitationIssueOutcome::Issued => {}
        InvitationIssueOutcome::Ineligible => return Err(IssueInvitationError::Ineligible),
        InvitationIssueOutcome::PasswordConfigured => {
            return Err(IssueInvitationError::PasswordConfigured)
        }
    }

    state
        .record_security_event(SecurityEventDraft::new(
            tenant,
            SecurityActor::admin(actor),
            Some(SecuritySubject::user(&user.user_id)),
            SecurityEventCategory::Credential,
            "credential.invitation.issue",
            SecurityEventOutcome::Success,
        ))
        .await;
    let token = format!("{locator}.{secret}");
    Ok(InvitationSecretResponse {
        invitation_url: format!(
            "{}/invite#token={token}",
            browser_origin.trim_end_matches('/')
        ),
        expires_at,
    })
}

fn json_error(status: StatusCode, message: &'static str) -> axum::response::Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({ "status": status.as_u16(), "message": message })),
    )
        .into_response()
}

/// Regenerate an invitation for an existing active local user whose password
/// remains unconfigured. Success supersedes the previous URL.
#[utoipa::path(
    post,
    path = "/admin/users/{id}/invitation",
    tag = "admin",
    params(("id" = String, Path)),
    responses(
        (status = 201, description = "Show-once invitation URL", body = InvitationSecretResponse),
        (status = 401),
        (status = 404, description = "User missing or SaaS user data plane unavailable"),
        (status = 409, description = "User is ineligible or already has a password"),
        (status = 503, description = "Invitation store unavailable")
    )
)]
pub async fn regenerate_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if crate::admin::saas_users_disabled(&state) {
        return json_error(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let tenant = admin.storage_tenant();
    let Some(browser_origin) = crate::hostutil::browser_origin(&state, &headers) else {
        return json_error(StatusCode::BAD_REQUEST, "invalid browser origin");
    };
    let user = match state.users.get_by_id(tenant, &id).await {
        Ok(Some(user)) => user,
        Ok(None) => return json_error(StatusCode::NOT_FOUND, "not found"),
        Err(_) => return json_error(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    };
    let actor = admin.audit_identity();
    match issue_for_user(&state, tenant, &user, &actor, &browser_origin).await {
        Ok(invitation) => (StatusCode::CREATED, Json(invitation)).into_response(),
        Err(IssueInvitationError::Ineligible) => {
            json_error(StatusCode::CONFLICT, "user is not eligible for invitation")
        }
        Err(IssueInvitationError::PasswordConfigured) => {
            json_error(StatusCode::CONFLICT, "password already configured")
        }
        Err(IssueInvitationError::Store) => {
            json_error(StatusCode::SERVICE_UNAVAILABLE, "store unavailable")
        }
    }
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AcceptInvitationRequest {
    #[schema(value_type = String, format = Password)]
    token: String,
}

#[derive(Serialize, ToSchema)]
pub struct AcceptInvitationResponse {
    authenticated: bool,
    redirect_to: &'static str,
}

fn parse_token(token: &str) -> Option<(&str, &str)> {
    let (locator, secret) = token.split_once('.')?;
    if locator.len() != TOKEN_COMPONENT_LEN
        || secret.len() != TOKEN_COMPONENT_LEN
        || secret.contains('.')
    {
        return None;
    }
    Some((locator, secret))
}

async fn audit_acceptance(
    state: &AppState,
    tenant: &str,
    user_id: Option<&str>,
    outcome: SecurityEventOutcome,
) {
    state
        .record_security_event(SecurityEventDraft::authentication(
            tenant,
            user_id,
            AuthenticationMethod::Invitation,
            outcome,
        ))
        .await;
}

/// Consume a dedicated invitation and establish a host-only AS session. There
/// is deliberately no caller-controlled continuation; the only destination is
/// `/account`.
#[utoipa::path(
    post,
    path = "/login/invitation",
    tag = "login",
    request_body = AcceptInvitationRequest,
    responses(
        (status = 200, description = "Invitation accepted", body = AcceptInvitationResponse),
        (status = 400, description = "Invalid, expired, replayed, or superseded invitation"),
        (status = 503, description = "Invitation authentication unavailable")
    )
)]
pub async fn accept_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AcceptInvitationRequest>,
) -> impl IntoResponse {
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(tenant) => tenant,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "invalid invitation"),
    };
    let Some((locator, secret)) = parse_token(&body.token) else {
        audit_acceptance(&state, &tenant, None, SecurityEventOutcome::Denied).await;
        return json_error(StatusCode::BAD_REQUEST, "invalid invitation");
    };
    let now = crate::token::current_unix_secs_pub();
    let outcome = state
        .invitations
        .accept(
            &tenant,
            InvitationAcceptRequest {
                locator: locator.to_string(),
                activation_id: state.region.issue_id("invitation"),
                verifier_hash: verifier_hash(secret),
                session_id: state.region.issue_id(crate::login::rand_id(32)),
                device: crate::login::session_device(&headers),
                now,
            },
        )
        .await;
    match outcome {
        Ok(InvitationAcceptOutcome::Accepted {
            user_id,
            session_id,
        }) => {
            crate::user_gate::touch_last_login(&state, &tenant, &user_id, now).await;
            audit_acceptance(
                &state,
                &tenant,
                Some(&user_id),
                SecurityEventOutcome::Success,
            )
            .await;
            (
                StatusCode::OK,
                [
                    (header::CACHE_CONTROL, "no-store".to_string()),
                    (
                        header::SET_COOKIE,
                        crate::login::set_cookie(
                            crate::login::SESSION_COOKIE,
                            &session_id,
                            crate::login::SESSION_TTL_SECS,
                        ),
                    ),
                ],
                Json(AcceptInvitationResponse {
                    authenticated: true,
                    redirect_to: "/account",
                }),
            )
                .into_response()
        }
        Ok(
            InvitationAcceptOutcome::Expired { user_id }
            | InvitationAcceptOutcome::Ineligible { user_id },
        ) => {
            audit_acceptance(
                &state,
                &tenant,
                Some(&user_id),
                SecurityEventOutcome::Denied,
            )
            .await;
            json_error(StatusCode::BAD_REQUEST, "invalid invitation")
        }
        Ok(InvitationAcceptOutcome::Invalid) => {
            audit_acceptance(&state, &tenant, None, SecurityEventOutcome::Denied).await;
            json_error(StatusCode::BAD_REQUEST, "invalid invitation")
        }
        Err(_) => {
            audit_acceptance(&state, &tenant, None, SecurityEventOutcome::Failure).await;
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "invitation authentication unavailable",
            )
        }
    }
}

pub(crate) async fn add_no_store(
    request: axum::extract::Request,
    next: Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(regenerate_invitation))
        .routes(routes!(accept_invitation))
        .layer(DefaultBodyLimit::max(2048))
        .layer(axum::middleware::from_fn(add_no_store))
}

#[cfg(test)]
mod tests {
    use super::issue_for_user_with_rng;
    use crate::{ports::UsersStore, state::AppState};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use rand::{CryptoRng, Error, RngCore};

    #[derive(Default)]
    struct CountingCryptoRng {
        bytes_requested: usize,
        next: u8,
    }

    impl RngCore for CountingCryptoRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }

        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.bytes_requested += dest.len();
            for byte in dest {
                *byte = self.next;
                self.next = self.next.wrapping_add(1);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for CountingCryptoRng {}

    #[tokio::test]
    async fn invitation_issuance_uses_exactly_256_bits_from_a_crypto_rng() {
        let state = AppState::dev("idp.example.com");
        let user = state
            .users
            .create_or_get_by_email("", "invitee@example.com", "user:invitee@example.com", 1)
            .await
            .unwrap();
        let mut rng = CountingCryptoRng::default();
        let response = issue_for_user_with_rng(
            &state,
            "",
            &user,
            "test-admin",
            "https://idp.example.com",
            &mut rng,
        )
        .await
        .unwrap_or_else(|_| panic!("full invitation issuance must succeed"));
        let token = response
            .invitation_url
            .split_once("#token=")
            .expect("show-once invitation URL")
            .1;
        let secret = token.split_once('.').expect("locator.secret token").1;

        assert_eq!(rng.bytes_requested, 32);
        assert_eq!(secret.len(), 43);
        assert_eq!(URL_SAFE_NO_PAD.decode(secret).unwrap().len(), 32);
    }
}
