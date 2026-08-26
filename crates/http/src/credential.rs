//! Long-lived credential verifier and rotation state.
//!
//! Client secrets, registration access tokens, and initial access tokens are
//! random bearer values. Persist only a domain-separated HMAC verifier; the
//! plaintext exists only while constructing the one-time API response.

use std::fmt;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

pub const DEFAULT_CLIENT_SECRET_TTL_SECS: i64 = 365 * 24 * 60 * 60;
pub const DEFAULT_REGISTRATION_TOKEN_TTL_SECS: i64 = 365 * 24 * 60 * 60;
pub const DEFAULT_IAT_TTL_SECS: i64 = 24 * 60 * 60;
pub const MAX_IAT_TTL_SECS: i64 = 30 * 24 * 60 * 60;
pub const MAX_ROTATION_OVERLAP_SECS: i64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    ClientSecret,
    RegistrationAccessToken,
    InitialAccessToken,
}

pub enum CredentialAuditEvent<'a> {
    ClientMutation {
        action: &'static str,
        actor: &'a str,
        tenant: &'a str,
        client_id: &'a str,
        kind: CredentialKind,
        credential_id: &'a str,
    },
    InitialAccessTokenCreate {
        actor: &'a str,
        tenant: &'a str,
        token_id: &'a str,
        owner: &'a str,
        one_time: bool,
    },
    InitialAccessTokenRevoke {
        actor: &'a str,
        tenant: &'a str,
        token_id: &'a str,
    },
    AdminBreakGlassUse {
        tenant: &'a str,
        owner: &'a str,
        credential_id: &'a str,
        slot: &'a str,
        revision: u64,
    },
    AdminAuthorization {
        tenant: &'a str,
        actor: &'a str,
        role: &'a str,
        action: &'a str,
        result: &'a str,
    },
    ScimCredentialUse {
        tenant: &'a str,
        credential_id: &'a str,
        slot: &'a str,
        revision: u64,
    },
    ScimMutation {
        action: &'static str,
        tenant: &'a str,
        user_id: &'a str,
        credential_epoch: u64,
        sessions: usize,
        families: usize,
        grants: usize,
    },
    UserSessionOperation {
        action: &'static str,
        tenant: &'a str,
        actor: &'a str,
        target: &'a str,
        result: &'static str,
        affected: Option<usize>,
    },
    UserCredentialOperation {
        action: &'static str,
        tenant: &'a str,
        actor: &'a str,
        kind: &'static str,
        target: &'a str,
        result: &'static str,
    },
}

fn credential_audit_outcome(result: &str) -> crate::security_event::SecurityEventOutcome {
    use crate::security_event::SecurityEventOutcome;

    match result {
        "success" | "allowed" | "replayed" => SecurityEventOutcome::Success,
        "denied"
        | "step_up_required"
        | "locked"
        | "consumed"
        | "conflict"
        | "already_exists"
        | "lockout_prevented"
        | "not_found"
        | "policy_rejected"
        | "unchanged"
        | "unsupported_identity"
        | "invalid_origin"
        | "reauthentication_required"
        | "change_required" => SecurityEventOutcome::Denied,
        "failed" | "verification_unavailable" | "hash_unavailable" => SecurityEventOutcome::Failure,
        _ => SecurityEventOutcome::Failure,
    }
}

impl CredentialAuditEvent<'_> {
    pub fn security_event(&self) -> crate::security_event::SecurityEventDraft {
        use crate::security_event::{
            SecurityActor, SecurityEventCategory, SecurityEventCorrelation, SecurityEventDraft,
            SecurityEventOutcome, SecuritySubject,
        };

        let actor = |value: &str| {
            if value.starts_with("user:") {
                SecurityActor::user(value)
            } else if value == "anonymous" {
                SecurityActor::system(value)
            } else {
                SecurityActor::admin(value)
            }
        };

        match self {
            Self::UserSessionOperation {
                action,
                tenant,
                actor: actor_id,
                target,
                result,
                affected,
            } => {
                let projectable_session_revoke =
                    *action == "revoke" && *result == "success" && *affected == Some(1);
                let action = if *result == "success"
                    && *affected == Some(0)
                    && matches!(*action, "revoke" | "revoke_others")
                {
                    format!("session.{action}_noop")
                } else {
                    format!("session.{action}")
                };
                let event = SecurityEventDraft::new(
                    *tenant,
                    actor(actor_id),
                    actor_id
                        .starts_with("user:")
                        .then(|| SecuritySubject::user(*actor_id)),
                    SecurityEventCategory::Authentication,
                    action,
                    credential_audit_outcome(result),
                );
                if projectable_session_revoke {
                    event.correlated(SecurityEventCorrelation {
                        session_fingerprint: Some((*target).to_string()),
                        ..Default::default()
                    })
                } else {
                    event
                }
            }
            Self::ClientMutation {
                action,
                actor: actor_id,
                tenant,
                client_id,
                credential_id,
                ..
            } => SecurityEventDraft::new(
                *tenant,
                actor(actor_id),
                Some(SecuritySubject::client(*client_id)),
                SecurityEventCategory::KeySecret,
                action.to_ascii_lowercase().replace('_', "."),
                SecurityEventOutcome::Success,
            )
            .correlated(SecurityEventCorrelation {
                client_id: Some((*client_id).to_string()),
                credential_id: Some((*credential_id).to_string()),
                ..Default::default()
            }),
            Self::InitialAccessTokenCreate {
                actor: actor_id,
                tenant,
                token_id,
                ..
            } => SecurityEventDraft::new(
                *tenant,
                actor(actor_id),
                Some(SecuritySubject::credential(*token_id)),
                SecurityEventCategory::KeySecret,
                "credential.initial_access_token.create",
                SecurityEventOutcome::Success,
            )
            .correlated(SecurityEventCorrelation {
                credential_id: Some((*token_id).to_string()),
                ..Default::default()
            }),
            Self::InitialAccessTokenRevoke {
                actor: actor_id,
                tenant,
                token_id,
            } => SecurityEventDraft::new(
                *tenant,
                actor(actor_id),
                Some(SecuritySubject::credential(*token_id)),
                SecurityEventCategory::KeySecret,
                "credential.initial_access_token.revoke",
                SecurityEventOutcome::Success,
            )
            .correlated(SecurityEventCorrelation {
                credential_id: Some((*token_id).to_string()),
                ..Default::default()
            }),
            Self::AdminBreakGlassUse {
                tenant,
                credential_id,
                ..
            } => SecurityEventDraft::new(
                *tenant,
                SecurityActor::admin(format!("break-glass:{credential_id}")),
                Some(SecuritySubject::tenant(if tenant.is_empty() {
                    "default"
                } else {
                    tenant
                })),
                SecurityEventCategory::Administration,
                "admin.break_glass.use",
                SecurityEventOutcome::Success,
            )
            .correlated(SecurityEventCorrelation {
                credential_id: Some((*credential_id).to_string()),
                ..Default::default()
            }),
            Self::AdminAuthorization {
                tenant,
                actor: actor_id,
                action,
                result,
                ..
            } => SecurityEventDraft::new(
                *tenant,
                SecurityActor::admin(*actor_id),
                Some(SecuritySubject::tenant(if tenant.is_empty() {
                    "default"
                } else {
                    tenant
                })),
                if *result == "step_up_required" {
                    SecurityEventCategory::StepUp
                } else {
                    SecurityEventCategory::Administration
                },
                format!("admin.authorization.{action}"),
                credential_audit_outcome(result),
            ),
            Self::ScimCredentialUse {
                tenant,
                credential_id,
                ..
            } => SecurityEventDraft::new(
                *tenant,
                SecurityActor::system("scim"),
                Some(SecuritySubject::credential(*credential_id)),
                SecurityEventCategory::KeySecret,
                "credential.scim.use",
                SecurityEventOutcome::Success,
            )
            .correlated(SecurityEventCorrelation {
                credential_id: Some((*credential_id).to_string()),
                ..Default::default()
            }),
            Self::ScimMutation {
                action,
                tenant,
                user_id,
                credential_epoch,
                ..
            } => SecurityEventDraft::new(
                *tenant,
                SecurityActor::system("scim"),
                Some(SecuritySubject::user(*user_id)),
                SecurityEventCategory::UserLifecycle,
                format!("user.{action}"),
                SecurityEventOutcome::Success,
            )
            .correlated(SecurityEventCorrelation {
                operation_id: Some(format!("scim-{action}-generation-{credential_epoch}")),
                ..Default::default()
            }),
            Self::UserCredentialOperation {
                action,
                tenant,
                actor: actor_id,
                kind,
                result,
                ..
            } => {
                if *kind == "recovery" && *action == "consume" {
                    SecurityEventDraft::authentication(
                        *tenant,
                        actor_id.starts_with("user:").then_some(*actor_id),
                        crate::security_event::AuthenticationMethod::Recovery,
                        credential_audit_outcome(result),
                    )
                } else {
                    SecurityEventDraft::new(
                        *tenant,
                        actor(actor_id),
                        actor_id
                            .starts_with("user:")
                            .then(|| SecuritySubject::user(*actor_id)),
                        SecurityEventCategory::Credential,
                        format!("credential.{kind}.{action}"),
                        credential_audit_outcome(result),
                    )
                }
            }
        }
    }
}

impl fmt::Display for CredentialAuditEvent<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientMutation {
                action,
                actor,
                tenant,
                client_id,
                kind,
                credential_id,
            } => write!(
                f,
                "{action} actor={actor} tenant={tenant} client_id={client_id} \
                 kind={kind:?} credential_id={credential_id}"
            ),
            Self::InitialAccessTokenCreate {
                actor,
                tenant,
                token_id,
                owner,
                one_time,
            } => write!(
                f,
                "ADMIN_IAT_CREATE actor={actor} tenant={tenant} token_id={token_id} \
                 owner={owner} one_time={one_time}"
            ),
            Self::InitialAccessTokenRevoke {
                actor,
                tenant,
                token_id,
            } => write!(
                f,
                "ADMIN_IAT_REVOKE actor={actor} tenant={tenant} token_id={token_id}"
            ),
            Self::AdminBreakGlassUse {
                tenant,
                owner,
                credential_id,
                slot,
                revision,
            } => write!(
                f,
                "ADMIN_BREAK_GLASS_USE priority=high tenant={tenant} owner={owner} \
                 credential_id={credential_id} slot={slot} revision={revision}"
            ),
            Self::AdminAuthorization {
                tenant,
                actor,
                role,
                action,
                result,
            } => write!(
                f,
                "ADMIN_AUTHORIZATION tenant={tenant} actor={actor} role={role} \
                 action={action} result={result}"
            ),
            Self::ScimCredentialUse {
                tenant,
                credential_id,
                slot,
                revision,
            } => write!(
                f,
                "SCIM_CREDENTIAL_USE tenant={tenant} credential_id={credential_id} \
                 slot={slot} revision={revision}"
            ),
            Self::ScimMutation {
                action,
                tenant,
                user_id,
                credential_epoch,
                sessions,
                families,
                grants,
            } => write!(
                f,
                "SCIM_MUTATION action={action} tenant={tenant} user_id={user_id} \
                 generation={credential_epoch} sessions={sessions} families={families} \
                 grants={grants}"
            ),
            Self::UserSessionOperation {
                action,
                tenant,
                actor,
                target,
                result,
                affected,
            } => {
                let affected = affected
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                write!(
                    f,
                    "USER_SESSION_OPERATION action={action} tenant={tenant} actor={actor} \
                     target={target} result={result} affected={affected}"
                )
            }
            Self::UserCredentialOperation {
                action,
                tenant,
                actor,
                kind,
                target,
                result,
            } => write!(
                f,
                "USER_CREDENTIAL_OPERATION action={action} tenant={tenant} actor={actor} \
                 kind={kind} target={target} result={result}"
            ),
        }
    }
}

#[derive(Clone)]
pub enum CredentialAuditSink {
    Stderr,
    Memory(Arc<Mutex<Vec<String>>>),
}

impl CredentialAuditSink {
    pub fn memory() -> Self {
        Self::Memory(Arc::new(Mutex::new(Vec::new())))
    }

    pub fn emit(&self, event: CredentialAuditEvent<'_>) {
        let line = event.to_string();
        match self {
            Self::Stderr => eprintln!("{line}"),
            Self::Memory(lines) => lines.lock().expect("credential audit lock").push(line),
        }
    }

    pub fn snapshot(&self) -> Vec<String> {
        match self {
            Self::Stderr => Vec::new(),
            Self::Memory(lines) => lines.lock().expect("credential audit lock").clone(),
        }
    }
}

impl CredentialKind {
    pub const fn purpose(self) -> &'static [u8] {
        match self {
            Self::ClientSecret => b"client-secret",
            Self::RegistrationAccessToken => b"registration-access-token",
            Self::InitialAccessToken => b"initial-access-token",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    Active,
    Revoked,
    Consumed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierVersion {
    HmacSha256V1,
    LegacyRegistrationTokenV0,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRecord {
    pub credential_id: String,
    pub owner: String,
    pub verifier: String,
    pub verifier_version: VerifierVersion,
    pub created_at: i64,
    pub expires_at: i64,
    pub status: CredentialStatus,
    pub audit_identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_request_id: Option<String>,
}

impl fmt::Debug for CredentialRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialRecord")
            .field("credential_id", &self.credential_id)
            .field("owner", &self.owner)
            .field("verifier", &"[REDACTED]")
            .field("verifier_version", &self.verifier_version)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("status", &self.status)
            .field("audit_identity", &self.audit_identity)
            .field("rotation_request_id", &self.rotation_request_id)
            .finish()
    }
}

impl CredentialRecord {
    pub fn is_usable(&self, now: i64) -> bool {
        self.status == CredentialStatus::Active && self.expires_at > now
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CredentialSet {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<CredentialRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<CredentialRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlap_expires_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_revoked_credential_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_revoked_rotation_request_id: Option<String>,
    #[serde(default)]
    pub version: u64,
}

impl CredentialSet {
    pub fn has_credential_state(&self) -> bool {
        self.current.is_some()
            || self.next.is_some()
            || self.overlap_expires_at.is_some()
            || self.last_revoked_credential_id.is_some()
            || self.last_revoked_rotation_request_id.is_some()
    }

    pub fn clear_and_advance(&mut self) {
        self.current = None;
        self.next = None;
        self.overlap_expires_at = None;
        self.last_revoked_credential_id = None;
        self.last_revoked_rotation_request_id = None;
        self.version = self.version.saturating_add(1);
    }

    fn overlap_ended(&self, now: i64) -> bool {
        self.next.is_some()
            && self
                .overlap_expires_at
                .is_some_and(|deadline| deadline <= now)
    }

    pub fn verify<'a>(
        &'a self,
        server_secret: &[u8],
        kind: CredentialKind,
        tenant: &str,
        presented: &str,
        now: i64,
    ) -> Option<&'a CredentialRecord> {
        let staged_next = self.next.as_ref();
        let overlap_ended = self.overlap_ended(now);
        let next = staged_next.filter(|record| record.is_usable(now));

        let current = self
            .current
            .as_ref()
            .filter(|record| record.is_usable(now) && !overlap_ended);
        [current, next]
            .into_iter()
            .flatten()
            .find(|record| record_matches(record, server_secret, kind, tenant, presented))
    }

    pub fn effective_expires_at(&self, now: i64) -> Option<i64> {
        let current_usable = self
            .current
            .as_ref()
            .filter(|record| record.is_usable(now) && !self.overlap_ended(now));
        let next_usable = self.next.as_ref().filter(|record| record.is_usable(now));
        let effective = if self.overlap_ended(now) {
            next_usable.or(self.next.as_ref())
        } else {
            current_usable
                .or(next_usable)
                .or(self.current.as_ref())
                .or(self.next.as_ref())
        };
        effective.map(|record| record.expires_at)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitialAccessTokenRecord {
    pub token_id: String,
    pub credential: CredentialRecord,
    pub scopes: Vec<String>,
    pub rate_limit_per_minute: u32,
    pub one_time: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_at: Option<i64>,
    #[serde(default)]
    pub version: u64,
}

impl fmt::Debug for InitialAccessTokenRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitialAccessTokenRecord")
            .field("token_id", &self.token_id)
            .field("credential", &self.credential)
            .field("scopes", &self.scopes)
            .field("rate_limit_per_minute", &self.rate_limit_per_minute)
            .field("one_time", &self.one_time)
            .field("used_at", &self.used_at)
            .field("version", &self.version)
            .finish()
    }
}

impl InitialAccessTokenRecord {
    pub fn is_authorized_for(&self, scope: &str, now: i64) -> bool {
        self.credential.is_usable(now)
            && self.scopes.iter().any(|candidate| candidate == scope)
            && (!self.one_time || self.used_at.is_none())
    }

    pub fn verify(&self, server_secret: &[u8], tenant: &str, plaintext: &str) -> bool {
        record_matches(
            &self.credential,
            server_secret,
            CredentialKind::InitialAccessToken,
            tenant,
            plaintext,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageResult {
    Initialized,
    Staged,
    Retry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialMutationError {
    InvalidOverlap,
    RotationPending,
    VersionConflict,
    CredentialNotFound,
    CredentialNotUsable,
}

pub fn stage_credential(
    set: &mut CredentialSet,
    record: CredentialRecord,
    overlap_secs: i64,
    now: i64,
    expected_version: u64,
) -> Result<StageResult, CredentialMutationError> {
    let is_retry = record
        .rotation_request_id
        .as_ref()
        .is_some_and(|request_id| {
            set.current
                .iter()
                .chain(set.next.iter())
                .any(|existing| existing.rotation_request_id.as_ref() == Some(request_id))
                || set.last_revoked_rotation_request_id.as_ref() == Some(request_id)
        });
    if is_retry {
        return Ok(StageResult::Retry);
    }
    if expected_version != set.version {
        return Err(CredentialMutationError::VersionConflict);
    }
    let overlap_expires_at = now.checked_add(overlap_secs);
    if !(1..=MAX_ROTATION_OVERLAP_SECS).contains(&overlap_secs) || overlap_expires_at.is_none() {
        return Err(CredentialMutationError::InvalidOverlap);
    }

    if set.overlap_ended(now) {
        set.current = set.next.take();
        set.overlap_expires_at = None;
    }

    if set.next.as_ref().is_some_and(|next| next.is_usable(now)) {
        return Err(CredentialMutationError::RotationPending);
    }

    if set
        .current
        .as_ref()
        .is_none_or(|current| !current.is_usable(now))
    {
        set.current = Some(record);
        set.next = None;
        set.overlap_expires_at = None;
        set.version = set.version.saturating_add(1);
        return Ok(StageResult::Initialized);
    }

    if record.expires_at <= overlap_expires_at.expect("checked above") {
        return Err(CredentialMutationError::InvalidOverlap);
    }
    set.next = Some(record);
    set.overlap_expires_at = overlap_expires_at;
    set.version = set.version.saturating_add(1);
    Ok(StageResult::Staged)
}

pub fn cutover_credential(
    set: &mut CredentialSet,
    credential_id: &str,
    now: i64,
    expected_version: u64,
) -> Result<bool, CredentialMutationError> {
    if set
        .current
        .as_ref()
        .is_some_and(|current| current.credential_id == credential_id)
        && set.next.is_none()
    {
        return Ok(false);
    }
    if expected_version != set.version {
        return Err(CredentialMutationError::VersionConflict);
    }
    let next = set
        .next
        .take()
        .filter(|next| next.credential_id == credential_id)
        .ok_or(CredentialMutationError::CredentialNotFound)?;
    if !next.is_usable(now) {
        set.next = Some(next);
        return Err(CredentialMutationError::CredentialNotUsable);
    }
    set.current = Some(next);
    set.overlap_expires_at = None;
    set.version = set.version.saturating_add(1);
    Ok(true)
}

pub fn revoke_credential(
    set: &mut CredentialSet,
    credential_id: &str,
    now: i64,
    expected_version: u64,
) -> Result<bool, CredentialMutationError> {
    let already_revoked = set
        .current
        .iter()
        .chain(set.next.iter())
        .find(|record| record.credential_id == credential_id)
        .is_some_and(|record| record.status == CredentialStatus::Revoked)
        || set.last_revoked_credential_id.as_deref() == Some(credential_id);
    if already_revoked {
        return Ok(false);
    }
    if expected_version != set.version {
        return Err(CredentialMutationError::VersionConflict);
    }
    let rollback_staged_next = set
        .next
        .as_ref()
        .is_some_and(|record| record.credential_id == credential_id)
        && set
            .overlap_expires_at
            .is_some_and(|deadline| now < deadline);
    if rollback_staged_next {
        let next = set.next.take().expect("rollback target checked above");
        set.last_revoked_credential_id = Some(next.credential_id);
        set.last_revoked_rotation_request_id = next.rotation_request_id;
        set.overlap_expires_at = None;
        set.version = set.version.saturating_add(1);
        return Ok(true);
    }
    let record = set
        .current
        .iter_mut()
        .chain(set.next.iter_mut())
        .find(|record| record.credential_id == credential_id)
        .ok_or(CredentialMutationError::CredentialNotFound)?;
    record.status = CredentialStatus::Revoked;
    record.expires_at = record.expires_at.min(now);
    set.version = set.version.saturating_add(1);
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
pub fn new_credential_record(
    server_secret: &[u8],
    kind: CredentialKind,
    tenant: &str,
    credential_id: String,
    owner: String,
    plaintext: &str,
    created_at: i64,
    expires_at: i64,
    audit_identity: String,
    rotation_request_id: Option<String>,
) -> CredentialRecord {
    CredentialRecord {
        verifier: credential_verifier(server_secret, kind, tenant, &owner, plaintext),
        verifier_version: VerifierVersion::HmacSha256V1,
        credential_id,
        owner,
        created_at,
        expires_at,
        status: CredentialStatus::Active,
        audit_identity,
        rotation_request_id,
    }
}

pub fn credential_verifier(
    server_secret: &[u8],
    kind: CredentialKind,
    tenant: &str,
    owner: &str,
    plaintext: &str,
) -> String {
    let mut mac = HmacSha256::new_from_slice(server_secret).expect("HMAC accepts any key length");
    mac.update(b"agent-auth-credential-v1\0");
    mac.update(kind.purpose());
    mac.update(b"\0");
    mac.update(tenant.as_bytes());
    mac.update(b"\0");
    mac.update(owner.as_bytes());
    mac.update(b"\0");
    mac.update(plaintext.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

pub fn legacy_registration_token_verifier(server_secret: &[u8], plaintext: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(server_secret).expect("HMAC accepts any key length");
    mac.update(b"reg-token:");
    mac.update(plaintext.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn record_matches(
    record: &CredentialRecord,
    server_secret: &[u8],
    kind: CredentialKind,
    tenant: &str,
    presented: &str,
) -> bool {
    let actual = match record.verifier_version {
        VerifierVersion::HmacSha256V1 => {
            credential_verifier(server_secret, kind, tenant, &record.owner, presented)
        }
        VerifierVersion::LegacyRegistrationTokenV0 => {
            legacy_registration_token_verifier(server_secret, presented)
        }
    };
    actual.len() == record.verifier.len()
        && bool::from(actual.as_bytes().ct_eq(record.verifier.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replayed_recovery_is_a_successful_authentication_event() {
        let event = CredentialAuditEvent::UserCredentialOperation {
            action: "consume",
            tenant: "t1",
            actor: "user:alice@example.com",
            kind: "recovery",
            target: "self",
            result: "replayed",
        }
        .security_event();

        assert_eq!(
            event.outcome,
            crate::security_event::SecurityEventOutcome::Success
        );
    }

    #[test]
    fn credential_audit_results_have_explicit_outcomes() {
        use crate::security_event::SecurityEventOutcome::{Denied, Failure, Success};

        for result in ["success", "allowed", "replayed"] {
            assert_eq!(credential_audit_outcome(result), Success, "{result}");
        }
        for result in [
            "denied",
            "step_up_required",
            "locked",
            "consumed",
            "conflict",
            "already_exists",
            "lockout_prevented",
            "not_found",
            "policy_rejected",
            "unchanged",
            "unsupported_identity",
            "invalid_origin",
            "reauthentication_required",
            "change_required",
        ] {
            assert_eq!(credential_audit_outcome(result), Denied, "{result}");
        }
        for result in [
            "failed",
            "verification_unavailable",
            "hash_unavailable",
            "unknown_future_result",
        ] {
            assert_eq!(credential_audit_outcome(result), Failure, "{result}");
        }
    }

    fn record(id: &str, secret: &str, now: i64, request: &str) -> CredentialRecord {
        new_credential_record(
            b"pepper",
            CredentialKind::ClientSecret,
            "t1",
            id.to_string(),
            "client-a".to_string(),
            secret,
            now,
            now + 1_000,
            "admin:test".to_string(),
            Some(request.to_string()),
        )
    }

    #[test]
    fn new_credential_records_store_only_owner_bound_hmac_verifiers() {
        let now = 10_000;
        let plaintext = "long-lived-plaintext-secret";
        let current = record("client-secret-v1", plaintext, now, "create");
        let serialized = serde_json::to_string(&current).unwrap();

        assert_eq!(current.owner, "client-a");
        assert_eq!(current.created_at, now);
        assert_eq!(current.expires_at, now + 1_000);
        assert_eq!(current.status, CredentialStatus::Active);
        assert_eq!(current.verifier_version, VerifierVersion::HmacSha256V1);
        assert_ne!(current.verifier, plaintext);
        assert!(!serialized.contains(plaintext));

        let set = CredentialSet {
            current: Some(current.clone()),
            version: 1,
            ..Default::default()
        };
        assert!(set
            .verify(
                b"pepper",
                CredentialKind::ClientSecret,
                "t1",
                plaintext,
                now
            )
            .is_some());
        assert!(set
            .verify(
                b"pepper",
                CredentialKind::ClientSecret,
                "t2",
                plaintext,
                now
            )
            .is_none());

        let registration = new_credential_record(
            b"pepper",
            CredentialKind::RegistrationAccessToken,
            "t1",
            "registration-v1".into(),
            "client-a".into(),
            plaintext,
            now,
            now + 1_000,
            "admin:test".into(),
            None,
        );
        let initial_access = new_credential_record(
            b"pepper",
            CredentialKind::InitialAccessToken,
            "t1",
            "iat-v1".into(),
            "bootstrap-job".into(),
            plaintext,
            now,
            now + 1_000,
            "admin:test".into(),
            None,
        );
        for (record, owner) in [
            (&registration, "client-a"),
            (&initial_access, "bootstrap-job"),
        ] {
            assert_eq!(record.owner, owner);
            assert_eq!(record.created_at, now);
            assert_eq!(record.expires_at, now + 1_000);
            assert_eq!(record.status, CredentialStatus::Active);
            assert_eq!(record.verifier_version, VerifierVersion::HmacSha256V1);
            assert_ne!(record.verifier, plaintext);
            assert!(!serde_json::to_string(record).unwrap().contains(plaintext));
        }

        let variants = [
            current.verifier,
            registration.verifier,
            initial_access.verifier,
            new_credential_record(
                b"pepper",
                CredentialKind::ClientSecret,
                "t2",
                "client-secret-v1".into(),
                "client-a".into(),
                plaintext,
                now,
                now + 1_000,
                "admin:test".into(),
                None,
            )
            .verifier,
            new_credential_record(
                b"pepper",
                CredentialKind::ClientSecret,
                "t1",
                "client-secret-v1".into(),
                "client-b".into(),
                plaintext,
                now,
                now + 1_000,
                "admin:test".into(),
                None,
            )
            .verifier,
        ];
        assert_eq!(
            variants
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            variants.len()
        );
    }

    #[test]
    fn bounded_overlap_ends_even_without_cleanup_cutover() {
        let now = 10_000;
        let mut set = CredentialSet {
            current: Some(record("old", "old-secret", now, "create")),
            version: 1,
            ..Default::default()
        };
        let next = record("next", "next-secret", now, "rotate-1");
        assert_eq!(
            stage_credential(&mut set, next, 60, now, 1),
            Ok(StageResult::Staged)
        );
        assert!(set
            .verify(
                b"pepper",
                CredentialKind::ClientSecret,
                "t1",
                "old-secret",
                now + 59
            )
            .is_some());
        assert!(set
            .verify(
                b"pepper",
                CredentialKind::ClientSecret,
                "t1",
                "next-secret",
                now + 59
            )
            .is_some());
        assert!(set
            .verify(
                b"pepper",
                CredentialKind::ClientSecret,
                "t1",
                "old-secret",
                now + 60
            )
            .is_none());
        assert!(set
            .verify(
                b"pepper",
                CredentialKind::ClientSecret,
                "t1",
                "next-secret",
                now + 60
            )
            .is_some());
    }

    #[test]
    fn rotation_rejects_a_next_value_that_expires_during_overlap() {
        let now = 1_000;
        let mut set = CredentialSet {
            current: Some(record("current", "old", now, "initial")),
            version: 1,
            ..Default::default()
        };
        let short_lived = new_credential_record(
            b"pepper",
            CredentialKind::ClientSecret,
            "t1",
            "next".into(),
            "client-a".into(),
            "new",
            now,
            now + 60,
            "admin:test".into(),
            Some("rotate-short".into()),
        );
        assert_eq!(
            stage_credential(&mut set, short_lived, 300, now, 1),
            Err(CredentialMutationError::InvalidOverlap)
        );
        assert!(set.next.is_none());
        assert_eq!(set.version, 1);
    }

    #[test]
    fn expired_active_next_cannot_resurrect_current_after_overlap() {
        let now = 1_000;
        let mut current = record("current", "old", now, "initial");
        current.expires_at = now + 10_000;
        let mut next = record("next", "new", now, "rotate");
        next.expires_at = now + 30;
        let set = CredentialSet {
            current: Some(current),
            next: Some(next),
            overlap_expires_at: Some(now + 60),
            last_revoked_credential_id: None,
            last_revoked_rotation_request_id: None,
            version: 2,
        };
        assert!(set
            .verify(
                b"pepper",
                CredentialKind::ClientSecret,
                "t1",
                "old",
                now + 61,
            )
            .is_none());
    }

    #[test]
    fn rotation_retry_does_not_create_another_credential() {
        let now = 10_000;
        let mut set = CredentialSet {
            current: Some(record("old", "old-secret", now, "create")),
            version: 1,
            ..Default::default()
        };
        assert_eq!(
            stage_credential(
                &mut set,
                record("next", "next-secret", now, "request-1"),
                60,
                now,
                1
            ),
            Ok(StageResult::Staged)
        );
        assert_eq!(
            stage_credential(
                &mut set,
                record("discarded", "discarded-secret", now, "request-1"),
                60,
                now,
                1
            ),
            Ok(StageResult::Retry)
        );
        assert_eq!(
            set.next
                .as_ref()
                .map(|record| record.credential_id.as_str()),
            Some("next")
        );
    }

    #[test]
    fn initialized_rotation_retry_is_idempotent() {
        let now = 10_000;
        let mut set = CredentialSet::default();
        assert_eq!(
            stage_credential(
                &mut set,
                record("current", "secret", now, "request-1"),
                60,
                now,
                0
            ),
            Ok(StageResult::Initialized)
        );
        assert_eq!(
            stage_credential(
                &mut set,
                record("discarded", "discarded-secret", now, "request-1"),
                60,
                now,
                0
            ),
            Ok(StageResult::Retry)
        );
        assert_eq!(
            set.current
                .as_ref()
                .map(|record| record.credential_id.as_str()),
            Some("current")
        );
        assert_eq!(set.version, 1);
    }

    #[test]
    fn rotation_after_automatic_cutover_uses_promoted_value_as_current() {
        let now = 10_000;
        let mut set = CredentialSet {
            current: Some(record("old", "old-secret", now, "create")),
            version: 1,
            ..Default::default()
        };
        stage_credential(
            &mut set,
            record("promoted", "promoted-secret", now, "rotate-1"),
            60,
            now,
            1,
        )
        .unwrap();

        assert_eq!(
            stage_credential(
                &mut set,
                record("next", "next-secret", now + 61, "rotate-2"),
                60,
                now + 61,
                2
            ),
            Ok(StageResult::Staged)
        );
        assert_eq!(
            set.current
                .as_ref()
                .map(|record| record.credential_id.as_str()),
            Some("promoted")
        );
        assert_eq!(
            set.next
                .as_ref()
                .map(|record| record.credential_id.as_str()),
            Some("next")
        );
        assert!(set
            .verify(
                b"pepper",
                CredentialKind::ClientSecret,
                "t1",
                "old-secret",
                now + 61
            )
            .is_none());
    }

    #[test]
    fn cutover_and_revoke_are_idempotent() {
        let now = 10_000;
        let mut set = CredentialSet {
            current: Some(record("old", "old-secret", now, "create")),
            version: 1,
            ..Default::default()
        };
        stage_credential(
            &mut set,
            record("next", "next-secret", now, "rotate"),
            60,
            now,
            1,
        )
        .unwrap();
        assert_eq!(cutover_credential(&mut set, "next", now, 2), Ok(true));
        assert_eq!(cutover_credential(&mut set, "next", now, 2), Ok(false));
        assert_eq!(revoke_credential(&mut set, "next", now + 1, 3), Ok(true));
        assert_eq!(revoke_credential(&mut set, "next", now + 1, 3), Ok(false));
        assert!(set
            .verify(
                b"pepper",
                CredentialKind::ClientSecret,
                "t1",
                "next-secret",
                now + 1
            )
            .is_none());
    }

    #[test]
    fn revoking_next_during_overlap_rolls_back_to_current() {
        let now = 10_000;
        let mut set = CredentialSet {
            current: Some(record("current", "current-secret", now, "create")),
            version: 1,
            ..Default::default()
        };
        stage_credential(
            &mut set,
            record("next", "next-secret", now, "rotate"),
            60,
            now,
            1,
        )
        .unwrap();

        assert_eq!(revoke_credential(&mut set, "next", now + 30, 2), Ok(true));
        assert!(set.next.is_none());
        assert!(set.overlap_expires_at.is_none());
        assert_eq!(revoke_credential(&mut set, "next", now + 31, 2), Ok(false));
        assert_eq!(
            stage_credential(
                &mut set,
                record("replacement", "replacement-secret", now + 31, "rotate"),
                60,
                now + 31,
                3
            ),
            Ok(StageResult::Retry)
        );
        assert!(set.next.is_none());
        assert_eq!(set.version, 3);
        assert!(set
            .verify(
                b"pepper",
                CredentialKind::ClientSecret,
                "t1",
                "current-secret",
                now + 61
            )
            .is_some());
        assert!(set
            .verify(
                b"pepper",
                CredentialKind::ClientSecret,
                "t1",
                "next-secret",
                now + 30
            )
            .is_none());
    }

    #[test]
    fn clearing_credentials_preserves_monotonic_version() {
        let now = 10_000;
        let mut set = CredentialSet {
            current: Some(record("current", "secret", now, "create")),
            version: 7,
            ..Default::default()
        };
        set.clear_and_advance();
        assert!(!set.has_credential_state());
        assert_eq!(set.version, 8);
    }

    #[test]
    fn revoking_next_after_overlap_does_not_restore_current() {
        let now = 10_000;
        let mut current = record("old", "old-secret", now, "create");
        current.expires_at = now + 2_000;
        let mut next = record("next", "next-secret", now, "rotate");
        next.expires_at = now + 1_000;
        let next_expires_at = next.expires_at;
        let mut set = CredentialSet {
            current: Some(current),
            version: 1,
            ..Default::default()
        };
        stage_credential(&mut set, next, 60, now, 1).unwrap();

        assert_eq!(set.effective_expires_at(now + 59), Some(now + 2_000));
        assert_eq!(set.effective_expires_at(now + 60), Some(next_expires_at));
        assert_eq!(revoke_credential(&mut set, "next", now + 61, 2), Ok(true));
        assert_eq!(set.effective_expires_at(now + 61), Some(now + 61));
        assert!(set
            .verify(
                b"pepper",
                CredentialKind::ClientSecret,
                "t1",
                "old-secret",
                now + 61
            )
            .is_none());

        let replacement = record("replacement", "replacement-secret", now + 62, "rotate-2");
        assert_eq!(
            stage_credential(&mut set, replacement, 60, now + 62, 3),
            Ok(StageResult::Initialized)
        );
        assert!(set
            .verify(
                b"pepper",
                CredentialKind::ClientSecret,
                "t1",
                "old-secret",
                now + 62
            )
            .is_none());
        assert!(set
            .verify(
                b"pepper",
                CredentialKind::ClientSecret,
                "t1",
                "replacement-secret",
                now + 62
            )
            .is_some());
    }

    #[test]
    fn rotate_does_not_discard_usable_next_when_current_is_revoked() {
        let now = 10_000;
        let mut current = record("old", "old-secret", now, "create");
        current.status = CredentialStatus::Revoked;
        let next = record("next", "next-secret", now, "rotate");
        let mut set = CredentialSet {
            current: Some(current),
            next: Some(next.clone()),
            overlap_expires_at: Some(now + 60),
            last_revoked_credential_id: None,
            last_revoked_rotation_request_id: None,
            version: 2,
        };

        assert_eq!(
            stage_credential(
                &mut set,
                record("replacement", "replacement-secret", now, "rotate-2"),
                60,
                now,
                2
            ),
            Err(CredentialMutationError::RotationPending)
        );
        assert_eq!(set.next, Some(next));
        assert_eq!(set.version, 2);
    }

    #[test]
    fn expired_or_revoked_effective_credential_still_reports_its_expiry() {
        let now = 10_000;
        let mut expired = record("expired", "secret", now, "create");
        expired.expires_at = now - 1;
        let mut set = CredentialSet {
            current: Some(expired),
            version: 1,
            ..Default::default()
        };
        assert_eq!(set.effective_expires_at(now), Some(now - 1));

        assert_eq!(revoke_credential(&mut set, "expired", now, 1), Ok(true));
        assert_eq!(set.effective_expires_at(now), Some(now - 1));
    }

    #[test]
    fn debug_output_redacts_verifier() {
        let record = record("id", "plaintext", 10_000, "request");
        let verifier = record.verifier.clone();
        let debug = format!("{record:?}");
        assert!(!debug.contains(&verifier));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("plaintext"));
    }
}
