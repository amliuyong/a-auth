//! Versioned, tenant-scoped security events.
//!
//! The interface is intentionally typed and has no free-form body or metadata
//! map. Callers can correlate an event with opaque identifiers, but cannot pass
//! request bodies or credential material through this module.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use utoipa::ToSchema;

use crate::ports::StoreError;

pub const SECURITY_EVENT_SCHEMA_VERSION: &str = "1.0";
pub const SECURITY_EVENT_HOT_RETENTION_DAYS: u32 = 400;
pub const SECURITY_EVENT_LONG_RETENTION_DAYS: u32 = 2555;
const MAX_ID_LEN: usize = 512;
const MAX_ACTION_LEN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecurityActorKind {
    User,
    Admin,
    Client,
    System,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecurityActor {
    kind: SecurityActorKind,
    id: String,
}

impl SecurityActor {
    pub fn user(id: impl Into<String>) -> Self {
        Self::new(SecurityActorKind::User, id)
    }

    pub fn admin(id: impl Into<String>) -> Self {
        Self::new(SecurityActorKind::Admin, id)
    }

    pub fn client(id: impl Into<String>) -> Self {
        Self::new(SecurityActorKind::Client, id)
    }

    pub fn system(id: impl Into<String>) -> Self {
        Self::new(SecurityActorKind::System, id)
    }

    fn new(kind: SecurityActorKind, id: impl Into<String>) -> Self {
        Self {
            kind,
            id: id.into(),
        }
    }

    fn validate(&self) -> Result<(), &'static str> {
        validate_id(&self.id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecuritySubjectKind {
    Unknown,
    User,
    Client,
    Grant,
    Credential,
    Tenant,
    Issuer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecuritySubject {
    kind: SecuritySubjectKind,
    id: String,
}

impl SecuritySubject {
    pub fn unknown(id: impl Into<String>) -> Self {
        Self::new(SecuritySubjectKind::Unknown, id)
    }

    pub fn user(id: impl Into<String>) -> Self {
        Self::new(SecuritySubjectKind::User, id)
    }

    pub fn client(id: impl Into<String>) -> Self {
        Self::new(SecuritySubjectKind::Client, id)
    }

    pub fn grant(id: impl Into<String>) -> Self {
        Self::new(SecuritySubjectKind::Grant, id)
    }

    pub fn credential(id: impl Into<String>) -> Self {
        Self::new(SecuritySubjectKind::Credential, id)
    }

    pub fn tenant(id: impl Into<String>) -> Self {
        Self::new(SecuritySubjectKind::Tenant, id)
    }

    pub fn issuer(id: impl Into<String>) -> Self {
        Self::new(SecuritySubjectKind::Issuer, id)
    }

    pub const fn kind(&self) -> SecuritySubjectKind {
        self.kind
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    fn new(kind: SecuritySubjectKind, id: impl Into<String>) -> Self {
        Self {
            kind,
            id: id.into(),
        }
    }

    fn validate(&self) -> Result<(), &'static str> {
        validate_id(&self.id)
    }
}

fn unknown_security_subject() -> SecuritySubject {
    SecuritySubject::unknown("anonymous")
}

fn deserialize_security_subject<'de, D>(deserializer: D) -> Result<SecuritySubject, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<SecuritySubject>::deserialize(deserializer)?
        .unwrap_or_else(unknown_security_subject))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventCategory {
    Authentication,
    StepUp,
    UserLifecycle,
    Credential,
    Administration,
    Grant,
    KeySecret,
    TenantBoundary,
    Infrastructure,
    Delivery,
}

impl SecurityEventCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::StepUp => "step_up",
            Self::UserLifecycle => "user_lifecycle",
            Self::Credential => "credential",
            Self::Administration => "administration",
            Self::Grant => "grant",
            Self::KeySecret => "key_secret",
            Self::TenantBoundary => "tenant_boundary",
            Self::Infrastructure => "infrastructure",
            Self::Delivery => "delivery",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventOutcome {
    Success,
    Denied,
    Failure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationMethod {
    Password,
    MagicLink,
    Invitation,
    Passkey,
    Recovery,
    Federation,
    AdminOidc,
}

impl AuthenticationMethod {
    const fn action(self) -> &'static str {
        match self {
            Self::Password => "authentication.password",
            Self::MagicLink => "authentication.magic_link",
            Self::Invitation => "authentication.invitation",
            Self::Passkey => "authentication.passkey",
            Self::Recovery => "authentication.recovery",
            Self::Federation => "authentication.federation",
            Self::AdminOidc => "authentication.admin_oidc",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserLifecycleAction {
    Create,
    Disable,
    Enable,
    Delete,
}

impl UserLifecycleAction {
    const fn action(self) -> &'static str {
        match self {
            Self::Create => "user.create",
            Self::Disable => "user.disable",
            Self::Enable => "user.enable",
            Self::Delete => "user.delete",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantAction {
    Create,
    Revoke,
    Deny,
}

impl GrantAction {
    const fn action(self) -> &'static str {
        match self {
            Self::Create => "grant.create",
            Self::Revoke => "grant.revoke",
            Self::Deny => "grant.deny",
        }
    }
}

impl SecurityEventOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Denied => "denied",
            Self::Failure => "failure",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecurityEventCorrelation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Irreversible reference only. Raw session cookie values are forbidden.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authz_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_idp_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapping_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapping_revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_key: Option<String>,
    /// Server-secret HMAC summary of the prior attribute presence/value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_value_summary: Option<String>,
    /// Server-secret HMAC summary of the attempted or installed attribute presence/value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_value_summary: Option<String>,
}

impl SecurityEventCorrelation {
    fn validate(&self) -> Result<(), &'static str> {
        for value in [
            &self.request_id,
            &self.session_fingerprint,
            &self.authz_session_id,
            &self.client_id,
            &self.grant_id,
            &self.credential_id,
            &self.operation_id,
            &self.upstream_idp_id,
            &self.mapping_id,
            &self.target_key,
            &self.old_value_summary,
            &self.new_value_summary,
        ]
        .into_iter()
        .flatten()
        {
            validate_id(value)?;
        }
        if self.mapping_revision == Some(0) {
            return Err("invalid mapping revision");
        }
        if self.target_namespace.as_ref().is_some_and(|value| {
            value.is_empty()
                || value.len() > crate::attribute_namespace::MAX_NAMESPACE_URI_BYTES
                || value
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte == b'\x7f')
        }) {
            return Err("invalid target namespace");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecurityEvent {
    pub schema_version: String,
    pub event_id: String,
    pub occurred_at: i64,
    pub tenant_id: String,
    pub actor: SecurityActor,
    #[serde(
        default = "unknown_security_subject",
        deserialize_with = "deserialize_security_subject"
    )]
    #[schema(required = true)]
    pub subject: SecuritySubject,
    pub category: SecurityEventCategory,
    pub action: String,
    pub outcome: SecurityEventOutcome,
    pub correlation: SecurityEventCorrelation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventDeliveryStatus {
    InMemory,
    Pending,
    Retrying,
    Failed,
    DeadLetterPending,
    ArchiveRefreshPending,
    Archived,
    DeadLettered,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecurityEventDeliveryAttempt {
    pub status: SecurityEventDeliveryStatus,
    pub occurred_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecurityEventDelivery {
    pub status: SecurityEventDeliveryStatus,
    pub attempts: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archived_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dead_lettered_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_key: Option<String>,
    pub history: Vec<SecurityEventDeliveryAttempt>,
}

impl SecurityEventDelivery {
    fn in_memory(occurred_at: i64) -> Self {
        Self {
            status: SecurityEventDeliveryStatus::InMemory,
            attempts: 0,
            last_attempt_at: None,
            archived_at: None,
            dead_lettered_at: None,
            archive_key: None,
            history: vec![SecurityEventDeliveryAttempt {
                status: SecurityEventDeliveryStatus::InMemory,
                occurred_at,
            }],
        }
    }

    pub fn pending(occurred_at: i64) -> Self {
        Self {
            status: SecurityEventDeliveryStatus::Pending,
            attempts: 0,
            last_attempt_at: None,
            archived_at: None,
            dead_lettered_at: None,
            archive_key: None,
            history: vec![SecurityEventDeliveryAttempt {
                status: SecurityEventDeliveryStatus::Pending,
                occurred_at,
            }],
        }
    }

    pub fn record(&mut self, status: SecurityEventDeliveryStatus, occurred_at: i64) {
        self.record_bounded(status, occurred_at, usize::MAX);
    }

    pub fn record_bounded(
        &mut self,
        status: SecurityEventDeliveryStatus,
        occurred_at: i64,
        max_history_entries: usize,
    ) {
        self.status = status;
        self.last_attempt_at = Some(occurred_at);
        if status == SecurityEventDeliveryStatus::DeadLettered {
            self.dead_lettered_at = Some(occurred_at);
        }
        if self.history.len() < max_history_entries {
            self.history.push(SecurityEventDeliveryAttempt {
                status,
                occurred_at,
            });
        }
    }

    pub fn start_attempt(&mut self, occurred_at: i64) {
        self.start_attempt_bounded(occurred_at, usize::MAX);
    }

    pub fn start_attempt_bounded(&mut self, occurred_at: i64, max_history_entries: usize) {
        self.attempts = self.attempts.saturating_add(1);
        self.record_bounded(
            SecurityEventDeliveryStatus::Pending,
            occurred_at,
            max_history_entries,
        );
    }
}

impl SecurityEventDeliveryStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InMemory => "in_memory",
            Self::Pending => "pending",
            Self::Retrying => "retrying",
            Self::Failed => "failed",
            Self::DeadLetterPending => "dead_letter_pending",
            Self::ArchiveRefreshPending => "archive_refresh_pending",
            Self::Archived => "archived",
            Self::DeadLettered => "dead_lettered",
        }
    }

    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "in_memory" => Ok(Self::InMemory),
            "pending" => Ok(Self::Pending),
            "retrying" => Ok(Self::Retrying),
            "failed" => Ok(Self::Failed),
            "dead_letter_pending" => Ok(Self::DeadLetterPending),
            "archive_refresh_pending" => Ok(Self::ArchiveRefreshPending),
            "archived" => Ok(Self::Archived),
            "dead_lettered" => Ok(Self::DeadLettered),
            _ => Err("invalid security event delivery status"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityEventIngress {
    pub event: SecurityEvent,
    pub delivery: SecurityEventDelivery,
    #[serde(default)]
    pub ingress_attempts: u32,
}

impl SecurityEventIngress {
    pub fn new(event: SecurityEvent) -> Self {
        let delivery = SecurityEventDelivery::pending(event.occurred_at);
        Self {
            event,
            delivery,
            ingress_attempts: 0,
        }
    }
}

pub fn encode_emergency_ingress(ingress: &SecurityEventIngress) -> Result<String, StoreError> {
    serde_json::to_vec(ingress)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|error| {
            StoreError::Permanent(format!(
                "security event emergency serialization failed: {error}"
            ))
        })
}

pub fn decode_emergency_ingress(encoded: &str) -> Result<SecurityEventIngress, StoreError> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
        StoreError::Permanent("invalid security event emergency encoding".to_string())
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        StoreError::Permanent(format!("invalid security event emergency payload: {error}"))
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct StoredSecurityEvent {
    pub event: SecurityEvent,
    pub delivery: SecurityEventDelivery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityEventCursor {
    tenant_id: String,
    occurred_at: i64,
    event_id: String,
}

impl SecurityEventCursor {
    pub(crate) fn new(event: &SecurityEvent) -> Self {
        Self {
            tenant_id: event.tenant_id.clone(),
            occurred_at: event.occurred_at,
            event_id: event.event_id.clone(),
        }
    }

    #[cfg(feature = "aws")]
    pub(crate) fn from_parts(
        tenant_id: impl Into<String>,
        occurred_at: i64,
        event_id: impl Into<String>,
    ) -> Result<Self, &'static str> {
        let cursor = Self {
            tenant_id: tenant_id.into(),
            occurred_at,
            event_id: event_id.into(),
        };
        validate_tenant(&cursor.tenant_id)?;
        validate_event_id(&cursor.event_id)?;
        if cursor.occurred_at <= 0 {
            return Err("invalid security event cursor timestamp");
        }
        Ok(cursor)
    }

    pub(crate) fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub(crate) fn occurred_at(&self) -> i64 {
        self.occurred_at
    }

    pub(crate) fn event_id(&self) -> &str {
        &self.event_id
    }

    pub fn encode(&self) -> Result<String, StoreError> {
        serde_json::to_vec(self)
            .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "security event cursor serialization failed: {error}"
                ))
            })
    }

    pub fn decode_for_query(
        encoded: &str,
        tenant_id: &str,
        from_inclusive: i64,
        through_inclusive: i64,
    ) -> Result<Self, StoreError> {
        let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
            StoreError::Permanent("invalid security event cursor encoding".to_string())
        })?;
        let cursor: Self = serde_json::from_slice(&bytes).map_err(|_| {
            StoreError::Permanent("invalid security event cursor payload".to_string())
        })?;
        validate_tenant(&cursor.tenant_id)
            .and_then(|_| validate_event_id(&cursor.event_id))
            .map_err(|error| StoreError::Permanent(error.to_string()))?;
        if cursor.tenant_id != tenant_id
            || !(from_inclusive..=through_inclusive).contains(&cursor.occurred_at)
        {
            return Err(StoreError::Permanent(
                "security event cursor does not match query scope".to_string(),
            ));
        }
        Ok(cursor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityEventPage {
    pub events: Vec<StoredSecurityEvent>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityEventDraft {
    pub tenant_id: String,
    pub actor: SecurityActor,
    pub subject: SecuritySubject,
    pub category: SecurityEventCategory,
    pub action: String,
    pub outcome: SecurityEventOutcome,
    pub correlation: SecurityEventCorrelation,
}

impl SecurityEventDraft {
    pub fn new(
        tenant_id: impl Into<String>,
        actor: SecurityActor,
        subject: Option<SecuritySubject>,
        category: SecurityEventCategory,
        action: impl Into<String>,
        outcome: SecurityEventOutcome,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            actor,
            subject: subject.unwrap_or_else(unknown_security_subject),
            category,
            action: action.into(),
            outcome,
            correlation: SecurityEventCorrelation::default(),
        }
    }

    pub fn correlated(mut self, correlation: SecurityEventCorrelation) -> Self {
        self.correlation = correlation;
        self
    }

    pub fn authentication(
        tenant_id: impl Into<String>,
        user_id: Option<&str>,
        method: AuthenticationMethod,
        outcome: SecurityEventOutcome,
    ) -> Self {
        // A denied attempt targets a known account but does not prove that the
        // account owner made the attempt. Attribute the actor only after a
        // successful authentication and retain the account as the subject.
        let actor = match (outcome, user_id) {
            (SecurityEventOutcome::Success, Some(user_id)) => SecurityActor::user(user_id),
            _ => SecurityActor::system("anonymous"),
        };
        Self::new(
            tenant_id,
            actor,
            user_id.map(SecuritySubject::user),
            SecurityEventCategory::Authentication,
            method.action(),
            outcome,
        )
    }

    pub fn user_lifecycle(
        tenant_id: impl Into<String>,
        actor: SecurityActor,
        user_id: &str,
        action: UserLifecycleAction,
        outcome: SecurityEventOutcome,
    ) -> Self {
        Self::new(
            tenant_id,
            actor,
            Some(SecuritySubject::user(user_id)),
            SecurityEventCategory::UserLifecycle,
            action.action(),
            outcome,
        )
    }

    pub fn grant(
        tenant_id: impl Into<String>,
        actor: SecurityActor,
        grant_id: &str,
        action: GrantAction,
        outcome: SecurityEventOutcome,
    ) -> Self {
        Self::new(
            tenant_id,
            actor,
            Some(SecuritySubject::grant(grant_id)),
            SecurityEventCategory::Grant,
            action.action(),
            outcome,
        )
        .correlated(SecurityEventCorrelation {
            grant_id: Some(grant_id.to_string()),
            ..Default::default()
        })
    }

    pub fn grant_denial(
        tenant_id: impl Into<String>,
        actor: SecurityActor,
        client_id: &str,
        operation_id: &str,
    ) -> Self {
        Self::new(
            tenant_id,
            actor,
            Some(SecuritySubject::client(client_id)),
            SecurityEventCategory::Grant,
            GrantAction::Deny.action(),
            SecurityEventOutcome::Denied,
        )
        .correlated(SecurityEventCorrelation {
            client_id: Some(client_id.to_string()),
            operation_id: Some(operation_id.to_string()),
            ..Default::default()
        })
    }

    pub fn workload_authentication(
        tenant_id: impl Into<String>,
        client_id: Option<&str>,
        outcome: SecurityEventOutcome,
    ) -> Self {
        let actor = client_id
            .map(SecurityActor::client)
            .unwrap_or_else(|| SecurityActor::system("anonymous"));
        Self::new(
            tenant_id,
            actor,
            client_id.map(SecuritySubject::client),
            SecurityEventCategory::Authentication,
            "authentication.workload",
            outcome,
        )
        .correlated(SecurityEventCorrelation {
            client_id: client_id.map(str::to_string),
            ..Default::default()
        })
    }

    pub fn workload_token_issuance(
        tenant_id: impl Into<String>,
        client_id: &str,
        outcome: SecurityEventOutcome,
    ) -> Self {
        Self::new(
            tenant_id,
            SecurityActor::client(client_id),
            Some(SecuritySubject::client(client_id)),
            SecurityEventCategory::Grant,
            "grant.workload_token.issue",
            outcome,
        )
        .correlated(SecurityEventCorrelation {
            client_id: Some(client_id.to_string()),
            ..Default::default()
        })
    }

    pub fn service_authentication(
        tenant_id: impl Into<String>,
        client_id: &str,
        outcome: SecurityEventOutcome,
    ) -> Self {
        let actor = match outcome {
            SecurityEventOutcome::Success => SecurityActor::client(client_id),
            SecurityEventOutcome::Denied | SecurityEventOutcome::Failure => {
                SecurityActor::system("anonymous")
            }
        };
        Self::new(
            tenant_id,
            actor,
            Some(SecuritySubject::client(client_id)),
            SecurityEventCategory::Authentication,
            "authentication.client",
            outcome,
        )
        .correlated(SecurityEventCorrelation {
            client_id: Some(client_id.to_string()),
            ..Default::default()
        })
    }

    pub fn service_token_issuance(
        tenant_id: impl Into<String>,
        client_id: &str,
        outcome: SecurityEventOutcome,
    ) -> Self {
        Self::new(
            tenant_id,
            SecurityActor::client(client_id),
            Some(SecuritySubject::client(client_id)),
            SecurityEventCategory::Grant,
            "grant.service_token.issue",
            outcome,
        )
        .correlated(SecurityEventCorrelation {
            client_id: Some(client_id.to_string()),
            ..Default::default()
        })
    }

    pub fn step_up(
        tenant_id: impl Into<String>,
        user_id: Option<&str>,
        client_id: &str,
        outcome: SecurityEventOutcome,
    ) -> Self {
        let actor = user_id
            .map(SecurityActor::user)
            .unwrap_or_else(|| SecurityActor::system("anonymous"));
        let subject = user_id
            .map(SecuritySubject::user)
            .unwrap_or_else(|| SecuritySubject::client(client_id));
        Self::new(
            tenant_id,
            actor,
            Some(subject),
            SecurityEventCategory::StepUp,
            "authentication.step_up",
            outcome,
        )
        .correlated(SecurityEventCorrelation {
            client_id: Some(client_id.to_string()),
            ..Default::default()
        })
    }

    pub fn tenant_boundary_denial(
        tenant_id: impl Into<String>,
        actor: SecurityActor,
        denied_tenant: &str,
    ) -> Self {
        Self::new(
            tenant_id,
            actor,
            Some(SecuritySubject::tenant(denied_tenant)),
            SecurityEventCategory::TenantBoundary,
            "tenant.access_denied",
            SecurityEventOutcome::Denied,
        )
    }

    pub fn issuer_boundary_denial(
        tenant_id: impl Into<String>,
        actor: SecurityActor,
        denied_issuer: &str,
    ) -> Self {
        Self::new(
            tenant_id,
            actor,
            Some(SecuritySubject::issuer(denied_issuer)),
            SecurityEventCategory::TenantBoundary,
            "tenant.access_denied",
            SecurityEventOutcome::Denied,
        )
    }

    pub fn into_event_at(
        self,
        event_id: impl Into<String>,
        occurred_at: i64,
    ) -> Result<SecurityEvent, &'static str> {
        SecurityEvent::new_at(
            event_id,
            occurred_at,
            self.tenant_id,
            self.actor,
            Some(self.subject),
            self.category,
            self.action,
            self.outcome,
            self.correlation,
        )
    }
}

impl SecurityEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new_at(
        event_id: impl Into<String>,
        occurred_at: i64,
        tenant_id: impl Into<String>,
        actor: SecurityActor,
        subject: Option<SecuritySubject>,
        category: SecurityEventCategory,
        action: impl Into<String>,
        outcome: SecurityEventOutcome,
        correlation: SecurityEventCorrelation,
    ) -> Result<Self, &'static str> {
        let event_id = event_id.into();
        let tenant_id = tenant_id.into();
        let tenant_id = if tenant_id.is_empty() {
            "default".to_string()
        } else {
            tenant_id
        };
        let action = action.into();
        let subject = subject.unwrap_or_else(unknown_security_subject);

        validate_event_id(&event_id)?;
        if occurred_at <= 0 {
            return Err("occurred_at must be positive");
        }
        validate_tenant(&tenant_id)?;
        actor.validate()?;
        subject.validate()?;
        if action.is_empty()
            || action.len() > MAX_ACTION_LEN
            || !action.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
            })
        {
            return Err("invalid action");
        }
        correlation.validate()?;

        Ok(Self {
            schema_version: SECURITY_EVENT_SCHEMA_VERSION.to_string(),
            event_id,
            occurred_at,
            tenant_id,
            actor,
            subject,
            category,
            action,
            outcome,
            correlation,
        })
    }
}

pub fn new_event_id() -> String {
    let mut bytes = [0u8; 18];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("evt_{}", URL_SAFE_NO_PAD.encode(bytes))
}

pub fn scim_lifecycle_event_id(
    tenant_id: &str,
    user_id: &str,
    action: &str,
    credential_epoch: u64,
) -> String {
    let mut digest = Sha256::new();
    for component in [
        b"agent-auth:scim-lifecycle:v1".as_slice(),
        tenant_id.as_bytes(),
        user_id.as_bytes(),
        action.as_bytes(),
        credential_epoch.to_string().as_bytes(),
    ] {
        digest.update((component.len() as u64).to_be_bytes());
        digest.update(component);
    }
    format!("evt_scim_{}", URL_SAFE_NO_PAD.encode(digest.finalize()))
}

fn validate_id(value: &str) -> Result<(), &'static str> {
    if value.is_empty()
        || value.len() > MAX_ID_LEN
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\x7f')
    {
        return Err("invalid identifier");
    }
    Ok(())
}

fn validate_event_id(value: &str) -> Result<(), &'static str> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
    {
        return Err("invalid event id");
    }
    Ok(())
}

fn validate_tenant(value: &str) -> Result<(), &'static str> {
    if value.is_empty()
        || value.len() > 63
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("invalid tenant");
    }
    Ok(())
}

pub trait SecurityEventStore: Send + Sync {
    /// Insert an immutable event. Returns false when the event ID already exists.
    fn put(&self, event: &SecurityEvent) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Insert an immutable event with delivery attempts accumulated before the
    /// hot ledger became available.
    fn put_with_delivery(
        &self,
        event: &SecurityEvent,
        delivery: &SecurityEventDelivery,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    fn list_by_tenant(
        &self,
        tenant_id: &str,
        from_inclusive: i64,
        through_inclusive: i64,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<StoredSecurityEvent>, StoreError>> + Send;

    fn list_by_tenant_page(
        &self,
        tenant_id: &str,
        from_inclusive: i64,
        through_inclusive: i64,
        limit: usize,
        cursor: Option<&SecurityEventCursor>,
    ) -> impl Future<Output = Result<SecurityEventPage, StoreError>> + Send;
}

pub trait SecurityEventFallback: Send + Sync {
    /// Durably enqueue an event that could not be inserted into the hot ledger.
    fn enqueue(
        &self,
        ingress: &SecurityEventIngress,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Durably enqueue a bounded batch. Implementations may override this with a
    /// native batch API; the default preserves compatibility for simple sinks.
    fn enqueue_batch(
        &self,
        ingresses: &[SecurityEventIngress],
    ) -> impl Future<Output = Result<Vec<SecurityEventFallbackOutcome>, StoreError>> + Send {
        async move {
            let mut outcomes = Vec::with_capacity(ingresses.len());
            for ingress in ingresses {
                outcomes.push(match self.enqueue(ingress).await {
                    Ok(()) => SecurityEventFallbackOutcome::Enqueued,
                    Err(StoreError::Transient(error)) => {
                        SecurityEventFallbackOutcome::Retryable(error)
                    }
                    Err(StoreError::Permanent(error)) => {
                        SecurityEventFallbackOutcome::Permanent(error)
                    }
                });
            }
            Ok(outcomes)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityEventFallbackOutcome {
    Enqueued,
    Retryable(String),
    Permanent(String),
}

#[derive(Clone, Default)]
pub struct MemorySecurityEventStore {
    events: Arc<Mutex<BTreeMap<String, StoredSecurityEvent>>>,
}

impl SecurityEventStore for MemorySecurityEventStore {
    async fn put(&self, event: &SecurityEvent) -> Result<bool, StoreError> {
        self.put_with_delivery(event, &SecurityEventDelivery::in_memory(event.occurred_at))
            .await
    }

    async fn put_with_delivery(
        &self,
        event: &SecurityEvent,
        delivery: &SecurityEventDelivery,
    ) -> Result<bool, StoreError> {
        let mut events = self.events.lock().await;
        if events.contains_key(&event.event_id) {
            return Ok(false);
        }
        events.insert(
            event.event_id.clone(),
            StoredSecurityEvent {
                event: event.clone(),
                delivery: delivery.clone(),
            },
        );
        Ok(true)
    }

    async fn list_by_tenant(
        &self,
        tenant_id: &str,
        from_inclusive: i64,
        through_inclusive: i64,
        limit: usize,
    ) -> Result<Vec<StoredSecurityEvent>, StoreError> {
        let tenant_id = if tenant_id.is_empty() {
            "default"
        } else {
            tenant_id
        };
        let mut events = self
            .events
            .lock()
            .await
            .values()
            .filter(|event| {
                event.event.tenant_id == tenant_id
                    && event.event.occurred_at >= from_inclusive
                    && event.event.occurred_at <= through_inclusive
            })
            .cloned()
            .collect::<Vec<_>>();
        events.sort_by(|left, right| {
            right
                .event
                .occurred_at
                .cmp(&left.event.occurred_at)
                .then_with(|| right.event.event_id.cmp(&left.event.event_id))
        });
        events.truncate(limit.min(1000));
        Ok(events)
    }

    async fn list_by_tenant_page(
        &self,
        tenant_id: &str,
        from_inclusive: i64,
        through_inclusive: i64,
        limit: usize,
        cursor: Option<&SecurityEventCursor>,
    ) -> Result<SecurityEventPage, StoreError> {
        let tenant_id = if tenant_id.is_empty() {
            "default"
        } else {
            tenant_id
        };
        let limit = limit.clamp(1, 1000);
        let mut events = self
            .events
            .lock()
            .await
            .values()
            .filter(|event| {
                event.event.tenant_id == tenant_id
                    && event.event.occurred_at >= from_inclusive
                    && event.event.occurred_at <= through_inclusive
            })
            .cloned()
            .collect::<Vec<_>>();
        events.sort_by(|left, right| {
            right
                .event
                .occurred_at
                .cmp(&left.event.occurred_at)
                .then_with(|| right.event.event_id.cmp(&left.event.event_id))
        });
        if let Some(cursor) = cursor {
            if cursor.tenant_id() != tenant_id {
                return Err(StoreError::Permanent(
                    "security event cursor tenant mismatch".to_string(),
                ));
            }
            events.retain(|stored| {
                (stored.event.occurred_at, stored.event.event_id.as_str())
                    < (cursor.occurred_at(), cursor.event_id())
            });
        }
        let has_more = events.len() > limit;
        events.truncate(limit);
        let next_cursor = if has_more {
            events
                .last()
                .map(|stored| SecurityEventCursor::new(&stored.event).encode())
                .transpose()?
        } else {
            None
        };
        Ok(SecurityEventPage {
            events,
            next_cursor,
        })
    }
}
