//! Admin 控制台后端(spec 025)——租户管理面 + SaaS 平台只读控制面。
//!
//! 三个互不重叠的鉴权域:
//! - SelfHosted `/admin/*` 凭部署级 `admin_token`;
//! - SaaS 租户 `/admin/*` 凭请求 Host 对应的逐租户 token;
//! - SaaS 控制 Host `/admin/control/*` 凭平台 `admin_token`。
//!
//! **RFC 7592 自助域** `/register/{id}` 凭 `registration_access_token`(每 client 独立,见 register.rs)。
//! 各域互不代替,凭据缺失时 fail-closed。
//!
//! 决策真相源 docs/DESIGN §0.5(控制面)/ §3.2(RFC 7592 鉴权)/ CONFORMANCE C4.3。

use agent_auth_discovery::{derive_issuer, issuer_for_tenant, Form, IssuerError, MetadataConfig};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::ports::{
    AuthzSessionStore, ClientRecord, ClientStore, DomainBinding, DomainMapStore,
    FederationConfigStore, GrantStore, InitialAccessTokenStore, InvitationStore, MessageOutbox,
    PasskeyStore, PasswordCredential, PasswordStore, RecoveryStore, SessionStore,
    UserListStatusFilter, UserRecord, UserStatus, UsersStore, WorkloadTrustStore,
};
use crate::security_event::{
    SecurityEventCursor, SecurityEventStore, StoredSecurityEvent,
    SECURITY_EVENT_HOT_RETENTION_DAYS, SECURITY_EVENT_SCHEMA_VERSION,
};
use crate::state::AppState;
use crate::tenant_admin::{authenticate_platform, AdminAction, TenantAdminContext};
use crate::tenant_keys::{
    TenantKeyCommand, TenantKeyCommandAction, TenantKeyCommandSink, TenantKeyRegistry,
};

pub(crate) use crate::tenant_admin::bearer;

type HmacSha256 = Hmac<Sha256>;

/// registration_access_token 的存储哈希(C4.3):HMAC-SHA256(server_secret, "reg-token:"‖token)。
pub fn reg_token_hash(server_secret: &[u8], token: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut mac = HmacSha256::new_from_slice(server_secret).expect("HMAC any key len");
    mac.update(b"reg-token:");
    mac.update(token.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// 常量时间比对 base64 哈希串(reg_token / admin_token 用)。
pub fn hash_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[derive(Serialize, ToSchema)]
pub struct ControlTenantView {
    pub tenant_id: String,
    pub issuer: String,
    pub admin_url: String,
    pub admin_secret_arn: String,
}

#[derive(Serialize, ToSchema)]
pub struct ControlTenants {
    pub tenants: Vec<ControlTenantView>,
}

fn control_tenant_views(state: &AppState) -> Option<Vec<ControlTenantView>> {
    use std::collections::HashSet;

    let Form::Saas { .. } = &state.form else {
        return None;
    };
    if state.saas_tenants.is_empty() {
        return None;
    }
    let configured: HashSet<&str> = state.saas_tenants.iter().map(String::as_str).collect();
    let tenant_secret_refs = state.admin_credentials.tenant_secret_refs();
    let arn_tenants: HashSet<&str> = tenant_secret_refs.keys().map(String::as_str).collect();
    let unique_arns: HashSet<&str> = tenant_secret_refs.values().map(String::as_str).collect();
    if configured.len() != state.saas_tenants.len()
        || configured != arn_tenants
        || unique_arns.len() != tenant_secret_refs.len()
        || tenant_secret_refs
            .values()
            .any(|arn| !arn.contains(":secretsmanager:") || !arn.contains(":secret:"))
        || state
            .admin_credentials
            .platform_secret_ref()
            .is_none_or(|platform| tenant_secret_refs.values().any(|tenant| tenant == platform))
    {
        return None;
    }

    let mut tenants = Vec::with_capacity(state.saas_tenants.len());
    for tenant_id in state.saas_tenants.iter() {
        let issuer = issuer_for_tenant(&state.form, tenant_id).ok()?;
        let admin_secret_arn = tenant_secret_refs.get(tenant_id)?;
        if admin_secret_arn.is_empty() {
            return None;
        }
        tenants.push(ControlTenantView {
            tenant_id: tenant_id.clone(),
            issuer: issuer.as_str().to_string(),
            admin_url: format!("{}/admin", issuer.as_str()),
            admin_secret_arn: admin_secret_arn.clone(),
        });
    }
    tenants.sort_by(|a, b| a.tenant_id.cmp(&b.tenant_id));
    Some(tenants)
}

/// `GET /admin/control/tenants`:SaaS 控制 Host 上的平台只读租户目录。
#[utoipa::path(get, path = "/admin/control/tenants", tag = "admin",
    responses(
        (status = 200, description = "只读租户目录", body = ControlTenants),
        (status = 401, description = "平台 admin 认证失败"),
        (status = 404, description = "非 SaaS 控制 Host"),
        (status = 503, description = "租户注册表或 Secret ARN 配置不完整")
    ))]
pub async fn control_tenants(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Form::Saas { control_host, .. } = &state.form else {
        return json_status(StatusCode::NOT_FOUND, "not found");
    };
    if crate::hostutil::issuer_host(&headers).as_deref() != Some(control_host.as_str()) {
        return json_status(StatusCode::NOT_FOUND, "not found");
    }
    if let Err(response) = authenticate_platform(&state, &headers).await {
        return response;
    }
    let Some(tenants) = control_tenant_views(&state) else {
        return json_status(
            StatusCode::SERVICE_UNAVAILABLE,
            "tenant admin configuration incomplete",
        );
    };
    (StatusCode::OK, Json(ControlTenants { tenants })).into_response()
}

#[derive(Serialize, ToSchema)]
pub struct ControlTenantKeysView {
    pub tenant_id: String,
    pub lifecycle: String,
    pub revision: Option<u64>,
    pub ready: bool,
    pub generation: Option<u64>,
    pub operation_id: Option<String>,
    pub retire_after: Option<i64>,
    pub last_failure: Option<String>,
    pub last_failure_operation_id: Option<String>,
    pub pending_deletions: usize,
}

#[derive(Deserialize, ToSchema)]
pub struct ControlTenantKeyCommandRequest {
    pub operation_id: String,
}

#[derive(Serialize, ToSchema)]
pub struct ControlTenantKeyCommandAccepted {
    pub tenant_id: String,
    pub action: String,
    pub operation_id: String,
    pub status: String,
}

async fn authorize_tenant_key_control(
    state: &AppState,
    headers: &HeaderMap,
    tenant_id: &str,
) -> Result<(), axum::response::Response> {
    let Form::Saas { control_host, .. } = &state.form else {
        return Err(json_status(StatusCode::NOT_FOUND, "not found"));
    };
    if crate::hostutil::issuer_host(headers).as_deref() != Some(control_host.as_str()) {
        return Err(json_status(StatusCode::NOT_FOUND, "not found"));
    }
    authenticate_platform(state, headers).await?;
    if !state.saas_tenants.iter().any(|tenant| tenant == tenant_id) {
        return Err(json_status(StatusCode::NOT_FOUND, "tenant not found"));
    }
    Ok(())
}

/// Read the authoritative onboarding/rotation state for one fixed-domain tenant.
#[utoipa::path(get, path = "/admin/control/tenants/{tenant_id}/keys", tag = "admin",
    params(("tenant_id" = String, Path, description = "SaaS tenant label")),
    responses(
        (status = 200, description = "Tenant key lifecycle", body = ControlTenantKeysView),
        (status = 401, description = "Platform admin authentication failed"),
        (status = 404, description = "Unknown tenant or non-control host"),
        (status = 503, description = "Registry unavailable")
    ))]
pub async fn control_tenant_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(response) = authorize_tenant_key_control(&state, &headers, &tenant_id).await {
        return response;
    }
    let record = match state.tenant_keys.registry().get(&tenant_id).await {
        Ok(record) => record,
        Err(_) => {
            return json_status(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant key registry unavailable",
            )
        }
    };
    let view = match record {
        Some(record) => ControlTenantKeysView {
            tenant_id,
            lifecycle: serde_json::to_value(&record.lifecycle)
                .ok()
                .and_then(|value| value.as_str().map(str::to_string))
                .unwrap_or_else(|| "invalid".to_string()),
            revision: Some(record.revision),
            ready: record.ready_snapshot().is_ok(),
            generation: record
                .served_snapshot
                .as_ref()
                .map(|snapshot| snapshot.generation),
            operation_id: record
                .operation
                .as_ref()
                .map(|operation| operation.operation_id.clone()),
            retire_after: record
                .operation
                .as_ref()
                .and_then(|operation| operation.retire_after),
            last_failure: record
                .last_failure
                .as_ref()
                .map(|failure| failure.error_class.clone()),
            last_failure_operation_id: record
                .last_failure
                .as_ref()
                .map(|failure| failure.operation_id.clone()),
            pending_deletions: record.pending_deletion_arns.len(),
        },
        None => ControlTenantKeysView {
            tenant_id,
            lifecycle: "unprovisioned".to_string(),
            revision: None,
            ready: false,
            generation: None,
            operation_id: None,
            retire_after: None,
            last_failure: None,
            last_failure_operation_id: None,
            pending_deletions: 0,
        },
    };
    (StatusCode::OK, Json(view)).into_response()
}

/// Queue an idempotent tenant-key lifecycle command.
#[utoipa::path(post, path = "/admin/control/tenants/{tenant_id}/keys/{action}", tag = "admin",
    params(
        ("tenant_id" = String, Path, description = "SaaS tenant label"),
        ("action" = String, Path, description = "ensure, rotate, activate, rollback, retire, or emergency-revoke")
    ),
    request_body = ControlTenantKeyCommandRequest,
    responses(
        (status = 202, description = "Command accepted", body = ControlTenantKeyCommandAccepted),
        (status = 400, description = "Invalid action or operation id"),
        (status = 401, description = "Platform admin authentication failed"),
        (status = 404, description = "Unknown tenant or non-control host"),
        (status = 503, description = "Command queue unavailable")
    ))]
pub async fn control_tenant_key_command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((tenant_id, action)): Path<(String, String)>,
    Json(request): Json<ControlTenantKeyCommandRequest>,
) -> impl IntoResponse {
    if let Err(response) = authorize_tenant_key_control(&state, &headers, &tenant_id).await {
        return response;
    }
    let action_kind = match action.as_str() {
        "ensure" => TenantKeyCommandAction::Ensure,
        "rotate" => TenantKeyCommandAction::Rotate,
        "activate" => TenantKeyCommandAction::Activate,
        "rollback" => TenantKeyCommandAction::Rollback,
        "retire" => TenantKeyCommandAction::Retire,
        "emergency-revoke" => TenantKeyCommandAction::EmergencyRevoke,
        _ => return json_status(StatusCode::BAD_REQUEST, "invalid tenant key action"),
    };
    if request.operation_id.is_empty()
        || request.operation_id.len() > 128
        || !request
            .operation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return json_status(StatusCode::BAD_REQUEST, "invalid operation_id");
    }
    let command = TenantKeyCommand {
        tenant_id: tenant_id.clone(),
        action: action_kind,
        operation_id: request.operation_id.clone(),
        requested_at: crate::current_unix_secs(),
        governance_dispatch: None,
    };
    if state
        .tenant_keys
        .command_sink()
        .send(command)
        .await
        .is_err()
    {
        state
            .record_security_event(crate::security_event::SecurityEventDraft::new(
                &tenant_id,
                crate::security_event::SecurityActor::admin("platform"),
                Some(crate::security_event::SecuritySubject::tenant(&tenant_id)),
                crate::security_event::SecurityEventCategory::KeySecret,
                format!("key.tenant.{action}"),
                crate::security_event::SecurityEventOutcome::Failure,
            ))
            .await;
        return json_status(
            StatusCode::SERVICE_UNAVAILABLE,
            "tenant key command queue unavailable",
        );
    }
    state
        .record_security_event(crate::security_event::SecurityEventDraft::new(
            &tenant_id,
            crate::security_event::SecurityActor::admin("platform"),
            Some(crate::security_event::SecuritySubject::tenant(&tenant_id)),
            crate::security_event::SecurityEventCategory::KeySecret,
            format!("key.tenant.{action}"),
            crate::security_event::SecurityEventOutcome::Success,
        ))
        .await;
    (
        StatusCode::ACCEPTED,
        Json(ControlTenantKeyCommandAccepted {
            tenant_id,
            action,
            operation_id: request.operation_id,
            status: "accepted".to_string(),
        }),
    )
        .into_response()
}

// ---- 仪表盘 ----

#[derive(Serialize, ToSchema)]
pub struct Overview {
    pub phase: String,
    pub issuer: String,
    /// discovery 该 phase 实际宣告的端点集(与 /.well-known 同源,不硬编码)。
    pub endpoints: Vec<String>,
    pub client_count: usize,
    /// 活跃授权会话数(非终态 + 未过期,spec 004)。
    pub active_sessions: usize,
}

/// `GET /admin/overview`:运行态快照(admin 认证)。
#[utoipa::path(get, path = "/admin/overview", tag = "admin",
    responses((status = 200, description = "运行态快照", body = Overview), (status = 401, description = "admin 认证失败")))]
pub async fn overview(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    // grey-state gate(评审 L1,同 list_messages):SaaS 分区关时 tenant="" → client_count/active_sessions
    // 聚合的是跨租户共享 "" 分区(泄露他租户聚合量)。故分区未就绪的 SaaS 恒 404。
    if saas_users_disabled(&state) {
        return json_status(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Read).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    let tenant = admin.storage_tenant();
    // issuer host(与 discovery 同口径 C1.6a):优先 X-Forwarded-Host(CloudFront 统一入口透传)、回落 Host。
    let Some(issuer) =
        crate::hostutil::issuer_host(&headers).and_then(|h| derive_issuer(&h, &state.form).ok())
    else {
        return json_status(StatusCode::BAD_REQUEST, "bad host");
    };
    // discovery 端点集(来自权威 phase golden,不硬编码)。
    let cfg = MetadataConfig {
        issuer: issuer.clone(),
        phase: state.phase,
        subject_type: state.subject_type_for_tenant(tenant),
        ciba_ping_push_active: state.ciba_ping_push_active(),
        mtls_svid_enabled: state.mtls_svid_enabled,
        private_key_jwt_enabled: state.private_key_jwt_active(),
        ema_enabled: state.ema_active_for_tenant(tenant),
        client_id_metadata_document_supported: state.cimd_active_for_tenant(tenant),
    };
    let meta = agent_auth_discovery::openid_configuration(&cfg);
    let endpoints: Vec<String> = meta
        .to_json()
        .as_object()
        .map(|m| {
            m.keys()
                .filter(|k| k.ends_with("_endpoint") || k.ends_with("_uri"))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let client_count = state
        .clients
        .list(tenant)
        .await
        .map(|v| v.len())
        .unwrap_or(0);
    // 活跃授权会话数(非终态 + 未过期,以 now 判过期;来自权威源 AuthzSessionStore,评审 M4)。
    let now = crate::token::current_unix_secs_pub();
    let active_sessions = state
        .authz_sessions
        .count_active(tenant, now)
        .await
        .unwrap_or(0);
    Json(Overview {
        phase: format!("{:?}", state.phase),
        issuer: issuer.as_str().to_string(),
        endpoints,
        client_count,
        active_sessions,
    })
    .into_response()
}

// ---- 消息 outbox(SES 未接前的 messages 表模拟观测,spec 003 §1.5)----

/// 一条已"发出"的消息视图(magic-link / recovery)。
#[derive(Serialize, ToSchema)]
pub struct MessageView {
    pub message_id: String,
    pub kind: String,
    pub recipient: String,
    pub body: String,
    pub created_at: i64,
    pub ttl: i64,
}

#[derive(Serialize, ToSchema)]
pub struct MessageList {
    pub messages: Vec<MessageView>,
    pub total: usize,
}

/// `GET /admin/messages`(admin 认证):看最近"发出"的消息(SES 未接前落 messages 表,TTL=1 天)。
/// 观测用——运营方无需真收邮件即可确认 magic-link / recovery 通知已产生。
#[utoipa::path(get, path = "/admin/messages", tag = "admin",
    responses((status = 200, description = "最近消息(倒序,上限 50)", body = MessageList), (status = 401)))]
pub async fn list_messages(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    // 🔴 grey-state gate(评审 codex#1 + Kiro-H1):SaaS + 分区**关**时 tenant_or_400 返空串 → 所有租户
    // 消息落同一 "" 分区 → list 会跨租户泄露 magic-link 登录 URL(可重放)+ email PII。故与 /admin/users*
    // 同 gate:分区未就绪的 SaaS 恒 404(比 user 数据更敏感,MUST 拦)。
    if saas_users_disabled(&state) {
        return json_status(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Read).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    let tenant = admin.storage_tenant();
    // tenant-scope(C10.19):只列本租户消息,绝不跨租户泄露 magic-link URL / PII。
    match state.messages.list_recent(tenant, 50).await {
        Ok(msgs) => {
            let messages: Vec<MessageView> = msgs
                .into_iter()
                .map(|m| MessageView {
                    message_id: m.message_id,
                    kind: m.kind,
                    recipient: m.recipient,
                    body: m.body,
                    created_at: m.created_at,
                    ttl: m.ttl,
                })
                .collect();
            let total = messages.len();
            Json(MessageList { messages, total }).into_response()
        }
        Err(_) => json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SecurityEventQuery {
    /// Inclusive Unix timestamp. Defaults to 30 days before now.
    pub from: Option<i64>,
    /// Inclusive Unix timestamp. Defaults to now.
    pub through: Option<i64>,
    /// Maximum events returned, from 1 through 500.
    pub limit: Option<usize>,
    /// Opaque continuation cursor from the prior response.
    pub cursor: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct SecurityEventList {
    pub schema_version: String,
    pub tenant_id: String,
    pub from: i64,
    pub through: i64,
    pub hot_retention_days: u32,
    pub events: Vec<StoredSecurityEvent>,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Export the authenticated tenant's recent versioned security events.
#[utoipa::path(
    get,
    path = "/admin/security-events",
    tag = "admin",
    params(
        ("from" = Option<i64>, Query, description = "Inclusive Unix timestamp"),
        ("through" = Option<i64>, Query, description = "Inclusive Unix timestamp"),
        (
            "limit" = Option<usize>,
            Query,
            minimum = 1,
            maximum = 500,
            description = "1 through 500"
        ),
        ("cursor" = Option<String>, Query, description = "Opaque continuation cursor")
    ),
    responses(
        (status = 200, description = "Tenant-scoped security event export", body = SecurityEventList),
        (status = 400, description = "Invalid query range"),
        (status = 401, description = "Admin authentication failed"),
        (status = 403, description = "Admin read permission required"),
        (status = 503, description = "Security event store unavailable")
    )
)]
pub async fn list_security_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SecurityEventQuery>,
) -> impl IntoResponse {
    if saas_users_disabled(&state) {
        return json_status(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Read).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let now = crate::current_unix_secs();
    let from = query.from.unwrap_or(now.saturating_sub(30 * 24 * 60 * 60));
    let through = query.through.unwrap_or(now);
    let limit = query.limit.unwrap_or(100);
    if from < 0 || through < from || !(1..=500).contains(&limit) {
        return json_status(StatusCode::BAD_REQUEST, "invalid security event query");
    }
    let tenant_id = admin.tenant_id().to_string();
    let cursor = match query.cursor.as_deref() {
        Some(cursor) => {
            match SecurityEventCursor::decode_for_query(cursor, &tenant_id, from, through) {
                Ok(cursor) => Some(cursor),
                Err(_) => {
                    return json_status(StatusCode::BAD_REQUEST, "invalid security event cursor")
                }
            }
        }
        None => None,
    };
    match state
        .security_events
        .list_by_tenant_page(&tenant_id, from, through, limit, cursor.as_ref())
        .await
    {
        Ok(page) => {
            let total = page.events.len();
            Json(SecurityEventList {
                schema_version: SECURITY_EVENT_SCHEMA_VERSION.to_string(),
                tenant_id,
                from,
                through,
                hot_retention_days: SECURITY_EVENT_HOT_RETENTION_DAYS,
                events: page.events,
                total,
                next_cursor: page.next_cursor,
            })
            .into_response()
        }
        Err(_) => json_status(
            StatusCode::SERVICE_UNAVAILABLE,
            "security event store unavailable",
        ),
    }
}

// ---- client 管理(admin 超级权限)----

/// client 对外视图(**不含 client_secret / reg_token_hash**,spec 025 H5)。
#[derive(Serialize, ToSchema)]
pub struct CredentialView {
    pub credential_id: String,
    pub owner: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub status: String,
    pub audit_identity: String,
}

#[derive(Serialize, ToSchema)]
pub struct CredentialSetView {
    #[schema(required = true)]
    pub current: Option<CredentialView>,
    #[schema(required = true)]
    pub next: Option<CredentialView>,
    #[schema(required = true)]
    pub overlap_expires_at: Option<i64>,
    pub version: u64,
}

#[derive(Serialize, ToSchema)]
pub struct ClientView {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub application_type: String,
    pub token_endpoint_auth_method: String,
    pub require_dpop: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<crate::ports::RegisteredClientJwks>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_resource: Option<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub introspect_enabled: bool,
    pub resource_ids: Vec<String>,
    /// AS 最后一次记录到的 token 签发活动所在 UTC 日起点(Unix 秒,天级精度);null = 从未记录。
    /// 这是保守信号:极窄竞态下可能包含随后被抑制/吊销的签名,且不保证交付或下游 RS 使用。
    #[schema(required = true)]
    pub last_used_at: Option<i64>,
    /// RFC 7591/7592 当前 client secret 的真实过期时间。
    #[schema(required = true)]
    pub client_secret_expires_at: Option<i64>,
    pub client_secret_credentials: CredentialSetView,
    pub registration_token_credentials: CredentialSetView,
}

fn credential_view(record: &crate::credential::CredentialRecord) -> CredentialView {
    CredentialView {
        credential_id: record.credential_id.clone(),
        owner: record.owner.clone(),
        created_at: record.created_at,
        expires_at: record.expires_at,
        status: credential_status_name(record.status).to_string(),
        audit_identity: record.audit_identity.clone(),
    }
}

fn credential_status_name(status: crate::credential::CredentialStatus) -> &'static str {
    match status {
        crate::credential::CredentialStatus::Active => "active",
        crate::credential::CredentialStatus::Revoked => "revoked",
        crate::credential::CredentialStatus::Consumed => "consumed",
    }
}

fn credential_set_view(set: &crate::credential::CredentialSet) -> CredentialSetView {
    CredentialSetView {
        current: set.current.as_ref().map(credential_view),
        next: set.next.as_ref().map(credential_view),
        overlap_expires_at: set.overlap_expires_at,
        version: set.version,
    }
}

pub(crate) fn view(c: &ClientRecord) -> ClientView {
    let now = crate::token::current_unix_secs_pub();
    ClientView {
        client_id: c.client_id.clone(),
        redirect_uris: c.redirect_uris.clone(),
        application_type: c.application_type().to_string(),
        token_endpoint_auth_method: c.token_endpoint_auth_method.clone(),
        require_dpop: c.require_dpop,
        redirect_mode: c.redirect_mode.clone(),
        jwks: c.jwks.clone(),
        jwks_uri: c.jwks_uri.clone(),
        token_endpoint_auth_signing_alg: c.token_endpoint_auth_signing_alg.clone(),
        default_resource: c.default_resource.clone(),
        post_logout_redirect_uris: c.post_logout_redirect_uris.clone(),
        introspect_enabled: c.introspect_enabled,
        resource_ids: c.resource_ids.clone(),
        last_used_at: c.last_used_day.and_then(|day| day.checked_mul(86_400)),
        client_secret_expires_at: c.client_secret_credentials.effective_expires_at(now),
        client_secret_credentials: credential_set_view(&c.client_secret_credentials),
        registration_token_credentials: credential_set_view(&c.registration_token_credentials),
    }
}

#[derive(Serialize, ToSchema)]
pub struct ClientList {
    pub clients: Vec<ClientView>,
    pub total: usize,
    /// Admin client form must render this server-owned executable projection.
    pub registered_client_auth_methods_supported: Vec<String>,
}

/// `GET /admin/clients`:列出所有 client(非敏感字段,不回 secret)。
#[utoipa::path(get, path = "/admin/clients", tag = "admin",
    responses((status = 200, description = "client 列表", body = ClientList), (status = 401, description = "admin 认证失败")))]
pub async fn list_clients(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Read).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    let tenant = admin.storage_tenant();
    match state.clients.list(tenant).await {
        Ok(cs) => {
            let clients: Vec<ClientView> = cs.iter().map(view).collect();
            let total = clients.len();
            let registered_client_auth_methods_supported = state
                .registered_client_auth_method_names()
                .into_iter()
                .map(str::to_string)
                .collect();
            Json(ClientList {
                clients,
                total,
                registered_client_auth_methods_supported,
            })
            .into_response()
        }
        Err(_) => json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    }
}

/// `GET /admin/clients/{client_id}`:单 client(不回 secret)。
#[utoipa::path(get, path = "/admin/clients/{client_id}", tag = "admin",
    params(("client_id" = String, Path)),
    responses((status = 200, description = "client", body = ClientView), (status = 401), (status = 404)))]
pub async fn get_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> impl IntoResponse {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Read).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    let tenant = admin.storage_tenant();
    match state.clients.get(tenant, &client_id).await {
        Ok(Some(c)) => Json(view(&c)).into_response(),
        Ok(None) => json_status(StatusCode::NOT_FOUND, "not found"),
        Err(_) => json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    }
}

/// `DELETE /admin/clients/{client_id}`:建立 client tombstone 写屏障后，级联吊销 refresh
/// family、物理删除 Grants，再删除 client(spec 025)。
#[utoipa::path(delete, path = "/admin/clients/{client_id}", tag = "admin",
    params(
        ("client_id" = String, Path),
        ("x-agent-auth-expected-authority-revision" = Option<u64>, Header)
    ),
    responses((status = 200, description = "已删除", body = ClientDeleteResponse), (status = 401), (status = 404, description = "不存在"), (status = 409, description = "authority revision conflict")))]
pub async fn delete_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> impl IntoResponse {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    let tenant = admin.storage_tenant();
    // 不存在 → 404(幂等:重复 DELETE 也 404)。
    let client = match state.clients.get(tenant, &client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => return json_status(StatusCode::NOT_FOUND, "not found"),
        Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    };
    let expected_authority_revision = match headers
        .get("x-agent-auth-expected-authority-revision")
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
        }) {
        None => None,
        Some(Some(revision)) => Some(revision),
        Some(None) => return json_status(StatusCode::BAD_REQUEST, "invalid authority revision"),
    };
    if expected_authority_revision.is_some_and(|revision| revision != client.authority_revision) {
        return json_status(StatusCode::CONFLICT, "authority revision conflict");
    }
    let outcome = match state
        .delete_registered_client_authority(tenant, &client)
        .await
    {
        Ok(outcome) => outcome,
        Err(_) => {
            return json_status(
                StatusCode::SERVICE_UNAVAILABLE,
                "client deletion did not converge",
            )
        }
    };
    // 级联清 BYOD 域名绑定(spec 010 §5.4)——**MUST 在 client 删成功之后**(评审 B2):否则若上面的
    // fail-closed 吊销/删失败(503,client 仍存活),却已提前释放了它的全局 domain map 行 → 该存活 client
    // 的域名 well-known 404、且被他人可 put_if_absent 抢注(劫持窗口)。放到删成功后:client 已不存在,
    // 残留行仅是"运维洁净度"(well-known 仍会因 issuer 从 tenant_id 重建而非泄露该 client);CAS on owner。
    //
    // 权威源 = `list_by_client`(client_id-index GSI 反查),**不用** existing.prm_domains(评审 M1/L3:
    // 那是可漂移的展示副本,并发 bind race 下会漏项 → 悬空行永不被级联清)。best-effort:GSI 查失败只记日志
    // (删 client 已成功;悬空行 well-known 不误导,可经 DELETE /admin/domains 补删)。
    match state.domain_map.list_by_client(&client_id).await {
        Ok(bindings) => {
            for b in &bindings {
                if let Ok(false) = state.domain_map.delete_if_owner(&b.domain, &client_id).await {
                    eprintln!(
                        "ADMIN_DOMAIN_CASCADE_MISS client_id={client_id} domain={}(owner 不符/已删)",
                        b.domain
                    );
                }
            }
        }
        Err(_) => eprintln!(
            "ADMIN_DOMAIN_CASCADE_LIST_FAIL client_id={client_id}(GSI 查失败;悬空行可经 DELETE /admin/domains 补删)"
        ),
    }
    state
        .record_security_event(
            crate::security_event::SecurityEventDraft::new(
                tenant,
                crate::security_event::SecurityActor::admin(admin.audit_identity()),
                Some(crate::security_event::SecuritySubject::client(&client_id)),
                crate::security_event::SecurityEventCategory::Administration,
                "client.delete",
                crate::security_event::SecurityEventOutcome::Success,
            )
            .correlated(crate::security_event::SecurityEventCorrelation {
                client_id: Some(client_id.clone()),
                ..Default::default()
            }),
        )
        .await;
    Json(ClientDeleteResponse {
        deleted: true,
        deleted_grants: outcome.deleted_grants,
        refresh_families: outcome.refresh_families,
    })
    .into_response()
}

#[derive(Serialize, ToSchema)]
pub struct ClientDeleteResponse {
    deleted: bool,
    deleted_grants: usize,
    refresh_families: usize,
}

/// client 元数据部分更新(PATCH 白名单字段;PUT 全量走同结构但全替换)。
#[derive(Deserialize, ToSchema, Default)]
pub struct ClientPatch {
    pub redirect_uris: Option<Vec<String>>,
    pub application_type: Option<String>,
    pub token_endpoint_auth_method: Option<String>,
    pub require_dpop: Option<bool>,
    pub jwks: Option<crate::ports::RegisteredClientJwks>,
    pub jwks_uri: Option<String>,
    pub token_endpoint_auth_signing_alg: Option<String>,
    pub default_resource: Option<String>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    pub redirect_mode: Option<String>,
    /// 降级确认(C4.7):朝更弱方向变更需带 true。
    #[serde(default)]
    pub confirm_downgrade: bool,
}

impl ClientPatch {
    pub(crate) fn has_conflicting_key_sources(&self) -> bool {
        self.jwks.is_some() && self.jwks_uri.is_some()
    }
}

/// 对一个已存在 client 应用白名单 PATCH,返回更新后的记录(不改 client_id/secret/introspect/resource_ids)。
/// secret 生命周期由 [`finalize_update`] 依 auth_method 变更统一调谐(不在此就地改)。
pub(crate) fn apply_patch(mut c: ClientRecord, p: &ClientPatch) -> ClientRecord {
    c.application_type = Some(c.application_type().to_string());
    if let Some(r) = &p.redirect_uris {
        c.redirect_uris = r.clone();
    }
    if let Some(application_type) = &p.application_type {
        c.application_type = Some(application_type.clone());
    }
    if let Some(m) = &p.token_endpoint_auth_method {
        c.token_endpoint_auth_method = m.clone();
        if m != "private_key_jwt" {
            c.token_endpoint_auth_signing_alg = None;
        }
    }
    if let Some(require_dpop) = p.require_dpop {
        c.require_dpop = require_dpop;
    }
    if let Some(jwks) = &p.jwks {
        c.jwks = Some(jwks.clone());
        c.jwks_uri = None;
    }
    if let Some(uri) = &p.jwks_uri {
        c.jwks_uri = (!uri.is_empty()).then(|| uri.clone());
        if c.jwks_uri.is_some() {
            c.jwks = None;
        }
    }
    if let Some(alg) = &p.token_endpoint_auth_signing_alg {
        c.token_endpoint_auth_signing_alg = (!alg.is_empty()).then(|| alg.clone());
    }
    if let Some(dr) = &p.default_resource {
        // 空串 = 显式清空(PATCH 可清 default_resource,评审 L4);非空 = 置值。
        c.default_resource = if dr.is_empty() {
            None
        } else {
            Some(dr.clone())
        };
    }
    if let Some(plr) = &p.post_logout_redirect_uris {
        c.post_logout_redirect_uris = plr.clone();
    }
    if let Some(mode) = &p.redirect_mode {
        c.redirect_mode = Some(mode.clone());
    }
    // redirect_uris 变更后重算 OIDC sector(评审 F2/F3/codex#3:否则旧 sector 残留 → 绕过多 host 拒绝、
    // 或 host 改后 sub 仍按旧 host)。P0 无 sector_identifier_uri,一律从当前 redirect_uris 归一。
    c.oidc_sector_identifier = agent_auth_token::oidc_sector_from_redirect_hosts(&c.redirect_uris);
    c
}

/// 数据模型已知的 token_endpoint_auth_method；准入另由 executable projection 控制。
pub(crate) fn known_auth_method(m: &str) -> bool {
    agent_auth_client::RegisteredClientAuthMethod::parse_known(m).is_some()
}

/// 依 auth_method 调谐 client_secret 生命周期(评审 M3),返回**新铸造、需一次性回显**的 secret。
/// - 切入 `client_secret_*` 且当前无 secret → 铸造(否则 client 无凭证认证 = brick);
/// - 切出到 `none`/`private_key_jwt` → 清空 secret(这些方法不用 client_secret);
/// - 已是 `client_secret_*` 且已有 secret → 保留不动(编辑元数据不轮换 secret)。
pub(crate) struct CredentialIssueContext<'a> {
    pub server_secret: &'a [u8],
    pub tenant: &'a str,
    pub audit_identity: &'a str,
    pub now: i64,
}

fn reconcile_secret(c: &mut ClientRecord, context: &CredentialIssueContext<'_>) -> Option<String> {
    let needs_secret =
        agent_auth_client::RegisteredClientAuthMethod::parse_known(&c.token_endpoint_auth_method)
            .is_some_and(agent_auth_client::RegisteredClientAuthMethod::requires_secret);
    if needs_secret {
        if c.client_secret_credentials.current.is_none() {
            if let Some(legacy_secret) = c.client_secret.take() {
                let created_at = if c.created_at > 0 {
                    c.created_at
                } else {
                    context.now
                };
                let expires_at = context
                    .now
                    .checked_add(crate::credential::DEFAULT_CLIENT_SECRET_TTL_SECS)
                    .expect("bounded client secret TTL");
                c.client_secret_credentials = crate::credential::CredentialSet {
                    current: Some(crate::credential::new_credential_record(
                        context.server_secret,
                        crate::credential::CredentialKind::ClientSecret,
                        context.tenant,
                        format!("cred_{}", crate::register::rand_token(12)),
                        c.client_id.clone(),
                        &legacy_secret,
                        created_at,
                        expires_at,
                        "system:legacy-update-migration".into(),
                        None,
                    )),
                    version: c.client_secret_credentials.version.saturating_add(1),
                    ..Default::default()
                };
                return None;
            }
            let sec = crate::register::rand_token(32);
            let expires_at = context
                .now
                .checked_add(crate::credential::DEFAULT_CLIENT_SECRET_TTL_SECS)
                .expect("bounded client secret TTL");
            c.client_secret_credentials = crate::credential::CredentialSet {
                current: Some(crate::credential::new_credential_record(
                    context.server_secret,
                    crate::credential::CredentialKind::ClientSecret,
                    context.tenant,
                    format!("cred_{}", crate::register::rand_token(12)),
                    c.client_id.clone(),
                    &sec,
                    context.now,
                    expires_at,
                    context.audit_identity.to_string(),
                    None,
                )),
                version: c.client_secret_credentials.version.saturating_add(1),
                ..Default::default()
            };
            c.client_secret = None;
            return Some(sec);
        }
        c.client_secret = None;
        None
    } else {
        let had_legacy_secret = c.client_secret.take().is_some();
        if had_legacy_secret || c.client_secret_credentials.has_credential_state() {
            c.client_secret_credentials.clear_and_advance();
        }
        None
    }
}

/// 编辑(PATCH/PUT)收尾:校 auth_method 白名单 → 校降级确认 → 调谐 secret。admin 与 RFC 7592 共用。
pub(crate) enum UpdateOutcome {
    Ok(Box<ClientRecord>, Option<String>), // 更新后记录 + 需回显一次的新 secret
    UnknownMethod,
    UnsupportedMethod,
    InvalidKeyConfig,
    InvalidApplicationMetadata(&'static str),
    DowngradeUnconfirmed(Vec<String>),
    /// ping/push 投递要求 confidential,但更新后 auth_method=none(spec 013 §4,codex 提交前评审 Medium:
    /// 挡"发起 ping/push 后把 client 降级为 none → CIBA /token 无认证签出 token"的降级绕过)。
    InvalidDeliveryCombo,
    /// push 直接投递 token,没有客户端 `/token` 请求可携带 DPoP proof。
    InvalidDpopDeliveryCombo,
}

pub(crate) fn finalize_update(
    old: &ClientRecord,
    mut updated: ClientRecord,
    confirm_downgrade: bool,
    private_key_jwt_enabled: bool,
    credential_context: &CredentialIssueContext<'_>,
) -> UpdateOutcome {
    let application_type =
        match crate::register::normalize_application_type(updated.application_type.as_deref()) {
            Ok(application_type) => application_type,
            Err(message) => return UpdateOutcome::InvalidApplicationMetadata(message),
        };
    if let Err(message) =
        crate::register::validate_application_redirects(application_type, &updated.redirect_uris)
    {
        return UpdateOutcome::InvalidApplicationMetadata(message);
    }
    updated.application_type = Some(application_type.to_string());
    if !known_auth_method(&updated.token_endpoint_auth_method) {
        return UpdateOutcome::UnknownMethod;
    }
    if old.token_endpoint_auth_method != updated.token_endpoint_auth_method
        && agent_auth_client::RegisteredClientAuthMethod::parse_executable(
            &updated.token_endpoint_auth_method,
        )
        .is_none_or(|method| {
            method == agent_auth_client::RegisteredClientAuthMethod::PrivateKeyJwt
                && !private_key_jwt_enabled
        })
    {
        return UpdateOutcome::UnsupportedMethod;
    }
    let key_config = match crate::client_auth::validate_registration_key_config(
        &updated.token_endpoint_auth_method,
        updated.jwks.clone(),
        updated.jwks_uri.clone(),
        updated.token_endpoint_auth_signing_alg.clone(),
    ) {
        Ok(config) => config,
        Err(_)
            if old.token_endpoint_auth_method == updated.token_endpoint_auth_method
                && old.jwks == updated.jwks
                && old.jwks_uri == updated.jwks_uri
                && old.token_endpoint_auth_signing_alg
                    == updated.token_endpoint_auth_signing_alg =>
        {
            crate::client_auth::RegistrationKeyConfig {
                jwks: updated.jwks.clone(),
                jwks_uri: updated.jwks_uri.clone(),
                signing_alg: updated.token_endpoint_auth_signing_alg.clone(),
            }
        }
        Err(_) => return UpdateOutcome::InvalidKeyConfig,
    };
    updated.jwks = key_config.jwks;
    updated.jwks_uri = key_config.jwks_uri;
    updated.token_endpoint_auth_signing_alg = key_config.signing_alg;
    // ping/push 投递 MUST 保持 confidential(codex 提交前评审 Medium:防降级绕过认证)。
    // 更新后若 delivery_mode∈{ping,push} 且 auth_method=none → 拒(不允许把 ping/push client 降级为 public)。
    if matches!(
        updated.backchannel_token_delivery_mode.as_deref(),
        Some("ping") | Some("push")
    ) && updated.token_endpoint_auth_method == "none"
    {
        return UpdateOutcome::InvalidDeliveryCombo;
    }
    if updated.backchannel_token_delivery_mode.as_deref() == Some("push") && updated.require_dpop {
        return UpdateOutcome::InvalidDpopDeliveryCombo;
    }
    let downgraded = downgrade_fields(old, &updated);
    if !downgraded.is_empty() && !confirm_downgrade {
        return UpdateOutcome::DowngradeUnconfirmed(downgraded);
    }
    // 降级已确认 / 无降级 → 才铸造 secret(不在被拒路径上产生副作用)。
    let secret = reconcile_secret(&mut updated, credential_context);
    UpdateOutcome::Ok(Box::new(updated), secret)
}

/// 编辑响应:ClientView + **可选** client_secret(仅 auth_method 切换新铸造时回显一次,H5)。
#[derive(Serialize, ToSchema)]
pub struct ClientUpdated {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(flatten)]
    pub view: ClientView,
}

/// `PATCH /admin/clients/{client_id}`:白名单部分更新 + 降级确认(C4.7)。
#[utoipa::path(patch, path = "/admin/clients/{client_id}", tag = "admin",
    params(("client_id" = String, Path)), request_body = ClientPatch,
    responses((status = 200, description = "已更新(auth_method 切换时回显新 secret 一次)", body = ClientUpdated), (status = 400, description = "降级需确认/未知认证方式"), (status = 401), (status = 404)))]
pub async fn patch_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
    Json(p): Json<ClientPatch>,
) -> impl IntoResponse {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    let tenant = admin.storage_tenant();
    let old = match state.clients.get(tenant, &client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return json_status(StatusCode::NOT_FOUND, "not found"),
        Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    };
    if p.has_conflicting_key_sources() {
        return json_status(
            StatusCode::BAD_REQUEST,
            "jwks and jwks_uri are mutually exclusive",
        );
    }
    let updated = apply_patch(old.clone(), &p);
    let audit_identity = admin.audit_identity();
    let credential_context = CredentialIssueContext {
        server_secret: &state.server_secret,
        tenant,
        audit_identity: &audit_identity,
        now: crate::token::current_unix_secs_pub(),
    };
    // 校 auth_method 白名单 + C4.7 降级确认 + secret 生命周期调谐(共用 finalize_update)。
    finalize_and_store(
        &state,
        tenant,
        &old,
        &audit_identity,
        finalize_update(
            &old,
            updated,
            p.confirm_downgrade,
            state.private_key_jwt_active(),
            &credential_context,
        ),
    )
    .await
}

/// finalize_update 结局 → 落库(admin PATCH/PUT 共用):pairwise sector 守卫 + put。
async fn finalize_and_store(
    state: &AppState,
    tenant: &str,
    old: &ClientRecord,
    audit_identity: &str,
    outcome: UpdateOutcome,
) -> axum::response::Response {
    match outcome {
        UpdateOutcome::UnknownMethod => json_status(
            StatusCode::BAD_REQUEST,
            "unknown token_endpoint_auth_method",
        ),
        UpdateOutcome::UnsupportedMethod => json_status(
            StatusCode::BAD_REQUEST,
            "unsupported token_endpoint_auth_method",
        ),
        UpdateOutcome::InvalidKeyConfig => json_status(
            StatusCode::BAD_REQUEST,
            "invalid private_key_jwt key metadata",
        ),
        UpdateOutcome::InvalidApplicationMetadata(message) => {
            json_status(StatusCode::BAD_REQUEST, message)
        }
        UpdateOutcome::DowngradeUnconfirmed(fields) => downgrade_error(fields),
        UpdateOutcome::InvalidDeliveryCombo => json_status(
            StatusCode::BAD_REQUEST,
            "ping/push delivery requires confidential client (token_endpoint_auth_method != none)",
        ),
        UpdateOutcome::InvalidDpopDeliveryCombo => json_status(
            StatusCode::BAD_REQUEST,
            "push delivery is incompatible with require_dpop",
        ),
        UpdateOutcome::Ok(rec, secret) => {
            if let Err(message) = crate::register::validate_redirect_policy(state, tenant, &rec) {
                return json_status(StatusCode::BAD_REQUEST, message);
            }
            // pairwise 部署:更新后多 host(sector 不可确定)→ 拒(评审 F1,与注册/RFC7592 同口径)。
            if state.subject_type_for_tenant(tenant) == agent_auth_discovery::SubjectType::Pairwise
                && rec.oidc_sector_identifier.is_none()
            {
                return json_status(
                    StatusCode::BAD_REQUEST,
                    "pairwise deployment: multi redirect host requires sector_identifier_uri",
                );
            }
            match state
                .clients
                .put_if_credential_versions(
                    tenant,
                    (*rec).clone(),
                    old.client_secret_credentials.version,
                    old.registration_token_credentials.version,
                )
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return json_status(StatusCode::CONFLICT, "credential version conflict")
                }
                Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
            }
            tokio::join!(
                state.record_security_event(
                    crate::security_event::SecurityEventDraft::new(
                        tenant,
                        crate::security_event::SecurityActor::admin(audit_identity),
                        Some(crate::security_event::SecuritySubject::client(
                            &rec.client_id,
                        )),
                        crate::security_event::SecurityEventCategory::Administration,
                        "client.update",
                        crate::security_event::SecurityEventOutcome::Success,
                    )
                    .correlated(
                        crate::security_event::SecurityEventCorrelation {
                            client_id: Some(rec.client_id.clone()),
                            ..Default::default()
                        }
                    ),
                ),
                audit_client_security_changes(state, tenant, audit_identity, old, &rec),
            );
            Json(ClientUpdated {
                client_secret: secret,
                view: view(&rec),
            })
            .into_response()
        }
    }
}

async fn audit_client_security_changes(
    state: &AppState,
    tenant: &str,
    audit_identity: &str,
    old: &ClientRecord,
    updated: &ClientRecord,
) {
    let mut drafts = Vec::with_capacity(2);
    if old.client_secret_credentials != updated.client_secret_credentials {
        let credential_id = updated
            .client_secret_credentials
            .next
            .as_ref()
            .or(updated.client_secret_credentials.current.as_ref())
            .map(|credential| credential.credential_id.as_str());
        let subject = credential_id
            .map(crate::security_event::SecuritySubject::credential)
            .unwrap_or_else(|| crate::security_event::SecuritySubject::client(&updated.client_id));
        drafts.push(
            crate::security_event::SecurityEventDraft::new(
                tenant,
                crate::security_event::SecurityActor::admin(audit_identity),
                Some(subject),
                crate::security_event::SecurityEventCategory::KeySecret,
                "credential.client_secret.update",
                crate::security_event::SecurityEventOutcome::Success,
            )
            .correlated(crate::security_event::SecurityEventCorrelation {
                client_id: Some(updated.client_id.clone()),
                credential_id: credential_id.map(str::to_string),
                ..Default::default()
            }),
        );
    }

    if old.jwks != updated.jwks
        || old.jwks_uri != updated.jwks_uri
        || old.token_endpoint_auth_signing_alg != updated.token_endpoint_auth_signing_alg
    {
        drafts.push(
            crate::security_event::SecurityEventDraft::new(
                tenant,
                crate::security_event::SecurityActor::admin(audit_identity),
                Some(crate::security_event::SecuritySubject::client(
                    &updated.client_id,
                )),
                crate::security_event::SecurityEventCategory::KeySecret,
                "key.client_jwks.update",
                crate::security_event::SecurityEventOutcome::Success,
            )
            .correlated(crate::security_event::SecurityEventCorrelation {
                client_id: Some(updated.client_id.clone()),
                ..Default::default()
            }),
        );
    }
    state.record_security_events(drafts).await;
}

/// C4.7 降级未确认的 400 响应(admin + RFC 7592 共用)。
pub(crate) fn downgrade_error(fields: Vec<String>) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": "downgrade_confirmation_required",
            "downgraded_fields": fields
        })),
    )
        .into_response()
}

/// 判定降级字段(C4.7 单调性;复用 client crate `downgrade::classify` 的方向定义)。
/// 返回降级字段名列表(空=无降级)。
pub(crate) fn downgrade_fields(old: &ClientRecord, new: &ClientRecord) -> Vec<String> {
    use agent_auth_client::downgrade::{classify, ChangeVerdict, FieldChange};
    let mut f = Vec::new();
    // auth_method 弱化(如 private_key_jwt→none)= 降级,由 classify 按强度序判定。
    if old.token_endpoint_auth_method != new.token_endpoint_auth_method {
        let c = FieldChange {
            field: "token_endpoint_auth_method".to_string(),
            old: old.token_endpoint_auth_method.clone(),
            new: new.token_endpoint_auth_method.clone(),
        };
        if matches!(classify(&c), ChangeVerdict::Downgrade) {
            f.push("token_endpoint_auth_method".to_string());
        }
    }
    if old.require_dpop != new.require_dpop {
        let c = FieldChange {
            field: "dpop".to_string(),
            old: if old.require_dpop {
                "required".to_string()
            } else {
                "optional".to_string()
            },
            new: if new.require_dpop {
                "required".to_string()
            } else {
                "optional".to_string()
            },
        };
        if matches!(classify(&c), ChangeVerdict::Downgrade) {
            f.push("require_dpop".to_string());
        }
    }
    // `web` and `native` are distinct redirect-security profiles rather than an
    // ordered strength scale. Treat either direction as a fail-safe downgrade.
    if old.application_type() != new.application_type() {
        f.push("application_type".to_string());
    }
    // redirect_uris 放宽 = 新增了旧集合外的值(更宽松 → 降级,防开放重定向面扩大)。
    if new
        .redirect_uris
        .iter()
        .any(|u| !old.redirect_uris.contains(u))
    {
        f.push("redirect_uris".to_string());
    }
    let old_mode = old.redirect_mode.as_deref().unwrap_or("exact");
    let new_mode = new.redirect_mode.as_deref().unwrap_or("exact");
    if old_mode != "prefix" && new_mode == "prefix" {
        f.push("redirect_mode".to_string());
    }
    f
}

/// admin 注册 client 的请求(超级权限;比 DCR 多能设 introspect_enabled/resource_ids —— MCP RS 信任
/// 属控制面,故只在 admin 域可设,不走公开 DCR / 普通自助)。
#[derive(Deserialize, ToSchema)]
pub struct AdminClientCreate {
    pub redirect_uris: Vec<String>,
    /// OIDC application type. Missing values default to `web`.
    #[serde(default)]
    pub application_type: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub require_dpop: bool,
    #[serde(default)]
    pub jwks: Option<crate::ports::RegisteredClientJwks>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_signing_alg: Option<String>,
    #[serde(default)]
    pub default_resource: Option<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub redirect_mode: Option<String>,
    /// 是否授予 introspect 权限(MCP RS;控制面信任,C8.6)。
    #[serde(default)]
    pub introspect_enabled: bool,
    /// introspect 允许的 resource 集合(introspect_enabled 时生效)。
    #[serde(default)]
    pub resource_ids: Vec<String>,
}

/// admin 注册响应:仅此一次回显 client_secret(若生成)。
#[derive(Serialize, ToSchema)]
pub struct AdminClientCreated {
    pub client_id: String,
    /// 仅 POST 一次回显(client_secret_basic/post 时);之后 GET 不再返回(H5)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(flatten)]
    pub view: ClientView,
}

/// `POST /admin/clients`:admin 超级权限注册 client(可设 introspect_enabled/resource_ids)。
#[utoipa::path(post, path = "/admin/clients", tag = "admin",
    request_body = AdminClientCreate,
    responses((status = 201, description = "已注册(client_secret 仅此一次回显)", body = AdminClientCreated),
        (status = 400, description = "invalid_client_metadata"), (status = 401)))]
pub async fn create_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AdminClientCreate>,
) -> impl IntoResponse {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    let tenant = admin.storage_tenant();
    let audit_identity = admin.audit_identity();
    if req.redirect_uris.is_empty() {
        return json_status(StatusCode::BAD_REQUEST, "redirect_uris required");
    }
    let application_type =
        match crate::register::normalize_application_type(req.application_type.as_deref()) {
            Ok(application_type) => application_type,
            Err(message) => return json_status(StatusCode::BAD_REQUEST, message),
        };
    if let Err(message) =
        crate::register::validate_application_redirects(application_type, &req.redirect_uris)
    {
        return json_status(StatusCode::BAD_REQUEST, message);
    }
    let oidc_sector_identifier = match crate::register::validated_oidc_sector(
        state.subject_type_for_tenant(tenant),
        &req.redirect_uris,
    ) {
        Ok(sector) => sector,
        Err(()) => {
            return json_status(
                StatusCode::BAD_REQUEST,
                "pairwise deployment: multi redirect host requires sector_identifier_uri",
            )
        }
    };
    let auth_method = req
        .token_endpoint_auth_method
        .clone()
        .unwrap_or_else(|| "none".to_string());
    let Some(auth_capability) = state.registered_client_auth_method(&auth_method) else {
        return json_status(
            StatusCode::BAD_REQUEST,
            "unsupported token_endpoint_auth_method",
        );
    };
    // secret 生成(与 DCR 一致口径;introspect 权限只 admin 能授)。none 无 secret。
    let secret_echo = if auth_capability.requires_secret() {
        Some(crate::register::rand_token(32))
    } else {
        None
    };
    let key_config = match crate::client_auth::validate_registration_key_config(
        &auth_method,
        req.jwks.clone(),
        req.jwks_uri.clone(),
        req.token_endpoint_auth_signing_alg.clone(),
    ) {
        Ok(config) => config,
        Err(message) => return json_status(StatusCode::BAD_REQUEST, message),
    };
    let client_id = format!("c_{}", crate::register::rand_token(16));
    let now = crate::token::current_unix_secs_pub();
    let client_secret_credentials = match secret_echo.as_deref() {
        Some(secret) => {
            let expires_at = now
                .checked_add(crate::credential::DEFAULT_CLIENT_SECRET_TTL_SECS)
                .expect("bounded client secret TTL");
            crate::credential::CredentialSet {
                current: Some(crate::credential::new_credential_record(
                    &state.server_secret,
                    crate::credential::CredentialKind::ClientSecret,
                    tenant,
                    format!("cred_{}", crate::register::rand_token(12)),
                    client_id.clone(),
                    secret,
                    now,
                    expires_at,
                    audit_identity.clone(),
                    None,
                )),
                version: 1,
                ..Default::default()
            }
        }
        None => crate::credential::CredentialSet::default(),
    };
    let record = ClientRecord {
        client_id: client_id.clone(),
        redirect_uris: req.redirect_uris.clone(),
        application_type: Some(application_type.to_string()),
        token_endpoint_auth_method: auth_method,
        client_secret: None,
        client_secret_credentials,
        jwks: key_config.jwks,
        jwks_uri: key_config.jwks_uri,
        token_endpoint_auth_signing_alg: key_config.signing_alg,
        default_resource: req.default_resource.clone(),
        introspect_enabled: req.introspect_enabled,
        resource_ids: req.resource_ids.clone(),
        post_logout_redirect_uris: req.post_logout_redirect_uris.clone(),
        // admin 注册的 client 无 reg_token(自助管理走 admin 域;不铸造 registration_access_token)。
        reg_token_hash: None,
        registration_token_credentials: crate::credential::CredentialSet::default(),
        client_type: None,
        id_token_signed_response_alg: None,
        oidc_sector_identifier,
        allowed_resources: vec![],
        allowed_scopes: vec![],
        redirect_mode: req.redirect_mode.clone(),
        // 回收元数据(spec 005 §9,C10.5):admin 建 client 也记 created_at;未使用/未 tombstone。
        created_at: now,
        last_used_day: None,
        authority_revision: 0,
        tombstoned_at: None,
        // CIBA 投递:admin 建 client 缺省 poll(ping/push 走公开 DCR 校验路径设,见 register.rs)。
        backchannel_token_delivery_mode: None,
        backchannel_client_notification_endpoint: None,
        require_dpop: req.require_dpop,
        prm_domains: vec![],
    };
    if let Err(message) = crate::register::validate_redirect_policy(&state, tenant, &record) {
        return json_status(StatusCode::BAD_REQUEST, message);
    }
    if state.clients.put(tenant, record.clone()).await.is_err() {
        return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable");
    }
    let client_event = crate::security_event::SecurityEventDraft::new(
        tenant,
        crate::security_event::SecurityActor::admin(&audit_identity),
        Some(crate::security_event::SecuritySubject::client(&client_id)),
        crate::security_event::SecurityEventCategory::Administration,
        "client.create",
        crate::security_event::SecurityEventOutcome::Success,
    )
    .correlated(crate::security_event::SecurityEventCorrelation {
        client_id: Some(client_id.clone()),
        ..Default::default()
    });
    if let Some(credential) = record.client_secret_credentials.current.as_ref() {
        tokio::join!(
            state.record_security_event(client_event),
            state.audit_credential_event(crate::credential::CredentialAuditEvent::ClientMutation {
                action: "ADMIN_CREDENTIAL_CREATE",
                actor: &audit_identity,
                tenant,
                client_id: &client_id,
                kind: crate::credential::CredentialKind::ClientSecret,
                credential_id: &credential.credential_id,
            }),
        );
    } else {
        state.record_security_event(client_event).await;
    }
    (
        StatusCode::CREATED,
        Json(AdminClientCreated {
            client_id,
            client_secret: secret_echo,
            view: view(&record),
        }),
    )
        .into_response()
}

/// `PUT /admin/clients/{client_id}`:admin 全量替换白名单元数据 + 降级确认(超级权限)。
#[utoipa::path(put, path = "/admin/clients/{client_id}", tag = "admin",
    params(("client_id" = String, Path)), request_body = crate::register::ClientPut,
    responses((status = 200, description = "已替换(auth_method 切换时回显新 secret 一次)", body = ClientUpdated), (status = 400), (status = 401), (status = 404)))]
pub async fn put_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
    Json(p): Json<crate::register::ClientPut>,
) -> impl IntoResponse {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    let tenant = admin.storage_tenant();
    let old = match state.clients.get(tenant, &client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return json_status(StatusCode::NOT_FOUND, "not found"),
        Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    };
    if p.redirect_uris.is_empty() {
        return json_status(StatusCode::BAD_REQUEST, "redirect_uris required");
    }
    let updated = apply_put(old.clone(), &p);
    let audit_identity = admin.audit_identity();
    let credential_context = CredentialIssueContext {
        server_secret: &state.server_secret,
        tenant,
        audit_identity: &audit_identity,
        now: crate::token::current_unix_secs_pub(),
    };
    finalize_and_store(
        &state,
        tenant,
        &old,
        &audit_identity,
        finalize_update(
            &old,
            updated,
            p.confirm_downgrade,
            state.private_key_jwt_active(),
            &credential_context,
        ),
    )
    .await
}

/// PUT 全量替换白名单元数据(admin `put_client` + RFC 7592 `put_registration` 共用);secret 生命周期
/// 由 finalize_update 依 auth_method 调谐。保留 secret/introspect/resource_ids/reg_token_hash 不改。
pub(crate) fn apply_put(mut c: ClientRecord, p: &crate::register::ClientPut) -> ClientRecord {
    c.redirect_uris = p.redirect_uris.clone();
    c.application_type = Some(
        p.application_type
            .clone()
            .unwrap_or_else(|| "web".to_string()),
    );
    c.token_endpoint_auth_method = p
        .token_endpoint_auth_method
        .clone()
        .unwrap_or_else(|| "none".to_string());
    c.require_dpop = p.require_dpop;
    c.jwks = p.jwks.clone();
    c.jwks_uri = p.jwks_uri.clone().filter(|uri| !uri.is_empty());
    c.token_endpoint_auth_signing_alg = p
        .token_endpoint_auth_signing_alg
        .clone()
        .filter(|alg| !alg.is_empty());
    // 全替换语义:PUT 未带(None)或空串 → 清空 default_resource。
    c.default_resource = p.default_resource.clone().filter(|s| !s.is_empty());
    c.post_logout_redirect_uris = p.post_logout_redirect_uris.clone();
    c.redirect_mode = p.redirect_mode.clone();
    // redirect_uris 全替换后重算 OIDC sector(评审 F2/F3/codex#3,同 apply_patch)。
    c.oidc_sector_identifier = agent_auth_token::oidc_sector_from_redirect_hosts(&c.redirect_uris);
    c
}

#[derive(Deserialize, ToSchema)]
pub struct RotateCredentialRequest {
    /// Idempotency key. Retrying the same id never creates another next value and never
    /// reveals the original plaintext again.
    pub rotation_request_id: String,
    pub expected_version: u64,
    pub expires_in_seconds: i64,
    pub overlap_seconds: i64,
}

#[derive(Deserialize, ToSchema)]
pub struct CredentialMutationRequest {
    pub credential_id: String,
    pub expected_version: u64,
}

#[derive(Serialize, ToSchema)]
pub struct CredentialMutationResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    pub replayed: bool,
    pub credentials: CredentialSetView,
}

fn client_credential_kind(path: &str) -> Option<crate::credential::CredentialKind> {
    match path {
        "client-secret" => Some(crate::credential::CredentialKind::ClientSecret),
        "registration-token" => Some(crate::credential::CredentialKind::RegistrationAccessToken),
        _ => None,
    }
}

fn client_credential_set(
    client: &ClientRecord,
    kind: crate::credential::CredentialKind,
) -> &crate::credential::CredentialSet {
    match kind {
        crate::credential::CredentialKind::ClientSecret => &client.client_secret_credentials,
        crate::credential::CredentialKind::RegistrationAccessToken => {
            &client.registration_token_credentials
        }
        crate::credential::CredentialKind::InitialAccessToken => unreachable!(),
    }
}

fn generated_credential(kind: crate::credential::CredentialKind) -> String {
    let prefix = match kind {
        crate::credential::CredentialKind::ClientSecret => "cs_",
        crate::credential::CredentialKind::RegistrationAccessToken => "rat_",
        crate::credential::CredentialKind::InitialAccessToken => "iat_",
    };
    format!("{prefix}{}", crate::register::rand_token(32))
}

fn credential_mutation_error(
    error: crate::credential::CredentialMutationError,
) -> axum::response::Response {
    use crate::credential::CredentialMutationError;
    let (status, message) = match error {
        CredentialMutationError::InvalidOverlap => {
            (StatusCode::BAD_REQUEST, "invalid bounded overlap")
        }
        CredentialMutationError::RotationPending => {
            (StatusCode::CONFLICT, "a next credential is already pending")
        }
        CredentialMutationError::VersionConflict => {
            (StatusCode::CONFLICT, "credential version conflict")
        }
        CredentialMutationError::CredentialNotFound => {
            (StatusCode::NOT_FOUND, "credential not found")
        }
        CredentialMutationError::CredentialNotUsable => {
            (StatusCode::CONFLICT, "credential is expired or revoked")
        }
    };
    json_status(status, message)
}

#[utoipa::path(
    post,
    path = "/admin/clients/{client_id}/credentials/{kind}/rotate",
    tag = "admin",
    params(("client_id" = String, Path), ("kind" = String, Path)),
    request_body = RotateCredentialRequest,
    responses(
        (status = 200, description = "current/next overlap established; plaintext appears once", body = CredentialMutationResponse),
        (status = 400),
        (status = 401),
        (status = 404),
        (status = 409)
    )
)]
pub async fn rotate_client_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((client_id, kind)): Path<(String, String)>,
    Json(request): Json<RotateCredentialRequest>,
) -> impl IntoResponse {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let tenant = admin.storage_tenant();
    let Some(kind) = client_credential_kind(&kind) else {
        return json_status(StatusCode::NOT_FOUND, "credential kind not found");
    };
    if request.rotation_request_id.trim().is_empty()
        || request.rotation_request_id.len() > 128
        || !(60..=2 * crate::credential::DEFAULT_CLIENT_SECRET_TTL_SECS)
            .contains(&request.expires_in_seconds)
    {
        return json_status(StatusCode::BAD_REQUEST, "invalid rotation request");
    }
    let client = match state.clients.get(tenant, &client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => return json_status(StatusCode::NOT_FOUND, "client not found"),
        Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    };
    if kind == crate::credential::CredentialKind::ClientSecret
        && !agent_auth_client::RegisteredClientAuthMethod::parse_known(
            &client.token_endpoint_auth_method,
        )
        .is_some_and(agent_auth_client::RegisteredClientAuthMethod::requires_secret)
    {
        return json_status(
            StatusCode::BAD_REQUEST,
            "client auth method does not use a client secret",
        );
    }

    let now = crate::token::current_unix_secs_pub();
    let expires_at = match now.checked_add(request.expires_in_seconds) {
        Some(expires_at) => expires_at,
        None => return json_status(StatusCode::BAD_REQUEST, "expiry overflow"),
    };
    let plaintext = generated_credential(kind);
    let mut credentials = client_credential_set(&client, kind).clone();
    let record = crate::credential::new_credential_record(
        &state.server_secret,
        kind,
        tenant,
        format!("cred_{}", crate::register::rand_token(12)),
        client_id.clone(),
        &plaintext,
        now,
        expires_at,
        admin.audit_identity(),
        Some(request.rotation_request_id),
    );
    let result = match crate::credential::stage_credential(
        &mut credentials,
        record,
        request.overlap_seconds,
        now,
        request.expected_version,
    ) {
        Ok(result) => result,
        Err(error) => return credential_mutation_error(error),
    };
    if result == crate::credential::StageResult::Retry {
        return Json(CredentialMutationResponse {
            credential: None,
            replayed: true,
            credentials: credential_set_view(&credentials),
        })
        .into_response();
    }
    match state
        .clients
        .replace_credential_set(
            tenant,
            &client_id,
            kind,
            request.expected_version,
            credentials.clone(),
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => return json_status(StatusCode::CONFLICT, "credential version conflict"),
        Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    }
    let actor = admin.audit_identity();
    state
        .audit_credential_event(crate::credential::CredentialAuditEvent::ClientMutation {
            action: "ADMIN_CREDENTIAL_ROTATE",
            actor: &actor,
            tenant,
            client_id: &client_id,
            kind,
            credential_id: credentials
                .next
                .as_ref()
                .or(credentials.current.as_ref())
                .map(|record| record.credential_id.as_str())
                .unwrap_or("none"),
        })
        .await;
    Json(CredentialMutationResponse {
        credential: Some(plaintext),
        replayed: false,
        credentials: credential_set_view(&credentials),
    })
    .into_response()
}

#[utoipa::path(
    post,
    path = "/admin/clients/{client_id}/credentials/{kind}/cutover",
    tag = "admin",
    params(("client_id" = String, Path), ("kind" = String, Path)),
    request_body = CredentialMutationRequest,
    responses((status = 200, body = CredentialMutationResponse), (status = 401), (status = 404), (status = 409))
)]
pub async fn cutover_client_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((client_id, kind)): Path<(String, String)>,
    Json(request): Json<CredentialMutationRequest>,
) -> impl IntoResponse {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let tenant = admin.storage_tenant();
    let Some(kind) = client_credential_kind(&kind) else {
        return json_status(StatusCode::NOT_FOUND, "credential kind not found");
    };
    let client = match state.clients.get(tenant, &client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => return json_status(StatusCode::NOT_FOUND, "client not found"),
        Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    };
    let mut credentials = client_credential_set(&client, kind).clone();
    let changed = match crate::credential::cutover_credential(
        &mut credentials,
        &request.credential_id,
        crate::token::current_unix_secs_pub(),
        request.expected_version,
    ) {
        Ok(changed) => changed,
        Err(error) => return credential_mutation_error(error),
    };
    if changed {
        match state
            .clients
            .replace_credential_set(
                tenant,
                &client_id,
                kind,
                request.expected_version,
                credentials.clone(),
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => return json_status(StatusCode::CONFLICT, "credential version conflict"),
            Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
        }
    }
    let actor = admin.audit_identity();
    state
        .audit_credential_event(crate::credential::CredentialAuditEvent::ClientMutation {
            action: "ADMIN_CREDENTIAL_CUTOVER",
            actor: &actor,
            tenant,
            client_id: &client_id,
            kind,
            credential_id: &request.credential_id,
        })
        .await;
    Json(CredentialMutationResponse {
        credential: None,
        replayed: !changed,
        credentials: credential_set_view(&credentials),
    })
    .into_response()
}

#[utoipa::path(
    post,
    path = "/admin/clients/{client_id}/credentials/{kind}/revoke",
    tag = "admin",
    params(("client_id" = String, Path), ("kind" = String, Path)),
    request_body = CredentialMutationRequest,
    responses((status = 200, body = CredentialMutationResponse), (status = 401), (status = 404), (status = 409))
)]
pub async fn revoke_client_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((client_id, kind)): Path<(String, String)>,
    Json(request): Json<CredentialMutationRequest>,
) -> impl IntoResponse {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let tenant = admin.storage_tenant();
    let Some(kind) = client_credential_kind(&kind) else {
        return json_status(StatusCode::NOT_FOUND, "credential kind not found");
    };
    let client = match state.clients.get(tenant, &client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => return json_status(StatusCode::NOT_FOUND, "client not found"),
        Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    };
    let mut credentials = client_credential_set(&client, kind).clone();
    let changed = match crate::credential::revoke_credential(
        &mut credentials,
        &request.credential_id,
        crate::token::current_unix_secs_pub(),
        request.expected_version,
    ) {
        Ok(changed) => changed,
        Err(error) => return credential_mutation_error(error),
    };
    if changed {
        match state
            .clients
            .replace_credential_set(
                tenant,
                &client_id,
                kind,
                request.expected_version,
                credentials.clone(),
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => return json_status(StatusCode::CONFLICT, "credential version conflict"),
            Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
        }
    }
    let actor = admin.audit_identity();
    state
        .audit_credential_event(crate::credential::CredentialAuditEvent::ClientMutation {
            action: "ADMIN_CREDENTIAL_REVOKE",
            actor: &actor,
            tenant,
            client_id: &client_id,
            kind,
            credential_id: &request.credential_id,
        })
        .await;
    Json(CredentialMutationResponse {
        credential: None,
        replayed: !changed,
        credentials: credential_set_view(&credentials),
    })
    .into_response()
}

fn default_iat_scopes() -> Vec<String> {
    vec!["dcr:register".to_string()]
}

fn default_iat_ttl() -> i64 {
    crate::credential::DEFAULT_IAT_TTL_SECS
}

fn default_iat_rate_limit() -> u32 {
    30
}

fn valid_oauth_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope.bytes().all(|byte| {
            byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
        })
}

#[derive(Deserialize, ToSchema)]
pub struct InitialAccessTokenCreate {
    pub owner: String,
    #[serde(default = "default_iat_scopes")]
    pub scopes: Vec<String>,
    #[serde(default = "default_iat_ttl")]
    pub expires_in_seconds: i64,
    #[serde(default = "default_iat_rate_limit")]
    pub rate_limit_per_minute: u32,
    #[serde(default)]
    pub one_time: bool,
}

#[derive(Serialize, ToSchema)]
pub struct InitialAccessTokenView {
    pub token_id: String,
    pub owner: String,
    pub scopes: Vec<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub status: String,
    pub audit_identity: String,
    pub rate_limit_per_minute: u32,
    pub one_time: bool,
    #[schema(required = true)]
    pub used_at: Option<i64>,
    pub version: u64,
}

#[derive(Serialize, ToSchema)]
pub struct InitialAccessTokenCreated {
    /// Bearer token shown exactly once. The persisted record contains only its verifier.
    pub token: String,
    #[serde(flatten)]
    pub view: InitialAccessTokenView,
}

#[derive(Serialize, ToSchema)]
pub struct InitialAccessTokenList {
    pub tokens: Vec<InitialAccessTokenView>,
    pub total: usize,
}

fn initial_access_token_view(
    record: &crate::credential::InitialAccessTokenRecord,
) -> InitialAccessTokenView {
    InitialAccessTokenView {
        token_id: record.token_id.clone(),
        owner: record.credential.owner.clone(),
        scopes: record.scopes.clone(),
        created_at: record.credential.created_at,
        expires_at: record.credential.expires_at,
        status: credential_status_name(record.credential.status).to_string(),
        audit_identity: record.credential.audit_identity.clone(),
        rate_limit_per_minute: record.rate_limit_per_minute,
        one_time: record.one_time,
        used_at: record.used_at,
        version: record.version,
    }
}

#[utoipa::path(
    get,
    path = "/admin/initial-access-tokens",
    tag = "admin",
    responses((status = 200, body = InitialAccessTokenList), (status = 401))
)]
pub async fn list_initial_access_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Read).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    match state
        .initial_access_tokens
        .list(admin.storage_tenant())
        .await
    {
        Ok(records) => {
            let tokens: Vec<_> = records.iter().map(initial_access_token_view).collect();
            let total = tokens.len();
            Json(InitialAccessTokenList { tokens, total }).into_response()
        }
        Err(_) => json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    }
}

#[utoipa::path(
    post,
    path = "/admin/initial-access-tokens",
    tag = "admin",
    request_body = InitialAccessTokenCreate,
    responses(
        (status = 201, description = "IAT issued; bearer value is returned once", body = InitialAccessTokenCreated),
        (status = 400),
        (status = 401)
    )
)]
pub async fn create_initial_access_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut request): Json<InitialAccessTokenCreate>,
) -> impl IntoResponse {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let tenant = admin.storage_tenant();
    request.owner = request.owner.trim().to_string();
    request.scopes.sort();
    request.scopes.dedup();
    if request.owner.is_empty()
        || request.owner.len() > 256
        || request.owner.chars().any(char::is_control)
        || request.scopes.is_empty()
        || request.scopes.len() > 16
        || request
            .scopes
            .iter()
            .any(|scope| scope.len() > 128 || !valid_oauth_scope_token(scope))
        || !(60..=crate::credential::MAX_IAT_TTL_SECS).contains(&request.expires_in_seconds)
        || !(1..=600).contains(&request.rate_limit_per_minute)
    {
        return json_status(
            StatusCode::BAD_REQUEST,
            "invalid initial access token policy",
        );
    }

    let now = crate::token::current_unix_secs_pub();
    let expires_at = match now.checked_add(request.expires_in_seconds) {
        Some(expires_at) => expires_at,
        None => return json_status(StatusCode::BAD_REQUEST, "expiry overflow"),
    };
    for _ in 0..3 {
        let token_id = format!(
            "iat_{}",
            state.region.issue_id(crate::register::rand_token(16))
        );
        let secret = crate::register::rand_token(32);
        let token = format!("{token_id}.{secret}");
        let record = crate::credential::InitialAccessTokenRecord {
            token_id: token_id.clone(),
            credential: crate::credential::new_credential_record(
                &state.server_secret,
                crate::credential::CredentialKind::InitialAccessToken,
                tenant,
                token_id.clone(),
                request.owner.clone(),
                &secret,
                now,
                expires_at,
                admin.audit_identity(),
                None,
            ),
            scopes: request.scopes.clone(),
            rate_limit_per_minute: request.rate_limit_per_minute,
            one_time: request.one_time,
            used_at: None,
            version: 1,
        };
        match state
            .initial_access_tokens
            .put_new(tenant, record.clone())
            .await
        {
            Ok(true) => {
                let actor = admin.audit_identity();
                state
                    .audit_credential_event(
                        crate::credential::CredentialAuditEvent::InitialAccessTokenCreate {
                            actor: &actor,
                            tenant,
                            token_id: &token_id,
                            owner: &request.owner,
                            one_time: request.one_time,
                        },
                    )
                    .await;
                return (
                    StatusCode::CREATED,
                    Json(InitialAccessTokenCreated {
                        token,
                        view: initial_access_token_view(&record),
                    }),
                )
                    .into_response();
            }
            Ok(false) => continue,
            Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
        }
    }
    json_status(
        StatusCode::SERVICE_UNAVAILABLE,
        "could not allocate initial access token",
    )
}

#[utoipa::path(
    post,
    path = "/admin/initial-access-tokens/{token_id}/revoke",
    tag = "admin",
    params(("token_id" = String, Path)),
    request_body = CredentialMutationRequest,
    responses((status = 200, body = InitialAccessTokenView), (status = 401), (status = 404), (status = 409))
)]
pub async fn revoke_initial_access_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token_id): Path<String>,
    Json(request): Json<CredentialMutationRequest>,
) -> impl IntoResponse {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let tenant = admin.storage_tenant();
    if request.credential_id != token_id {
        return json_status(StatusCode::BAD_REQUEST, "credential id mismatch");
    }
    let _existing = match state.initial_access_tokens.get(tenant, &token_id).await {
        Ok(Some(record)) => record,
        Ok(None) => return json_status(StatusCode::NOT_FOUND, "token not found"),
        Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    };
    match state
        .initial_access_tokens
        .revoke(
            tenant,
            &token_id,
            request.expected_version,
            crate::token::current_unix_secs_pub(),
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => return json_status(StatusCode::CONFLICT, "credential version conflict"),
        Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    }
    let view = match state.initial_access_tokens.get(tenant, &token_id).await {
        Ok(Some(record)) => record,
        Ok(None) => return json_status(StatusCode::NOT_FOUND, "token not found"),
        Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    };
    let actor = admin.audit_identity();
    state
        .audit_credential_event(
            crate::credential::CredentialAuditEvent::InitialAccessTokenRevoke {
                actor: &actor,
                tenant,
                token_id: &token_id,
            },
        )
        .await;
    Json(initial_access_token_view(&view)).into_response()
}

// ---- workload 信任绑定管理(spec 012 C5.5;管理面登记,MUST NOT 走 DCR)----

/// 登记一条 workload 信任绑定的请求(OIDC 或 SPIFFE JWT-SVID;SigV4 随真实 STS 接入另补)。
#[derive(Deserialize, ToSchema)]
pub struct WorkloadTrustCreate {
    /// 幂等键(binding_id;同 id 覆盖)。
    pub binding_id: String,
    pub tenant_id: String,
    /// 机制:`oidc`(默认,平台 OIDC-JWT)/ `spiffe_jwt`(SPIFFE JWT-SVID,§1.4)/ `spiffe_x509`(X.509-mTLS,§1.4/C5.7)。
    #[serde(default)]
    pub mechanism: Option<String>,
    /// **OIDC**:平台 issuer(`iss` 精确匹配)。SPIFFE 路径忽略。
    #[serde(default)]
    pub platform_issuer: Option<String>,
    /// **SPIFFE**:trust domain(从 SVID `sub`/证书 SAN 的 `spiffe://<td>` 解出、精确匹配;信任锚,不用 iss/证书 issuer DN)。OIDC 忽略。
    #[serde(default)]
    pub trust_domain: Option<String>,
    /// 平台 / trust bundle JWKS 取处(oidc/spiffe_jwt 用;SPIFFE bundle **MUST 独立于 AS 自身 JWKS**)。
    /// **`spiffe_x509` 无此字段**(链验证在 API Gateway mTLS truststore,评审 M1 改 Option)。
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// 匹配模式:OIDC=`sub` 模式;SPIFFE=**完整 SPIFFE ID** 模式(精确 / `.../*` 任意深度前缀)。
    pub subject_pattern: String,
    /// 命中后映射到的本 AS client_id(须为已存在的 workload client)。
    pub mapped_client_id: String,
}

/// workload 信任绑定视图(列表回显;不含敏感值)。
#[derive(Serialize, ToSchema)]
pub struct WorkloadTrustView {
    pub tenant_id: String,
    pub mechanism: String,
    pub mapped_client_id: String,
    /// OIDC:platform_issuer;SigV4:aws_account_id。
    pub trust_anchor: String,
    /// OIDC:subject_pattern;SigV4:role_arn_pattern。
    pub subject_pattern: String,
}

#[derive(Serialize, ToSchema)]
pub struct WorkloadTrustList {
    pub bindings: Vec<WorkloadTrustView>,
    pub total: usize,
}

/// `POST /admin/workload-trust`:登记 workload 信任绑定(OIDC 或 SPIFFE JWT-SVID;admin 认证,C5.5)。
#[utoipa::path(post, path = "/admin/workload-trust", tag = "admin",
    request_body = WorkloadTrustCreate,
    responses((status = 201, description = "已登记"), (status = 400, description = "mapped_client_id 非 workload"),
        (status = 401), (status = 403, description = "请求 tenant 不属于已认证租户")))]
pub async fn create_workload_trust(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<WorkloadTrustCreate>,
) -> impl IntoResponse {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    let tenant = admin.storage_tenant();
    if let Err(resp) = admin.require_tenant(&state, &req.tenant_id).await {
        return resp;
    }
    // 目标 client 必须存在且为 workload(信任锚只绑 workload;避免误绑普通 client)。
    match state.clients.get(tenant, &req.mapped_client_id).await {
        Ok(Some(c)) if c.is_workload() => {}
        Ok(Some(_)) => {
            return json_status(
                StatusCode::BAD_REQUEST,
                "mapped_client_id 不是 workload client",
            )
        }
        Ok(None) => return json_status(StatusCode::BAD_REQUEST, "mapped_client_id 不存在"),
        Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    }
    // subject_pattern 校验(评审 M1 纵深防御):拒过宽模式(空模式 / 纯 `*` / 中间 `*` / `**`)——
    // 只允许精确 或 末尾单段 glob(前缀非空)。用一个已知非空样本探测:若 `*` 前缀为空即拒。
    let pat = req.subject_pattern.trim();
    let star_count = pat.matches('*').count();
    let bad_pattern = pat.is_empty()
        || star_count > 1
        || (star_count == 1 && !pat.ends_with('*')) // `*` 必须在末尾
        || pat == "*"; // 纯通配
    if bad_pattern {
        return json_status(
            StatusCode::BAD_REQUEST,
            "invalid subject_pattern(仅精确或末尾单段 glob,前缀非空;拒纯 */中间 */**)",
        );
    }
    // 机制分派(默认 oidc,向后兼容):oidc 用 platform_issuer;spiffe_jwt 用 trust_domain(spec 012 §1.4)。
    let mechanism = match req.mechanism.as_deref().unwrap_or("oidc") {
        "oidc" => {
            let Some(platform_issuer) = req.platform_issuer.clone().filter(|s| !s.is_empty())
            else {
                return json_status(
                    StatusCode::BAD_REQUEST,
                    "oidc 机制须提供非空 platform_issuer",
                );
            };
            let Some(jwks_uri) = req.jwks_uri.clone().filter(|s| !s.is_empty()) else {
                return json_status(StatusCode::BAD_REQUEST, "oidc 机制须提供非空 jwks_uri");
            };
            agent_auth_workload::TrustMechanism::Oidc {
                platform_issuer,
                jwks_uri,
                subject_pattern: req.subject_pattern.clone(),
            }
        }
        "spiffe_jwt" => {
            // SPIFFE(spec 012 §1.4):非空 trust_domain + pattern MUST 完整 SPIFFE ID + bundle 独立于 AS JWKS。
            let Some(trust_domain) = req.trust_domain.clone().filter(|s| !s.is_empty()) else {
                return json_status(
                    StatusCode::BAD_REQUEST,
                    "spiffe_jwt 机制须提供非空 trust_domain",
                );
            };
            if !pat.starts_with("spiffe://") {
                return json_status(
                    StatusCode::BAD_REQUEST,
                    "spiffe_jwt 的 subject_pattern 须为完整 SPIFFE ID(spiffe://<td>/<path>[/*])",
                );
            }
            // 整域通配 `spiffe://<td>/*`(或 `spiffe://<td>*`)禁止——过宽吞掉整个 trust domain(评审 Medium)。
            let td_root = format!("spiffe://{trust_domain}");
            if pat == format!("{td_root}/*") || pat == format!("{td_root}*") || pat == td_root {
                return json_status(
                    StatusCode::BAD_REQUEST,
                    "禁整域通配(spiffe://<td>/*):pattern 须约束到域内具体路径前缀",
                );
            }
            // pattern 的 trust domain 段 MUST == 声明的 trust_domain(防 pattern 指向别域)。
            if agent_auth_workload::spiffe_trust_domain(pat) != Some(trust_domain.as_str()) {
                return json_status(
                    StatusCode::BAD_REQUEST,
                    "subject_pattern 的 trust domain 与 trust_domain 字段不一致",
                );
            }
            let Some(jwks_uri) = req.jwks_uri.clone().filter(|s| !s.is_empty()) else {
                return json_status(
                    StatusCode::BAD_REQUEST,
                    "spiffe_jwt 机制须提供非空 jwks_uri",
                );
            };
            // bundle JWKS MUST 独立于 AS 自身 JWKS(评审 codex/Kiro:防被 AS key 签的畸形 SVID 混入 access
            // 面)。强校验(评审 codex M2,防 query/fragment/大小写绕过):按**本 AS issuer 前缀 + 去掉
            // query/fragment 后以 `/jwks.json` 结尾**判定,而非裸子串。issuer 从请求 Host 派生(与其它端点同源)。
            let jwks_norm = jwks_uri
                .split(['?', '#'])
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            let as_issuer = crate::hostutil::issuer_host(&headers)
                .and_then(|h| derive_issuer(&h, &state.form).ok());
            let reuses_as_jwks = jwks_norm.ends_with("/jwks.json")
                && as_issuer
                    .map(|iss| jwks_norm.starts_with(&iss.as_str().to_ascii_lowercase()))
                    .unwrap_or(true); // issuer 派生不出(Host 非法)时保守判为复用 → 拒
            if reuses_as_jwks {
                return json_status(
                    StatusCode::BAD_REQUEST,
                    "spiffe bundle jwks_uri 不得复用 AS 自身 JWKS(须外部 trust bundle)",
                );
            }
            agent_auth_workload::TrustMechanism::SpiffeJwt {
                trust_domain,
                jwks_uri,
                spiffe_id_pattern: req.subject_pattern.clone(),
            }
        }
        "spiffe_x509" => {
            // X.509-SVID / mTLS(spec 012 §1.4 / C5.7):无 jwks_uri(链验证在 API Gateway truststore);
            // 校验同 spiffe_jwt——非空 trust_domain + pattern 完整 SPIFFE ID + 禁整域通配 + pattern td 一致。
            let Some(trust_domain) = req.trust_domain.clone().filter(|s| !s.is_empty()) else {
                return json_status(
                    StatusCode::BAD_REQUEST,
                    "spiffe_x509 机制须提供非空 trust_domain",
                );
            };
            if !pat.starts_with("spiffe://") {
                return json_status(
                    StatusCode::BAD_REQUEST,
                    "spiffe_x509 的 subject_pattern 须为完整 SPIFFE ID(spiffe://<td>/<path>[/*])",
                );
            }
            let td_root = format!("spiffe://{trust_domain}");
            if pat == format!("{td_root}/*") || pat == format!("{td_root}*") || pat == td_root {
                return json_status(
                    StatusCode::BAD_REQUEST,
                    "禁整域通配(spiffe://<td>/*):pattern 须约束到域内具体路径前缀",
                );
            }
            if agent_auth_workload::spiffe_trust_domain(pat) != Some(trust_domain.as_str()) {
                return json_status(
                    StatusCode::BAD_REQUEST,
                    "subject_pattern 的 trust domain 与 trust_domain 字段不一致",
                );
            }
            agent_auth_workload::TrustMechanism::SpiffeX509 {
                trust_domain,
                // 存**trim 后**的 pattern(评审 M3:校验用 trim 值,存 untrimmed 会因首尾空白使
                // spiffe_id_matches 永不命中 = 静默死绑定;存 trim 值与校验一致)。
                spiffe_id_pattern: pat.to_string(),
            }
        }
        _ => {
            return json_status(
                StatusCode::BAD_REQUEST,
                "mechanism 仅支持 oidc / spiffe_jwt / spiffe_x509",
            )
        }
    };
    let binding = agent_auth_workload::TrustBinding {
        tenant_id: req.tenant_id.clone(),
        mechanism,
        mapped_client_id: req.mapped_client_id.clone(),
    };
    if state
        .workload_trust
        .put(tenant, req.binding_id.clone(), binding)
        .await
        .is_err()
    {
        return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable");
    }
    json_status(StatusCode::CREATED, "registered")
}

/// `GET /admin/workload-trust/{tenant_id}`:列该租户的 workload 信任绑定(admin 认证)。
#[utoipa::path(get, path = "/admin/workload-trust/{tenant_id}", tag = "admin",
    params(("tenant_id" = String, Path)),
    responses((status = 200, description = "信任绑定列表", body = WorkloadTrustList), (status = 401),
        (status = 403, description = "路径 tenant 不属于已认证租户")))]
pub async fn list_workload_trust(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Read).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    if let Err(resp) = admin.require_tenant(&state, &tenant_id).await {
        return resp;
    }
    match state.workload_trust.list_by_tenant(&tenant_id).await {
        Ok(bs) => {
            let bindings: Vec<WorkloadTrustView> = bs
                .into_iter()
                .map(|entry| {
                    let binding = entry.binding;
                    let (mechanism, anchor, pat) = match &binding.mechanism {
                        agent_auth_workload::TrustMechanism::Oidc {
                            platform_issuer,
                            subject_pattern,
                            ..
                        } => ("oidc", platform_issuer.clone(), subject_pattern.clone()),
                        agent_auth_workload::TrustMechanism::Sigv4 {
                            aws_account_id,
                            role_arn_pattern,
                        } => ("sigv4", aws_account_id.clone(), role_arn_pattern.clone()),
                        agent_auth_workload::TrustMechanism::SpiffeJwt {
                            trust_domain,
                            spiffe_id_pattern,
                            ..
                        } => (
                            "spiffe_jwt",
                            trust_domain.clone(),
                            spiffe_id_pattern.clone(),
                        ),
                        agent_auth_workload::TrustMechanism::SpiffeX509 {
                            trust_domain,
                            spiffe_id_pattern,
                        } => (
                            "spiffe_x509",
                            trust_domain.clone(),
                            spiffe_id_pattern.clone(),
                        ),
                    };
                    WorkloadTrustView {
                        tenant_id: binding.tenant_id,
                        mechanism: mechanism.to_string(),
                        mapped_client_id: binding.mapped_client_id,
                        trust_anchor: anchor,
                        subject_pattern: pat,
                    }
                })
                .collect();
            let total = bindings.len();
            Json(WorkloadTrustList { bindings, total }).into_response()
        }
        Err(_) => json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    }
}

// ---- 联邦上游 IdP 注册管理面(spec 003 §4 Task 4.7,C9.5b)。admin 认证;控制面登记,不走 DCR。----

/// 登记/更新一条联邦上游 OIDC IdP 配置(admin 面 PUT)。secret 只收**引用名**(不收明文)。
#[derive(Deserialize, ToSchema)]
pub struct FederationIdpCreate {
    pub tenant_id: String,
    /// 上游 IdP 标识(复合键第二段;同 (tenant, idp) 覆盖)。
    pub upstream_idp_id: String,
    /// 上游 issuer(`iss` 信任锚)。
    pub upstream_issuer: String,
    pub client_id: String,
    /// client_secret 的**引用名**(Secrets Manager/SSM;**绝不收明文**)。
    pub client_secret_ref: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    /// 请求 scope(至少含 `openid`)。
    pub scopes: Vec<String>,
    /// Upstream ACR values explicitly trusted to satisfy Agent Auth strong assurance.
    #[serde(default)]
    pub strong_acr_values: Vec<String>,
}

/// 联邦 IdP 配置视图(列表回显;**不含 client_secret_ref**——引用名也不回显,防信息面扩大)。
#[derive(Serialize, ToSchema)]
pub struct FederationIdpView {
    pub tenant_id: String,
    pub upstream_idp_id: String,
    pub upstream_issuer: String,
    pub client_id: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub scopes: Vec<String>,
    pub strong_acr_values: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct FederationIdpList {
    pub idps: Vec<FederationIdpView>,
    pub total: usize,
}

async fn audit_federation_idp_secret_config(
    state: &AppState,
    tenant_id: &str,
    actor: &str,
    upstream_idp_id: &str,
    action: &'static str,
    outcome: crate::security_event::SecurityEventOutcome,
) {
    state
        .record_security_event(crate::security_event::SecurityEventDraft::new(
            tenant_id,
            crate::security_event::SecurityActor::admin(actor),
            Some(crate::security_event::SecuritySubject::issuer(
                upstream_idp_id,
            )),
            crate::security_event::SecurityEventCategory::KeySecret,
            action,
            outcome,
        ))
        .await;
}

/// `PUT /admin/federation`:登记上游 OIDC IdP 配置(admin 认证,C9.5b)。
#[utoipa::path(put, path = "/admin/federation", tag = "admin",
    request_body = FederationIdpCreate,
    responses((status = 201, description = "已登记"), (status = 400, description = "config 校验失败"),
        (status = 401), (status = 403, description = "请求 tenant 不属于已认证租户"),
        (status = 409, description = "仍有 attribute mappings 时不得变更 issuer"),
        (status = 503)))]
pub async fn put_federation_idp(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<FederationIdpCreate>,
) -> impl IntoResponse {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    if let Err(resp) = admin.require_tenant(&state, &req.tenant_id).await {
        return resp;
    }
    let config = agent_auth_authn::federation::FederationConfig {
        tenant_id: req.tenant_id.clone(),
        upstream_idp_id: req.upstream_idp_id.clone(),
        protocol: agent_auth_authn::federation::UpstreamProtocol::Oidc,
        upstream_issuer: req.upstream_issuer.clone(),
        strong_acr_values: req.strong_acr_values.clone(),
        oidc: Some(agent_auth_authn::federation::OidcRpParams {
            client_id: req.client_id.clone(),
            client_secret_ref: req.client_secret_ref.clone(),
            authorization_endpoint: req.authorization_endpoint.clone(),
            token_endpoint: req.token_endpoint.clone(),
            jwks_uri: req.jwks_uri.clone(),
            scopes: req.scopes.clone(),
        }),
    };
    // fail-closed 校验(endpoint MUST https 绝对 URL[SSRF 防线] / secret 引用名非空 / scopes 含 openid)。
    if let Err(e) = config.validate() {
        return (
            StatusCode::BAD_REQUEST,
            format!("联邦 config 校验失败:{e:?}"),
        )
            .into_response();
    }
    let mutation = if matches!(state.form, Form::SelfHosted { .. }) {
        state.put_federation_config(config).await
    } else {
        state
            .federation_config
            .put(config)
            .await
            .map(|_| crate::state::FederationConfigMutationOutcome::Applied)
    };
    match mutation {
        Ok(crate::state::FederationConfigMutationOutcome::Applied) => {}
        Ok(crate::state::FederationConfigMutationOutcome::MappingsPresent) => {
            audit_federation_idp_secret_config(
                &state,
                &req.tenant_id,
                &admin.audit_identity(),
                &req.upstream_idp_id,
                "secret.federation_idp.configure",
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return json_status(
                StatusCode::CONFLICT,
                "federation config or mapping authority conflict",
            );
        }
        Err(_) => {
            audit_federation_idp_secret_config(
                &state,
                &req.tenant_id,
                &admin.audit_identity(),
                &req.upstream_idp_id,
                "secret.federation_idp.configure",
                crate::security_event::SecurityEventOutcome::Failure,
            )
            .await;
            return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable");
        }
    }
    audit_federation_idp_secret_config(
        &state,
        &req.tenant_id,
        &admin.audit_identity(),
        &req.upstream_idp_id,
        "secret.federation_idp.configure",
        crate::security_event::SecurityEventOutcome::Success,
    )
    .await;
    json_status(StatusCode::CREATED, "registered")
}

/// `GET /admin/federation/{tenant_id}`:列该租户的联邦 IdP 配置(admin 认证;不回显 secret 引用名)。
#[utoipa::path(get, path = "/admin/federation/{tenant_id}", tag = "admin",
    params(("tenant_id" = String, Path)),
    responses((status = 200, description = "联邦 IdP 列表", body = FederationIdpList), (status = 401),
        (status = 403, description = "路径 tenant 不属于已认证租户")))]
pub async fn list_federation_idps(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Read).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    if let Err(resp) = admin.require_tenant(&state, &tenant_id).await {
        return resp;
    }
    match state.federation_config.list_by_tenant(&tenant_id).await {
        Ok(cs) => {
            let idps: Vec<FederationIdpView> = cs
                .into_iter()
                .filter_map(|c| {
                    // 只回显 OIDC(SAML 参数留后);无 oidc 的跳过(不回显残缺条)。
                    c.oidc.map(|p| FederationIdpView {
                        tenant_id: c.tenant_id,
                        upstream_idp_id: c.upstream_idp_id,
                        upstream_issuer: c.upstream_issuer,
                        client_id: p.client_id,
                        authorization_endpoint: p.authorization_endpoint,
                        token_endpoint: p.token_endpoint,
                        jwks_uri: p.jwks_uri,
                        scopes: p.scopes,
                        strong_acr_values: c.strong_acr_values,
                        // client_secret_ref 故意不回显。
                    })
                })
                .collect();
            let total = idps.len();
            Json(FederationIdpList { idps, total }).into_response()
        }
        Err(_) => json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    }
}

/// `DELETE /admin/federation/{tenant_id}/{upstream_idp_id}`:删一条联邦 config(admin 认证,复合键防跨租户删)。
#[utoipa::path(delete, path = "/admin/federation/{tenant_id}/{upstream_idp_id}", tag = "admin",
    params(("tenant_id" = String, Path), ("upstream_idp_id" = String, Path)),
    responses((status = 200, description = "已删(不存在也幂等 200)"), (status = 401),
        (status = 403, description = "路径 tenant 不属于已认证租户"),
        (status = 409, description = "仍有 attribute mappings 或 authority 并发冲突"),
        (status = 503, description = "config 或 mapping authority store 不可用")))]
pub async fn delete_federation_idp(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((tenant_id, upstream_idp_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    if let Err(resp) = admin.require_tenant(&state, &tenant_id).await {
        return resp;
    }
    let mutation = if matches!(state.form, Form::SelfHosted { .. }) {
        state
            .delete_federation_config(&tenant_id, &upstream_idp_id)
            .await
    } else {
        state
            .federation_config
            .delete(&tenant_id, &upstream_idp_id)
            .await
            .map(|_| crate::state::FederationConfigMutationOutcome::Applied)
    };
    match mutation {
        Ok(crate::state::FederationConfigMutationOutcome::Applied) => {}
        Ok(crate::state::FederationConfigMutationOutcome::MappingsPresent) => {
            audit_federation_idp_secret_config(
                &state,
                &tenant_id,
                &admin.audit_identity(),
                &upstream_idp_id,
                "secret.federation_idp.delete",
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return json_status(
                StatusCode::CONFLICT,
                "federation config or mapping authority conflict",
            );
        }
        Err(_) => {
            audit_federation_idp_secret_config(
                &state,
                &tenant_id,
                &admin.audit_identity(),
                &upstream_idp_id,
                "secret.federation_idp.delete",
                crate::security_event::SecurityEventOutcome::Failure,
            )
            .await;
            return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable");
        }
    }
    audit_federation_idp_secret_config(
        &state,
        &tenant_id,
        &admin.audit_identity(),
        &upstream_idp_id,
        "secret.federation_idp.delete",
        crate::security_event::SecurityEventOutcome::Success,
    )
    .await;
    json_status(StatusCode::OK, "deleted")
}

// ============ admin 人类用户管理面(spec 003 §1.4,类 Cognito User Pool)============
//
// create 仍只按 email 预建本地用户;list/get/disable/enable/delete 同时覆盖已 JIT 落 UserRecord 的
// 联邦用户(`user:fed:*`)。SaaS 仅在 tenant_partitioning 开启后放行,见下方 gate。

/// SaaS runtime gate(§1.4,spec 020 P0-D 收敛):**gate 绑数据面分区,而非绑形态**。
/// - SelfHosted → false(放行,单租户)。
/// - SaaS **且 tenant_partitioning 开** → false(放行:数据面已分区,user 管理跨租户物理隔离,020 §2.3 done)。
/// - SaaS **且 tenant_partitioning 关**(灰度过渡:子域已切、分区未开)→ **true(404)**:此时
///   `tenant_or_400` 返空串 → tpk 透传 → 所有租户共享同一物理分区,放行 user 管理会跨租户越权读/禁/删
///   (违反 C10.19 最高底线)。故未开分区前 SaaS 仍拒。
///
/// SaaS 租户管理面使用请求 Host 对应的独立 tenant admin token;平台 token 只用于 control Host。
pub(crate) fn saas_users_disabled(state: &AppState) -> bool {
    matches!(state.form, agent_auth_discovery::Form::Saas { .. }) && !state.tenant_partitioning
}

/// **RS 命名空间用户属性 API 的 SaaS gate**(spec 007 C8.12:**仅 SelfHosted**,SaaS 恒 404)。
/// 独立于 `saas_users_disabled`(评审 codex #5):P0-D 把 user 管理 gate 从"绑 Form"改"绑分区",
/// 若属性 API 复用同一 gate,则分区就绪的 SaaS 会**意外开放** spec 007 属性写——违反 C8.12"SaaS 恒 404"
/// 契约(属性 API 的跨租户隔离 + RBAC 尚未按 SaaS 审计验收)。故属性 API **恒绑 Form::Saas**、不看分区 flag,
/// SaaS 就绪需另立 spec 验收后再开。
fn saas_attributes_disabled(state: &AppState) -> bool {
    matches!(state.form, agent_auth_discovery::Form::Saas { .. })
}

/// admin-users 端点统一 **JSON** 响应(`{status, message}`)。**不返裸 text/plain**:前端 openapi-fetch
/// 对 2xx 恒尝试 `JSON.parse` body,text/plain 会抛异常使 `await` reject(前端 e2e 实证)。故所有
/// admin-users 状态/错误响应走 JSON(REST 更规范 + 前端契约兼容)。
fn json_status(code: StatusCode, msg: &str) -> axum::response::Response {
    (
        code,
        Json(serde_json::json!({ "status": code.as_u16(), "message": msg })),
    )
        .into_response()
}

fn status_str(s: UserStatus) -> &'static str {
    match s {
        UserStatus::Active => "active",
        UserStatus::Disabled => "disabled",
        UserStatus::Tombstoned => "tombstoned",
    }
}

/// 用户视图(list/get 回;绝不含敏感值)。
#[derive(Serialize, ToSchema)]
pub struct UserView {
    pub user_id: String,
    pub email: String,
    pub status: String,
    pub created_at: i64,
    /// AS 最后一次成功建立该用户认证会话的时刻(Unix 秒);null = 从未登录。
    #[schema(required = true)]
    pub last_login_at: Option<i64>,
}

impl From<&UserRecord> for UserView {
    fn from(r: &UserRecord) -> Self {
        UserView {
            user_id: r.user_id.clone(),
            email: r.email.clone(),
            status: status_str(r.status).to_string(),
            created_at: r.created_at,
            last_login_at: r.last_login_at,
        }
    }
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateUserRequest {
    pub email: String,
    #[serde(default)]
    #[schema(value_type = String, format = Password)]
    pub initial_password: Option<agent_auth_authn::password::PasswordValue>,
    #[serde(default)]
    pub issue_invitation: bool,
}

#[derive(Serialize, ToSchema)]
pub struct CreateUserResponse {
    #[serde(flatten)]
    pub user: UserView,
    #[schema(required = true)]
    pub invitation: Option<crate::invitation::InvitationSecretResponse>,
}

async fn discard_initial_credential(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    cleanup_eligible: bool,
) -> bool {
    if !cleanup_eligible {
        return true;
    }
    for _ in 0..3 {
        match state.passwords.delete_if_version(tenant, user_id, 1).await {
            Ok(true) => return true,
            Ok(false) | Err(_) => match state.passwords.get(tenant, user_id).await {
                Ok(None) => return true,
                Ok(Some(credential)) if credential.version != 1 => return true,
                Ok(Some(_)) | Err(_) => {}
            },
        }
    }
    false
}

async fn complete_initial_credential(state: &AppState, tenant: &str, user_id: &str) -> bool {
    for _ in 0..3 {
        match state
            .passwords
            .complete_reset_revocation(tenant, user_id, 1)
            .await
        {
            Ok(true) => return true,
            Ok(false) | Err(_) => match state.passwords.get(tenant, user_id).await {
                Ok(Some(credential))
                    if credential.version == 1
                        && credential.must_change
                        && !credential.revocation_pending =>
                {
                    return true;
                }
                Ok(Some(_)) | Ok(None) | Err(_) => {}
            },
        }
    }
    false
}

/// `POST /admin/users`:幂等预建本地用户(类 Cognito AdminCreateUser)。
/// 归一 email → 解析已有 canonical id,否则派生 `user:{email}` → create;若该 email 处
/// **Tombstoned → 409**(不复活,须显式 restore)。
#[utoipa::path(post, path = "/admin/users", tag = "admin", request_body = CreateUserRequest,
    responses((status = 201, description = "用户已创建；邀请 URL 仅在邀请模式返回一次", body = CreateUserResponse),
        (status = 400, description = "email 非法、密码策略失败或 bootstrap 方法并非恰好一个"), (status = 401),
        (status = 409, description = "email 已 tombstone、bootstrap 冲突或用户不再符合条件"),
        (status = 503, description = "密码计算、邀请或存储不可用"),
        (status = 404, description = "SaaS 下不可用")))]
pub async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateUserRequest>,
) -> impl IntoResponse {
    if saas_users_disabled(&state) {
        return json_status(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    let tenant = admin.storage_tenant();
    let CreateUserRequest {
        email,
        initial_password,
        issue_invitation,
    } = req;
    enum Bootstrap {
        TemporaryPassword(agent_auth_authn::password::PasswordValue),
        Invitation,
    }
    let bootstrap = match (initial_password, issue_invitation) {
        (Some(password), false) => Bootstrap::TemporaryPassword(password),
        (None, true) => Bootstrap::Invitation,
        _ => {
            return json_status(
                StatusCode::BAD_REQUEST,
                "select exactly one bootstrap method",
            )
        }
    };
    let norm_email = crate::local_identity::normalize_email(&email);
    // 极简 email 校验:非空 + 单个 @ + 两侧非空(不做完整 RFC 5322;仅挡明显畸形)。
    // 🔴 **控制字符必拒**(评审 Kiro-M1,与 login.rs:143 magic-link 入口一致):email 进 `user:{email}` 逻辑键,
    // 含 `\x1f`(US 分隔符)会破坏 tpk/strip_tpk 的"逻辑键不含 \x1f"不变量 → 身份键错位/list 漏行。
    if !crate::local_identity::is_valid_email(&norm_email) {
        return json_status(StatusCode::BAD_REQUEST, "invalid email");
    }
    let derived_user_id = format!("user:{norm_email}");
    for (kind, value) in [
        (
            crate::governance::GovernanceAliasKind::Email,
            norm_email.as_str(),
        ),
        (
            crate::governance::GovernanceAliasKind::CanonicalId,
            derived_user_id.as_str(),
        ),
    ] {
        match crate::governance::user_alias_is_suppressed(&state, admin.tenant_id(), kind, value)
            .await
        {
            Ok(true) => {
                return json_status(
                    StatusCode::CONFLICT,
                    "identity alias is permanently suppressed",
                )
            }
            Ok(false) => {}
            Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
        }
    }
    if matches!(&bootstrap, Bootstrap::Invitation) {
        let Some(browser_origin) = crate::hostutil::browser_origin(&state, &headers) else {
            return json_status(StatusCode::BAD_REQUEST, "invalid browser origin");
        };
        let derived_user_id = format!("user:{norm_email}");
        let now = crate::token::current_unix_secs_pub();
        let existing_user = match state.users.get_by_email(tenant, &norm_email).await {
            Ok(Some(record)) if record.status == UserStatus::Tombstoned => {
                let locator = crate::invitation::invitation_locator(
                    &state.server_secret,
                    tenant,
                    &record.user_id,
                );
                if state
                    .invitations
                    .invalidate(tenant, &locator)
                    .await
                    .is_err()
                {
                    return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable");
                }
                return json_status(StatusCode::CONFLICT, "email tombstoned; restore required");
            }
            Ok(Some(record)) if !is_local_email_user(&record) => {
                return json_status(
                    StatusCode::CONFLICT,
                    "invitation is not available for this identity",
                )
            }
            Ok(user) => user,
            Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
        };
        let user_id = existing_user
            .as_ref()
            .map_or(derived_user_id, |record| record.user_id.clone());
        let created_new = existing_user.is_none();
        let _user = match state
            .users
            .create_or_get_by_email(tenant, &norm_email, &user_id, now)
            .await
        {
            Ok(user) if user.user_id == user_id && user.email == norm_email => user,
            Ok(_) | Err(_) => {
                return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable")
            }
        };
        let current = match state.users.get_by_id(tenant, &user_id).await {
            Ok(Some(current))
                if current.user_id == user_id
                    && current.email == norm_email
                    && current.status == UserStatus::Active =>
            {
                current
            }
            Ok(Some(_)) => {
                return json_status(StatusCode::CONFLICT, "user is not active");
            }
            Ok(None) | Err(_) => {
                return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable")
            }
        };
        let invitation_actor = admin.audit_identity();
        let invitation = match crate::invitation::issue_for_user(
            &state,
            tenant,
            &current,
            &invitation_actor,
            &browser_origin,
        )
        .await
        {
            Ok(invitation) => invitation,
            Err(crate::invitation::IssueInvitationError::Ineligible) => {
                return json_status(StatusCode::CONFLICT, "user is not eligible for invitation")
            }
            Err(crate::invitation::IssueInvitationError::PasswordConfigured) => {
                return json_status(StatusCode::CONFLICT, "password already configured")
            }
            Err(crate::invitation::IssueInvitationError::Store) => {
                return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable")
            }
        };
        if created_new {
            state
                .record_security_event(crate::security_event::SecurityEventDraft::user_lifecycle(
                    tenant,
                    crate::security_event::SecurityActor::admin(admin.audit_identity()),
                    &current.user_id,
                    crate::security_event::UserLifecycleAction::Create,
                    crate::security_event::SecurityEventOutcome::Success,
                ))
                .await;
        }
        eprintln!(
            "ADMIN_USER_CREATE actor={} user_id={} email={} status={} bootstrap=invitation",
            admin.audit_identity(),
            current.user_id,
            current.email,
            status_str(current.status)
        );
        return (
            StatusCode::CREATED,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(CreateUserResponse {
                user: UserView::from(&current),
                invitation: Some(invitation),
            }),
        )
            .into_response();
    }
    let Bootstrap::TemporaryPassword(initial_password) = bootstrap else {
        unreachable!("invitation branch returned")
    };
    if agent_auth_authn::password::validate_password(initial_password.expose()).is_err() {
        return json_status(
            StatusCode::BAD_REQUEST,
            "initial password must be 12 to 128 bytes",
        );
    }
    // Validate and hash before creating the user. A rejected password or an
    // unavailable Argon2 worker must never leave a user without a credential.
    let (initial_password, password_hash) =
        match crate::password_login::hash_with_budget(&state, initial_password).await {
            Ok(result) => result,
            Err(_) => {
                return json_status(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "password hashing unavailable",
                )
            }
        };
    let now = crate::token::current_unix_secs_pub();
    // Resolve mutable email aliases before choosing the credential owner.
    let existing_user = match state.users.get_by_email(tenant, &norm_email).await {
        Ok(Some(rec)) if rec.status == UserStatus::Tombstoned => {
            if state.passwords.delete(tenant, &rec.user_id).await.is_err() {
                return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable");
            }
            return json_status(StatusCode::CONFLICT, "email tombstoned; restore required");
        }
        Ok(Some(rec)) if !is_local_email_user(&rec) => {
            return json_status(
                StatusCode::CONFLICT,
                "password provisioning is not available for this identity",
            )
        }
        Ok(user) => user,
        Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    };
    let credential_user_id = existing_user
        .as_ref()
        .map_or(derived_user_id, |record| record.user_id.clone());
    let had_existing_user = existing_user.is_some();
    // Persist the temporary credential before making a new user eligible for
    // any login method. If the subsequent user write is ambiguous or fails,
    // the orphan credential is harmless and a same-password retry completes
    // provisioning; user-first ordering could expose a passwordless user to
    // magic-link and bypass the mandatory first change.
    let create_result = state
        .passwords
        .create_if_absent(
            tenant,
            PasswordCredential {
                user_id: credential_user_id.clone(),
                password_hash,
                must_change: true,
                // Initial provisioning is fail-closed until canonical identity,
                // status, and old-session cleanup have all been rechecked.
                revocation_pending: true,
                credential_change_id: None,
                version: 1,
                updated_at: now,
            },
        )
        .await;
    let created = matches!(create_result, Ok(true));
    let existing_credential = if created {
        None
    } else {
        let existing = match state.passwords.get(tenant, &credential_user_id).await {
            Ok(Some(existing)) => existing,
            Ok(None) | Err(_) => {
                return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable")
            }
        };
        if !existing.must_change {
            return json_status(StatusCode::CONFLICT, "password already active");
        }
        match crate::password_login::verify_with_budget(
            &state,
            initial_password,
            existing.password_hash.clone(),
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => return json_status(StatusCode::CONFLICT, "different initial password"),
            Err(_) => {
                return json_status(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "password verification unavailable",
                )
            }
        }
        Some(existing)
    };
    let provisioning_pending = created
        || existing_credential
            .as_ref()
            .is_some_and(|credential| credential.version == 1 && credential.revocation_pending);
    let rec = match state
        .users
        .create_or_get_by_email(tenant, &norm_email, &credential_user_id, now)
        .await
    {
        Ok(u) => u,
        Err(_) => {
            // A new-user write may have committed despite an ambiguous response;
            // keep its credential to block passwordless-login bypass. An
            // existing canonical user needs no creation recovery, so remove the
            // exact version created by this request.
            if had_existing_user
                && !discard_initial_credential(
                    &state,
                    tenant,
                    &credential_user_id,
                    provisioning_pending,
                )
                .await
            {
                return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable");
            }
            return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable");
        }
    };
    if rec.user_id != credential_user_id || rec.email != norm_email {
        if !discard_initial_credential(&state, tenant, &credential_user_id, provisioning_pending)
            .await
        {
            return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable");
        }
        return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable");
    }
    // Re-read the canonical primary key strongly before returning so a
    // concurrent delete or alias move cannot leave an eligible credential.
    let current = match state.users.get_by_id(tenant, &credential_user_id).await {
        Ok(Some(current))
            if current.user_id == credential_user_id && current.email == norm_email =>
        {
            current
        }
        Ok(_) => {
            if !discard_initial_credential(
                &state,
                tenant,
                &credential_user_id,
                provisioning_pending,
            )
            .await
            {
                return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable");
            }
            return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable");
        }
        Err(_) => {
            if had_existing_user
                && !discard_initial_credential(
                    &state,
                    tenant,
                    &credential_user_id,
                    provisioning_pending,
                )
                .await
            {
                return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable");
            }
            return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable");
        }
    };
    if current.status == UserStatus::Tombstoned {
        // Close create/delete interleavings: whichever operation observes the
        // tombstone last enforces the terminal invariant of no credential.
        if state
            .passwords
            .delete(tenant, &credential_user_id)
            .await
            .is_err()
        {
            return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable");
        }
        return json_status(StatusCode::CONFLICT, "email tombstoned; restore required");
    }
    // Existing legacy users may already have passwordless sessions. Once a
    // temporary credential exists, those sessions must not bypass the first
    // password change. A strongly consistent user scan plus the callback's
    // post-create credential check closes both orderings of the race.
    if state
        .sessions
        .delete_by_user(tenant, &credential_user_id)
        .await
        .is_err()
    {
        return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable");
    }
    if provisioning_pending
        && !complete_initial_credential(&state, tenant, &credential_user_id).await
    {
        return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable");
    }
    let invitation_locator =
        crate::invitation::invitation_locator(&state.server_secret, tenant, &credential_user_id);
    if state
        .invitations
        .invalidate(tenant, &invitation_locator)
        .await
        .is_err()
    {
        return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable");
    }
    eprintln!(
        "ADMIN_USER_CREATE actor={} user_id={} email={} status={}",
        admin.audit_identity(),
        rec.user_id,
        rec.email,
        status_str(current.status)
    );
    state
        .record_security_event(crate::security_event::SecurityEventDraft::user_lifecycle(
            tenant,
            crate::security_event::SecurityActor::admin(admin.audit_identity()),
            &current.user_id,
            crate::security_event::UserLifecycleAction::Create,
            crate::security_event::SecurityEventOutcome::Success,
        ))
        .await;
    (
        StatusCode::CREATED,
        Json(CreateUserResponse {
            user: UserView::from(&current),
            invitation: None,
        }),
    )
        .into_response()
}

#[derive(Serialize, ToSchema)]
pub struct UserListResponse {
    pub users: Vec<UserView>,
    /// 不透明续页 token(base64url JSON);None = 末页。原样回传给下次 `?cursor=`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Deserialize)]
pub struct ListUsersQuery {
    pub limit: Option<usize>,
    pub cursor: Option<String>,
    pub q: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ListUsersStatus {
    NonDeleted,
    Active,
    Disabled,
    Tombstoned,
    All,
}

impl From<ListUsersStatus> for UserListStatusFilter {
    fn from(value: ListUsersStatus) -> Self {
        match value {
            ListUsersStatus::NonDeleted => Self::NonDeleted,
            ListUsersStatus::Active => Self::Active,
            ListUsersStatus::Disabled => Self::Disabled,
            ListUsersStatus::Tombstoned => Self::Tombstoned,
            ListUsersStatus::All => Self::All,
        }
    }
}

impl ListUsersStatus {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "non_deleted" => Some(Self::NonDeleted),
            "active" => Some(Self::Active),
            "disabled" => Some(Self::Disabled),
            "tombstoned" => Some(Self::Tombstoned),
            "all" => Some(Self::All),
            _ => None,
        }
    }
}

/// `GET /admin/users?limit=&cursor=&q=&status=`:按 email/user_id 搜索并分页列出。
/// 非法/篡改 cursor、搜索或状态参数 → **400 非 500**(§1.4,Kiro #7)。
#[utoipa::path(get, path = "/admin/users", tag = "admin",
    params(("limit" = Option<usize>, Query), ("cursor" = Option<String>, Query),
        ("q" = Option<String>, Query, description = "email/user_id 大小写不敏感包含搜索"),
        ("status" = Option<ListUsersStatus>, Query,
            description = "生命周期状态筛选；省略时默认排除 tombstoned")),
    responses((status = 200, description = "分页用户列表", body = UserListResponse),
        (status = 400, description = "非法 cursor/search/status"),
        (status = 401), (status = 404)))]
pub async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<ListUsersQuery>,
) -> impl IntoResponse {
    if saas_users_disabled(&state) {
        return json_status(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Read).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    let tenant = admin.storage_tenant();
    let limit = q.limit.unwrap_or(50).clamp(1, 100);
    let query =
        q.q.as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
    let status = match q.status.as_deref() {
        None => UserListStatusFilter::NonDeleted,
        Some(value) => match ListUsersStatus::parse(value) {
            Some(value) => UserListStatusFilter::from(value),
            None => return json_status(StatusCode::BAD_REQUEST, "invalid status"),
        },
    };
    if query.is_some_and(|value| value.len() > 256 || value.chars().any(char::is_control)) {
        return json_status(StatusCode::BAD_REQUEST, "invalid search");
    }
    match state
        .users
        .list(tenant, limit, q.cursor.as_deref(), query, status)
        .await
    {
        Ok((recs, next_cursor)) => {
            let users = recs.iter().map(UserView::from).collect();
            Json(UserListResponse { users, next_cursor }).into_response()
        }
        // Permanent = 非法/篡改 cursor(客户端输入)→ 400,不当 500(§1.4,Kiro #7)。
        Err(crate::ports::StoreError::Permanent(_)) => {
            json_status(StatusCode::BAD_REQUEST, "invalid cursor")
        }
        Err(_) => json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    }
}

/// 计数字段:成功=数值;store 失败=`unavailable`(§1.4,codex #4:绝不当 0/false)。
#[derive(Serialize, ToSchema)]
#[serde(untagged)]
pub enum Count {
    Value(usize),
    Unavailable { unavailable: bool },
}

fn count_or_unavailable(r: Result<usize, crate::ports::StoreError>) -> Count {
    match r {
        Ok(n) => Count::Value(n),
        Err(_) => Count::Unavailable { unavailable: true },
    }
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PasswordStatus {
    NotConfigured,
    ChangeRequired,
    Active,
    Unavailable,
}

#[derive(Serialize, ToSchema)]
pub struct UserDetail {
    #[serde(flatten)]
    pub user: UserView,
    /// 活跃 grant 数(store 失败标 unavailable)。
    pub active_grants: Count,
    /// passkey 凭证数。
    pub passkeys: Count,
    /// 活跃(未过期)AS 会话数。
    pub sessions: Count,
    /// 是否配置了恢复码(布尔;绝不回明文码)。store 失败 → null。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_recovery: Option<bool>,
    /// 恢复码查询失败标记(has_recovery 为 null 时说明原因)。
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub recovery_unavailable: bool,
    /// Password state summary only. The PHC hash is never part of this schema.
    pub password_status: PasswordStatus,
    /// RS 命名空间用户属性(spec 007,§6.1):管理面**超级权限全局视图**——回带**全部** namespace
    /// 的属性(区别于 RS 侧 `/rs/attributes` 只见自身 aud)。形如 `{<namespace>: {revision, kv:{k:v}}}`。
    pub attributes: std::collections::BTreeMap<String, AttrNamespaceView>,
}

/// UserDetail 里单个 namespace 属性的展示视图(spec 007):带 revision 供前端 RMW `If-Match`。
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct AttrNamespaceView {
    /// Stable canonical namespace. During a pending migration the map key may still be a source
    /// namespace, while this field identifies the target canonical namespace.
    #[schema(max_length = 1024)]
    pub canonical_namespace: String,
    /// Exact RFC 8707 audience URIs currently declared by the registration.
    #[schema(max_items = 32)]
    pub exact_audiences: Vec<String>,
    /// `unbound`, `pending`, `active`, or `retired`.
    pub registration_state: String,
    /// 乐观锁版本(前端改属性时带 If-Match 回传)。
    pub revision: u64,
    /// 该 namespace 下的 key→value。
    pub kv: std::collections::BTreeMap<String, String>,
    /// Federation-managed keys keyed by attribute name. This is a provenance summary only:
    /// configured source claims and values are never returned from the user detail API.
    pub federation_owners: std::collections::BTreeMap<String, FederatedAttributeOwnerView>,
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct FederatedAttributeOwnerView {
    pub upstream_idp_id: String,
    pub mapping_id: String,
    pub mapping_revision: u64,
    /// `active` when the exact mapping revision still owns this target; otherwise `stale`.
    pub state: String,
}

/// `GET /admin/users/{id}`:基本信息 + 关联资源计数/布尔(绝不回敏感值,§1.4)。
#[utoipa::path(get, path = "/admin/users/{id}", tag = "admin",
    params(("id" = String, Path)),
    responses((status = 200, description = "用户详情 + 聚合计数", body = UserDetail),
        (status = 401), (status = 404, description = "不存在 / SaaS 下不可用")))]
pub async fn get_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if saas_users_disabled(&state) {
        return json_status(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Read).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    let tenant = admin.storage_tenant();
    let rec = match state.users.get_by_id(tenant, &id).await {
        Ok(Some(r)) => r,
        Ok(None) => return json_status(StatusCode::NOT_FOUND, "not found"),
        Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    };
    let now = crate::token::current_unix_secs_pub();
    // 聚合计数:任一失败标 unavailable(不当 0/false,codex #4)。
    let active_grants = count_or_unavailable(
        state
            .grants
            .list_by_user(tenant, &id)
            .await
            .map(|gs| gs.iter().filter(|g| g.is_usable(now).is_ok()).count()),
    );
    let passkeys = count_or_unavailable(
        state
            .passkeys
            .list_by_user(tenant, &id)
            .await
            .map(|v| v.len()),
    );
    let sessions = count_or_unavailable(state.sessions.count_by_user(tenant, &id, now).await);
    let lookup = crate::recover::user_lookup(&id);
    let (has_recovery, recovery_unavailable) = match state.recovery.get(tenant, &lookup).await {
        // 配置了恢复码 ⟺ 存在记录且有未消费码。
        Ok(Some(r)) => (Some(r.code_hashes.iter().any(|e| !e.consumed)), false),
        Ok(None) => (Some(false), false),
        Err(_) => (None, true),
    };
    let password_status = match state.passwords.get(tenant, &id).await {
        Ok(None) => PasswordStatus::NotConfigured,
        Ok(Some(credential)) if credential.must_change => PasswordStatus::ChangeRequired,
        Ok(Some(_)) => PasswordStatus::Active,
        Err(_) => PasswordStatus::Unavailable,
    };
    use crate::attribute_namespace::{AttributeNamespaceStore, RegistrationState};
    let registrations = match state.attribute_namespaces.list(tenant).await {
        Ok(registrations) => registrations,
        Err(_) => {
            return json_status(
                StatusCode::SERVICE_UNAVAILABLE,
                "namespace store unavailable",
            );
        }
    };
    use crate::federation_attributes::FederationAttributeMappingsStore as _;
    let owner_idps: std::collections::BTreeSet<String> = rec
        .attributes
        .values()
        .flat_map(|attributes| attributes.federation_owners.values())
        .map(|owner| owner.upstream_idp_id.clone())
        .collect();
    let mut mapping_registries = std::collections::BTreeMap::new();
    for upstream_idp_id in owner_idps {
        let registry = match state
            .federation_attribute_mappings
            .get_registry(admin.tenant_id(), &upstream_idp_id)
            .await
        {
            Ok(registry) => registry,
            Err(_) => {
                return json_status(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "federation mapping store unavailable",
                )
            }
        };
        mapping_registries.insert(upstream_idp_id, registry);
    }
    let mut registration_by_namespace = std::collections::BTreeMap::new();
    for (index, registration) in registrations.iter().enumerate() {
        registration_by_namespace.insert(registration.canonical_namespace.clone(), index);
        for audience in &registration.exact_audiences {
            registration_by_namespace.insert(audience.clone(), index);
        }
        if let Some(operation) = &registration.operation {
            for namespace in operation
                .source_namespaces
                .iter()
                .chain(&operation.desired_exact_audiences)
            {
                registration_by_namespace.insert(namespace.clone(), index);
            }
        }
    }
    // spec 007:管理面超级权限视图——回带全部 namespace 属性、canonical binding 与状态。
    let attributes = rec
        .attributes
        .iter()
        .map(|(ns, n)| {
            let registration = registration_by_namespace
                .get(ns)
                .and_then(|index| registrations.get(*index));
            let (canonical_namespace, exact_audiences, registration_state) = match registration {
                Some(registration) => (
                    registration.canonical_namespace.clone(),
                    registration
                        .operation
                        .as_ref()
                        .map(|operation| {
                            operation.desired_exact_audiences.iter().cloned().collect()
                        })
                        .unwrap_or_else(|| registration.exact_audiences.iter().cloned().collect()),
                    match registration.state {
                        RegistrationState::Pending => "pending",
                        RegistrationState::Active => "active",
                        RegistrationState::Retired => "retired",
                    }
                    .to_string(),
                ),
                None => (ns.clone(), Vec::new(), "unbound".to_string()),
            };
            (
                ns.clone(),
                AttrNamespaceView {
                    canonical_namespace,
                    exact_audiences,
                    registration_state,
                    revision: n.revision,
                    kv: n.kv.clone(),
                    federation_owners: n
                        .federation_owners
                        .iter()
                        .map(|(key, owner)| {
                            (
                                key.clone(),
                                FederatedAttributeOwnerView {
                                    upstream_idp_id: owner.upstream_idp_id.clone(),
                                    mapping_id: owner.mapping_id.clone(),
                                    mapping_revision: owner.mapping_revision,
                                    state: if crate::federation_attributes::federated_attribute_owner_is_active(
                                        mapping_registries
                                            .get(&owner.upstream_idp_id)
                                            .and_then(Option::as_ref),
                                        owner,
                                        ns,
                                        key,
                                    ) {
                                        "active"
                                    } else {
                                        "stale"
                                    }
                                    .to_string(),
                                },
                            )
                        })
                        .collect(),
                },
            )
        })
        .collect();
    Json(UserDetail {
        user: UserView::from(&rec),
        active_grants,
        passkeys,
        sessions,
        has_recovery,
        recovery_unavailable,
        password_status,
        attributes,
    })
    .into_response()
}

#[derive(Deserialize, ToSchema)]
pub struct ResetPasswordRequest {
    #[schema(value_type = String, format = Password)]
    pub temporary_password: agent_auth_authn::password::PasswordValue,
}

fn is_local_email_user(record: &UserRecord) -> bool {
    let email = crate::local_identity::normalize_email(&record.email);
    crate::local_identity::is_valid_email(&email)
        && crate::local_identity::is_password_capable_user_id(&record.user_id)
}

/// `POST /admin/users/{id}/reset-password`:为本地 email 用户设置新的临时密码。
/// 成功后旧密码失效、现有 session/refresh 被吊销,下次登录必须先改密。
#[utoipa::path(post, path = "/admin/users/{id}/reset-password", tag = "admin",
    params(("id" = String, Path)), request_body = ResetPasswordRequest,
    responses((status = 200, description = "临时密码已重置,认证态已吊销"),
        (status = 400, description = "临时密码不符合策略或与当前密码相同"), (status = 401),
        (status = 404, description = "用户不存在 / SaaS 数据面未就绪"),
        (status = 409, description = "墓碑用户或非本地 email 用户不可重置"),
        (status = 503, description = "密码计算、存储或认证态吊销不可用")))]
pub async fn reset_user_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<ResetPasswordRequest>,
) -> impl IntoResponse {
    if saas_users_disabled(&state) {
        return json_status(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    let tenant = admin.storage_tenant();
    let record = match state.users.get_by_id(tenant, &id).await {
        Ok(Some(record)) => record,
        Ok(None) => return json_status(StatusCode::NOT_FOUND, "not found"),
        Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    };
    if record.status == UserStatus::Tombstoned {
        // Also clean any credential left by an interrupted reset/delete race.
        if state.passwords.delete(tenant, &id).await.is_err() {
            return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable");
        }
        return json_status(StatusCode::CONFLICT, "tombstoned; cannot reset password");
    }
    if !is_local_email_user(&record) {
        return json_status(
            StatusCode::CONFLICT,
            "password reset is only available for local email users",
        );
    }
    if agent_auth_authn::password::validate_password(req.temporary_password.expose()).is_err() {
        return json_status(
            StatusCode::BAD_REQUEST,
            "temporary password must be 12 to 128 bytes",
        );
    }
    let existing_credential = match state.passwords.get(tenant, &id).await {
        Ok(credential) => credential,
        Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    };
    let expected_version = existing_credential
        .as_ref()
        .map(|credential| credential.version);
    let mut resume_pending = None;
    if let Some(existing) = existing_credential {
        let existing_version = existing.version;
        let pending_reset = existing.must_change && existing.revocation_pending;
        let completed_retry =
            existing.must_change && !existing.revocation_pending && !record.revocation_pending;
        let candidate = agent_auth_authn::password::PasswordValue::new(
            req.temporary_password.expose().to_string(),
        );
        match crate::password_login::verify_with_budget(&state, candidate, existing.password_hash)
            .await
        {
            Ok(true) if pending_reset => {
                resume_pending = existing
                    .credential_change_id
                    .map(|operation_id| (existing_version, operation_id));
            }
            Ok(true) if completed_retry => {
                eprintln!(
                    "ADMIN_USER_PASSWORD_RESET_RETRY actor={} user_id={}",
                    admin.audit_identity(),
                    id
                );
                return json_status(StatusCode::OK, "password reset");
            }
            Ok(true) => {
                return json_status(
                    StatusCode::BAD_REQUEST,
                    "temporary password must differ from the current password",
                )
            }
            Ok(false) => {}
            Err(_) => {
                return json_status(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "password verification unavailable",
                )
            }
        }
        if pending_reset && resume_pending.is_none() {
            return json_status(
                StatusCode::CONFLICT,
                "password reset changed concurrently; retry",
            );
        }
    }
    let now = crate::token::current_unix_secs_pub();
    let mut resumed_epoch = None;
    if let Some((_, operation_id)) = resume_pending.as_ref() {
        let expected_epoch = if record.revocation_pending {
            let Some(expected_epoch) = record.credential_epoch.checked_sub(1) else {
                return json_status(
                    StatusCode::CONFLICT,
                    "password reset changed concurrently; retry",
                );
            };
            expected_epoch
        } else {
            record.credential_epoch
        };
        let Some(expected_started_epoch) = expected_epoch.checked_add(1) else {
            return json_status(StatusCode::CONFLICT, "credential epoch exhausted");
        };
        match state
            .users
            .begin_admin_credential_change(tenant, &id, expected_epoch, operation_id, now)
            .await
        {
            Ok(crate::ports::CredentialChangeStart::Started { epoch })
                if epoch == expected_started_epoch =>
            {
                resumed_epoch = Some(epoch);
            }
            Ok(_) => {
                return json_status(
                    StatusCode::CONFLICT,
                    "password reset changed concurrently; retry",
                )
            }
            Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
        }
    }
    if record.revocation_pending && resume_pending.is_none() {
        let started_before = now.saturating_sub(crate::user_gate::CREDENTIAL_CHANGE_LEASE_SECS);
        if record.updated_at > started_before {
            return json_status(
                StatusCode::CONFLICT,
                "password reset changed concurrently; retry",
            );
        }
        match state
            .users
            .recover_expired_credential_change(
                tenant,
                &id,
                record.credential_epoch,
                started_before,
                now,
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                return json_status(
                    StatusCode::CONFLICT,
                    "password reset changed concurrently; retry",
                )
            }
            Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
        }
    }
    let password_hash = if resume_pending.is_none() {
        let (_, password_hash) =
            match crate::password_login::hash_with_budget(&state, req.temporary_password).await {
                Ok(result) => result,
                Err(_) => {
                    return json_status(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "password hashing unavailable",
                    )
                }
            };
        Some(password_hash)
    } else {
        None
    };
    let (reset_epoch, reset_operation_id) = if let Some((_, operation_id)) = resume_pending.as_ref()
    {
        (
            resumed_epoch.expect("a resumable reset has re-established its exact fence"),
            operation_id.clone(),
        )
    } else {
        let operation_id = crate::account_credentials::credential_operation_id();
        let epoch = match state
            .users
            .begin_admin_credential_change(tenant, &id, record.credential_epoch, &operation_id, now)
            .await
        {
            Ok(crate::ports::CredentialChangeStart::Started { epoch }) => epoch,
            Ok(crate::ports::CredentialChangeStart::NotFound) => {
                return json_status(StatusCode::NOT_FOUND, "not found")
            }
            Ok(
                crate::ports::CredentialChangeStart::Ineligible
                | crate::ports::CredentialChangeStart::ConcurrentChange,
            ) => {
                return json_status(
                    StatusCode::CONFLICT,
                    "password reset changed concurrently; retry",
                )
            }
            Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
        };
        (epoch, operation_id)
    };
    let reset_owner = crate::ports::CredentialChangeOwner {
        epoch: reset_epoch,
        operation_id: &reset_operation_id,
    };
    let reset_version = match (resume_pending.map(|(version, _)| version), password_hash) {
        (Some(version), _) => version,
        (None, Some(password_hash)) => {
            match state
                .passwords
                .stage_admin_reset(
                    &state.users,
                    crate::ports::FencedPasswordMutation {
                        tenant,
                        user_id: &id,
                        password_hash,
                        expected_version,
                        credential_epoch: reset_epoch,
                        updated_at: now,
                    },
                    reset_owner,
                )
                .await
            {
                Ok(Some(version)) => version,
                Ok(None) => {
                    let _ = state
                        .users
                        .abort_admin_credential_change(tenant, &id, reset_owner, now)
                        .await;
                    return json_status(
                        StatusCode::CONFLICT,
                        "password reset changed concurrently; retry",
                    );
                }
                Err(_) => {
                    // A transaction or its reconciliation reads may have committed
                    // without returning a usable response. Preserve the exact owner
                    // so a same-password retry can resume the staged credential.
                    return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable");
                }
            }
        }
        (None, None) => unreachable!("new admin reset always hashes the password"),
    };
    let revoked =
        match crate::user_lifecycle::revoke_authentication_state(&state, tenant, &id).await {
            Ok(revoked) => revoked,
            Err(_) => {
                eprintln!(
                    "ADMIN_USER_PASSWORD_RESET_REVOKE_FAILED actor={} user_id={}",
                    admin.audit_identity(),
                    id
                );
                return json_status(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "password reset; authentication revoke failed",
                );
            }
        };
    match state
        .passwords
        .complete_admin_reset(
            &state.users,
            tenant,
            &id,
            reset_version,
            reset_owner,
            crate::token::current_unix_secs_pub(),
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return json_status(
                StatusCode::CONFLICT,
                "password reset changed concurrently; retry",
            )
        }
        Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    }
    let invitation_locator =
        crate::invitation::invitation_locator(&state.server_secret, tenant, &id);
    if state
        .invitations
        .invalidate(tenant, &invitation_locator)
        .await
        .is_err()
    {
        return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable");
    }
    eprintln!(
        "ADMIN_USER_PASSWORD_RESET actor={} user_id={} sessions={} families={}",
        admin.audit_identity(),
        id,
        revoked.sessions,
        revoked.families
    );
    state
        .record_security_event(
            crate::security_event::SecurityEventDraft::new(
                tenant,
                crate::security_event::SecurityActor::admin(admin.audit_identity()),
                Some(crate::security_event::SecuritySubject::user(&id)),
                crate::security_event::SecurityEventCategory::Credential,
                "credential.password.reset",
                crate::security_event::SecurityEventOutcome::Success,
            )
            .correlated(crate::security_event::SecurityEventCorrelation {
                operation_id: Some(reset_operation_id),
                ..Default::default()
            }),
        )
        .await;
    json_status(StatusCode::OK, "password reset")
}

/// `POST /admin/users/{id}/disable`:status=Disabled + 级联即时吊销(§1.4)。
#[utoipa::path(post, path = "/admin/users/{id}/disable", tag = "admin",
    params(("id" = String, Path)),
    responses((status = 200, description = "已禁用 + 级联吊销"), (status = 401),
        (status = 404, description = "不存在 / SaaS 下不可用")))]
pub async fn disable_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if saas_users_disabled(&state) {
        return json_status(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    let tenant = admin.storage_tenant();
    let now = crate::token::current_unix_secs_pub();
    match crate::user_lifecycle::disable(&state, tenant, &id, now).await {
        Ok(crate::user_lifecycle::DisableOutcome::Disabled { record, counts }) => {
            eprintln!(
                "ADMIN_USER_DISABLE actor={} user_id={} epoch={} sessions={} families={} grants={}",
                admin.audit_identity(),
                id,
                record.credential_epoch,
                counts.sessions,
                counts.families,
                counts.grants
            );
            state
                .record_security_event(crate::security_event::SecurityEventDraft::user_lifecycle(
                    tenant,
                    crate::security_event::SecurityActor::admin(admin.audit_identity()),
                    &id,
                    crate::security_event::UserLifecycleAction::Disable,
                    crate::security_event::SecurityEventOutcome::Success,
                ))
                .await;
            json_status(StatusCode::OK, "disabled")
        }
        Ok(crate::user_lifecycle::DisableOutcome::NotFound) => {
            json_status(StatusCode::NOT_FOUND, "not found")
        }
        Ok(crate::user_lifecycle::DisableOutcome::Tombstoned) => {
            json_status(StatusCode::CONFLICT, "tombstoned; immutable")
        }
        Err(_) => {
            state
                .record_security_event(crate::security_event::SecurityEventDraft::user_lifecycle(
                    tenant,
                    crate::security_event::SecurityActor::admin(admin.audit_identity()),
                    &id,
                    crate::security_event::UserLifecycleAction::Disable,
                    crate::security_event::SecurityEventOutcome::Failure,
                ))
                .await;
            json_status(StatusCode::SERVICE_UNAVAILABLE, "cascade revoke failed")
        }
    }
}

/// `POST /admin/users/{id}/enable`:status=Active(反向;不恢复已吊销凭证,用户重新登录)。
#[utoipa::path(post, path = "/admin/users/{id}/enable", tag = "admin",
    params(("id" = String, Path)),
    responses((status = 200, description = "已恢复 Active"), (status = 401),
        (status = 404, description = "不存在 / SaaS 下不可用"),
        (status = 409, description = "已 tombstone,不可 enable")))]
pub async fn enable_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if saas_users_disabled(&state) {
        return json_status(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    let tenant = admin.storage_tenant();
    let now = crate::token::current_unix_secs_pub();
    match crate::user_lifecycle::enable(&state, tenant, &id, now).await {
        Ok(crate::user_lifecycle::LifecycleEnableOutcome::Enabled(record)) => {
            eprintln!(
                "ADMIN_USER_ENABLE actor={} user_id={} new_status=active epoch={}",
                admin.audit_identity(),
                id,
                record.credential_epoch
            );
            state
                .record_security_event(crate::security_event::SecurityEventDraft::user_lifecycle(
                    tenant,
                    crate::security_event::SecurityActor::admin(admin.audit_identity()),
                    &id,
                    crate::security_event::UserLifecycleAction::Enable,
                    crate::security_event::SecurityEventOutcome::Success,
                ))
                .await;
            json_status(StatusCode::OK, "enabled")
        }
        Ok(crate::user_lifecycle::LifecycleEnableOutcome::NotFound) => {
            json_status(StatusCode::NOT_FOUND, "not found")
        }
        Ok(crate::user_lifecycle::LifecycleEnableOutcome::Tombstoned) => {
            json_status(StatusCode::CONFLICT, "tombstoned; cannot enable")
        }
        Err(_) => json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    }
}

/// `DELETE /admin/users/{id}`:tombstone(§1.4,评审两方 Blocker)——**非纯物理删**(纯删后同 email
/// JIT 会复活 Active)。置 Tombstoned + 全量级联(disable 全部 + passkey + recovery)。幂等 2xx(已
/// tombstone 再 delete → 200;注明偏离 delete_client 的 404)。
#[utoipa::path(delete, path = "/admin/users/{id}", tag = "admin",
    params(("id" = String, Path)),
    responses((status = 200, description = "已 tombstone + 全级联(幂等)"), (status = 401),
        (status = 404, description = "不存在 / SaaS 下不可用")))]
pub async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if saas_users_disabled(&state) {
        return json_status(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    let tenant = admin.storage_tenant();
    // 存在性:不存在 → 404(delete 目标须存在;幂等指"已 tombstone 再删"仍 200)。
    let old = match state.users.get_by_id(tenant, &id).await {
        Ok(Some(r)) => r,
        Ok(None) => return json_status(StatusCode::NOT_FOUND, "not found"),
        Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    };
    let now = crate::token::current_unix_secs_pub();
    match state
        .users
        .set_status(tenant, &id, UserStatus::Tombstoned, now)
        .await
    {
        Ok(true) => {}
        Ok(false) => return json_status(StatusCode::NOT_FOUND, "not found"),
        Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    }
    // 全量级联(含 passkey + recovery)。fail-closed。
    match crate::user_lifecycle::cascade_revoke(&state, tenant, &id, true).await {
        Ok(c) => {
            eprintln!(
                "ADMIN_USER_DELETE actor={} user_id={} old_status={} new_status=tombstoned sessions={} families={} grants={} passkeys={} recovery_deleted={} password_deleted={}",
                admin.audit_identity(),
                id,
                status_str(old.status),
                c.sessions,
                c.families,
                c.grants,
                c.passkeys,
                c.recovery_deleted,
                c.password_deleted
            );
            state
                .record_security_event(crate::security_event::SecurityEventDraft::user_lifecycle(
                    tenant,
                    crate::security_event::SecurityActor::admin(admin.audit_identity()),
                    &id,
                    crate::security_event::UserLifecycleAction::Delete,
                    crate::security_event::SecurityEventOutcome::Success,
                ))
                .await;
            json_status(StatusCode::OK, "tombstoned")
        }
        Err(_) => {
            state
                .record_security_event(crate::security_event::SecurityEventDraft::user_lifecycle(
                    tenant,
                    crate::security_event::SecurityActor::admin(admin.audit_identity()),
                    &id,
                    crate::security_event::UserLifecycleAction::Delete,
                    crate::security_event::SecurityEventOutcome::Failure,
                ))
                .await;
            json_status(StatusCode::SERVICE_UNAVAILABLE, "cascade revoke failed")
        }
    }
}

/// `PUT /admin/users/{id}/attributes?namespace=<uri>` 的 query 参数(spec 007 §6.1)。
/// **namespace 走 query 而非 path 段**:RS resource 标识是 URI(含 `/`),API Gateway HTTP API 会把 path 段里的
/// `%2F` 当真实 `/` 拆开导致 `{namespace}` 路由 404(真机实测)——query 参数不受此限。
#[derive(Deserialize, ToSchema)]
pub struct AttrNamespaceQuery {
    #[schema(max_length = 1024)]
    pub namespace: String,
}

#[derive(Deserialize, ToSchema)]
pub struct FederatedAttributeOwnerPurgeQuery {
    #[schema(max_length = 1024)]
    pub namespace: String,
    #[schema(max_length = 128)]
    pub key: String,
}

fn attribute_write_operation_id(
    server_secret: &[u8],
    namespace: &str,
    expected_revision: u64,
    keys: impl Iterator<Item = impl AsRef<str>>,
) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let mut mac = HmacSha256::new_from_slice(server_secret).expect("HMAC any key len");
    mac.update(b"attribute-write:v1");
    for component in [
        namespace.as_bytes(),
        expected_revision.to_string().as_bytes(),
    ] {
        mac.update(&(component.len() as u64).to_be_bytes());
        mac.update(component);
    }
    for key in keys {
        let key = key.as_ref().as_bytes();
        mac.update(&(key.len() as u64).to_be_bytes());
        mac.update(key);
    }
    format!(
        "attribute-write-{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

fn federated_attribute_purge_value_summary(
    server_secret: &[u8],
    tenant: &str,
    user_id: &str,
    namespace: &str,
    key: &str,
    owner: &crate::ports::FederatedAttributeOwner,
    value: Option<&str>,
) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let mut mac = HmacSha256::new_from_slice(server_secret).expect("HMAC any key len");
    mac.update(b"federated-attribute-value:v1");
    let presence = if value.is_some() { "present" } else { "absent" };
    for component in [
        tenant,
        owner.upstream_idp_id.as_str(),
        user_id,
        owner.mapping_id.as_str(),
        namespace,
        key,
        presence,
        value.unwrap_or_default(),
    ] {
        mac.update(&(component.len() as u64).to_be_bytes());
        mac.update(component.as_bytes());
    }
    format!(
        "fav_{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

async fn audit_user_attribute_write(
    state: &AppState,
    tenant: &str,
    actor: &str,
    user_id: &str,
    operation_id: String,
    outcome: crate::security_event::SecurityEventOutcome,
) {
    state
        .record_security_event(
            crate::security_event::SecurityEventDraft::new(
                tenant,
                crate::security_event::SecurityActor::admin(actor),
                Some(crate::security_event::SecuritySubject::user(user_id)),
                crate::security_event::SecurityEventCategory::Administration,
                "user.attributes.write",
                outcome,
            )
            .correlated(crate::security_event::SecurityEventCorrelation {
                operation_id: Some(operation_id),
                ..Default::default()
            }),
        )
        .await;
}

struct FederatedAttributeOwnerPurgeAudit<'a> {
    tenant: &'a str,
    actor: &'a str,
    user_id: &'a str,
    namespace: &'a str,
    key: &'a str,
    expected_revision: u64,
    owner: Option<&'a crate::ports::FederatedAttributeOwner>,
    previous_value: Option<&'a str>,
}

async fn audit_federated_attribute_owner_purge(
    state: &AppState,
    audit: FederatedAttributeOwnerPurgeAudit<'_>,
    outcome: crate::security_event::SecurityEventOutcome,
) {
    state
        .record_security_event(
            crate::security_event::SecurityEventDraft::new(
                audit.tenant,
                crate::security_event::SecurityActor::admin(audit.actor),
                Some(crate::security_event::SecuritySubject::user(audit.user_id)),
                crate::security_event::SecurityEventCategory::Administration,
                "federation.attribute_owner.purge",
                outcome,
            )
            .correlated(crate::security_event::SecurityEventCorrelation {
                operation_id: Some(attribute_write_operation_id(
                    &state.server_secret,
                    audit.namespace,
                    audit.expected_revision,
                    std::iter::once(audit.key),
                )),
                upstream_idp_id: audit.owner.map(|owner| owner.upstream_idp_id.clone()),
                mapping_id: audit.owner.map(|owner| owner.mapping_id.clone()),
                mapping_revision: audit.owner.map(|owner| owner.mapping_revision),
                target_namespace: Some(audit.namespace.to_string()),
                target_key: Some(audit.key.to_string()),
                old_value_summary: audit.owner.zip(audit.previous_value).map(|(owner, value)| {
                    federated_attribute_purge_value_summary(
                        &state.server_secret,
                        audit.tenant,
                        audit.user_id,
                        audit.namespace,
                        audit.key,
                        owner,
                        Some(value),
                    )
                }),
                new_value_summary: audit.owner.zip(audit.previous_value).map(|(owner, _)| {
                    federated_attribute_purge_value_summary(
                        &state.server_secret,
                        audit.tenant,
                        audit.user_id,
                        audit.namespace,
                        audit.key,
                        owner,
                        None,
                    )
                }),
                ..Default::default()
            }),
        )
        .await;
}

#[utoipa::path(delete, path = "/admin/users/{id}/attributes/federation-owner", tag = "admin",
    params(
        ("id" = String, Path),
        ("namespace" = String, Query, description = "Canonical RS attribute namespace"),
        ("key" = String, Query, description = "Exact federation-owned attribute key"),
        ("if-match" = Option<String>, Header, description = "Expected namespace revision")
    ),
    responses(
        (status = 200, description = "Stale owner and its value were purged"),
        (status = 400, description = "Invalid namespace or key"),
        (status = 401, description = "admin authentication failed"),
        (status = 404, description = "User/owner not found or SaaS unavailable"),
        (status = 409, description = "Owner is active, revision conflicted, user tombstoned, or authority changed"),
        (status = 503, description = "Authority or user store unavailable")))]
pub async fn purge_federated_attribute_owner(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<FederatedAttributeOwnerPurgeQuery>,
) -> impl IntoResponse {
    use crate::federation_attributes::FederationAttributeOwnerPurgeOutcome;

    if saas_attributes_disabled(&state) {
        return json_status(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let audit_identity = admin.audit_identity();
    let expected_revision = headers
        .get(axum::http::header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().trim_matches('"').parse::<u64>().ok())
        .unwrap_or(0);
    if !crate::attribute_namespace::validate_namespace_uri(&q.namespace)
        || q.key.is_empty()
        || q.key.len() > 128
        || q.key.trim() != q.key
        || q.key.chars().any(char::is_control)
    {
        audit_federated_attribute_owner_purge(
            &state,
            FederatedAttributeOwnerPurgeAudit {
                tenant: admin.storage_tenant(),
                actor: &audit_identity,
                user_id: &id,
                namespace: &q.namespace,
                key: &q.key,
                expected_revision,
                owner: None,
                previous_value: None,
            },
            crate::security_event::SecurityEventOutcome::Denied,
        )
        .await;
        return json_status(StatusCode::BAD_REQUEST, "invalid namespace or key");
    }

    let result = state
        .purge_stale_federated_attribute_owner(
            admin.tenant_id(),
            admin.storage_tenant(),
            &id,
            &q.namespace,
            &q.key,
            expected_revision,
        )
        .await;
    let (owner, previous_value, audit_outcome) = match &result {
        Ok(FederationAttributeOwnerPurgeOutcome::Purged {
            owner,
            previous_value,
            ..
        }) => (
            Some(owner),
            Some(previous_value.as_str()),
            crate::security_event::SecurityEventOutcome::Success,
        ),
        Ok(FederationAttributeOwnerPurgeOutcome::ActiveOwner { owner }) => (
            Some(owner),
            None,
            crate::security_event::SecurityEventOutcome::Denied,
        ),
        Ok(_) => (
            None,
            None,
            crate::security_event::SecurityEventOutcome::Denied,
        ),
        Err(_) => (
            None,
            None,
            crate::security_event::SecurityEventOutcome::Failure,
        ),
    };
    audit_federated_attribute_owner_purge(
        &state,
        FederatedAttributeOwnerPurgeAudit {
            tenant: admin.storage_tenant(),
            actor: &audit_identity,
            user_id: &id,
            namespace: &q.namespace,
            key: &q.key,
            expected_revision,
            owner,
            previous_value,
        },
        audit_outcome,
    )
    .await;

    match result {
        Ok(FederationAttributeOwnerPurgeOutcome::Purged { user, .. }) => {
            let revision = user
                .attributes
                .get(&q.namespace)
                .map(|attributes| attributes.revision)
                .unwrap_or(expected_revision);
            Json(serde_json::json!({ "revision": revision })).into_response()
        }
        Ok(
            FederationAttributeOwnerPurgeOutcome::NotFound
            | FederationAttributeOwnerPurgeOutcome::OwnerNotFound,
        ) => json_status(StatusCode::NOT_FOUND, "user or federation owner not found"),
        Ok(FederationAttributeOwnerPurgeOutcome::RevisionConflict { current }) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "revision_conflict",
                "current_revision": current
            })),
        )
            .into_response(),
        Ok(FederationAttributeOwnerPurgeOutcome::Tombstoned) => {
            json_status(StatusCode::CONFLICT, "user tombstoned")
        }
        Ok(FederationAttributeOwnerPurgeOutcome::ActiveOwner { .. }) => json_status(
            StatusCode::CONFLICT,
            "active federation owner cannot be purged",
        ),
        Ok(FederationAttributeOwnerPurgeOutcome::AuthorityChanged) => {
            json_status(StatusCode::CONFLICT, "federation authority changed; retry")
        }
        Err(_) => json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    }
}

/// `PUT /admin/users/{id}/attributes?namespace=<uri>`(spec 007 §6.1,C8.12):整命名空间**乐观锁全量替换**。
///
/// - tenant admin 认证 + SelfHosted only(SaaS 恒 404,与其它 user 管理面一致)。
/// - body = JSON object,值 MUST 为字符串(非字符串 400);`{}` = 清空该 namespace;**零长 body = 400**(区别于 `{}`)。
/// - namespace(query)MUST 为 RFC 8707 绝对 URI(非 URI 400)——否则永远匹配不上 RS token 的 `aud`。
/// - `If-Match` header = 期望 revision(缺省 0 = 首写该 namespace);不符 → 409(乐观锁,防丢更新)。
/// - PutAttrOutcome:NotFound 404 / RevisionConflict 409 / Tombstoned 409 / TooLarge 413。
/// - AS **不解释** value 语义;每次写落结构化审计。
#[utoipa::path(put, path = "/admin/users/{id}/attributes", tag = "admin",
    params(
        ("id" = String, Path),
        ("namespace" = String, Query, description = "RS 命名空间(= resource/aud,RFC 8707 绝对 URI)。**query 参数**——URI 含 `/` 经 path 段会被 API Gateway 误当路径分隔,故走 query"),
        ("if-match" = Option<String>, Header, description = "期望 revision(乐观锁;缺省 0 = 首写该 namespace)")
    ),
    request_body(content = std::collections::BTreeMap<String, String>, content_type = "application/json"),
    responses(
        (status = 200, description = "已全量替换该 namespace 属性(返回新 revision)"),
        (status = 400, description = "缺/非 URI namespace / 值非字符串 / 零长 body"),
        (status = 401, description = "admin 认证失败"),
        (status = 404, description = "用户不存在 / SaaS 下不可用"),
        (status = 409, description = "revision 冲突(If-Match 不符)/ Tombstoned 用户"),
        (status = 413, description = "attributes 总大小超 4096B 上限"),
        (status = 503, description = "namespace registry、用户存储或审计依赖不可用")))]
pub async fn put_user_attributes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<AttrNamespaceQuery>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    use crate::ports::PutAttrOutcome;
    let namespace = q.namespace;
    // spec 007 C8.12:属性 API **仅 SelfHosted**,SaaS 恒 404(独立于 user 管理 gate,评审 codex #5:
    // P0-D 放宽 user gate 时属性 API 不得随之开放——其跨租户隔离/RBAC 未按 SaaS 验收)。
    if saas_attributes_disabled(&state) {
        return json_status(StatusCode::NOT_FOUND, "not available in SaaS form");
    }
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    let tenant = admin.storage_tenant();
    let expected_revision: u64 = headers
        .get(axum::http::header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().trim_matches('"').parse().ok())
        .unwrap_or(0);
    // namespace 必须是 RFC 8707 绝对 URI(否则永远匹配不上 token aud)。
    if !crate::attribute_namespace::validate_namespace_uri(&namespace) {
        audit_user_attribute_write(
            &state,
            tenant,
            &admin.audit_identity(),
            &id,
            attribute_write_operation_id(
                &state.server_secret,
                &namespace,
                expected_revision,
                std::iter::empty::<&str>(),
            ),
            crate::security_event::SecurityEventOutcome::Denied,
        )
        .await;
        return json_status(StatusCode::BAD_REQUEST, "namespace must be an absolute URI");
    }
    // 零长 body → 400(区别于 `{}` 清空);非空则 MUST 是 {string: string} object。
    if body.is_empty() {
        audit_user_attribute_write(
            &state,
            tenant,
            &admin.audit_identity(),
            &id,
            attribute_write_operation_id(
                &state.server_secret,
                &namespace,
                expected_revision,
                std::iter::empty::<&str>(),
            ),
            crate::security_event::SecurityEventOutcome::Denied,
        )
        .await;
        return json_status(StatusCode::BAD_REQUEST, "empty body (use {} to clear)");
    }
    let rejected_payload_operation_id = attribute_write_operation_id(
        &state.server_secret,
        &namespace,
        expected_revision,
        std::iter::empty::<&str>(),
    );
    let parsed: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            audit_user_attribute_write(
                &state,
                tenant,
                &admin.audit_identity(),
                &id,
                rejected_payload_operation_id,
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return json_status(StatusCode::BAD_REQUEST, "body must be a JSON object");
        }
    };
    let obj = match parsed.as_object() {
        Some(o) => o,
        None => {
            audit_user_attribute_write(
                &state,
                tenant,
                &admin.audit_identity(),
                &id,
                rejected_payload_operation_id,
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return json_status(StatusCode::BAD_REQUEST, "body must be a JSON object");
        }
    };
    let mut kv = std::collections::BTreeMap::new();
    for (k, v) in obj {
        match v.as_str() {
            Some(s) => {
                kv.insert(k.clone(), s.to_string());
            }
            None => {
                audit_user_attribute_write(
                    &state,
                    tenant,
                    &admin.audit_identity(),
                    &id,
                    attribute_write_operation_id(
                        &state.server_secret,
                        &namespace,
                        expected_revision,
                        obj.keys(),
                    ),
                    crate::security_event::SecurityEventOutcome::Denied,
                )
                .await;
                return json_status(StatusCode::BAD_REQUEST, "attribute values must be strings");
            }
        }
    }
    let operation_id = attribute_write_operation_id(
        &state.server_secret,
        &namespace,
        expected_revision,
        kv.keys(),
    );
    let write = match state
        .put_user_attributes_authorized(tenant, &id, &namespace, kv.clone(), expected_revision)
        .await
    {
        Ok(write) => write,
        Err(_) => {
            audit_user_attribute_write(
                &state,
                tenant,
                &admin.audit_identity(),
                &id,
                operation_id,
                crate::security_event::SecurityEventOutcome::Failure,
            )
            .await;
            return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable");
        }
    };
    let canonical_namespace = write.canonical_namespace;
    let outcome = write.outcome;
    audit_user_attribute_write(
        &state,
        tenant,
        &admin.audit_identity(),
        &id,
        operation_id,
        if matches!(outcome, PutAttrOutcome::Ok { .. }) {
            crate::security_event::SecurityEventOutcome::Success
        } else {
            crate::security_event::SecurityEventOutcome::Denied
        },
    )
    .await;
    match outcome {
        PutAttrOutcome::Ok { revision } => {
            // 审计(§1.4 口径):不落 value 明文,只记 keys 摘要(namespace + key 集合 + 新 revision)。
            let key_summary: Vec<&String> = kv.keys().collect();
            eprintln!(
                "ADMIN_USER_ATTR_PUT actor={} user_id={} namespace={} keys={:?} new_revision={}",
                admin.audit_identity(),
                id,
                canonical_namespace,
                key_summary,
                revision
            );
            Json(serde_json::json!({ "revision": revision })).into_response()
        }
        PutAttrOutcome::NotFound => json_status(StatusCode::NOT_FOUND, "not found"),
        PutAttrOutcome::RevisionConflict { current } => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "revision_conflict",
                "current_revision": current
            })),
        )
            .into_response(),
        PutAttrOutcome::Tombstoned => json_status(
            StatusCode::CONFLICT,
            "user tombstoned (cannot write attributes)",
        ),
        PutAttrOutcome::NamespaceBlocked => json_status(
            StatusCode::CONFLICT,
            "namespace audience is blocked or retired",
        ),
        PutAttrOutcome::OwnershipConflict => json_status(
            StatusCode::CONFLICT,
            "federation-owned attributes cannot be changed by an admin write",
        ),
        PutAttrOutcome::TooLarge => (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({
                "error": "attributes_too_large",
                "max_bytes": crate::ports::ATTRIBUTES_MAX_BYTES
            })),
        )
            .into_response(),
    }
}

// ============ BYOD 域名绑定管理面(spec 010 §5.4 / C8.1b,P3)============
//
// admin 把 RS 自带域名绑定到 (resource_id, owning tenant),数据面 well-known PRM 据此托管(投放方式 b)。
// **权威绑定 = 全局 domain map 行**(pk=归一小写 domain,conditional put 保 fleet 全局唯一);client 上
// 的 prm_domains 仅供反查/级联展示。**真威胁 = 跨租户 issuer 误导**,防线全在此登记时(域名归属 + 全局唯一
// + issuer-origin 护栏),非请求时(见 prm.rs well-known handler 注释)。

/// 域名是否落在 **AS issuer origin** 上(注册期护栏,评审 H2,把 C8.1 从数据属性升级为代码属性)。
/// 命中即 MUST 拒登记——否则该域名的 well-known 会在 issuer origin 返 PRM,破 C8.1。
/// - SelfHosted:== `configured_host`。
/// - SaaS:== `control_host` / == `zone`(apex)/ 任何 `*.zone` 子域(不止单层租户子域,含嵌套)。
///
/// `pub(crate)`:well-known handler 亦在**查询时**复用(评审 L1,防登记后 zone 重配置使旧绑定落 issuer origin)。
pub(crate) fn is_issuer_origin_host(form: &Form, domain: &str) -> bool {
    match form {
        Form::SelfHosted { configured_host } => domain == configured_host,
        Form::Saas { zone, control_host } => {
            domain == control_host || domain == zone || domain.ends_with(&format!(".{zone}"))
        }
    }
}

/// BYOD 域名基本合法性(pk 用):非空、纯 ASCII 小写域名字符 [a-z0-9.-]、含点(FQDN)、无 scheme/端口/斜杠/空白。
/// **逐标签 ≤63 且不以连字符开头/结尾**(评审 L4,与 discovery::validate_host 同口径;SelfHosted 域名不过 derive,
/// 靠此挡畸形标签)。严格归属证明(DNS TXT / ACM 挑战)= P3 独立后续;本切片 = 运维已验证的域名(operator-verified)。
fn looks_like_prm_domain(d: &str) -> bool {
    if d.is_empty()
        || d.len() > 253
        || !d.contains('.')
        || d.starts_with('.')
        || d.ends_with('.')
        || d.contains("..")
        || !d
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'))
    {
        return false;
    }
    // 逐标签:非空、≤63、不以连字符开头/结尾(DNS 规则)。
    d.split('.')
        .all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-'))
}

#[derive(Deserialize, ToSchema)]
pub struct DomainBindRequest {
    /// RS 自带域名(将归一小写作 pk;CNAME 到本系统 CloudFront)。
    pub domain: String,
    /// 该域名 PRM 的 `resource` 字段;MUST ∈ 该 client 的 `resource_ids`(绑到 RS 实际拥有的资源)。
    pub resource_id: String,
    /// 拥有该绑定的 RS client_id(须已存在;删 client 时级联清本行)。
    pub client_id: String,
    /// 归属 **SaaS 租户标签**(PRM issuer 由它 + form 重建 = `https://{tenant_id}.{zone}`)。
    /// SelfHosted MUST 省略或为 `"default"`(issuer 恒 configured_host)。
    #[serde(default)]
    pub tenant_id: Option<String>,
}

/// `POST /admin/domains`:登记一条 BYOD 域名绑定(admin 认证,C8.1b)。全局唯一 conditional-write。
#[utoipa::path(post, path = "/admin/domains", tag = "admin",
    request_body = DomainBindRequest,
    responses((status = 201, description = "已登记"),
        (status = 400, description = "BYOD 未启用 / 域名非法 / issuer-origin 护栏拒 / resource 非该 client 所属"),
        (status = 401), (status = 403, description = "请求 tenant 不属于已认证租户"),
        (status = 409, description = "该域名已被(他人)登记(全局唯一冲突)")))]
pub async fn bind_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DomainBindRequest>,
) -> impl IntoResponse {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    if let Some(claimed) = req.tenant_id.as_deref() {
        if let Err(resp) = admin.require_tenant(&state, claimed).await {
            return resp;
        }
    }
    // BYOD 未启用 → 拒登记(避免登记进未上线数据面;flag 开才启用,与 well-known 短路同源)。
    if !state.byod_enabled {
        return json_status(StatusCode::BAD_REQUEST, "BYOD not enabled");
    }
    let tenant = admin.storage_tenant();
    let domain = req.domain.trim().to_ascii_lowercase();
    if !looks_like_prm_domain(&domain) {
        return json_status(StatusCode::BAD_REQUEST, "invalid domain");
    }
    // 归属 tenant_id 只来自认证上下文；body 仅作一致性断言。
    let owner_tenant_id = admin.tenant_id().to_string();
    // 护栏 A(评审 H2):拒 issuer-origin host——否则 PRM 出现在 AS issuer origin,破 C8.1。
    if is_issuer_origin_host(&state.form, &domain) {
        return json_status(
            StatusCode::BAD_REQUEST,
            "domain 是 AS issuer origin(configured_host/control_host/zone 子域),不可登记为 BYOD 域名",
        );
    }
    // 护栏 B:owner tenant_id MUST 能重建出合法 issuer(fail-closed:重建不出则拒,不留会 404 的死绑定)。
    match issuer_for_tenant(&state.form, &owner_tenant_id) {
        Ok(_) => {}
        Err(IssuerError::ControlPlaneHost(_)) => {
            return json_status(StatusCode::BAD_REQUEST, "tenant_id 重建为控制面 host,拒")
        }
        Err(_) => return json_status(StatusCode::BAD_REQUEST, "tenant_id 无法重建合法 issuer"),
    }
    // client 须存在;resource_id MUST ∈ 该 client 的 resource_ids(绑到 RS 实际拥有的资源,防绑他人 resource)。
    let client = match state.clients.get(tenant, &req.client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return json_status(StatusCode::BAD_REQUEST, "client_id 不存在"),
        Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    };
    if !client.resource_ids.iter().any(|r| r == &req.resource_id) {
        return json_status(
            StatusCode::BAD_REQUEST,
            "resource_id 不在该 client 的 resource_ids 内",
        );
    }
    let binding = DomainBinding {
        domain: domain.clone(),
        resource_id: req.resource_id.clone(),
        tenant_id: owner_tenant_id,
        client_id: req.client_id.clone(),
    };
    // 全局唯一 conditional put(attribute_not_exists):已被(他人)登记 → 409(先到先得,防跨租户劫持)。
    match state.domain_map.put_if_absent(binding).await {
        Ok(true) => {}
        Ok(false) => return json_status(StatusCode::CONFLICT, "domain already registered"),
        Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    }
    // 反查便利:把 domain 追加进 client.prm_domains(权威仍是 map 行;失败不回滚——map 行已是权威,best-effort)。
    let mut updated = client;
    if !updated.prm_domains.contains(&domain) {
        updated.prm_domains.push(domain.clone());
        let client_secret_version = updated.client_secret_credentials.version;
        let registration_token_version = updated.registration_token_credentials.version;
        let _ = state
            .clients
            .put_if_credential_versions(
                tenant,
                updated,
                client_secret_version,
                registration_token_version,
            )
            .await;
    }
    eprintln!(
        "ADMIN_DOMAIN_BIND actor={} domain={} resource_id={} client_id={}",
        admin.audit_identity(),
        domain,
        req.resource_id,
        req.client_id
    );
    json_status(StatusCode::CREATED, "bound")
}

/// `DELETE /admin/domains/{domain}`:解绑一条 BYOD 域名(admin 认证)。CAS on owner 原子删,防换租户悬空。
#[utoipa::path(delete, path = "/admin/domains/{domain}", tag = "admin",
    params(("domain" = String, Path)),
    responses((status = 200, description = "已解绑(不存在也幂等 200)"), (status = 401),
        (status = 403, description = "域名绑定不属于已认证租户")))]
pub async fn unbind_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    let admin = match TenantAdminContext::authenticate(&state, &headers, AdminAction::Write).await {
        Ok(admin) => admin,
        Err(resp) => return resp,
    };
    let tenant = admin.storage_tenant();
    let domain = domain.trim().to_ascii_lowercase();
    // 先取 owner(map 行权威),再 CAS on owner 删(防误删/换租户悬空返错 issuer)。不存在 → 幂等 200。
    let binding = match state.domain_map.get(&domain).await {
        Ok(Some(binding)) => binding,
        Ok(None) => return json_status(StatusCode::OK, "unbound"),
        Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    };
    if let Err(resp) = admin.require_tenant(&state, &binding.tenant_id).await {
        return resp;
    }
    let owner = binding.client_id;
    match state.domain_map.delete_if_owner(&domain, &owner).await {
        Ok(true) => {}
        // Ok(false):get 与 delete 之间该域名被解绑后由他人重绑(owner 已变)——CAS 正确保住了新 owner 的行。
        // 不谎报 "unbound"(评审 Kiro nit):返 409 表"该域名现属他人,未动"。
        Ok(false) => return json_status(StatusCode::CONFLICT, "domain rebound to another owner"),
        Err(_) => return json_status(StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    }
    // 反查便利:从 owner client 的 prm_domains 摘除(best-effort;权威 map 行已删)。
    if let Ok(Some(mut c)) = state.clients.get(tenant, &owner).await {
        if c.prm_domains.iter().any(|d| d == &domain) {
            c.prm_domains.retain(|d| d != &domain);
            let client_secret_version = c.client_secret_credentials.version;
            let registration_token_version = c.registration_token_credentials.version;
            let _ = state
                .clients
                .put_if_credential_versions(
                    tenant,
                    c,
                    client_secret_version,
                    registration_token_version,
                )
                .await;
        }
    }
    eprintln!(
        "ADMIN_DOMAIN_UNBIND actor={} domain={} client_id={}",
        admin.audit_identity(),
        domain,
        owner
    );
    json_status(StatusCode::OK, "unbound")
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(control_tenants))
        .routes(routes!(control_tenant_keys))
        .routes(routes!(control_tenant_key_command))
        .routes(routes!(overview))
        .routes(routes!(list_messages))
        .routes(routes!(list_clients, create_client))
        .routes(routes!(get_client, delete_client, patch_client, put_client))
        .routes(routes!(rotate_client_credential))
        .routes(routes!(cutover_client_credential))
        .routes(routes!(revoke_client_credential))
        .routes(routes!(
            list_initial_access_tokens,
            create_initial_access_token
        ))
        .routes(routes!(revoke_initial_access_token))
        .routes(routes!(create_workload_trust))
        .routes(routes!(list_workload_trust))
        .routes(routes!(put_federation_idp))
        .routes(routes!(list_federation_idps))
        .routes(routes!(delete_federation_idp))
        .routes(routes!(list_users))
        .merge(
            OpenApiRouter::new()
                .routes(routes!(create_user))
                .layer(axum::middleware::from_fn(crate::invitation::add_no_store)),
        )
        .routes(routes!(list_security_events))
        .routes(routes!(get_user, delete_user))
        .routes(routes!(disable_user))
        .routes(routes!(enable_user))
        .routes(routes!(reset_user_password))
        .routes(routes!(put_user_attributes))
        .routes(routes!(purge_federated_attribute_owner))
        .routes(routes!(bind_domain))
        .routes(routes!(unbind_domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn admin_reset_request(
        router: &axum::Router,
        user_id: &str,
        temporary_password: &str,
    ) -> axum::response::Response {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;

        router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/admin/users/{user_id}/reset-password"))
                    .header("host", "localhost")
                    .header("authorization", "Bearer dev-admin-token-not-for-prod")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "temporary_password": temporary_password
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn staged_admin_reset_retry_resumes_the_exact_owner_without_rewriting_version() {
        let state = AppState::dev("localhost");
        let user_id = "user:staged-admin-reset@example.com";
        let password = "Staged replacement password 123!";
        let operation_id = "staged-admin-reset-owner";
        let now = crate::token::current_unix_secs_pub();
        state
            .users
            .create_or_get_by_email("", "staged-admin-reset@example.com", user_id, now)
            .await
            .unwrap();
        assert_eq!(
            state
                .users
                .begin_admin_credential_change("", user_id, 0, operation_id, now)
                .await
                .unwrap(),
            crate::ports::CredentialChangeStart::Started { epoch: 1 }
        );
        assert_eq!(
            state
                .passwords
                .stage_admin_reset(
                    &state.users,
                    crate::ports::FencedPasswordMutation {
                        tenant: "",
                        user_id,
                        password_hash: agent_auth_authn::password::hash_password(password).unwrap(),
                        expected_version: None,
                        credential_epoch: 1,
                        updated_at: now,
                    },
                    crate::ports::CredentialChangeOwner {
                        epoch: 1,
                        operation_id,
                    },
                )
                .await
                .unwrap(),
            Some(1)
        );

        let (router, _) = crate::build_router(state.clone());
        let response = admin_reset_request(&router, user_id, password).await;
        assert_eq!(response.status(), StatusCode::OK);

        let user = state.users.get_by_id("", user_id).await.unwrap().unwrap();
        assert_eq!(user.credential_epoch, 1);
        assert!(!user.revocation_pending);
        let credential = state.passwords.get("", user_id).await.unwrap().unwrap();
        assert_eq!(credential.version, 1);
        assert!(!credential.revocation_pending);
        assert!(credential.credential_change_id.is_none());
    }

    #[tokio::test]
    async fn stale_admin_retry_cannot_claim_or_abort_a_newer_self_service_owner() {
        let state = AppState::dev("localhost");
        let user_id = "user:stale-admin-reset@example.com";
        let password = "Stale staged replacement 123!";
        let admin_operation = "stale-admin-reset-owner";
        let self_service_operation = "newer-self-service-owner";
        let now = crate::token::current_unix_secs_pub();
        let stale_started_at =
            now.saturating_sub(crate::user_gate::CREDENTIAL_CHANGE_LEASE_SECS + 1);
        state
            .users
            .create_or_get_by_email(
                "",
                "stale-admin-reset@example.com",
                user_id,
                stale_started_at,
            )
            .await
            .unwrap();
        assert_eq!(
            state
                .users
                .begin_admin_credential_change("", user_id, 0, admin_operation, stale_started_at,)
                .await
                .unwrap(),
            crate::ports::CredentialChangeStart::Started { epoch: 1 }
        );
        assert_eq!(
            state
                .passwords
                .stage_admin_reset(
                    &state.users,
                    crate::ports::FencedPasswordMutation {
                        tenant: "",
                        user_id,
                        password_hash: agent_auth_authn::password::hash_password(password).unwrap(),
                        expected_version: None,
                        credential_epoch: 1,
                        updated_at: stale_started_at,
                    },
                    crate::ports::CredentialChangeOwner {
                        epoch: 1,
                        operation_id: admin_operation,
                    },
                )
                .await
                .unwrap(),
            Some(1)
        );
        assert!(state
            .users
            .recover_expired_credential_change(
                "",
                user_id,
                1,
                now.saturating_sub(crate::user_gate::CREDENTIAL_CHANGE_LEASE_SECS),
                now,
            )
            .await
            .unwrap());
        assert_eq!(
            state
                .users
                .begin_credential_change("", user_id, 1, self_service_operation, now)
                .await
                .unwrap(),
            crate::ports::CredentialChangeStart::Started { epoch: 2 }
        );

        let (router, _) = crate::build_router(state.clone());
        let response = admin_reset_request(&router, user_id, password).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let user = state.users.get_by_id("", user_id).await.unwrap().unwrap();
        assert_eq!(user.credential_epoch, 2);
        assert!(user.revocation_pending);
        let credential = state.passwords.get("", user_id).await.unwrap().unwrap();
        assert_eq!(credential.version, 1);
        assert!(credential.revocation_pending);
        assert_eq!(
            credential.credential_change_id.as_deref(),
            Some(admin_operation)
        );
        assert!(!state
            .users
            .abort_admin_credential_change(
                "",
                user_id,
                crate::ports::CredentialChangeOwner {
                    epoch: 2,
                    operation_id: admin_operation,
                },
                now + 1,
            )
            .await
            .unwrap());
        assert!(state
            .users
            .complete_credential_change(
                "",
                user_id,
                crate::ports::CredentialChangeOwner {
                    epoch: 2,
                    operation_id: self_service_operation,
                },
                now + 1,
            )
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn admin_reset_does_not_recover_a_legacy_markerless_user_fence() {
        let state = AppState::dev("localhost");
        let user_id = "user:legacy-markerless-fence@example.com";
        let now = crate::token::current_unix_secs_pub();
        let stale_started_at =
            now.saturating_sub(crate::user_gate::CREDENTIAL_CHANGE_LEASE_SECS + 1);
        state
            .users
            .create_or_get_by_email(
                "",
                "legacy-markerless-fence@example.com",
                user_id,
                stale_started_at,
            )
            .await
            .unwrap();
        assert!(matches!(
            state
                .users
                .begin_disable("", user_id, stale_started_at)
                .await
                .unwrap(),
            crate::ports::DisableStart::Ready { epoch: 1, .. }
        ));

        let (router, _) = crate::build_router(state.clone());
        let response =
            admin_reset_request(&router, user_id, "Legacy replacement password 123!").await;
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let user = state.users.get_by_id("", user_id).await.unwrap().unwrap();
        assert_eq!(user.status, UserStatus::Disabled);
        assert_eq!(user.credential_epoch, 1);
        assert!(user.revocation_pending);
        assert!(state.passwords.get("", user_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn expired_admin_reset_fence_recovers_for_a_disabled_user() {
        let state = AppState::dev("localhost");
        let user_id = "user:disabled-stale-admin-reset@example.com";
        state
            .users
            .create_or_get_by_email("", "disabled-stale-admin-reset@example.com", user_id, 1)
            .await
            .unwrap();
        state
            .users
            .set_status("", user_id, UserStatus::Disabled, 2)
            .await
            .unwrap();
        let stale_started_at = crate::token::current_unix_secs_pub()
            .saturating_sub(crate::user_gate::CREDENTIAL_CHANGE_LEASE_SECS + 1);
        assert_eq!(
            state
                .users
                .begin_admin_credential_change(
                    "",
                    user_id,
                    0,
                    "abandoned-admin-reset",
                    stale_started_at,
                )
                .await
                .unwrap(),
            crate::ports::CredentialChangeStart::Started { epoch: 1 }
        );

        let (router, _) = crate::build_router(state.clone());
        let response = admin_reset_request(&router, user_id, "Replacement password 123!").await;
        assert_eq!(response.status(), StatusCode::OK);

        let user = state.users.get_by_id("", user_id).await.unwrap().unwrap();
        assert_eq!(user.status, UserStatus::Disabled);
        assert_eq!(user.credential_epoch, 2);
        assert!(!user.revocation_pending);
        let credential = state.passwords.get("", user_id).await.unwrap().unwrap();
        assert!(credential.must_change);
        assert!(!credential.revocation_pending);
    }

    fn client_with_uris(uris: &[&str], sector: Option<&str>) -> ClientRecord {
        ClientRecord {
            client_id: "c1".into(),
            redirect_uris: uris.iter().map(|s| s.to_string()).collect(),
            application_type: None,
            token_endpoint_auth_method: "none".into(),
            client_secret: None,
            client_secret_credentials: Default::default(),
            jwks: None,
            jwks_uri: None,
            token_endpoint_auth_signing_alg: None,
            default_resource: None,
            introspect_enabled: false,
            resource_ids: vec![],
            post_logout_redirect_uris: vec![],
            reg_token_hash: None,
            registration_token_credentials: Default::default(),
            client_type: None,
            id_token_signed_response_alg: None,
            oidc_sector_identifier: sector.map(String::from),
            allowed_resources: vec![],
            allowed_scopes: vec![],
            redirect_mode: None,
            created_at: 0,
            last_used_day: None,
            authority_revision: 0,
            tombstoned_at: None,
            backchannel_token_delivery_mode: None,
            backchannel_client_notification_endpoint: None,
            require_dpop: false,
            prm_domains: vec![],
        }
    }

    // F2/F3:PATCH 改 redirect_uris 后 oidc_sector 必重算(不残留旧值)。
    #[test]
    fn apply_patch_recomputes_oidc_sector() {
        // 旧:单 host,持久 sector=app.example.com。PATCH 改为另一单 host → sector 应随之变。
        let old = client_with_uris(&["https://app.example.com/cb"], Some("app.example.com"));
        let p = ClientPatch {
            redirect_uris: Some(vec!["https://other.example.com/cb".into()]),
            ..Default::default()
        };
        let updated = apply_patch(old, &p);
        assert_eq!(
            updated.oidc_sector_identifier.as_deref(),
            Some("other.example.com"),
            "PATCH 改 host 后 sector 必更新为新 host(不残留旧值)"
        );
    }

    // F2/F3:PATCH 改为多 host → sector 归零(None),绕过多 host 拒绝的旧值被清。
    #[test]
    fn apply_patch_multi_host_clears_sector() {
        let old = client_with_uris(&["https://app.example.com/cb"], Some("app.example.com"));
        let p = ClientPatch {
            redirect_uris: Some(vec![
                "https://a.example.com/cb".into(),
                "https://b.example.com/cb".into(),
            ]),
            ..Default::default()
        };
        let updated = apply_patch(old, &p);
        assert_eq!(
            updated.oidc_sector_identifier, None,
            "PATCH 改为多 host 后 sector 必归 None(旧单 host 值不得残留)"
        );
    }

    // F2/F3:PATCH 不带 redirect_uris → 从当前(未变的)redirect_uris 归一(保持一致)。
    #[test]
    fn apply_patch_no_uri_change_keeps_consistent_sector() {
        let old = client_with_uris(&["https://app.example.com/cb"], Some("stale.example.com"));
        let p = ClientPatch::default();
        let updated = apply_patch(old, &p);
        // 即便旧持久值是 stale,重算后按当前 redirect_uris 归一为正确值。
        assert_eq!(
            updated.oidc_sector_identifier.as_deref(),
            Some("app.example.com"),
            "重算修正了残留的 stale sector"
        );
    }

    #[test]
    fn apply_patch_normalizes_unknown_application_type_to_web() {
        let mut old = client_with_uris(&["https://app.example.com/cb"], Some("app.example.com"));
        old.application_type = Some("future-value".into());

        let updated = apply_patch(old, &ClientPatch::default());

        assert_eq!(updated.application_type.as_deref(), Some("web"));
    }

    #[test]
    fn apply_patch_repeated_non_private_method_preserves_general_jwks_uri() {
        let mut old = client_with_uris(&["https://app.example.com/cb"], Some("app.example.com"));
        old.token_endpoint_auth_method = "client_secret_basic".into();
        old.jwks_uri = Some("https://keys.example.com/client.jwks".into());
        let patch = ClientPatch {
            token_endpoint_auth_method: Some("client_secret_basic".into()),
            ..Default::default()
        };

        let updated = apply_patch(old, &patch);

        assert_eq!(
            updated.jwks_uri.as_deref(),
            Some("https://keys.example.com/client.jwks")
        );
        assert!(updated.jwks.is_none());
        assert!(updated.token_endpoint_auth_signing_alg.is_none());
    }

    // C8.1b 注册期护栏:issuer-origin host 判定(SelfHosted / SaaS 各种越界形态)。
    #[test]
    fn is_issuer_origin_host_selfhosted() {
        let f = Form::SelfHosted {
            configured_host: "auth.customer.example".into(),
        };
        assert!(is_issuer_origin_host(&f, "auth.customer.example"));
        assert!(!is_issuer_origin_host(&f, "mcp.acme.example"));
        // 不误伤仅后缀相似的域名。
        assert!(!is_issuer_origin_host(&f, "evil-auth.customer.example"));
    }

    #[test]
    fn is_issuer_origin_host_saas() {
        let f = Form::Saas {
            zone: "aws.example.com".into(),
            control_host: "c.aws.example.com".into(),
        };
        assert!(is_issuer_origin_host(&f, "c.aws.example.com")); // control_host
        assert!(is_issuer_origin_host(&f, "aws.example.com")); // zone apex
        assert!(is_issuer_origin_host(&f, "t1.aws.example.com")); // 租户子域
        assert!(is_issuer_origin_host(&f, "a.t2.aws.example.com")); // 嵌套子域
        assert!(!is_issuer_origin_host(&f, "mcp.acme.example")); // 真 BYOD 域名
                                                                 // 后缀相似但非子域(无分隔点)→ 不误判。
        assert!(!is_issuer_origin_host(&f, "evilaws.example.com"));
    }

    #[test]
    fn prm_domain_shape_validation() {
        assert!(looks_like_prm_domain("mcp.acme.example"));
        assert!(!looks_like_prm_domain("")); // 空
        assert!(!looks_like_prm_domain("localhost")); // 无点
        assert!(!looks_like_prm_domain("MCP.ACME.EXAMPLE")); // 大写(应先归一)
        assert!(!looks_like_prm_domain("https://mcp.acme.example")); // 带 scheme
        assert!(!looks_like_prm_domain("mcp.acme.example:443")); // 带端口
        assert!(!looks_like_prm_domain("mcp.acme.example/x")); // 带路径
        assert!(!looks_like_prm_domain(".mcp.acme.example")); // 前导点
        assert!(!looks_like_prm_domain("mcp..acme.example")); // 连续点
                                                              // 逐标签 ≤63 + 不以连字符开头/结尾(评审 L4)。
        assert!(!looks_like_prm_domain("-mcp.acme.example")); // 标签首连字符
        assert!(!looks_like_prm_domain("mcp-.acme.example")); // 标签尾连字符
        assert!(!looks_like_prm_domain(&format!(
            "{}.acme.example",
            "a".repeat(64)
        ))); // 标签 >63
        assert!(looks_like_prm_domain(&format!(
            "{}.acme.example",
            "a".repeat(63)
        ))); // 标签 =63 ok
    }

    // F2/F3:PUT 全替换 redirect_uris 后同样重算 sector。
    #[test]
    fn apply_put_recomputes_oidc_sector() {
        let old = client_with_uris(&["https://app.example.com/cb"], Some("app.example.com"));
        let p = crate::register::ClientPut {
            redirect_uris: vec!["https://new.example.com/cb".into()],
            application_type: None,
            token_endpoint_auth_method: None,
            require_dpop: false,
            jwks: None,
            jwks_uri: None,
            token_endpoint_auth_signing_alg: None,
            default_resource: None,
            post_logout_redirect_uris: vec![],
            redirect_mode: None,
            confirm_downgrade: false,
        };
        let updated = apply_put(old, &p);
        assert_eq!(
            updated.oidc_sector_identifier.as_deref(),
            Some("new.example.com")
        );
    }
}
